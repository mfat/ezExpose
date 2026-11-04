// Package cloudflare manages the one DNS record that points a name at this
// machine. It only ever changes a record its own install created, marked by a
// comment holding that install's ID.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	apiBase = "https://api.cloudflare.com/client/v4"
	// marker starts the comment that marks a record as ours. Comments have no
	// effect on DNS answers.
	marker = "Managed by ezExpose, install "
	ttl    = 60
)

// TokenURL opens Cloudflare's token page and tries to fill in the permissions.
// Cloudflare doesn't always keep them, so show TokenSteps too.
const TokenURL = "https://dash.cloudflare.com/profile/api-tokens?" +
	"permissionGroupKeys=%5B%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C" +
	"%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22edit%22%7D%5D" +
	"&accountId=%2A&zoneId=all&name=ezExpose"

// TokenSteps says how to make a token by hand, for when TokenURL opens on the
// list of templates instead.
const TokenSteps = `1. Open https://dash.cloudflare.com/profile/api-tokens and click Create Token.
2. Next to "Edit zone DNS", click Use template.
3. Under Permissions, click Add more and choose Zone, Zone, Read.
4. Under Zone Resources, choose Include, Specific zone, and your domain.
5. Click Continue to summary, then Create Token, and copy it.`

// Client talks to the Cloudflare API with one token, for one install.
type Client struct {
	base  string
	token string
	owner string
	http  *http.Client
}

var validOwner = regexp.MustCompile(`^[a-z0-9]{16,64}$`)

// NewOwner returns an install ID for New. Save it with the install: it's what
// tells this install's records from another's, even for the same name.
func NewOwner() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// New returns a client for token that acts only on records owner created.
func New(token, owner string) (Client, error) {
	if !validOwner.MatchString(owner) {
		return Client{}, errors.New("an install ID must be 16 to 64 lowercase letters and digits")
	}
	return Client{base: apiBase, token: token, owner: owner, http: &http.Client{Timeout: 20 * time.Second}}, nil
}

func (c Client) comment() string { return marker + c.owner }

// ours is false for every record when the client has no owner, so a zero Client
// can't change anything.
func (c Client) ours(r record) bool { return c.owner != "" && r.Comment == c.comment() }

type record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

type reply struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Info struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (c Client) do(ctx context.Context, method, path string, body any) (reply, error) {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return reply{}, err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, payload)
	if err != nil {
		return reply{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	var r reply
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return reply{}, fmt.Errorf("cloudflare answered %s", resp.Status)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return reply{}, errors.New("Cloudflare refused that token. It needs Zone:Read and DNS:Edit for this domain")
	}
	if !r.Success {
		if len(r.Errors) > 0 {
			return reply{}, fmt.Errorf("cloudflare: %s", r.Errors[0].Message)
		}
		return reply{}, fmt.Errorf("cloudflare answered %s", resp.Status)
	}
	return r, nil
}

func (c Client) call(ctx context.Context, method, path string, body, into any) error {
	r, err := c.do(ctx, method, path, body)
	if err != nil || into == nil {
		return err
	}
	return json.Unmarshal(r.Result, into)
}

// Zone finds the zone holding host, trying each parent name in turn.
func (c Client) Zone(ctx context.Context, host string) (string, error) {
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var zones []struct {
			ID string `json:"id"`
		}
		if err := c.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(name), nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("this token can't see a Cloudflare domain containing %s", host)
}

// ErrNotOurs means a record ezExpose didn't create is in the way. Nothing was
// changed when it's returned.
var ErrNotOurs = errors.New("so it was left alone")

// records returns host's address records, A and AAAA, from every page.
func (c Client) records(ctx context.Context, zone, host string) ([]record, error) {
	var all, found []record
	for page := 1; ; page++ {
		q := url.Values{"name.exact": {host}, "per_page": {"100"}, "page": {fmt.Sprint(page)}}
		r, err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		var batch []record
		if err := json.Unmarshal(r.Result, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if page >= r.Info.TotalPages {
			break
		}
	}
	for _, r := range all {
		if !strings.EqualFold(r.Name, host) {
			continue
		}
		switch r.Type {
		case "A", "AAAA":
			found = append(found, r)
		case "CNAME":
			return nil, fmt.Errorf("%s is an alias (CNAME) for %s. Remove the alias first, %w", host, r.Content, ErrNotOurs)
		}
	}
	return found, nil
}

func ofType(records []record, kind string) []record {
	var out []record
	for _, r := range records {
		if r.Type == kind {
			out = append(out, r)
		}
	}
	return out
}

// Point makes host resolve to ip. A record it didn't create is left alone. owned
// is true when the record is this install's, false when someone else's record
// already says the same thing: that one can be used, but never deleted.
func (c Client) Point(ctx context.Context, zone, host, ip string) (owned bool, err error) {
	if c.owner == "" {
		return false, errors.New("this client has no install ID; use New")
	}
	all, err := c.records(ctx, zone, host)
	if err != nil {
		return false, err
	}
	kind := "A"
	if addr := net.ParseIP(ip); addr == nil {
		return false, fmt.Errorf("%q isn't an address", ip)
	} else if addr.To4() == nil {
		kind = "AAAA"
	}
	want := record{Type: kind, Name: host, Content: ip, TTL: ttl, Comment: c.comment()}
	path := "/zones/" + zone + "/dns_records"
	// Decide before changing anything, so a conflict leaves every record as it was.
	found := ofType(all, kind)
	var change func() error
	switch {
	case len(found) == 0:
		owned, change = true, func() error { return c.call(ctx, http.MethodPost, path, want, nil) }
	case len(found) == 1 && c.ours(found[0]):
		owned = true
		if found[0].Content != ip {
			id := found[0].ID
			change = func() error { return c.call(ctx, http.MethodPatch, path+"/"+id, want, nil) }
		}
	case len(found) == 1 && found[0].Content == ip:
		owned = false
	default:
		return false, fmt.Errorf("%s already has a DNS record that ezExpose didn't create, %w", host, ErrNotOurs)
	}
	if change != nil {
		if err := change(); err != nil {
			return false, err
		}
	}
	// The machine moved between IPv4 and IPv6. The new record is in place, so this
	// install's old one can go.
	for _, r := range all {
		if r.Type != kind && c.ours(r) {
			if err := c.call(ctx, http.MethodDelete, path+"/"+r.ID, nil, nil); err != nil {
				return owned, err
			}
		}
	}
	return owned, nil
}

// Pointing returns where this install's record for host points, or "" if it
// has none.
func (c Client) Pointing(ctx context.Context, zone, host string) (string, error) {
	found, err := c.records(ctx, zone, host)
	if err != nil {
		return "", err
	}
	for _, r := range found {
		if c.ours(r) {
			return r.Content, nil
		}
	}
	return "", nil
}

// Remove deletes the record if this install created it.
func (c Client) Remove(ctx context.Context, zone, host string) error {
	found, err := c.records(ctx, zone, host)
	if err != nil {
		return err
	}
	for _, r := range found {
		if c.ours(r) {
			if err := c.call(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+r.ID, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
