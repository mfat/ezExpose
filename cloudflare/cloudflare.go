// Package cloudflare manages the one DNS record that points a name at this
// machine. It only ever changes a record it created, marked by a comment.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	apiBase = "https://api.cloudflare.com/client/v4"
	// comment marks a record as ours. It has no effect on DNS answers.
	comment = "Managed by ezExpose"
	ttl     = 60
)

// TokenURL opens Cloudflare's token page with the permissions filled in.
const TokenURL = "https://dash.cloudflare.com/profile/api-tokens?" +
	"permissionGroupKeys=%5B%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C" +
	"%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22edit%22%7D%5D" +
	"&accountId=%2A&zoneId=all&name=ezExpose"

// Client talks to the Cloudflare API with one token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for token.
func New(token string) Client {
	return Client{base: apiBase, token: token, http: &http.Client{Timeout: 20 * time.Second}}
}

type record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

func (c Client) call(ctx context.Context, method, path string, body, into any) error {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var reply struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return fmt.Errorf("cloudflare answered %s", resp.Status)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return errors.New("Cloudflare refused that token. It needs Zone:Read and DNS:Edit for this domain")
	}
	if !reply.Success {
		if len(reply.Errors) > 0 {
			return fmt.Errorf("cloudflare: %s", reply.Errors[0].Message)
		}
		return fmt.Errorf("cloudflare answered %s", resp.Status)
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(reply.Result, into)
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

func (c Client) records(ctx context.Context, zone, host string) ([]record, error) {
	q := url.Values{"type": {"A"}, "name.exact": {host}, "per_page": {"100"}}
	var all, found []record
	if err := c.call(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?"+q.Encode(), nil, &all); err != nil {
		return nil, err
	}
	for _, r := range all {
		if strings.EqualFold(r.Name, host) {
			found = append(found, r)
		}
	}
	return found, nil
}

// Point makes host resolve to ip. A record it didn't create is left alone.
func (c Client) Point(ctx context.Context, zone, host, ip string) error {
	found, err := c.records(ctx, zone, host)
	if err != nil {
		return err
	}
	want := record{Type: "A", Name: host, Content: ip, TTL: ttl, Comment: comment}
	path := "/zones/" + zone + "/dns_records"
	switch {
	case len(found) == 0:
		return c.call(ctx, http.MethodPost, path, want, nil)
	case len(found) == 1 && found[0].Comment == comment:
		if found[0].Content == ip {
			return nil
		}
		return c.call(ctx, http.MethodPatch, path+"/"+found[0].ID, want, nil)
	case len(found) == 1 && found[0].Content == ip:
		return nil
	}
	return fmt.Errorf("%s already has a DNS record that ezExpose didn't create, so it was left alone", host)
}

// Remove deletes the record if it's ours.
func (c Client) Remove(ctx context.Context, zone, host string) error {
	found, err := c.records(ctx, zone, host)
	if err != nil {
		return err
	}
	for _, r := range found {
		if r.Comment == comment {
			if err := c.call(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+r.ID, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
