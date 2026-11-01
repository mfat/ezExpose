package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI is a small Cloudflare holding example.com.
type fakeAPI struct {
	records []record
	writes  []string
	auth    string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.auth = r.Header.Get("Authorization")
	reply := func(result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}
	switch {
	case r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == "example.com" {
			reply([]map[string]string{{"id": "zone1"}})
			return
		}
		reply([]any{})
	case r.Method == http.MethodGet:
		reply(f.records)
	default:
		var body record
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.writes = append(f.writes, r.Method+" "+body.Content)
		switch r.Method {
		case http.MethodPost:
			f.records = append(f.records, body)
		case http.MethodDelete:
			f.records = nil
		}
		reply(nil)
	}
}

func client(t *testing.T, f http.Handler) Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return Client{base: srv.URL, token: "tok", http: srv.Client()}
}

const host = "vault.example.com"

func TestZoneWalksUpToTheDomain(t *testing.T) {
	f := &fakeAPI{}
	got, err := client(t, f).Zone(context.Background(), "a.b.example.com")
	if err != nil || got != "zone1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if f.auth != "Bearer tok" {
		t.Fatalf("auth %q", f.auth)
	}
}

func TestZoneSaysWhenTheDomainIsMissing(t *testing.T) {
	_, err := client(t, &fakeAPI{}).Zone(context.Background(), "vault.other.org")
	if err == nil || !strings.Contains(err.Error(), "can't see") {
		t.Fatalf("got %v", err)
	}
}

func TestRejectedTokenNamesThePermissions(t *testing.T) {
	c := client(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"nope"}]}`))
	}))
	if _, err := c.Zone(context.Background(), host); err == nil || !strings.Contains(err.Error(), "DNS:Edit") {
		t.Fatalf("got %v", err)
	}
}

func TestPointCreatesThenFollowsTheAddress(t *testing.T) {
	f := &fakeAPI{}
	c := client(t, f)
	ctx := context.Background()
	for _, ip := range []string{"192.168.1.20", "192.168.1.20", "192.168.1.31"} {
		if err := c.Point(ctx, "zone1", host, ip); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(f.writes, ","); got != "POST 192.168.1.20,PATCH 192.168.1.31" {
		t.Fatalf("writes: %s", got)
	}
}

func TestPointNeverTakesOverSomeoneElsesRecord(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "203.0.113.9"}}}
	err := client(t, f).Point(context.Background(), "zone1", host, "192.168.1.20")
	if err == nil || !strings.Contains(err.Error(), "left alone") || len(f.writes) != 0 {
		t.Fatalf("err %v, writes %v", err, f.writes)
	}
}

func TestPointAcceptsARecordThatAlreadyMatches(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "192.168.1.20"}}}
	if err := client(t, f).Point(context.Background(), "zone1", host, "192.168.1.20"); err != nil || len(f.writes) != 0 {
		t.Fatalf("err %v, writes %v", err, f.writes)
	}
}

func TestRemoveOnlyDeletesOurRecord(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "203.0.113.9"}}}
	if err := client(t, f).Remove(context.Background(), "zone1", host); err != nil || len(f.writes) != 0 {
		t.Fatalf("err %v, writes %v", err, f.writes)
	}
	f.records[0].Comment = comment
	if err := client(t, f).Remove(context.Background(), "zone1", host); err != nil || len(f.writes) != 1 {
		t.Fatalf("err %v, writes %v", err, f.writes)
	}
}
