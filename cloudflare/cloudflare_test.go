package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI is a small Cloudflare holding example.com.
type fakeAPI struct {
	failWrites bool
	records    []record
	writes     []string
	auth       string
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
	case f.failWrites:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]string{{"message": "timeout"}}})
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
	return Client{base: srv.URL, token: "tok", owner: owner, http: srv.Client()}
}

const owner = "0123456789abcdef"

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
		if owned, err := c.Point(ctx, "zone1", host, ip); err != nil || !owned {
			t.Fatal(owned, err)
		}
	}
	if got := strings.Join(f.writes, ","); got != "POST 192.168.1.20,PATCH 192.168.1.31" {
		t.Fatalf("writes: %s", got)
	}
}

func TestPointNeverTakesOverSomeoneElsesRecord(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "203.0.113.9"}}}
	_, err := client(t, f).Point(context.Background(), "zone1", host, "192.168.1.20")
	if err == nil || !strings.Contains(err.Error(), "left alone") || len(f.writes) != 0 {
		t.Fatalf("err %v, writes %v", err, f.writes)
	}
}

func TestPointAcceptsARecordThatAlreadyMatches(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "192.168.1.20"}}}
	owned, err := client(t, f).Point(context.Background(), "zone1", host, "192.168.1.20")
	if err != nil || owned || len(f.writes) != 0 {
		t.Fatalf("owned %v, err %v, writes %v", owned, err, f.writes)
	}
}

func TestRemoveOnlyDeletesOurRecord(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "203.0.113.9"}}}
	if err := client(t, f).Remove(context.Background(), "zone1", host); err != nil || len(f.writes) != 0 {
		t.Fatalf("err %v, writes %v", err, f.writes)
	}
	f.records[0].Comment = marker + owner
	if err := client(t, f).Remove(context.Background(), "zone1", host); err != nil || len(f.writes) != 1 {
		t.Fatalf("err %v, writes %v", err, f.writes)
	}
}

func TestAnotherInstallsRecordIsNotOurs(t *testing.T) {
	other := marker + "fedcba9876543210"
	for _, legacy := range []string{other, "Managed by ezExpose"} {
		f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "203.0.113.9", Comment: legacy}}}
		c := client(t, f)
		if _, err := c.Point(context.Background(), "zone1", host, "192.168.1.20"); err == nil {
			t.Errorf("%q: took over the record", legacy)
		}
		if got, err := c.Pointing(context.Background(), "zone1", host); err != nil || got != "" {
			t.Errorf("%q: pointing %q, %v", legacy, got, err)
		}
		if err := c.Remove(context.Background(), "zone1", host); err != nil || len(f.writes) != 0 {
			t.Errorf("%q: err %v, writes %v", legacy, err, f.writes)
		}
	}
}

func TestAClientNeedsAnInstallID(t *testing.T) {
	for _, bad := range []string{"", "short", "Has-Capitals0000", strings.Repeat("a", 65)} {
		if _, err := New("tok", bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	id, err := NewOwner()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("tok", id); err != nil {
		t.Fatalf("NewOwner made an ID New refuses: %v", err)
	}
	f := &fakeAPI{}
	zero := client(t, f)
	zero.owner = ""
	if _, err := zero.Point(context.Background(), "zone1", host, "192.168.1.20"); err == nil || len(f.writes) != 0 {
		t.Fatalf("a client with no install ID wrote: %v, %v", err, f.writes)
	}
}

func TestIPv6GetsAnAAAARecord(t *testing.T) {
	f := &fakeAPI{}
	if _, err := client(t, f).Point(context.Background(), "zone1", host, "2001:db8::7"); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || f.records[0].Type != "AAAA" {
		t.Fatalf("%+v", f.records)
	}
	if got, _ := client(t, f).Pointing(context.Background(), "zone1", host); got != "2001:db8::7" {
		t.Fatalf("pointing %q", got)
	}
}

func TestMovingToIPv6ReplacesOurOldRecord(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "203.0.113.7", Comment: marker + owner}}}
	if _, err := client(t, f).Point(context.Background(), "zone1", host, "2001:db8::7"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.writes, ",") != "POST 2001:db8::7,DELETE " {
		t.Fatalf("writes %v, records %+v", f.writes, f.records)
	}
}

func TestAnAliasIsLeftAlone(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "CNAME", Name: host, Content: "elsewhere.example.net"}}}
	_, err := client(t, f).Point(context.Background(), "zone1", host, "203.0.113.7")
	if err == nil || !strings.Contains(err.Error(), "CNAME") || len(f.writes) != 0 {
		t.Fatalf("%v, %v", err, f.writes)
	}
	if _, err := client(t, f).Point(context.Background(), "zone1", host, "not an ip"); err == nil {
		t.Fatal("pointed at nonsense")
	}
}

func TestAConflictLeavesTheOldRecordInPlace(t *testing.T) {
	ours := record{ID: "r", Type: "A", Name: host, Content: "203.0.113.7", Comment: marker + owner}
	theirs := record{ID: "s", Type: "AAAA", Name: host, Content: "2001:db8::99"}
	f := &fakeAPI{records: []record{ours, theirs}}
	_, err := client(t, f).Point(context.Background(), "zone1", host, "2001:db8::7")
	if !errors.Is(err, ErrNotOurs) || len(f.writes) != 0 {
		t.Fatalf("%v, writes %v", err, f.writes)
	}
}

func TestAFailedCreateLeavesTheOldRecordInPlace(t *testing.T) {
	f := &fakeAPI{records: []record{{ID: "r", Type: "A", Name: host, Content: "203.0.113.7", Comment: marker + owner}}, failWrites: true}
	if _, err := client(t, f).Point(context.Background(), "zone1", host, "2001:db8::7"); err == nil {
		t.Fatal("expected an error")
	}
	if len(f.records) != 1 || f.records[0].Type != "A" {
		t.Fatalf("lost the old record: %+v", f.records)
	}
}

func TestEveryPageIsRead(t *testing.T) {
	theirs := record{ID: "s", Type: "A", Name: host, Content: "198.51.100.20"}
	c := client(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := []record{}
		if r.URL.Query().Get("page") == "2" {
			result = []record{theirs}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result,
			"result_info": map[string]int{"total_pages": 2}})
	}))
	if _, err := c.Point(context.Background(), "zone1", host, "203.0.113.7"); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("missed a record on the second page: %v", err)
	}
}
