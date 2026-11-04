package manager

import (
	"context"
	"errors"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/mfat/ezExpose/internal/state"
)

var ctx = context.Background()

var (
	private = Request{Backend: "127.0.0.1:8080", Access: state.Private}
	public  = Request{Backend: "127.0.0.1:8080", Access: state.Public, Host: "app.example.com", Cloudflare: true, Confirmed: true}
	lan     = Request{Backend: "127.0.0.1:8080", Access: state.LAN, Host: "home.example.com"}
)

func TestPrivateLifecycle(t *testing.T) {
	w := newWorld(t)
	m := w.manager()
	e, err := m.Apply(ctx, private)
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != state.Active || e.URL() != "https://"+box || w.ts.routes[443] != "http://127.0.0.1:8080" {
		t.Fatalf("%+v, routes %v", e, w.ts.routes)
	}
	again, err := m.Apply(ctx, private)
	if err != nil || again.ID != e.ID || len(w.ts.routes) != 1 {
		t.Fatalf("a second apply wasn't harmless: %+v, %v, %v", again, err, w.ts.routes)
	}
	if err := m.Remove(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	if len(w.ts.routes) != 0 {
		t.Fatalf("still served: %v", w.ts.routes)
	}
	if list, _ := m.List(); len(list) != 0 {
		t.Fatalf("still recorded: %+v", list)
	}
	if err := m.Remove(ctx, e.ID); CodeOf(err) != NotFound {
		t.Fatalf("second remove: %v", err)
	}
}

func TestSomeoneElsesRouteSurvivesEverything(t *testing.T) {
	w := newWorld(t)
	w.ts.routes[443] = "http://127.0.0.1:3000"
	m := w.manager()
	e, err := m.Apply(ctx, private)
	if err != nil {
		t.Fatal(err)
	}
	if e.Port != 8443 {
		t.Fatalf("took port %d", e.Port)
	}
	if _, err := m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	if w.ts.routes[443] != "http://127.0.0.1:3000" || len(w.ts.routes) != 1 {
		t.Fatalf("someone else's route changed: %v", w.ts.routes)
	}
	if _, err := m.Apply(ctx, Request{Backend: "127.0.0.1:8080", Access: state.Private, Port: 443}); CodeOf(err) != NotOurs {
		t.Fatalf("asked for the taken port: %v", err)
	}
	if w.ts.routes[443] != "http://127.0.0.1:3000" {
		t.Fatal("replaced it on request")
	}
}

func TestTheSameAppOnAnotherRouteIsStillNotOurs(t *testing.T) {
	w := newWorld(t)
	w.ts.routes[443] = "http://127.0.0.1:8080" // set up by hand, not by ezExpose
	e, err := w.manager().Apply(ctx, private)
	if err != nil || e.Port != 8443 {
		t.Fatalf("%+v, %v", e, err)
	}
	if err := w.manager().Remove(ctx, e.ID); err != nil || w.ts.routes[443] != "http://127.0.0.1:8080" {
		t.Fatalf("%v, %v", err, w.ts.routes)
	}
}

func TestNothingHappensWithoutTheApp(t *testing.T) {
	w := newWorld(t)
	_, err := w.manager().Apply(ctx, Request{Backend: "127.0.0.1:1234", Access: state.Private})
	if CodeOf(err) != BackendDown || len(w.ts.routes) != 0 {
		t.Fatalf("%v, %v", err, w.ts.routes)
	}
}

func TestBadRequests(t *testing.T) {
	w := newWorld(t)
	for name, r := range map[string]Request{
		"no port":        {Backend: "127.0.0.1", Access: state.Private},
		"a name":         {Backend: "app.example.com:80", Access: state.Private},
		"bad access":     {Backend: "127.0.0.1:8080", Access: "open"},
		"private host":   {Backend: "127.0.0.1:8080", Access: state.Private, Host: "a.example.com"},
		"public no host": {Backend: "127.0.0.1:8080", Access: state.Public, Confirmed: true},
		"public port":    {Backend: "127.0.0.1:8080", Access: state.Public, Host: "a.example.com", Port: 8443, Confirmed: true},
		"bad host":       {Backend: "127.0.0.1:8080", Access: state.LAN, Host: "a b"},
	} {
		if _, err := w.manager().Apply(ctx, r); CodeOf(err) != Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPublicNeedsConfirmation(t *testing.T) {
	w := newWorld(t)
	r := public
	r.Confirmed = false
	if _, err := w.manager().Apply(ctx, r); CodeOf(err) != NeedsConfirmation || len(w.proxy.sites) != 0 {
		t.Fatalf("%v", err)
	}
}

func TestPublicLifecycleWithCloudflare(t *testing.T) {
	w := newWorld(t)
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	m := w.manager()
	e, err := m.Apply(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != state.Active || w.dns.records["app.example.com"].ip != "203.0.113.7" ||
		!slices.Equal(w.proxy.hosts(), []string{"app.example.com"}) {
		t.Fatalf("%+v, %v, %v", e, w.dns.records, w.proxy.sites)
	}
	if err := m.Remove(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	if len(w.dns.records) != 0 || len(w.proxy.sites) != 0 {
		t.Fatalf("left behind: %v, %v", w.dns.records, w.proxy.sites)
	}
}

func TestPublicWithoutCloudflareSaysWhatRecordToAdd(t *testing.T) {
	w := newWorld(t)
	r := public
	r.Cloudflare = false
	_, err := w.manager().Apply(ctx, r)
	if CodeOf(err) != DNSNotReady || !strings.Contains(err.Error(), "A  app.example.com  203.0.113.7") {
		t.Fatalf("%v", err)
	}
	if len(w.proxy.sites) != 0 {
		t.Fatal("started Caddy before DNS was right")
	}
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	if e, err := w.manager().Apply(ctx, r); err != nil || e.Status != state.Active {
		t.Fatalf("retry: %+v, %v", e, err)
	}
}

func TestPublicUsesOneAddressWhenTailscaleHasPort443(t *testing.T) {
	w := newWorld(t)
	w.net.public, w.net.local = "203.0.113.7", "203.0.113.7"
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	w.net.taken[":443"] = syscall.EADDRINUSE
	e, err := w.manager().Apply(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	if w.proxy.sites[0].Bind != "203.0.113.7" || e.Status != state.Active {
		t.Fatalf("%+v, %+v", e, w.proxy.sites)
	}
	w.net.taken["203.0.113.7:443"] = syscall.EADDRINUSE
	other := public
	other.Host, other.Backend = "b.example.com", "127.0.0.1:9090"
	w.net.dns["b.example.com"] = []string{"203.0.113.7"}
	if _, err := w.manager().Apply(ctx, other); err != nil {
		t.Fatalf("a second site on the same Caddy: %v", err)
	}
	if len(w.proxy.sites) != 2 {
		t.Fatalf("%+v", w.proxy.sites)
	}
}

func TestPort443NeedsPermission(t *testing.T) {
	w := newWorld(t)
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	w.net.taken[":443"] = syscall.EACCES
	w.net.taken["192.168.1.20:443"] = syscall.EACCES
	_, err := w.manager().Apply(ctx, public)
	if CodeOf(err) != PortUnavailable || !strings.Contains(err.Error(), "ip_unprivileged_port_start") {
		t.Fatalf("%v", err)
	}
}

func TestSomeoneElsesDNSRecordIsNeverChanged(t *testing.T) {
	w := newWorld(t)
	w.dns.records["app.example.com"] = dnsRecord{"198.51.100.20", "someone"}
	_, err := w.manager().Apply(ctx, public)
	if CodeOf(err) != NotOurs || w.dns.records["app.example.com"].ip != "198.51.100.20" {
		t.Fatalf("%v, %v", err, w.dns.records)
	}
}

func TestAMatchingRecordIsUsedButNeverDeleted(t *testing.T) {
	w := newWorld(t)
	w.dns.records["app.example.com"] = dnsRecord{"203.0.113.7", "someone"}
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	m := w.manager()
	e, err := m.Apply(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	if res := e.Resource(state.DNSRecord); res == nil || res.Owned {
		t.Fatalf("%+v", e.Resources)
	}
	if err := m.Remove(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	if w.dns.records["app.example.com"].owner != "someone" {
		t.Fatal("deleted a record ezExpose didn't create")
	}
}

func TestLANLifecycleAndRenewal(t *testing.T) {
	w := newWorld(t)
	w.net.dns["home.example.com"] = []string{"192.168.1.20"}
	m := w.manager()
	e, err := m.Apply(ctx, lan)
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != state.Active || e.URL() != "https://home.example.com:8443" || !w.renewal.on ||
		w.certs.certs["home.example.com"] != 1 || w.proxy.sites[0].CertFile == "" {
		t.Fatalf("%+v, %+v, renewal %v", e, w.proxy.sites, w.renewal.on)
	}
	renewed, err := m.Renew(ctx, false)
	if err != nil || len(renewed) != 0 {
		t.Fatalf("renewed when not due: %v, %v", renewed, err)
	}
	applied := w.proxy.applied
	renewed, err = m.Renew(ctx, true)
	if err != nil || len(renewed) != 1 || w.proxy.applied != applied+1 {
		t.Fatalf("forced renewal: %v, %v, reloads %d", renewed, err, w.proxy.applied-applied)
	}
	if err := m.Remove(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	if w.renewal.on || len(w.certs.certs) != 0 || len(w.dns.records) != 0 {
		t.Fatalf("left behind: renewal %v, %v, %v", w.renewal.on, w.certs.certs, w.dns.records)
	}
}

func TestAFailedRenewalIsReported(t *testing.T) {
	w := newWorld(t)
	m := w.manager()
	if _, err := m.Apply(ctx, lan); err != nil {
		t.Fatal(err)
	}
	w.certs.fail = errors.New("rate limited")
	if _, err := m.Renew(ctx, true); CodeOf(err) != CertificateFailed {
		t.Fatalf("%v", err)
	}
	list, _ := m.List()
	if list[0].Status != state.Degraded || !strings.Contains(list[0].Error, "rate limited") {
		t.Fatalf("%+v", list[0])
	}
}

func TestReconcileReportsButDoesntRecreate(t *testing.T) {
	w := newWorld(t)
	m := w.manager()
	e, _ := m.Apply(ctx, private)
	delete(w.ts.routes, 443) // removed by hand
	list, err := m.Reconcile(ctx)
	if err != nil || list[0].Status != state.Degraded || len(w.ts.routes) != 0 {
		t.Fatalf("%+v, %v, %v", list, err, w.ts.routes)
	}
	if e, err = m.Apply(ctx, private); err != nil || e.Status != state.Active || w.ts.routes[443] == "" {
		t.Fatalf("apply didn't repair: %+v, %v", e, err)
	}
	w.ts.down = errors.New("daemon not running")
	if list, _ := m.Reconcile(ctx); list[0].Status != state.Unknown {
		t.Fatalf("couldn't check, but said %s", list[0].Status)
	}
}

func TestACommandWaitsForAnother(t *testing.T) {
	w := newWorld(t)
	unlock, _ := w.manager().Store.Lock(0)
	defer unlock()
	if _, err := w.manager().Apply(ctx, private); CodeOf(err) != Busy || len(w.ts.routes) != 0 {
		t.Fatalf("%v", err)
	}
}
