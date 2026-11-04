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

func TestLANOnTheTailscaleAddress(t *testing.T) {
	w := newWorld(t)
	w.net.public, w.net.local = "203.0.113.7", "203.0.113.7" // a server with no home network
	if _, err := w.manager().Apply(ctx, lan); CodeOf(err) != Invalid || !strings.Contains(err.Error(), "--address") {
		t.Fatalf("a public address for lan: %v", err)
	}
	// Another program holds 8443 on every address but the Tailscale one.
	w.net.taken[":8443"] = syscall.EADDRINUSE
	w.net.taken["203.0.113.7:8443"] = syscall.EADDRINUSE
	r := lan
	r.Address = "100.68.1.2"
	e, err := w.manager().Apply(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if w.dns.records["home.example.com"].ip != "100.68.1.2" || w.proxy.sites[0].Bind != "100.68.1.2" || e.Status != state.Active {
		t.Fatalf("%+v, %v, %+v", e, w.dns.records, w.proxy.sites)
	}
	for _, bad := range []string{"203.0.113.9", "nonsense"} {
		r.Address = bad
		if _, err := w.manager().Apply(ctx, r); CodeOf(err) != Invalid {
			t.Errorf("%s: %v", bad, err)
		}
	}
	r.Address = "100.68.1.2"
	r.Port = 9443
	if _, err := w.manager().Apply(ctx, r); CodeOf(err) != Invalid || !strings.Contains(err.Error(), "Remove it first") {
		t.Errorf("changed settings on a live exposure: %v", err)
	}
	r.Address = "10.9.9.9"
	r.Host = "other.example.com"
	if _, err := w.manager().Apply(ctx, r); CodeOf(err) != Invalid {
		t.Errorf("an address that isn't this machine's: %v", err)
	}
}

func TestAnApprovedPlanIsAppliedAsShown(t *testing.T) {
	w := newWorld(t)
	m := w.manager()
	p, err := m.Plan(ctx, private)
	if err != nil || p.Exposure.Port != 443 {
		t.Fatalf("%+v, %v", p, err)
	}
	e, err := m.ApplyPlan(ctx, p, false)
	if err != nil || e.Port != 443 || w.ts.routes[443] == "" {
		t.Fatalf("%+v, %v", e, err)
	}
}

func TestAStalePlanChangesNothing(t *testing.T) {
	w := newWorld(t)
	m := w.manager()
	p, _ := m.Plan(ctx, private)
	w.ts.routes[443] = "http://127.0.0.1:3000" // someone took the port in between
	if _, err := m.ApplyPlan(ctx, p, false); CodeOf(err) != PlanChanged || !strings.Contains(err.Error(), ":8443") {
		t.Fatalf("%v", err)
	}
	if len(w.ts.routes) != 1 {
		t.Fatalf("changed something: %v", w.ts.routes)
	}
}

func TestAPublicPlanStillNeedsConfirming(t *testing.T) {
	w := newWorld(t)
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	m := w.manager()
	p, err := m.Plan(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplyPlan(ctx, p, false); CodeOf(err) != NeedsConfirmation {
		t.Fatalf("%v", err)
	}
	if e, err := m.ApplyPlan(ctx, p, true); err != nil || e.Status != state.Active {
		t.Fatalf("%+v, %v", e, err)
	}
	// Now it exists, the same plan is stale: applying would repair, not create.
	if _, err := m.ApplyPlan(ctx, p, true); CodeOf(err) != PlanChanged {
		t.Fatalf("%v", err)
	}
}

func TestAFailureThatChangedNothingLeavesNoRecord(t *testing.T) {
	w := newWorld(t)
	m := w.manager()
	if _, err := m.Apply(ctx, Request{Backend: "127.0.0.1:1234", Access: state.Private}); CodeOf(err) != BackendDown {
		t.Fatal(err)
	}
	if list, _ := m.List(); len(list) != 0 {
		t.Fatalf("left a record: %+v", list)
	}
	p, err := m.Plan(ctx, Request{Backend: "127.0.0.1:1234", Access: state.Private})
	if err != nil || p.Existing || p.Exposure.Host != box {
		t.Fatalf("%+v, %v", p, err)
	}
}

func TestPublicOnAnIPv6OnlyMachine(t *testing.T) {
	w := newWorld(t)
	w.net.public, w.net.local = "2001:db8::7", "2001:db8::7"
	w.net.dns["app.example.com"] = []string{"2001:db8::7"}
	e, err := w.manager().Apply(ctx, public)
	if err != nil || e.Status != state.Active || w.dns.records["app.example.com"].ip != "2001:db8::7" {
		t.Fatalf("%+v, %v, %v", e, err, w.dns.records)
	}
	w.net.taken[":443"] = syscall.EADDRINUSE
	other := public
	other.Host, other.Backend = "b.example.com", "127.0.0.1:9090"
	w.net.dns["b.example.com"] = []string{"2001:db8::7"}
	if _, err := w.manager().Apply(ctx, other); err != nil {
		t.Fatal(err)
	}
}

func TestPublicBehindCGNATIsRefusedClearly(t *testing.T) {
	w := newWorld(t)
	w.net.local = "100.72.1.9" // the provider's shared range
	_, err := w.manager().Apply(ctx, public)
	if CodeOf(err) != PortUnavailable || !strings.Contains(err.Error(), "CGNAT") {
		t.Fatalf("%v", err)
	}
	if len(w.dns.records) != 0 || len(w.proxy.sites) != 0 {
		t.Fatal("changed something")
	}
}

func TestAnUnreachablePublicMachineIsExplained(t *testing.T) {
	w := newWorld(t)
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	w.proxy.unreachable = true // Let's Encrypt can't get in: no port forwarding
	m := w.manager()
	_, err := m.Apply(ctx, public)
	if CodeOf(err) != CertificateFailed || !strings.Contains(err.Error(), "forward port 443") {
		t.Fatalf("%v", err)
	}
	if len(w.proxy.sites) != 0 {
		t.Fatalf("left the site served without a certificate: %+v", w.proxy.sites)
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].Status != state.Failed || list[0].Resource(state.CaddySite) != nil {
		t.Fatalf("%+v", list)
	}
	w.proxy.unreachable = false
	if e, err := m.Apply(ctx, public); err != nil || e.Status != state.Active || len(w.proxy.sites) != 1 {
		t.Fatalf("retry: %+v, %v", e, err)
	}
	if err := m.Remove(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if len(w.proxy.sites) != 0 || len(w.dns.records) != 0 {
		t.Fatalf("left behind: %+v, %v", w.proxy.sites, w.dns.records)
	}
}

func TestALostCloudflareReplyNeverOrphansARecord(t *testing.T) {
	w := newWorld(t)
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	w.dns.loseResponse = true
	m := w.manager()
	if _, err := m.Apply(ctx, public); CodeOf(err) != DNSNotReady {
		t.Fatalf("%v", err)
	}
	if w.dns.records["app.example.com"].ip == "" {
		t.Fatal("the stand-in should have made the record")
	}
	list, _ := m.List()
	if len(list) != 1 || list[0].Resource(state.DNSRecord) == nil {
		t.Fatalf("forgot the record it may have made: %+v", list)
	}
	w.dns.loseResponse = false
	if err := m.Remove(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if len(w.dns.records) != 0 {
		t.Fatalf("orphaned: %v", w.dns.records)
	}
}

func TestADefiniteConflictKeepsTrackOfOurOldRecord(t *testing.T) {
	w := newWorld(t)
	w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	m := w.manager()
	e, err := m.Apply(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	// The machine's address changes, and someone else's record is now in the way.
	w.net.public = "203.0.113.8"
	w.dns.records["app.example.com"] = dnsRecord{"198.51.100.20", "someone"}
	if _, err := m.Apply(ctx, public); CodeOf(err) != NotOurs {
		t.Fatalf("%v", err)
	}
	list, _ := m.List()
	if res := list[0].Resource(state.DNSRecord); res == nil || !res.Done || res.Target != "203.0.113.7" {
		t.Fatalf("lost track of %s's old record: %+v", e.ID, list[0].Resources)
	}
}

func TestOneNameServesOneApp(t *testing.T) {
	w := newWorld(t)
	w.net.dns["home.example.com"] = []string{"203.0.113.7"}
	m := w.manager()
	first, err := m.Apply(ctx, lan)
	if err != nil {
		t.Fatal(err)
	}
	certs, sites := w.certs.certs["home.example.com"], len(w.proxy.sites)
	for name, r := range map[string]Request{
		"lan, another app and port": {Backend: "127.0.0.1:9090", Access: state.LAN, Host: "home.example.com", Port: 8444},
		"public, same name":         {Backend: "127.0.0.1:9090", Access: state.Public, Host: "home.example.com", Cloudflare: true, Confirmed: true},
		"public, same app and name": {Backend: "127.0.0.1:8080", Access: state.Public, Host: "home.example.com", Confirmed: true},
	} {
		if _, err := m.Plan(ctx, r); CodeOf(err) != Invalid || !strings.Contains(err.Error(), first.ID) {
			t.Errorf("%s: plan: %v", name, err)
		}
		if _, err := m.Apply(ctx, r); CodeOf(err) != Invalid {
			t.Errorf("%s: apply: %v", name, err)
		}
	}
	if w.certs.certs["home.example.com"] != certs || len(w.proxy.sites) != sites || len(w.dns.records) != 1 {
		t.Fatal("a refused request changed something")
	}
	if list, _ := m.List(); len(list) != 1 {
		t.Fatalf("recorded a refused request: %+v", list)
	}
	// The same app again is a repair, not a second user of the name.
	if e, err := m.Apply(ctx, lan); err != nil || e.ID != first.ID {
		t.Fatalf("%+v, %v", e, err)
	}
}
