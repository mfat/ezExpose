package manager

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/mfat/ezExpose/caddy"
	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/tailscale"
)

const box = "box.tail1.ts.net"

// crash stands in for the process dying: a panic at the nth change, before or
// after the change takes effect.
type crash struct{}

type crasher struct {
	at    int  // 0 never
	after bool // the change happens, then the crash
	n     int
}

func (c *crasher) step(change func()) {
	c.n++
	if c.n == c.at && !c.after {
		panic(crash{})
	}
	change()
	if c.n == c.at && c.after {
		panic(crash{})
	}
}

type fakeTailnet struct {
	c      *crasher
	routes map[int]string
	down   error
}

func (f *fakeTailnet) Lookup(context.Context) (string, error) { return box, f.down }
func (f *fakeTailnet) Proxying(_ context.Context, host string, port int) (string, error) {
	if host != box {
		return "", fmt.Errorf("unknown host %s", host)
	}
	return f.routes[port], f.down
}
func (f *fakeTailnet) Serve(_ context.Context, _ string, port int, target string) error {
	if cur := f.routes[port]; cur != "" && cur != target {
		return tailscale.ErrNotOurs
	}
	f.c.step(func() { f.routes[port] = target })
	return nil
}
func (f *fakeTailnet) Close(_ context.Context, _ string, port int, target string) error {
	switch f.routes[port] {
	case "":
		return nil
	case target:
		f.c.step(func() { delete(f.routes, port) })
		return nil
	}
	return tailscale.ErrNotOurs
}

type dnsRecord struct{ ip, owner string }

type fakeDNS struct {
	c       *crasher
	records map[string]dnsRecord
	owner   string
}

func (f *fakeDNS) Zone(context.Context, string) (string, error) { return "zone1", nil }
func (f *fakeDNS) Point(_ context.Context, _, host, ip string) (bool, error) {
	r, ok := f.records[host]
	switch {
	case !ok || r.owner == f.owner:
		if ok && r.ip == ip {
			return true, nil
		}
		f.c.step(func() { f.records[host] = dnsRecord{ip, f.owner} })
		return true, nil
	case r.ip == ip:
		return false, nil
	}
	return false, errors.New(host + " already has a DNS record that ezExpose didn't create, so it was left alone")
}
func (f *fakeDNS) Pointing(_ context.Context, _, host string) (string, error) {
	if r := f.records[host]; r.owner == f.owner {
		return r.ip, nil
	}
	return "", nil
}
func (f *fakeDNS) Remove(_ context.Context, _, host string) error {
	if r, ok := f.records[host]; ok && r.owner == f.owner {
		f.c.step(func() { delete(f.records, host) })
	}
	return nil
}

type fakeProxy struct {
	c           *crasher
	unreachable bool
	sites       []caddy.Site
	applied     int
	fail        error
}

func (f *fakeProxy) Apply(_ context.Context, sites []caddy.Site) error {
	if f.fail != nil {
		return f.fail
	}
	if _, err := caddy.Render("/d", sites); err != nil {
		return err
	}
	f.c.step(func() { f.sites, f.applied = sites, f.applied+1 })
	return nil
}
func (f *fakeProxy) Check(_ context.Context, _, host string) error {
	if f.unreachable {
		return errors.New("no trusted certificate for " + host + " yet: timeout")
	}
	if slices.ContainsFunc(f.sites, func(s caddy.Site) bool { return s.Host == host }) {
		return nil
	}
	return errors.New("no certificate for " + host)
}
func (f *fakeProxy) hosts() []string {
	var out []string
	for _, s := range f.sites {
		out = append(out, s.Host)
	}
	return out
}

type fakeCerts struct {
	c     *crasher
	certs map[string]int
	fail  error
}

func (f *fakeCerts) Issue(_ context.Context, host string, force bool) error {
	if f.fail != nil {
		return f.fail
	}
	if f.certs[host] == 0 || force {
		f.c.step(func() { f.certs[host]++ })
	}
	return nil
}
func (f *fakeCerts) Files(host string) (string, string) {
	return "/c/" + host + ".crt", "/c/" + host + ".key"
}
func (f *fakeCerts) Fingerprint(host string) string {
	if f.certs[host] == 0 {
		return ""
	}
	return fmt.Sprint(f.certs[host])
}
func (f *fakeCerts) Delete(host string) error {
	f.c.step(func() { delete(f.certs, host) })
	return nil
}
func (f *fakeCerts) Expires(host string) (time.Time, error) {
	if f.certs[host] == 0 {
		return time.Time{}, errors.New("no certificate")
	}
	return time.Now().Add(60 * 24 * time.Hour), nil
}

type fakeRenewal struct{ on bool }

func (f *fakeRenewal) Enable(context.Context) error  { f.on = true; return nil }
func (f *fakeRenewal) Disable(context.Context) error { f.on = false; return nil }

type fakeNet struct {
	public, local, tailnet string
	dns                    map[string][]string
	taken                  map[string]error
	backends               map[string]bool
}

func (f *fakeNet) PublicIP(context.Context) (string, error) { return f.public, nil }
func (f *fakeNet) LocalIP() string                          { return f.local }
func (f *fakeNet) Resolve(_ context.Context, host string) ([]string, error) {
	return f.dns[host], nil
}
func (f *fakeNet) OnThisMachine(addr string) bool { return addr == f.local || addr == f.tailnet }
func (f *fakeNet) Listen(addr string) error       { return f.taken[addr] }
func (f *fakeNet) Dial(_ context.Context, addr string) error {
	if f.backends[addr] {
		return nil
	}
	return errors.New("connection refused")
}
func (f *fakeNet) Get(context.Context, string) (int, error) { return 200, nil }

// world is everything outside ezExpose, shared by every Manager a test makes, so
// a new one after a crash sees what the old one left behind.
type world struct {
	c       *crasher
	ts      *fakeTailnet
	dns     *fakeDNS
	proxy   *fakeProxy
	certs   *fakeCerts
	renewal *fakeRenewal
	net     *fakeNet
	dir     string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	c := &crasher{}
	return &world{
		c:       c,
		ts:      &fakeTailnet{c: c, routes: map[int]string{}},
		dns:     &fakeDNS{c: c, records: map[string]dnsRecord{}},
		proxy:   &fakeProxy{c: c},
		certs:   &fakeCerts{c: c, certs: map[string]int{}},
		renewal: &fakeRenewal{},
		net: &fakeNet{public: "203.0.113.7", local: "192.168.1.20", tailnet: "100.68.1.2", dns: map[string][]string{},
			taken: map[string]error{}, backends: map[string]bool{"127.0.0.1:8080": true, "127.0.0.1:9090": true}},
		dir: t.TempDir(),
	}
}

func (w *world) manager() *Manager {
	return &Manager{
		Store:   state.Store{Dir: w.dir},
		Tailnet: w.ts,
		DNS: func(install string) (DNS, error) {
			w.dns.owner = install
			return w.dns, nil
		},
		Proxy: w.proxy, Certs: w.certs, Renewal: w.renewal, Net: w.net,
		Patience: time.Millisecond,
	}
}

// crashes runs fn and reports whether it died at the planned step.
func crashes(fn func()) (died bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crash); !ok {
				panic(r)
			}
			died = true
		}
	}()
	fn()
	return false
}
