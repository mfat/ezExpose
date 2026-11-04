// Package manager puts local apps behind HTTPS and takes them down again, using
// the record in package state. Every change is saved as pending before it's made
// and marked done once it's checked, so an interrupted run can always be finished
// or undone, and nothing outside the record is ever changed.
package manager

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mfat/ezExpose/caddy"
	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/netcheck"
	"github.com/mfat/ezExpose/tailscale"
)

// Tailnet serves a local port on this machine's tailnet name.
type Tailnet interface {
	Lookup(ctx context.Context) (string, error)
	Proxying(ctx context.Context, host string, port int) (string, error)
	Serve(ctx context.Context, host string, port int, target string) error
	Close(ctx context.Context, host string, port int, target string) error
}

// DNS keeps records pointing at this machine. Only records it created are ever
// changed.
type DNS interface {
	Zone(ctx context.Context, host string) (string, error)
	Point(ctx context.Context, zone, host, ip string) (owned bool, err error)
	Pointing(ctx context.Context, zone, host string) (string, error)
	Remove(ctx context.Context, zone, host string) error
}

// Proxy is ezExpose's own Caddy. It owns its whole config.
type Proxy interface {
	// Apply makes Caddy serve exactly sites, keeping the old config if the new
	// one fails. No sites stops it.
	Apply(ctx context.Context, sites []caddy.Site) error
	// Check waits until addr answers for host with a certificate browsers trust.
	Check(ctx context.Context, addr, host string) error
}

// Certs gets real certificates over the DNS challenge.
type Certs interface {
	Issue(ctx context.Context, host string, force bool) error
	Files(host string) (cert, key string)
	Fingerprint(host string) string // changes when the certificate does; "" if there's none
	Delete(host string) error
	Expires(host string) (time.Time, error)
}

// Renewal runs ezexpose renew on a timer.
type Renewal interface {
	Enable(ctx context.Context) error
	Disable(ctx context.Context) error
}

// Net is what the manager asks of the network.
type Net interface {
	PublicIP(ctx context.Context) (string, error)
	LocalIP() string
	Resolve(ctx context.Context, host string) ([]string, error)
	OnThisMachine(addr string) bool
	Listen(addr string) error
	Dial(ctx context.Context, addr string) error
	// Get fetches url and returns its status code.
	Get(ctx context.Context, url string) (int, error)
}

// Manager does the work. Fields left nil are only needed by some kinds of access.
type Manager struct {
	Store   state.Store
	Tailnet Tailnet
	// DNS returns a Cloudflare client for this install, or an error saying how to
	// add a token.
	DNS     func(install string) (DNS, error)
	Proxy   Proxy
	Certs   Certs
	Renewal Renewal
	Net     Net
	Log     io.Writer // progress for people; nil is quiet
	Now     func() time.Time
	// Wait is how long to wait for the lock.
	Wait time.Duration
	// Patience scales the waits for DNS and certificates. Tests make it tiny.
	Patience time.Duration
}

// Request says what to expose and how.
type Request struct {
	Backend string       // such as 127.0.0.1:8080
	Access  state.Access // private, public or lan
	Host    string       // your name, for public and lan
	Port    int          // 0 picks one
	Name    string
	// Cloudflare lets ezExpose create the public DNS record. LAN access always
	// uses it.
	Cloudflare bool
	// Address is where a LAN name points, such as this machine's Tailscale
	// address. Left out, it's the address the machine uses on its network.
	Address string
	// Confirmed says the person knows HTTPS isn't a login: public access needs it.
	Confirmed bool
}

// Plan is what Apply would do, worked out without changing anything.
type Plan struct {
	Exposure state.Exposure `json:"exposure"`
	Steps    []string       `json:"steps"`
	// Existing is true when this app is already exposed this way, so applying
	// checks it and repairs it.
	Existing bool `json:"existing"`
}

func (m *Manager) say(format string, args ...any) {
	if m.Log != nil {
		fmt.Fprintf(m.Log, format+"\n", args...)
	}
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().UTC()
}

func (m *Manager) patience(d time.Duration) time.Duration {
	if m.Patience > 0 {
		return d * m.Patience / time.Second
	}
	return d
}

// locked runs fn holding the lock, with the record loaded. fn saves as it goes.
func (m *Manager) locked(fn func(st *state.State) error) error {
	unlock, err := m.Store.Lock(m.Wait)
	if errors.Is(err, state.ErrBusy) {
		return wrap(Busy, err)
	}
	if err != nil {
		return err
	}
	defer unlock()
	st, err := m.Store.Load()
	if err != nil {
		return wrap(BadRecord, err)
	}
	return fn(&st)
}

func (m *Manager) save(st *state.State) error { return m.Store.Save(*st) }

// privatePorts are tried in turn on the tailnet name.
var privatePorts = []int{443, 8443, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009}

func checkRequest(r *Request) error {
	host, port, err := net.SplitHostPort(r.Backend)
	if err != nil || host == "" {
		return errorf(Invalid, "%q isn't an address such as 127.0.0.1:8080", r.Backend)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errorf(Invalid, "%q isn't an address such as 127.0.0.1:8080", r.Backend)
	}
	if net.ParseIP(host) == nil && host != "localhost" {
		return errorf(Invalid, "use the app's address, such as 127.0.0.1:%s, not a name", port)
	}
	if r.Port < 0 || r.Port > 65535 {
		return errorf(Invalid, "%d isn't a port", r.Port)
	}
	switch r.Access {
	case state.Private:
		if r.Host != "" {
			return errorf(Invalid, "private access uses this machine's tailnet name, so it takes no --host")
		}
	case state.Public, state.LAN:
		r.Host = strings.ToLower(strings.TrimSuffix(r.Host, "."))
		if r.Host == "localhost" || !caddy.ValidHost(r.Host) {
			return errorf(Invalid, "%q isn't a domain name such as app.example.com", r.Host)
		}
		if r.Address != "" && (r.Access != state.LAN || net.ParseIP(r.Address) == nil || netcheck.IsPublic(r.Address)) {
			return errorf(Invalid, "--address takes a private address, such as this machine's Tailscale one, and only for lan")
		}
		if r.Access == state.Public && r.Port != 0 && r.Port != 443 {
			return errorf(Invalid, "public access uses port 443, because that's where Let's Encrypt checks")
		}
	default:
		return errorf(Invalid, "access must be private, public or lan")
	}
	return nil
}

func target(e state.Exposure) string { return "http://" + e.Backend }

// find returns the exposure for the same app and access, if there is one.
func find(st *state.State, r Request) *state.Exposure {
	for i := range st.Exposures {
		e := &st.Exposures[i]
		if e.Backend == r.Backend && e.Access == r.Access && (r.Host == "" || e.Host == r.Host) {
			return e
		}
	}
	return nil
}

// Plan works out what Apply would do. It changes nothing.
func (m *Manager) Plan(ctx context.Context, r Request) (Plan, error) {
	if err := checkRequest(&r); err != nil {
		return Plan{}, err
	}
	st, err := m.Store.Load()
	if err != nil {
		return Plan{}, wrap(BadRecord, err)
	}
	if e := find(&st, r); e != nil {
		return Plan{Exposure: *e, Existing: true, Steps: []string{"Check " + e.URL() + " and repair anything missing"}}, nil
	}
	e := state.Exposure{Backend: r.Backend, Access: r.Access, Host: r.Host, Port: r.Port, Name: r.Name}
	steps := []string{"Check that " + r.Backend + " answers"}
	switch r.Access {
	case state.Private:
		host, err := m.Tailnet.Lookup(ctx)
		if err != nil {
			return Plan{}, wrap(TailscaleNotReady, err)
		}
		e.Host = host
		if e.Port, err = m.pickPort(ctx, &st, "", host, r.Port); err != nil {
			return Plan{}, err
		}
		steps = append(steps, fmt.Sprintf("Forward %s to %s over Tailscale, for your own devices only", e.URL(), target(e)))
	case state.Public:
		e.Port = 443
		if r.Cloudflare {
			steps = append(steps, "Point "+r.Host+" at this machine's public address in Cloudflare")
		} else {
			steps = append(steps, "Check that "+r.Host+" points at this machine")
		}
		steps = append(steps, "Check that port 443 is free",
			"Serve "+e.URL()+" through Caddy, with a certificate from Let's Encrypt",
			"Anyone on the internet can reach it: the app's own login is all that protects it")
	case state.LAN:
		if e.Port == 0 {
			e.Port = 8443
		}
		where := "this machine's local address"
		if r.Address != "" {
			where = r.Address
		}
		steps = append(steps, "Point "+r.Host+" at "+where+" in Cloudflare",
			"Get a certificate for "+r.Host+" from Let's Encrypt, through Cloudflare",
			"Serve "+e.URL()+" on your network through Caddy",
			"Renew the certificate on a timer")
	}
	return Plan{Exposure: e, Steps: steps}, nil
}

// pickPort chooses a free tailnet port. A port that already forwards somewhere,
// even to this same app, belongs to whoever set it up.
func (m *Manager) pickPort(ctx context.Context, st *state.State, self, host string, want int) (int, error) {
	candidates := privatePorts
	if want != 0 {
		candidates = []int{want}
	}
	for _, port := range candidates {
		if usedByUs(st, self, host, port) {
			continue
		}
		current, err := m.Tailnet.Proxying(ctx, host, port)
		if err != nil {
			return 0, wrap(TailscaleNotReady, err)
		}
		if current == "" {
			return port, nil
		}
	}
	if want != 0 {
		return 0, errorf(NotOurs, "port %d on %s is already in use, so it was left alone", want, host)
	}
	return 0, errorf(NotOurs, "every Tailscale port ezExpose uses on %s is taken", host)
}

func usedByUs(st *state.State, self, host string, port int) bool {
	for _, e := range st.Exposures {
		if e.ID != self && e.Host == host && e.Port == port {
			return true
		}
	}
	return false
}

// Apply makes the app reachable as asked, or checks and repairs it if it already
// is. Running it again after an interruption carries on where it stopped.
func (m *Manager) Apply(ctx context.Context, r Request) (state.Exposure, error) {
	if err := checkRequest(&r); err != nil {
		return state.Exposure{}, err
	}
	if r.Access == state.Public && !r.Confirmed {
		return state.Exposure{}, errorf(NeedsConfirmation, "public access lets anyone on the internet reach %s. "+
			"HTTPS encrypts the connection but isn't a login, so the app needs its own", r.Backend)
	}
	var result state.Exposure
	err := m.locked(func(st *state.State) error {
		e := find(st, r)
		if e == nil {
			id, err := state.NewID("exp_", 4)
			if err != nil {
				return err
			}
			st.Exposures = append(st.Exposures, state.Exposure{
				ID: id, Name: r.Name, Backend: r.Backend, Access: r.Access, Host: r.Host, Port: r.Port,
				Cloudflare: r.Cloudflare || r.Access == state.LAN, Address: r.Address, Status: state.Applying, Created: m.now(),
			})
			e = &st.Exposures[len(st.Exposures)-1]
		}
		if e.Status == state.Removing {
			return errorf(Invalid, "%s is being removed. Run: ezexpose remove %s", e.ID, e.ID)
		}
		if changed := (r.Address != "" && r.Address != e.Address) || (r.Port != 0 && r.Port != e.Port) || (r.Cloudflare && !e.Cloudflare); changed {
			if len(e.Resources) > 0 {
				return errorf(Invalid, "%s is already set up differently. Remove it first: ezexpose remove %s", e.ID, e.ID)
			}
			// Nothing was set up yet, so the new settings simply replace the old.
			if r.Address != "" {
				e.Address = r.Address
			}
			e.Cloudflare = e.Cloudflare || r.Cloudflare
			if r.Port != 0 {
				e.Port = r.Port
			}
		}
		e.Status, e.Error = state.Applying, ""
		if err := m.save(st); err != nil {
			return err
		}
		err := m.up(ctx, st, e, r)
		e = st.Find(e.ID)
		if err != nil {
			e.Status, e.Error = state.Failed, err.Error()
			if saveErr := m.save(st); saveErr != nil {
				return errors.Join(err, saveErr)
			}
			result = *e
			return err
		}
		result = *e
		return nil
	})
	return result, err
}

// up does each step in turn. Each one is safe to repeat.
func (m *Manager) up(ctx context.Context, st *state.State, e *state.Exposure, r Request) error {
	if err := m.settlePending(ctx, st, e); err != nil {
		return err
	}
	m.say("Checking %s answers...", e.Backend)
	if err := m.Net.Dial(ctx, e.Backend); err != nil {
		return errorf(BackendDown, "nothing answers on %s (%v). Start the app first", e.Backend, err)
	}
	var err error
	switch e.Access {
	case state.Private:
		err = m.upPrivate(ctx, st, e, r)
	case state.Public:
		err = m.upPublic(ctx, st, e, r)
	case state.LAN:
		err = m.upLAN(ctx, st, e)
	}
	if err != nil {
		return err
	}
	e = st.Find(e.ID)
	e.Status, e.Checked, e.Error = state.Active, m.now(), ""
	if problem := m.answers(ctx, *e); problem != "" {
		e.Status, e.Error = state.Degraded, problem
	}
	return m.save(st)
}

// answers asks the app through its new address, as a browser would.
func (m *Manager) answers(ctx context.Context, e state.Exposure) string {
	deadline := time.Now().Add(m.patience(60 * time.Second))
	var last error
	for {
		code, err := m.Net.Get(ctx, e.URL())
		if err == nil && code < 500 {
			return ""
		}
		last = err
		if err == nil {
			last = fmt.Errorf("it answered %d", code)
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return fmt.Sprintf("set up, but %s didn't answer from this machine yet: %v", e.URL(), last)
		}
		sleep(ctx, m.patience(2*time.Second))
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// begin saves r as pending, so a crash in the middle still knows it might exist.
func (m *Manager) begin(st *state.State, e *state.Exposure, r state.Resource) (*state.Exposure, error) {
	e.Drop(r.Kind)
	r.Done = false
	e.Resources = append(e.Resources, r)
	if err := m.save(st); err != nil {
		return e, err
	}
	return e, nil
}

func (m *Manager) finish(st *state.State, e *state.Exposure, kind state.Kind, owned bool) error {
	res := e.Resource(kind)
	res.Done, res.Owned = true, owned
	return m.save(st)
}

func (m *Manager) upPrivate(ctx context.Context, st *state.State, e *state.Exposure, r Request) error {
	host, err := m.Tailnet.Lookup(ctx)
	if err != nil {
		return wrap(TailscaleNotReady, err)
	}
	if res := e.Resource(state.TailscaleRoute); res != nil {
		// Already ours: check it's still there, and put it back if it's gone.
		current, err := m.Tailnet.Proxying(ctx, e.Host, e.Port)
		if err != nil {
			return wrap(TailscaleNotReady, err)
		}
		switch current {
		case res.Target:
			return nil
		case "":
			m.say("Putting back the Tailscale route for %s...", e.URL())
			return wrap(TailscaleNotReady, m.Tailnet.Serve(ctx, e.Host, e.Port, res.Target))
		default:
			return errorf(NotOurs, "%s now forwards to %s, which ezExpose didn't set up. Left alone", e.URL(), current)
		}
	}
	e.Host = host
	if e.Port, err = m.pickPort(ctx, st, e.ID, host, r.Port); err != nil {
		return err
	}
	to := target(*e)
	if e, err = m.begin(st, e, state.Resource{Kind: state.TailscaleRoute, Ref: fmt.Sprintf("%s:%d", host, e.Port), Target: to, Owned: true}); err != nil {
		return err
	}
	m.say("Forwarding %s to %s over Tailscale...", e.URL(), to)
	if err := m.Tailnet.Serve(ctx, host, e.Port, to); err != nil {
		if errors.Is(err, tailscale.ErrNotOurs) {
			e.Drop(state.TailscaleRoute)
			_ = m.save(st)
			return wrap(NotOurs, err)
		}
		return wrap(TailscaleNotReady, err)
	}
	if current, err := m.Tailnet.Proxying(ctx, host, e.Port); err != nil || current != to {
		return errorf(Failed, "Tailscale didn't take the route (found %q, %v)", current, err)
	}
	return m.finish(st, e, state.TailscaleRoute, true)
}

func (m *Manager) dns(st *state.State) (DNS, error) {
	if m.DNS == nil {
		return nil, errorf(NoCloudflare, "Cloudflare isn't available")
	}
	d, err := m.DNS(st.Install)
	if err != nil {
		return nil, wrap(NoCloudflare, err)
	}
	return d, nil
}

// pointDNS makes host resolve to ip through Cloudflare, as a pending resource.
func (m *Manager) pointDNS(ctx context.Context, st *state.State, e *state.Exposure, ip string) error {
	d, err := m.dns(st)
	if err != nil {
		return err
	}
	if res := e.Resource(state.DNSRecord); res != nil && res.Done && res.Target == ip {
		if !res.Owned {
			return nil
		}
		if got, err := d.Pointing(ctx, zoneOf(res.Ref), e.Host); err == nil && got == ip {
			return nil
		}
	}
	zone, err := d.Zone(ctx, e.Host)
	if err != nil {
		return wrap(NoCloudflare, err)
	}
	st.Zone = zone
	if e, err = m.begin(st, e, state.Resource{Kind: state.DNSRecord, Ref: zone + "/" + e.Host, Target: ip, Owned: true}); err != nil {
		return err
	}
	m.say("Pointing %s at %s in Cloudflare...", e.Host, ip)
	owned, err := d.Point(ctx, zone, e.Host, ip)
	if err != nil {
		e.Drop(state.DNSRecord)
		_ = m.save(st)
		if strings.Contains(err.Error(), "left alone") {
			return wrap(NotOurs, err)
		}
		return wrap(DNSNotReady, err)
	}
	return m.finish(st, e, state.DNSRecord, owned)
}

func zoneOf(ref string) string { zone, _, _ := strings.Cut(ref, "/"); return zone }

// waitForDNS waits until public DNS gives ip for host.
func (m *Manager) waitForDNS(ctx context.Context, host, ip string) error {
	deadline := time.Now().Add(m.patience(2 * time.Minute))
	for {
		found, err := m.Net.Resolve(ctx, host)
		if err == nil && slices.Contains(found, ip) {
			if problem := netcheck.DNSProblem(host, ip, found, m.Net.OnThisMachine); problem == "" {
				return nil
			} else if !time.Now().Before(deadline) {
				return errorf(DNSNotReady, "%s", problem)
			}
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return errorf(DNSNotReady, "%s doesn't point to %s yet. DNS can take a few minutes; run this again", host, ip)
		}
		sleep(ctx, m.patience(5*time.Second))
	}
}

func (m *Manager) upPublic(ctx context.Context, st *state.State, e *state.Exposure, r Request) error {
	e.Port = 443
	m.say("Finding this machine's public address...")
	ip, err := m.Net.PublicIP(ctx)
	if err != nil {
		return errorf(PortUnavailable, "couldn't find this machine's public address: %v", err)
	}
	if !netcheck.IsPublic(ip) {
		return errorf(PortUnavailable, "this machine's address %s isn't public, so the internet can't reach it", ip)
	}
	if e.Cloudflare {
		if err := m.pointDNS(ctx, st, e, ip); err != nil {
			return err
		}
		e = st.Find(e.ID)
		if err := m.waitForDNS(ctx, e.Host, ip); err != nil {
			return err
		}
	} else {
		found, err := m.Net.Resolve(ctx, e.Host)
		if err != nil {
			return errorf(DNSNotReady, "couldn't look up %s: %v", e.Host, err)
		}
		if problem := netcheck.DNSProblem(e.Host, ip, found, m.Net.OnThisMachine); problem != "" {
			return errorf(DNSNotReady, "%s", problem)
		}
	}
	return m.serve(ctx, st, e)
}

func (m *Manager) upLAN(ctx context.Context, st *state.State, e *state.Exposure) error {
	if e.Port == 0 {
		e.Port = 8443
	}
	ip := m.lanAddress(*e)
	if ip == "" || netcheck.IsPublic(ip) {
		return errorf(Invalid, "this machine's address %q isn't a home network one. Use public access, "+
			"or --address with a private one such as its Tailscale address", ip)
	}
	if !m.Net.OnThisMachine(ip) {
		return errorf(Invalid, "%s isn't one of this machine's addresses", ip)
	}
	if err := m.pointDNS(ctx, st, e, ip); err != nil {
		return err
	}
	e = st.Find(e.ID)
	if res := e.Resource(state.Certificate); res == nil || !res.Done || m.Certs.Fingerprint(e.Host) == "" {
		var err error
		if e, err = m.begin(st, e, state.Resource{Kind: state.Certificate, Ref: e.Host, Owned: true}); err != nil {
			return err
		}
		m.say("Getting a certificate for %s from Let's Encrypt. This takes about a minute...", e.Host)
		if err := m.Certs.Issue(ctx, e.Host, false); err != nil {
			return wrap(CertificateFailed, err)
		}
		if err := m.finish(st, e, state.Certificate, true); err != nil {
			return err
		}
	}
	if err := m.Renewal.Enable(ctx); err != nil {
		return wrap(Failed, err)
	}
	return m.serve(ctx, st, st.Find(e.ID))
}

// sites is the whole Caddy config: every exposure with a Caddy site, plus extra.
func (m *Manager) sites(st *state.State, except string) []caddy.Site {
	var sites []caddy.Site
	for _, e := range st.Exposures {
		if e.ID == except || e.Resource(state.CaddySite) == nil {
			continue
		}
		s := caddy.Site{Host: e.Host, Upstream: e.Backend, Bind: e.Resource(state.CaddySite).Target}
		if e.Port != 443 {
			s.Port = e.Port
		}
		if e.Access == state.LAN {
			s.CertFile, s.KeyFile = m.Certs.Files(e.Host)
		}
		sites = append(sites, s)
	}
	return sites
}

func listenAddr(bind string, port int) string {
	return net.JoinHostPort(bind, strconv.Itoa(port))
}

// serve adds the exposure's Caddy site and waits for a trusted certificate.
func (m *Manager) serve(ctx context.Context, st *state.State, e *state.Exposure) error {
	if res := e.Resource(state.CaddySite); res == nil || !res.Done {
		bind, err := m.freePort(st, e)
		if err != nil {
			return err
		}
		if e, err = m.begin(st, e, state.Resource{Kind: state.CaddySite, Ref: fmt.Sprintf("%s:%d", e.Host, e.Port), Target: bind, Owned: true}); err != nil {
			return err
		}
	}
	m.say("Starting Caddy for %s...", e.URL())
	if err := m.Proxy.Apply(ctx, m.sites(st, "")); err != nil {
		return wrap(Failed, err)
	}
	m.say("Waiting for a trusted certificate. Let's Encrypt can take a minute...")
	addr := listenAddr(e.Resource(state.CaddySite).Target, e.Port)
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	if err := m.Proxy.Check(ctx, addr, e.Host); err != nil {
		return wrap(CertificateFailed, err)
	}
	return m.finish(st, e, state.CaddySite, true)
}

// lanAddress is where the exposure's LAN name points.
func (m *Manager) lanAddress(e state.Exposure) string {
	if e.Address != "" {
		return e.Address
	}
	return m.Net.LocalIP()
}

// freePort checks the port can be used, and returns an address to bind if only
// one of this machine's addresses is free. Tailscale serving the same port on its
// own address is the usual reason.
func (m *Manager) freePort(st *state.State, e *state.Exposure) (string, error) {
	for _, other := range st.Exposures {
		if other.ID != e.ID && other.Port == e.Port && other.Resource(state.CaddySite) != nil {
			return other.Resource(state.CaddySite).Target, nil // our Caddy already listens there
		}
	}
	err := m.Net.Listen(listenAddr("", e.Port))
	if err == nil {
		return "", nil
	}
	// Only the address people are sent to will do.
	ip := m.Net.LocalIP()
	if e.Access == state.LAN {
		ip = m.lanAddress(*e)
	}
	if ip != "" && m.Net.Listen(listenAddr(ip, e.Port)) == nil {
		return ip, nil
	}
	if e.Port == 443 {
		return "", errorf(PortUnavailable, "%s", netcheck.Port443(func() error { return err }))
	}
	return "", errorf(PortUnavailable, "port %d can't be used: %v", e.Port, err)
}
