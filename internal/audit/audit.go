// Package audit looks at what's already on this machine: what ezExpose has set
// up, what Tailscale serves, what's listening and what Docker publishes. It only
// ever reads. Seeing something never makes it ezExpose's: ownership comes from
// ezExpose's own record alone.
package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/tailscale"
)

// Ownership says whose something is.
type Ownership string

const (
	Ours     Ownership = "ezexpose" // in ezExpose's record, and matching it exactly
	External Ownership = "external" // someone else's, and left alone
	Unknown  Ownership = "unknown"  // couldn't tell
)

// Severity says how much a finding matters.
type Severity string

const (
	Blocking Severity = "blocking" // something ezExpose can't do here until it's dealt with
	Warning  Severity = "warning"  // worth fixing
	Info     Severity = "info"     // worth knowing
)

// A Finding is one thing worth telling the person, in a plain sentence.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	// About names what it concerns, such as an exposure ID or host:port.
	About string `json:"about,omitempty"`
}

// Route is a Tailscale route and whose it is.
type Route struct {
	tailscale.Route
	Ownership Ownership `json:"ownership"`
}

// Port is something listening, whose it is, and which container it's for.
type Port struct {
	Listener
	Ownership Ownership `json:"ownership"`
	Container string    `json:"container,omitempty"`
}

// Detector says how one part of the look went.
type Detector struct {
	ID     string `json:"id"`
	Status string `json:"status"` // complete, partial, skipped or failed
	Reason string `json:"reason,omitempty"`
}

// Report is everything the audit saw.
type Report struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Exposures   []state.Exposure `json:"exposures"`
	Routes      []Route          `json:"routes"`
	Listening   []Port           `json:"listening"`
	Containers  []Container      `json:"containers"`
	Findings    []Finding        `json:"findings"`
	Detectors   []Detector       `json:"detectors"`
}

// Sources are the read-only ways to look. Any left nil is skipped.
type Sources struct {
	Owned      func() ([]state.Exposure, error)
	Listeners  func() ([]Listener, int, error)
	Routes     func(ctx context.Context) ([]tailscale.Route, error)
	Containers func(ctx context.Context) ([]Container, error)
	// CaddyPID is the process ID of ezExpose's own Caddy, or 0.
	CaddyPID func(ctx context.Context) int
	// Root is true when every program's name can be seen.
	Root bool
}

// timeout bounds each part, so one stuck command can't hang the whole audit.
const timeout = 10 * time.Second

// Run looks, and never changes anything. A part that fails is reported as
// failed, and the rest still counts: a failure never looks like "nothing found".
func Run(ctx context.Context, src Sources, now time.Time) Report {
	r := Report{GeneratedAt: now, Exposures: []state.Exposure{}, Routes: []Route{}, Listening: []Port{},
		Containers: []Container{}, Findings: []Finding{}}
	done := func(id string, err error, partial string) {
		d := Detector{ID: id, Status: "complete"}
		switch {
		case errors.Is(err, errSkipped):
			d.Status, d.Reason = "skipped", strings.TrimPrefix(err.Error(), errSkipped.Error()+": ")
		case err != nil:
			d.Status, d.Reason = "failed", err.Error()
		case partial != "":
			d.Status, d.Reason = "partial", partial
		}
		r.Detectors = append(r.Detectors, d)
	}

	if src.Owned != nil {
		owned, err := src.Owned()
		if owned != nil {
			r.Exposures = owned
		}
		done("ezexpose", err, "")
	}

	var routes []tailscale.Route
	if src.Routes != nil {
		var err error
		routes, err = bounded(ctx, src.Routes)
		for _, route := range routes {
			r.Routes = append(r.Routes, Route{Route: route, Ownership: routeOwner(route, r.Exposures)})
		}
		done("tailscale", err, "")
	} else {
		done("tailscale", skipped("Tailscale isn't installed"), "")
	}

	if src.Containers != nil {
		containers, err := bounded(ctx, src.Containers)
		if errors.Is(err, ErrNoDocker) {
			err = skipped(err.Error())
		}
		if containers != nil {
			r.Containers = containers
		}
		done("docker", err, "")
	} else {
		done("docker", skipped("Docker isn't installed"), "")
	}

	if src.Listeners != nil {
		listeners, hidden, err := src.Listeners()
		caddy := 0
		if src.CaddyPID != nil {
			caddy = src.CaddyPID(ctx)
		}
		for _, l := range listeners {
			r.Listening = append(r.Listening, Port{Listener: l, Ownership: listenerOwner(l, caddy),
				Container: containerFor(l.Port, r.Containers)})
		}
		slices.SortStableFunc(r.Listening, func(a, b Port) int {
			if a.Port != b.Port {
				return a.Port - b.Port
			}
			return strings.Compare(a.Address, b.Address)
		})
		partial := ""
		if hidden > 0 && !src.Root {
			partial = fmt.Sprintf("%d programs belong to other users, so their names aren't shown", hidden)
			if hidden == 1 {
				partial = "1 program belongs to another user, so its name isn't shown"
			}
		}
		done("listening", err, partial)
	}

	r.Findings = findings(r, src.Root)
	return r
}

var errSkipped = errors.New("skipped")

func skipped(reason string) error { return fmt.Errorf("%w: %s", errSkipped, reason) }

func bounded[T any](ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(ctx)
}

// routeOwner says a route is ezExpose's only when the record has that very
// route, done, pointing at the same place. A route to the same app set up by
// hand is still someone else's.
func routeOwner(route tailscale.Route, owned []state.Exposure) Ownership {
	if route.Path != "/" || route.Host == "" {
		return External
	}
	ref := fmt.Sprintf("%s:%d", route.Host, route.Port)
	for _, e := range owned {
		for _, res := range e.Resources {
			if res.Kind == state.TailscaleRoute && res.Done && res.Ref == ref && res.Target == route.Proxy {
				return Ours
			}
		}
	}
	return External
}

func listenerOwner(l Listener, caddyPID int) Ownership {
	switch {
	case caddyPID != 0 && l.PID == caddyPID:
		return Ours
	case l.Process != "":
		return External
	}
	return Unknown
}

func containerFor(port int, containers []Container) string {
	for _, c := range containers {
		for _, p := range c.Published {
			if p.Port == port {
				return c.Name
			}
		}
	}
	return ""
}

// findings turns what was seen into plain sentences.
func findings(r Report, root bool) []Finding {
	out := []Finding{}
	add := func(code string, sev Severity, about, format string, args ...any) {
		out = append(out, Finding{Code: code, Severity: sev, About: about, Message: fmt.Sprintf(format, args...)})
	}
	for _, e := range r.Exposures {
		if e.Status != state.Active {
			msg := string(e.Status)
			if e.Error != "" {
				msg += ": " + e.Error
			}
			add("exposure_not_active", Warning, e.ID, "%s (%s) is %s", e.URL(), e.ID, msg)
		}
		port := backendPort(e.Backend)
		listening := portsOn(r.Listening, port)
		if len(listening) == 0 {
			add("backend_down", Warning, e.ID, "nothing is listening on %s, so %s can't work. Is the app running?", e.Backend, e.URL())
			continue
		}
		for _, l := range listening {
			if l.Local() {
				continue
			}
			how := "Set the app to listen on 127.0.0.1 only"
			if l.Container != "" {
				how = fmt.Sprintf("Publish the %s container's port as 127.0.0.1:%d instead", l.Container, port)
			}
			where := "on every address"
			if !l.Everywhere() {
				where = "on " + l.Address
			}
			add("backend_reachable_directly", Warning, e.ID, "%s goes through ezExpose, but the app also listens %s "+
				"on port %d, so anyone who can reach this machine can open it directly, without HTTPS. %s",
				e.URL(), where, port, how)
			break
		}
	}
	for _, route := range r.Routes {
		if route.Funnel {
			add("tailscale_funnel", Warning, fmt.Sprintf("%s:%d", route.Host, route.Port),
				"Tailscale Funnel makes %s reachable from the whole internet, not just your devices. "+
					"ezExpose didn't set this up, and leaves it alone", routeURL(route.Route))
		}
	}
	for _, l := range r.Listening {
		if l.Port == 443 && l.Everywhere() && l.Ownership != Ours {
			who := "another program"
			if l.Process != "" {
				who = l.Process
			}
			add("port_443_taken", Blocking, "443", "%s already uses port 443 on every address, so public access "+
				"can't be set up here until it's stopped or moved", who)
			break
		}
	}
	for _, d := range r.Detectors {
		switch {
		case d.Status == "failed":
			add("look_failed", Info, d.ID, "couldn't check %s (%s), so this report doesn't cover it", d.ID, d.Reason)
		case d.Status == "partial" && d.ID == "listening" && !root:
			add("names_hidden", Info, d.ID, "%s. Run as root to see them", d.Reason)
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int { return severityRank(a.Severity) - severityRank(b.Severity) })
	return out
}

func severityRank(s Severity) int { return map[Severity]int{Blocking: 0, Warning: 1, Info: 2}[s] }

func backendPort(backend string) int {
	_, port, err := net.SplitHostPort(backend)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}

func portsOn(ports []Port, port int) []Port {
	var out []Port
	for _, p := range ports {
		if p.Port == port {
			out = append(out, p)
		}
	}
	return out
}

func routeURL(r tailscale.Route) string {
	if r.Host == "" {
		return fmt.Sprintf("port %d", r.Port)
	}
	url := "https://" + r.Host
	if r.Port != 443 {
		url += fmt.Sprintf(":%d", r.Port)
	}
	if r.Path != "/" {
		url += r.Path
	}
	return url
}
