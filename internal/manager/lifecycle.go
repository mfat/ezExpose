package manager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/tailscale"
)

// settlePending decides, for each change that may or may not have happened, which
// it was. Exactly what was asked for is ours; nothing there means it never
// happened; anything else is someone else's and stays as it is.
func (m *Manager) settlePending(ctx context.Context, st *state.State, e *state.Exposure) error {
	for _, res := range append([]state.Resource(nil), e.Resources...) {
		if res.Done {
			continue
		}
		switch res.Kind {
		case state.TailscaleRoute:
			current, err := m.Tailnet.Proxying(ctx, e.Host, e.Port)
			if err != nil {
				return wrap(TailscaleNotReady, err)
			}
			switch current {
			case res.Target:
				e.Resource(res.Kind).Done = true
			case "":
				e.Drop(res.Kind)
			default:
				e.Drop(res.Kind)
				_ = m.save(st)
				return errorf(NotOurs, "%s forwards to %s, which ezExpose didn't set up. Left alone", e.URL(), current)
			}
		case state.DNSRecord:
			d, err := m.dns(st)
			if err != nil {
				return err
			}
			got, err := d.Pointing(ctx, zoneOf(res.Ref), e.Host)
			if err != nil {
				return wrap(DNSNotReady, err)
			}
			if got == "" {
				e.Drop(res.Kind) // Cloudflare marks ours with the install ID, so none exists
				break
			}
			r := e.Resource(res.Kind)
			r.Done, r.Owned, r.Target = true, true, got
		case state.Certificate:
			if m.Certs.Fingerprint(e.Host) != "" {
				e.Resource(res.Kind).Done = true
			} else {
				e.Drop(res.Kind)
			}
		case state.CaddySite:
			// The whole Caddy config is ours and rebuilt from the record each time.
			e.Drop(res.Kind)
		}
	}
	return m.save(st)
}

// Remove takes an exposure down, newest part first, and forgets it once every
// part is confirmed gone. Interrupted, running it again carries on.
func (m *Manager) Remove(ctx context.Context, id string) error {
	return m.locked(func(st *state.State) error {
		e := st.Find(id)
		if e == nil {
			return errorf(NotFound, "there's no exposure %s. See: ezexpose status", id)
		}
		e.Status = state.Removing
		if err := m.save(st); err != nil {
			return err
		}
		if err := m.down(ctx, st, e); err != nil {
			e = st.Find(id)
			e.Error = err.Error()
			return errors.Join(err, m.save(st))
		}
		st.Delete(id)
		if !hasLAN(st) && m.Renewal != nil {
			if err := m.Renewal.Disable(ctx); err != nil {
				return errors.Join(wrap(Failed, err), m.save(st))
			}
		}
		return m.save(st)
	})
}

func hasLAN(st *state.State) bool {
	for _, e := range st.Exposures {
		if e.Access == state.LAN {
			return true
		}
	}
	return false
}

func (m *Manager) down(ctx context.Context, st *state.State, e *state.Exposure) error {
	if err := m.settlePending(ctx, st, e); err != nil && CodeOf(err) != NotOurs {
		return err
	}
	if e.Access != state.Private {
		m.say("Removing %s from Caddy...", e.URL())
		if err := m.Proxy.Apply(ctx, m.sites(st, e.ID)); err != nil {
			return wrap(Failed, err)
		}
		e.Drop(state.CaddySite)
		if err := m.save(st); err != nil {
			return err
		}
	}
	if res := e.Resource(state.Certificate); res != nil {
		if res.Owned {
			if err := m.Certs.Delete(e.Host); err != nil {
				return wrap(Failed, err)
			}
		}
		e.Drop(state.Certificate)
		if err := m.save(st); err != nil {
			return err
		}
	}
	if res := e.Resource(state.DNSRecord); res != nil {
		if res.Owned {
			d, err := m.dns(st)
			if err != nil {
				return err
			}
			m.say("Removing the DNS record for %s...", e.Host)
			zone := zoneOf(res.Ref)
			if err := d.Remove(ctx, zone, e.Host); err != nil {
				return wrap(DNSNotReady, err)
			}
			if got, err := d.Pointing(ctx, zone, e.Host); err != nil || got != "" {
				return errorf(Failed, "couldn't confirm the DNS record for %s is gone (%q, %v)", e.Host, got, err)
			}
		}
		e.Drop(state.DNSRecord)
		if err := m.save(st); err != nil {
			return err
		}
	}
	if res := e.Resource(state.TailscaleRoute); res != nil {
		m.say("Closing %s on Tailscale...", e.URL())
		err := m.Tailnet.Close(ctx, e.Host, e.Port, res.Target)
		switch {
		case errors.Is(err, tailscale.ErrNotOurs):
			m.say("%s now forwards somewhere else, so it was left alone.", e.URL())
		case err != nil:
			return wrap(TailscaleNotReady, err)
		}
		e.Drop(state.TailscaleRoute)
		if err := m.save(st); err != nil {
			return err
		}
	}
	return nil
}

// List returns the record as saved. It changes and checks nothing.
func (m *Manager) List() ([]state.Exposure, error) {
	st, err := m.Store.Load()
	if err != nil {
		return nil, wrap(BadRecord, err)
	}
	return st.Exposures, nil
}

// Reconcile checks every exposure against the machine. It finishes work a crash
// interrupted, and reports anything missing or changed, but never recreates
// something removed by hand: apply does that.
func (m *Manager) Reconcile(ctx context.Context) ([]state.Exposure, error) {
	var result []state.Exposure
	err := m.locked(func(st *state.State) error {
		for _, id := range ids(st) {
			e := st.Find(id)
			switch e.Status {
			case state.Removing:
				m.say("Finishing the removal of %s...", e.ID)
				if err := m.down(ctx, st, e); err != nil {
					st.Find(id).Error = err.Error()
				} else {
					st.Delete(id)
				}
			case state.Applying:
				m.say("Finishing setting up %s...", e.ID)
				r := Request{Backend: e.Backend, Access: e.Access, Host: e.Host, Port: e.Port, Cloudflare: e.Cloudflare, Address: e.Address, Confirmed: true}
				if e.Access == state.Private {
					r.Host = ""
				}
				if err := m.up(ctx, st, e, r); err != nil {
					e = st.Find(id)
					e.Status, e.Error = state.Failed, err.Error()
				}
			case state.Failed:
				// Left for the person: apply tries again, remove takes it down.
			default:
				m.check(ctx, st, e)
			}
			if err := m.save(st); err != nil {
				return err
			}
		}
		if !hasLAN(st) && m.Renewal != nil {
			_ = m.Renewal.Disable(ctx)
		}
		result = st.Exposures
		return nil
	})
	return result, err
}

func ids(st *state.State) []string {
	var out []string
	for _, e := range st.Exposures {
		out = append(out, e.ID)
	}
	return out
}

// check compares one exposure with the machine and records what it found.
func (m *Manager) check(ctx context.Context, st *state.State, e *state.Exposure) {
	e.Checked = m.now()
	if err := m.settlePending(ctx, st, e); err != nil {
		e.Status, e.Error = state.Degraded, err.Error()
		return
	}
	var problems []string
	unknown := false
	for _, res := range e.Resources {
		switch res.Kind {
		case state.TailscaleRoute:
			current, err := m.Tailnet.Proxying(ctx, e.Host, e.Port)
			switch {
			case err != nil:
				unknown = true
				problems = append(problems, "couldn't ask Tailscale: "+err.Error())
			case current == "":
				problems = append(problems, "Tailscale no longer serves "+e.URL()+". Run apply again to put it back")
			case current != res.Target:
				problems = append(problems, fmt.Sprintf("%s now forwards to %s instead", e.URL(), current))
			}
		case state.DNSRecord:
			if !res.Owned {
				continue
			}
			d, err := m.dns(st)
			if err == nil {
				var got string
				if got, err = d.Pointing(ctx, zoneOf(res.Ref), e.Host); err == nil && got != res.Target {
					problems = append(problems, fmt.Sprintf("the DNS record for %s points to %q, not %s", e.Host, got, res.Target))
				}
			}
			if err != nil {
				unknown = true
				problems = append(problems, "couldn't ask Cloudflare: "+err.Error())
			}
		case state.Certificate:
			expires, err := m.Certs.Expires(e.Host)
			switch {
			case err != nil:
				problems = append(problems, "the certificate is missing: "+err.Error())
			case expires.Before(m.now().Add(7 * 24 * time.Hour)):
				problems = append(problems, "the certificate expires "+expires.Format("2 Jan")+". Run: ezexpose renew")
			}
		}
	}
	if err := m.Net.Dial(ctx, e.Backend); err != nil {
		problems = append(problems, "nothing answers on "+e.Backend+". Is the app running?")
	} else if len(problems) == 0 {
		quick := *m
		quick.Patience = time.Second * 5 / 60 // 5 seconds instead of a minute
		if problem := quick.answers(ctx, *e); problem != "" {
			problems = append(problems, problem)
		}
	}
	switch {
	case unknown:
		e.Status = state.Unknown
	case len(problems) > 0:
		e.Status = state.Degraded
	default:
		e.Status = state.Active
	}
	e.Error = strings.Join(problems, "; ")
}

// Renew renews every LAN certificate that's due, or all of them with force, and
// reloads Caddy if any changed. It returns the names it renewed.
func (m *Manager) Renew(ctx context.Context, force bool) ([]string, error) {
	var renewed []string
	err := m.locked(func(st *state.State) error {
		var failures []error
		for i := range st.Exposures {
			e := &st.Exposures[i]
			if e.Access != state.LAN || e.Resource(state.Certificate) == nil {
				continue
			}
			before := m.Certs.Fingerprint(e.Host)
			if err := m.Certs.Issue(ctx, e.Host, force); err != nil {
				e.Status, e.Error = state.Degraded, "renewing the certificate failed: "+err.Error()
				failures = append(failures, fmt.Errorf("%s: %w", e.Host, err))
				continue
			}
			if m.Certs.Fingerprint(e.Host) != before {
				renewed = append(renewed, e.Host)
			}
		}
		if len(renewed) > 0 {
			m.say("Reloading Caddy with the new certificates...")
			if err := m.Proxy.Apply(ctx, m.sites(st, "")); err != nil {
				failures = append(failures, err)
			}
		}
		if err := m.save(st); err != nil {
			failures = append(failures, err)
		}
		if len(failures) > 0 {
			return wrap(CertificateFailed, errors.Join(failures...))
		}
		return nil
	})
	return renewed, err
}
