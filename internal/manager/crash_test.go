package manager

import (
	"fmt"
	"testing"

	"github.com/mfat/ezExpose/internal/state"
)

// setups covers every kind of access, with a route that isn't ours already there.
var setups = map[string]struct {
	r       Request
	prepare func(*world)
}{
	"private": {private, func(w *world) {}},
	"public": {public, func(w *world) {
		w.net.dns["app.example.com"] = []string{"203.0.113.7"}
	}},
	"lan": {lan, func(w *world) {}},
}

func foreign(w *world) { w.ts.routes[10000] = "http://127.0.0.1:3000" }

func checkForeign(t *testing.T, w *world, label string) {
	t.Helper()
	if w.ts.routes[10000] != "http://127.0.0.1:3000" {
		t.Fatalf("%s: someone else's route changed: %v", label, w.ts.routes)
	}
}

// TestACrashDuringApplyIsAlwaysRecovered kills apply at every change, before
// and after it takes effect, then checks recovery leaves it fully working.
func TestACrashDuringApplyIsAlwaysRecovered(t *testing.T) {
	for name, s := range setups {
		for _, after := range []bool{false, true} {
			for step := 1; ; step++ {
				label := fmt.Sprintf("%s, crash %s change %d", name, map[bool]string{false: "before", true: "after"}[after], step)
				w := newWorld(t)
				s.prepare(w)
				foreign(w)
				w.c.at, w.c.after = step, after
				if !crashes(func() { _, _ = w.manager().Apply(ctx, s.r) }) {
					if step < 2 {
						t.Fatalf("%s: apply changed nothing", label)
					}
					t.Logf("%s apply: crashed at each of %d changes", name, step-1)
					break // apply finished: every change has had its crash
				}
				w.c.at = 0
				list, err := w.manager().Reconcile(ctx)
				if err != nil {
					t.Fatalf("%s: reconcile: %v", label, err)
				}
				if len(list) != 1 || list[0].Status != state.Active {
					t.Fatalf("%s: after recovery: %+v", label, list)
				}
				checkWorks(t, w, list[0], label)
				checkForeign(t, w, label)
				if err := w.manager().Remove(ctx, list[0].ID); err != nil {
					t.Fatalf("%s: remove: %v", label, err)
				}
				checkClean(t, w, label)
			}
		}
	}
}

// TestACrashDuringRemoveIsAlwaysRecovered does the same for remove.
func TestACrashDuringRemoveIsAlwaysRecovered(t *testing.T) {
	for name, s := range setups {
		for _, after := range []bool{false, true} {
			for step := 1; ; step++ {
				label := fmt.Sprintf("%s, crash %s change %d", name, map[bool]string{false: "before", true: "after"}[after], step)
				w := newWorld(t)
				s.prepare(w)
				foreign(w)
				e, err := w.manager().Apply(ctx, s.r)
				if err != nil {
					t.Fatal(err)
				}
				w.c.n, w.c.at, w.c.after = 0, step, after
				if !crashes(func() { _ = w.manager().Remove(ctx, e.ID) }) {
					if step < 2 {
						t.Fatalf("%s: remove changed nothing", label)
					}
					t.Logf("%s remove: crashed at each of %d changes", name, step-1)
					break
				}
				w.c.at = 0
				list, err := w.manager().Reconcile(ctx)
				if err != nil || len(list) != 0 {
					t.Fatalf("%s: reconcile didn't finish the removal: %+v, %v", label, list, err)
				}
				checkClean(t, w, label)
				checkForeign(t, w, label)
			}
		}
	}
}

// TestRetryingApplyAfterACrashAlsoWorks covers the person running apply again
// instead of reconcile.
func TestRetryingApplyAfterACrashAlsoWorks(t *testing.T) {
	for name, s := range setups {
		for step := 1; ; step++ {
			w := newWorld(t)
			s.prepare(w)
			w.c.at, w.c.after = step, true
			if !crashes(func() { _, _ = w.manager().Apply(ctx, s.r) }) {
				break
			}
			w.c.at = 0
			e, err := w.manager().Apply(ctx, s.r)
			label := fmt.Sprintf("%s, crash after change %d", name, step)
			if err != nil || e.Status != state.Active {
				t.Fatalf("%s: %+v, %v", label, e, err)
			}
			checkWorks(t, w, e, label)
			if list, _ := w.manager().List(); len(list) != 1 {
				t.Fatalf("%s: %d exposures recorded", label, len(list))
			}
		}
	}
}

func checkWorks(t *testing.T, w *world, e state.Exposure, label string) {
	t.Helper()
	for _, res := range e.Resources {
		if !res.Done {
			t.Fatalf("%s: still pending: %+v", label, res)
		}
	}
	switch e.Access {
	case state.Private:
		if w.ts.routes[e.Port] != "http://"+e.Backend {
			t.Fatalf("%s: not served: %v", label, w.ts.routes)
		}
	case state.Public, state.LAN:
		if len(w.proxy.sites) != 1 || w.proxy.sites[0].Host != e.Host || w.dns.records[e.Host].ip == "" {
			t.Fatalf("%s: %+v, %v", label, w.proxy.sites, w.dns.records)
		}
	}
	if e.Access == state.LAN && (w.certs.certs[e.Host] == 0 || !w.renewal.on) {
		t.Fatalf("%s: certificate %v, renewal %v", label, w.certs.certs, w.renewal.on)
	}
}

func checkClean(t *testing.T, w *world, label string) {
	t.Helper()
	for port := range w.ts.routes {
		if port != 10000 {
			t.Fatalf("%s: left a route: %v", label, w.ts.routes)
		}
	}
	if len(w.dns.records) != 0 || len(w.proxy.sites) != 0 || len(w.certs.certs) != 0 || w.renewal.on {
		t.Fatalf("%s: left behind: dns %v, sites %v, certs %v, renewal %v",
			label, w.dns.records, w.proxy.sites, w.certs.certs, w.renewal.on)
	}
}
