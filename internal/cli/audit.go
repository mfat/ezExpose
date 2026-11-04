package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/mfat/ezExpose/internal/audit"
)

// Audit is what the audit command needs: a way to look, which only ever reads.
type Audit func(ctx context.Context) audit.Report

func (a *App) audit(ctx context.Context, args []string) error {
	fs := a.flags("audit")
	if err := parse(fs, args); err != nil {
		return err
	}
	r := a.Look(ctx)
	if a.json {
		a.emit(map[string]any{"audit": r}, true)
		return nil
	}
	w := a.Out
	section := func(title string) { fmt.Fprintf(w, "\n%s\n", title) }
	section("Set up by ezExpose")
	if len(r.Exposures) == 0 {
		fmt.Fprintln(w, "  nothing")
	}
	for _, e := range r.Exposures {
		fmt.Fprintf(w, "  %-13s %-8s %s → %s  (%s)\n", e.ID, e.Access, e.URL(), e.Backend, e.Status)
	}
	var others []audit.Route
	for _, route := range r.Routes {
		if route.Ownership != audit.Ours {
			others = append(others, route)
		}
	}
	if len(others) > 0 {
		section("Other Tailscale routes, left alone")
		for _, route := range others {
			target := route.Proxy
			if target == "" {
				target = route.Other
			}
			scope := "your devices"
			if route.Funnel {
				scope = "the whole internet (Funnel)"
			}
			fmt.Fprintf(w, "  %-45s → %s  for %s\n", routeLabel(route), target, scope)
		}
	}
	section("Listening on this machine")
	for _, p := range r.Listening {
		who := p.Process
		if p.Container != "" {
			who = "Docker: " + p.Container
		}
		if who == "" {
			who = "(another user's program)"
		}
		if p.Ownership == audit.Ours {
			who += ", ezExpose's Caddy"
		}
		fmt.Fprintf(w, "  %-34s %-14s %s\n", hostPort(p.Address, p.Port), scopeOf(p.Listener), who)
	}
	if len(r.Findings) > 0 {
		section("Worth knowing")
		for _, f := range r.Findings {
			mark := map[audit.Severity]string{audit.Blocking: "✗", audit.Warning: "⚠", audit.Info: "·"}[f.Severity]
			fmt.Fprintf(w, "  %s %s\n", mark, strings.ReplaceAll(f.Message, "\n", "\n    "))
		}
	}
	fmt.Fprintln(w, "\nNothing was changed.")
	return nil
}

func routeLabel(r audit.Route) string {
	if r.Host == "" {
		return fmt.Sprintf("tcp port %d", r.Port)
	}
	label := "https://" + r.Host
	if r.Port != 443 {
		label += fmt.Sprintf(":%d", r.Port)
	}
	if r.Path != "/" {
		label += r.Path
	}
	return label
}

func hostPort(addr string, port int) string {
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func scopeOf(l audit.Listener) string {
	switch {
	case l.Local():
		return "this machine"
	case l.Everywhere():
		return "every address"
	}
	return "one address"
}
