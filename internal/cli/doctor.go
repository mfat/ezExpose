package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/mfat/ezExpose/fetch"
	"github.com/mfat/ezExpose/internal/manager"
	"github.com/mfat/ezExpose/internal/system"
	"github.com/mfat/ezExpose/netcheck"
	"github.com/mfat/ezExpose/tailscale"
)

// A Check is one thing doctor looked at.
type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	// For says which access needs it: all, private, public or lan.
	For    string `json:"for"`
	Detail string `json:"detail"`
}

// Doctor checks the real machine.
func Doctor(dir string, sys system.Systemd, ts tailscale.CLI) func(ctx context.Context) []Check {
	return func(ctx context.Context) []Check {
		var checks []Check
		add := func(name, scope string, ok bool, detail string) {
			checks = append(checks, Check{Name: name, For: scope, OK: ok, Detail: detail})
		}
		_, archErr := fetch.Caddy(runtime.GOARCH)
		add("Linux, 64-bit", "all", runtime.GOOS == "linux" && archErr == nil, runtime.GOOS+"/"+runtime.GOARCH)
		if err := sys.Available(ctx); err != nil {
			add("systemd", "public", false, err.Error())
		} else {
			add("systemd", "public", true, "Caddy and renewals run as services")
			if sys.Lingering(ctx) {
				add("Keeps running after logout", "public", true, "services start at boot")
			} else {
				add("Keeps running after logout", "public", false, "ezExpose turns this on when it can. If not, run: sudo loginctl enable-linger $USER")
			}
		}
		if host, err := ts.Lookup(ctx); err != nil {
			add("Tailscale", "private", false, err.Error())
		} else if _, err := ts.Proxying(ctx, host, 443); err != nil {
			add("Tailscale", "private", false, err.Error())
		} else {
			add("Tailscale", "private", true, host)
		}
		if problem := netcheck.Port443(netcheck.Listen443); problem != "" {
			add("Port 443", "public", false, problem)
		} else {
			add("Port 443", "public", true, "free")
		}
		info, err := os.Stat(system.TokenFile(dir))
		switch {
		case err != nil:
			add("Cloudflare token", "lan", false, "none saved. See: ezexpose cloudflare-token")
		case info.Mode().Perm()&0o077 != 0:
			add("Cloudflare token", "lan", false, "other users can read it. Run: chmod 600 "+system.TokenFile(dir))
		default:
			add("Cloudflare token", "lan", true, "saved")
		}
		return checks
	}
}

func (a *App) doctor(ctx context.Context, args []string) error {
	fs := a.flags("doctor")
	if err := parse(fs, args); err != nil {
		return err
	}
	checks := a.Doctor(ctx)
	ready := map[string]bool{"private": true, "public": true, "lan": true}
	for _, c := range checks {
		if c.OK {
			continue
		}
		switch c.For {
		case "all":
			ready = map[string]bool{"private": false, "public": false, "lan": false}
		case "public":
			ready["public"], ready["lan"] = false, false
		default:
			ready[c.For] = false
		}
	}
	var err error
	if !ready["private"] && !ready["public"] && !ready["lan"] {
		err = &manager.Error{Code: manager.Failed, Err: errors.New("this machine isn't ready for any kind of access yet")}
	}
	if a.json {
		a.emit(map[string]any{"checks": checks, "ready": ready}, err == nil)
		return err
	}
	for _, c := range checks {
		mark := "✓"
		if !c.OK {
			mark = "✗"
		}
		fmt.Fprintf(a.Out, "%s %-28s %s\n", mark, c.Name, strings.ReplaceAll(c.Detail, "\n", "\n  "))
	}
	fmt.Fprintln(a.Out)
	for _, access := range []string{"private", "public", "lan"} {
		state := "ready"
		if !ready[access] {
			state = "not ready"
		}
		fmt.Fprintf(a.Out, "  %-8s %s\n", access, state)
	}
	return err
}
