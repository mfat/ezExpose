// Command ezexpose puts apps you already run behind real HTTPS.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/mfat/ezExpose/internal/audit"
	"github.com/mfat/ezExpose/internal/cli"
	"github.com/mfat/ezExpose/internal/manager"
	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/internal/system"
	"github.com/mfat/ezExpose/tailscale"
)

// version is set by the release build.
var version = "dev"

func main() {
	signal.Ignore(syscall.SIGPIPE)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dir, err := state.DefaultDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		os.Exit(1)
	}
	progress := cli.NewProgress(os.Stderr)
	sys := system.NewSystemd(progress)
	ts := tailscale.New()
	report := func(name string) func(int64) {
		const step = 5 << 20
		var shown int64
		return func(received int64) {
			if received/step > shown {
				shown = received / step
				fmt.Fprintf(progress, "  %s: %d MB\n", name, received>>20)
			}
		}
	}
	caddy := system.Caddy{Dir: dir, Systemd: sys, Report: report("Caddy")}
	m := &manager.Manager{
		Store:   state.Store{Dir: dir},
		Tailnet: ts,
		DNS:     system.DNS(dir),
		Proxy:   caddy,
		Certs:   system.Certs{Dir: dir, Report: report("lego")},
		Renewal: system.Renewal{Dir: dir, Self: self, Systemd: sys},
		Net:     system.Net{},
		Log:     progress,
		Wait:    10 * time.Second,
	}
	m.PortUser = func(port int) string {
		listeners, _, _ := audit.Listeners("/proc")
		for _, l := range listeners {
			if l.Port == port && l.Process != "" {
				return l.Process
			}
		}
		return ""
	}
	look := func(ctx context.Context) audit.Report {
		src := audit.Sources{
			Owned:     m.List,
			Listeners: func() ([]audit.Listener, int, error) { return audit.Listeners("/proc") },
			CaddyPID:  caddy.PID,
			Root:      os.Geteuid() == 0,
		}
		if _, err := exec.LookPath("tailscale"); err == nil {
			src.Routes = ts.Routes
		}
		if _, err := exec.LookPath("docker"); err == nil {
			src.Containers = func(ctx context.Context) ([]audit.Container, error) {
				return audit.Containers(ctx, func(ctx context.Context, args ...string) ([]byte, error) {
					return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
				})
			}
		}
		return audit.Run(ctx, src, time.Now().UTC())
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "renew" {
		m.Wait = 30 * time.Minute // a timer has nobody to tell, so it takes its turn
	}
	app := &cli.App{
		Out: os.Stdout, Err: os.Stderr, In: bufio.NewReader(os.Stdin),
		Dir: dir, Manager: m, Version: version,
		Terminal: term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())),
		Doctor:   cli.Doctor(dir, sys, ts),
		ReadSecret: func() (string, error) {
			raw, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			return strings.TrimSpace(string(raw)), err
		},
		Tailscale: ts.Version,
		Progress:  progress,
		Look:      look,
		Logs: func(ctx context.Context, lines int) error {
			cmd := caddy.Logs(ctx, lines)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			return cmd.Run()
		},
	}
	os.Exit(app.Run(ctx, args))
}
