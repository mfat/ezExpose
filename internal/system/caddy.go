package system

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mfat/ezExpose/caddy"
	"github.com/mfat/ezExpose/fetch"
)

const caddyUnit = "ezexpose-caddy.service"

// Caddy is ezExpose's own Caddy, run by systemd. It owns its whole config, so it
// never touches a Caddy you run yourself.
type Caddy struct {
	Dir     string // ezExpose's folder
	Systemd Systemd
	Report  fetch.Report
	// CheckFor is how long Check waits for a trusted certificate.
	CheckFor time.Duration
}

func (c Caddy) file() string    { return filepath.Join(c.Dir, "Caddyfile") }
func (c Caddy) storage() string { return filepath.Join(c.Dir, "caddy") }

// Apply implements manager.Proxy. The new config is checked by Caddy itself
// before it replaces the old one, and the old one comes back if Caddy won't
// start with it.
func (c Caddy) Apply(ctx context.Context, sites []caddy.Site) error {
	if len(sites) == 0 {
		if err := c.Systemd.Delete(ctx, caddyUnit); err != nil {
			return err
		}
		if err := os.Remove(c.file()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := c.Systemd.Available(ctx); err != nil {
		return err
	}
	bin, err := fetch.Install(ctx, filepath.Join(c.Dir, "tools"), fetch.Caddy, c.Report)
	if err != nil {
		return err
	}
	text, err := caddy.Render(c.storage(), sites)
	if err != nil {
		return err
	}
	staged := c.file() + ".new"
	if err := os.WriteFile(staged, []byte(text), 0o600); err != nil {
		return err
	}
	defer os.Remove(staged)
	if out, err := exec.CommandContext(ctx, bin, "validate", "--config", staged, "--adapter", "caddyfile").CombinedOutput(); err != nil {
		return fmt.Errorf("caddy refused the new config, so the old one stays: %s", lastLine(out))
	}
	old, oldErr := os.ReadFile(c.file())
	if err := os.Rename(staged, c.file()); err != nil {
		return err
	}
	if err := c.start(ctx, bin); err != nil {
		if oldErr == nil {
			_ = os.WriteFile(c.file(), old, 0o600)
			_ = c.Systemd.Run(ctx, "restart", caddyUnit)
		} else {
			_ = c.Systemd.Delete(ctx, caddyUnit)
			_ = os.Remove(c.file())
		}
		return err
	}
	return nil
}

func (c Caddy) start(ctx context.Context, bin string) error {
	unit := fmt.Sprintf(`[Unit]
Description=ezExpose HTTPS proxy
Wants=network-online.target
After=network-online.target

[Service]
ExecStart="%s" run --config "%s" --adapter caddyfile
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
UMask=0077

[Install]
WantedBy=%s
`, bin, c.file(), c.Systemd.WantedBy())
	if err := c.Systemd.Write(ctx, map[string]string{caddyUnit: unit}); err != nil {
		return err
	}
	c.Systemd.KeepRunning(ctx)
	if err := c.Systemd.Run(ctx, "enable", caddyUnit); err != nil {
		return err
	}
	// Caddy's admin API is off, so a restart is how it picks up changes.
	if err := c.Systemd.Run(ctx, "restart", caddyUnit); err != nil {
		return err
	}
	// A bad port or certificate file makes Caddy exit a moment after starting.
	time.Sleep(2 * time.Second)
	if !c.Systemd.Active(ctx, caddyUnit) {
		hint := "journalctl --user -u " + caddyUnit
		if c.Systemd.Root {
			hint = "journalctl -u " + caddyUnit
		}
		return fmt.Errorf("caddy didn't stay running. See: %s", hint)
	}
	return nil
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines[len(lines)-1]
}

// Check implements manager.Proxy: addr must answer for host with a certificate
// this machine trusts, which for a public name means a real one.
func (c Caddy) Check(ctx context.Context, addr, host string) error {
	wait := c.CheckFor
	if wait == 0 {
		wait = 3 * time.Minute
	}
	deadline := time.Now().Add(wait)
	var last error
	for {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{ServerName: host}}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return fmt.Errorf("no trusted certificate for %s yet: %v. See: ezexpose logs", host, last)
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
}

// Logs shows Caddy's recent output.
func (c Caddy) Logs(ctx context.Context, lines int) *exec.Cmd {
	args := []string{"--no-pager", "-n", fmt.Sprint(lines), "-u", caddyUnit, "-u", renewUnit}
	if !c.Systemd.Root {
		args = append([]string{"--user"}, args...)
	}
	return exec.CommandContext(ctx, "journalctl", args...)
}

// PID returns the process ID of ezExpose's Caddy, or 0 if it isn't running. It
// only asks systemd.
func (c Caddy) PID(ctx context.Context) int {
	args := []string{"show", "-p", "MainPID", "--value", caddyUnit}
	if !c.Systemd.Root {
		args = append([]string{"--user"}, args...)
	}
	out, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return pid
}
