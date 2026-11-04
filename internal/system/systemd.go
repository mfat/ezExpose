// Package system is the real machine behind the manager: systemd services for
// Caddy and renewal, certificates, the network, and the Cloudflare token.
package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

// Systemd runs units as the user, or as system units for root.
type Systemd struct {
	Root bool
	Log  io.Writer
}

// NewSystemd picks system units for root and user units for everyone else.
func NewSystemd(log io.Writer) Systemd { return Systemd{Root: os.Geteuid() == 0, Log: log} }

// UnitDir is where unit files go.
func (s Systemd) UnitDir() (string, error) {
	if s.Root {
		return "/etc/systemd/system", nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "systemd", "user"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

// WantedBy is the target units start with.
func (s Systemd) WantedBy() string {
	if s.Root {
		return "multi-user.target"
	}
	return "default.target"
}

// Run calls systemctl.
func (s Systemd) Run(ctx context.Context, args ...string) error {
	if !s.Root {
		args = append([]string{"--user"}, args...)
	}
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if detail := strings.TrimSpace(stderr.String()); detail != "" {
			return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), detail)
		}
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// Available says why services can't run here, or returns nil.
func (s Systemd) Available(ctx context.Context) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd wasn't found. ezExpose needs it to keep Caddy and renewals running")
	}
	if s.Root {
		return nil
	}
	args := []string{"--user", "is-system-running"}
	out, _ := exec.CommandContext(ctx, "systemctl", args...).Output()
	switch strings.TrimSpace(string(out)) {
	case "running", "degraded", "starting", "initializing":
		return nil
	}
	return errors.New("your user systemd session isn't running")
}

// Write saves units, reloading systemd if any changed.
func (s Systemd) Write(ctx context.Context, units map[string]string) error {
	dir, err := s.UnitDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	changed := false
	for name, body := range units {
		path := filepath.Join(dir, name)
		if old, err := os.ReadFile(path); err == nil && string(old) == body {
			continue
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return s.Run(ctx, "daemon-reload")
}

// Delete stops and removes units. Ones that were never there are fine.
func (s Systemd) Delete(ctx context.Context, names ...string) error {
	dir, err := s.UnitDir()
	if err != nil {
		return err
	}
	removed := false
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		_ = s.Run(ctx, "disable", "--now", name)
		if err := os.Remove(path); err != nil {
			return err
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return s.Run(ctx, "daemon-reload")
}

// Active reports whether unit is running.
func (s Systemd) Active(ctx context.Context, unit string) bool {
	return s.Run(ctx, "is-active", "--quiet", unit) == nil
}

// KeepRunning lets user services run without a login session and start at boot.
// It needs no password when the policy allows it; otherwise it says what to run.
func (s Systemd) KeepRunning(ctx context.Context) {
	if s.Root {
		return
	}
	u, err := user.Current()
	if err != nil {
		return
	}
	out, _ := exec.CommandContext(ctx, "loginctl", "show-user", u.Username, "-p", "Linger").Output()
	if strings.TrimSpace(string(out)) == "Linger=yes" {
		return
	}
	if exec.CommandContext(ctx, "loginctl", "enable-linger", u.Username).Run() == nil {
		return
	}
	if s.Log != nil {
		fmt.Fprintf(s.Log, "⚠ Caddy will stop when you log out, and won't start after a reboot. To fix that, run:\n"+
			"  sudo loginctl enable-linger %s\n", u.Username)
	}
}

// Lingering reports whether user services keep running without a login.
func (s Systemd) Lingering(ctx context.Context) bool {
	if s.Root {
		return true
	}
	u, err := user.Current()
	if err != nil {
		return false
	}
	out, _ := exec.CommandContext(ctx, "loginctl", "show-user", u.Username, "-p", "Linger").Output()
	return strings.TrimSpace(string(out)) == "Linger=yes"
}
