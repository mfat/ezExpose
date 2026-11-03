// Package tailscale drives the tailscale command. The daemon terminates TLS and
// renews its own certificate, so we never handle one.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const servePort = "443"

// CLI talks to the local daemon through the tailscale command.
type CLI struct {
	run func(ctx context.Context, args ...string) ([]byte, error)
}

// New returns a CLI using the installed tailscale command.
func New() CLI {
	return CLI{run: func(ctx context.Context, args ...string) ([]byte, error) {
		if _, err := exec.LookPath("tailscale"); err != nil {
			return nil, errors.New("Tailscale isn't installed. Get it from https://tailscale.com/download")
		}
		return exec.CommandContext(ctx, "tailscale", args...).CombinedOutput()
	}}
}

type status struct {
	BackendState string
	CertDomains  []string
	Self         struct{ DNSName string }
}

// Lookup returns this machine's tailnet name, once it can have a certificate.
func (c CLI) Lookup(ctx context.Context) (string, error) {
	out, err := c.run(ctx, "status", "--json")
	if err != nil {
		return "", fmt.Errorf("couldn't read Tailscale's status: %w", detail(out, err))
	}
	var st status
	if err := json.Unmarshal(out, &st); err != nil {
		return "", fmt.Errorf("couldn't read Tailscale's status: %w", err)
	}
	if st.BackendState != "Running" {
		return "", errors.New("Tailscale isn't connected. Run: sudo tailscale up")
	}
	host := strings.TrimSuffix(st.Self.DNSName, ".")
	if host == "" {
		return "", errors.New("this machine has no tailnet name. Turn on MagicDNS at https://console.tailscale.com/admin/dns")
	}
	for _, domain := range st.CertDomains {
		if domain == host {
			return host, nil
		}
	}
	return "", errors.New("your tailnet can't issue certificates yet. Turn on HTTPS at https://console.tailscale.com/admin/dns")
}

type serveConfig struct {
	Web map[string]struct {
		Handlers map[string]struct{ Proxy string }
	}
}

// Proxying returns what host's port 443 forwards to, or "" if it's free.
func (c CLI) Proxying(ctx context.Context, host string) (string, error) {
	out, err := c.run(ctx, "serve", "status", "--json")
	if err != nil {
		return "", permission(out, err)
	}
	var sc serveConfig
	if err := json.Unmarshal(out, &sc); err != nil {
		return "", fmt.Errorf("couldn't read Tailscale's serve settings: %w", err)
	}
	web, ok := sc.Web[host+":"+servePort]
	if !ok {
		return "", nil
	}
	// Anything but a single proxy at the root isn't ours to replace.
	if root, ok := web.Handlers["/"]; ok && len(web.Handlers) == 1 && root.Proxy != "" {
		return root.Proxy, nil
	}
	return "something else", nil
}

// ErrNotOurs means port 443 on the tailnet forwards somewhere else, so it was
// left alone.
var ErrNotOurs = errors.New("Tailscale's port 443 is already in use by something else, so it was left alone")

// Serve forwards port 443 on the tailnet to target. It survives reboots. Port 443
// must be free or already forward to target: someone else's route is never replaced.
func (c CLI) Serve(ctx context.Context, host, target string) error {
	current, err := c.Proxying(ctx, host)
	if err != nil {
		return err
	}
	switch current {
	case target:
		return nil
	case "":
	default:
		return ErrNotOurs
	}
	// Tailscale can wait forever on a prompt to enable a feature.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := c.run(ctx, "serve", "--bg", "--https="+servePort, target)
	if err != nil {
		return permission(out, err)
	}
	return nil
}

// Close stops forwarding port 443 to target and confirms it really stopped.
// Tailscale forwards straight to the app, past Caddy, so a caller must not claim
// access is closed without this. A route to anything else is left alone.
func (c CLI) Close(ctx context.Context, host, target string) error {
	current, err := c.Proxying(ctx, host)
	if err != nil {
		return fmt.Errorf("couldn't check what Tailscale serves: %w", err)
	}
	switch current {
	case "":
		return nil
	case target:
	default:
		return ErrNotOurs
	}
	// A reset would also drop the user's other services, so only port 443 goes.
	if out, err := c.run(ctx, "serve", "--https="+servePort, "off"); err != nil {
		return fmt.Errorf("Tailscale can still reach this app: %w", permission(out, err))
	}
	if current, err = c.Proxying(ctx, host); err != nil {
		return fmt.Errorf("couldn't confirm Tailscale stopped: %w", err)
	}
	if current != "" {
		return errors.New("Tailscale can still reach this app")
	}
	return nil
}

func permission(out []byte, err error) error {
	if strings.Contains(strings.ToLower(string(out)), "access denied") {
		return errors.New("Tailscale needs your permission once. Run: sudo tailscale set --operator=$USER")
	}
	return detail(out, err)
}

func detail(out []byte, err error) error {
	if text := strings.TrimSpace(string(out)); text != "" {
		return fmt.Errorf("tailscale: %s", text)
	}
	return err
}
