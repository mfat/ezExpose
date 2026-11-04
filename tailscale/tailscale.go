// Package tailscale drives the tailscale command. The daemon terminates TLS and
// renews its own certificate, so we never handle one.
package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

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

// MinVersion is the oldest Tailscale whose serve command works the way this
// package uses it, with --bg and a port per route.
const MinVersion = "1.52.0"

// Version returns the installed Tailscale's version, such as 1.104.4.
func (c CLI) Version(ctx context.Context) (string, error) {
	out, err := c.run(ctx, "version")
	if err != nil {
		return "", fmt.Errorf("couldn't read Tailscale's version: %w", detail(out, err))
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return strings.TrimSpace(first), nil
}

// Older reports whether version a comes before b. Anything after a dash, as in
// 1.104.4-t9382131, is ignored.
func Older(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func parts(v string) [3]int {
	v, _, _ = strings.Cut(strings.TrimPrefix(v, "v"), "-")
	var out [3]int
	for i, field := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(field)
	}
	return out
}

// Lookup returns this machine's tailnet name, once it can have a certificate.
func (c CLI) Lookup(ctx context.Context) (string, error) {
	version, err := c.Version(ctx)
	if err != nil {
		return "", err
	}
	if Older(version, MinVersion) {
		return "", fmt.Errorf("Tailscale %s is too old. Update it to %s or later: https://tailscale.com/download", version, MinVersion)
	}
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

// Proxying returns what port on host forwards to, or "" if it's free.
func (c CLI) Proxying(ctx context.Context, host string, port int) (string, error) {
	out, err := c.run(ctx, "serve", "status", "--json")
	if err != nil {
		return "", permission(out, err)
	}
	var sc serveConfig
	if err := json.Unmarshal(out, &sc); err != nil {
		return "", fmt.Errorf("couldn't read Tailscale's serve settings: %w", err)
	}
	web, ok := sc.Web[host+":"+strconv.Itoa(port)]
	if !ok {
		return "", nil
	}
	// Anything but a single proxy at the root isn't ours to replace.
	if root, ok := web.Handlers["/"]; ok && len(web.Handlers) == 1 && root.Proxy != "" {
		return root.Proxy, nil
	}
	return "something else", nil
}

// ErrNotOurs means the port on the tailnet forwards somewhere else, so it was
// left alone.
var ErrNotOurs = errors.New("that Tailscale port is already in use by something else, so it was left alone")

// Serve forwards port on the tailnet to target, over HTTPS. It survives reboots.
// The port must be free or already forward to target: someone else's route is
// never replaced.
func (c CLI) Serve(ctx context.Context, host string, port int, target string) error {
	current, err := c.Proxying(ctx, host, port)
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
	out, err := c.run(ctx, "serve", "--bg", "--https="+strconv.Itoa(port), target)
	if err != nil {
		return permission(out, err)
	}
	return nil
}

// Close stops forwarding port to target and confirms it really stopped.
// Tailscale forwards straight to the app, past Caddy, so a caller must not claim
// access is closed without this. A route to anything else is left alone.
func (c CLI) Close(ctx context.Context, host string, port int, target string) error {
	current, err := c.Proxying(ctx, host, port)
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
	// A reset would also drop the user's other services, so only this port goes.
	if out, err := c.run(ctx, "serve", "--https="+strconv.Itoa(port), "off"); err != nil {
		return fmt.Errorf("Tailscale can still reach this app: %w", permission(out, err))
	}
	if current, err = c.Proxying(ctx, host, port); err != nil {
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
