// Package netcheck answers the questions to ask before exposing anything: is this
// machine reachable, can it use port 443, and does a name point here?
package netcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var client = &http.Client{Timeout: 10 * time.Second}

// IsPublic reports whether ip can be reached from the internet. 100.64.0.0/10 is
// carrier NAT and Tailscale. A cloud machine with a private address and a mapped
// public one looks private here, so treat "false" as unknown, never as safe.
func IsPublic(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	shared := net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	return !shared.Contains(addr)
}

// LocalIP finds the address this machine uses on its network. Dialing UDP sends
// nothing.
func LocalIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:9")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// PublicIP asks an outside service, so only call it when the user chose public
// access.
func PublicIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return traceIP(string(raw))
}

func traceIP(body string) (string, error) {
	for _, line := range strings.Split(body, "\n") {
		if ip, ok := strings.CutPrefix(line, "ip="); ok {
			return ip, nil
		}
	}
	return "", errors.New("no answer from the address service")
}

// Resolve uses DNS over HTTPS, because many networks intercept or filter ordinary
// DNS, and Let's Encrypt sees the public answer anyway.
func Resolve(ctx context.Context, host string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://1.1.1.1/dns-query?type=A&name="+url.QueryEscape(host), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var reply struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	var found []string
	for _, answer := range reply.Answer {
		if answer.Type == 1 {
			found = append(found, answer.Data)
		}
	}
	return found, nil
}

// Port443 says why port 443 can't be used, in words a person can act on, or
// returns "".
func Port443(listen func() error) string {
	switch err := listen(); {
	case err == nil:
		return ""
	case errors.Is(err, syscall.EACCES):
		return "Port 443 needs permission once. Run this in another terminal:\n" +
			"    echo 'net.ipv4.ip_unprivileged_port_start=443' | sudo tee /etc/sysctl.d/90-ezexpose.conf\n" +
			"    sudo sysctl --system"
	case errors.Is(err, syscall.EADDRINUSE):
		return "Something else on this machine is using port 443. Stop it first."
	default:
		return fmt.Sprintf("Port 443 can't be used: %v", err)
	}
}

// Listen443 tries the port.
func Listen443() error {
	l, err := net.Listen("tcp", ":443")
	if err != nil {
		return err
	}
	return l.Close()
}
