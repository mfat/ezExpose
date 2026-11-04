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

// notRoutable are IPv4 ranges the internet doesn't route: "this network",
// carrier NAT and Tailscale, and the reserved block.
var notRoutable = []net.IPNet{
	{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)},
	{IP: net.IPv4(240, 0, 0, 0), Mask: net.CIDRMask(4, 32)},
}

// RecordType is the DNS record that holds ip: A for IPv4, AAAA for IPv6.
func RecordType(ip string) string {
	if addr := net.ParseIP(ip); addr != nil && addr.To4() == nil {
		return "AAAA"
	}
	return "A"
}

// IsTailnet reports whether ip is in the range Tailscale gives its devices.
func IsTailnet(ip string) bool {
	addr := net.ParseIP(ip)
	return addr != nil && notRoutable[1].Contains(addr)
}

// IsPublic reports whether ip is the kind of address the internet routes. It says
// nothing about whether anything can actually reach it: firewalls and missing
// port forwarding still get in the way, and only an outside check proves that. A
// cloud machine with a private address and a mapped public one looks private here,
// so treat "false" as unknown, never as safe.
func IsPublic(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, r := range notRoutable {
		if r.Contains(addr) {
			return false
		}
	}
	return true
}

// LocalIP finds the address this machine uses on its network. Dialing UDP sends
// nothing.
func LocalIP() string {
	// IPv4 first; an IPv6-only machine has no route for it.
	for _, target := range []string{"192.0.2.1:9", "[2001:db8::1]:9"} {
		conn, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		addr, ok := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		if ok {
			return addr.IP.String()
		}
	}
	return ""
}

// cloudflareDNS is tried by IPv4 first, then IPv6 for machines without IPv4.
var cloudflareDNS = []string{"1.1.1.1", "[2606:4700:4700::1111]"}

// fromCloudflare fetches path from the first of Cloudflare's addresses that answers.
func fromCloudflare(ctx context.Context, path string, header http.Header) (*http.Response, error) {
	var last error
	for _, host := range cloudflareDNS {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// PublicIP asks an outside service, so only call it when the user chose public
// access.
func PublicIP(ctx context.Context) (string, error) {
	resp, err := fromCloudflare(ctx, "/cdn-cgi/trace", nil)
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
			if net.ParseIP(ip) == nil {
				return "", fmt.Errorf("the address service answered %q, which isn't an address", ip)
			}
			return ip, nil
		}
	}
	return "", errors.New("no answer from the address service")
}

// Resolve uses DNS over HTTPS, because many networks intercept or filter ordinary
// DNS, and Let's Encrypt sees the public answer anyway.
func Resolve(ctx context.Context, host string) ([]string, error) {
	v4, err := resolveType(ctx, host, "A", 1)
	if err != nil {
		return nil, err
	}
	v6, err := resolveType(ctx, host, "AAAA", 28)
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}

func resolveType(ctx context.Context, host, kind string, code int) ([]string, error) {
	resp, err := fromCloudflare(ctx, "/dns-query?type="+kind+"&name="+url.QueryEscape(host),
		http.Header{"Accept": {"application/dns-json"}})
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
		if answer.Type == code {
			found = append(found, answer.Data)
		}
	}
	return found, nil
}

// DNSProblem checks every answer for host, because one stray record sends some
// devices elsewhere. It says what to change, or returns "". onHost accepts an
// address this machine has beyond ip, such as its IPv6 one; see OnThisMachine.
func DNSProblem(host, ip string, found []string, onHost func(string) bool) string {
	matched := false
	var others []string
	for _, addr := range found {
		switch {
		case addr == ip:
			matched = true
		case !onHost(addr):
			others = append(others, addr)
		}
	}
	if !matched {
		return fmt.Sprintf("%s doesn't point to this machine yet. At your domain provider, add this record:\n"+
			"    "+RecordType(ip)+"  %s  %s\n"+
			"  If a proxy is on for this name, such as Cloudflare's orange cloud, turn it off.", host, host, ip)
	}
	if len(others) > 0 {
		return fmt.Sprintf("%s also points to %s, so some devices would go there instead.\n"+
			"  At your domain provider, remove those records, keeping only %s.", host, strings.Join(others, ", "), ip)
	}
	return ""
}

// OnThisMachine reports whether addr belongs to one of this machine's interfaces.
func OnThisMachine(addr string) bool {
	want := net.ParseIP(addr)
	found, err := net.InterfaceAddrs()
	if want == nil || err != nil {
		return false
	}
	for _, a := range found {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(want) {
			return true
		}
	}
	return false
}

// Port443 says why port 443 can't be used, in words a person can act on, or
// returns "".
func Port443(listen func() error) string {
	switch err := listen(); {
	case err == nil:
		return ""
	case errors.Is(err, syscall.EACCES):
		return "Port 443 needs permission once. This lets every program on this machine use it.\n" +
			"  Run this in another terminal, or run as root:\n" +
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
