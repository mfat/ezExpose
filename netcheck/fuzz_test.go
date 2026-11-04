package netcheck

import (
	"net"
	"testing"
)

func FuzzTraceIPOnlyReturnsAddresses(f *testing.F) {
	f.Add("h=1.1.1.1\nip=203.0.113.7\nloc=US\n")
	f.Add("ip=<html>\n")
	f.Add("ip=2001:db8::1")
	f.Fuzz(func(t *testing.T, body string) {
		if ip, err := traceIP(body); err == nil && net.ParseIP(ip) == nil {
			t.Fatalf("returned %q", ip)
		}
	})
}

func FuzzAddressChecksAgree(f *testing.F) {
	for _, ip := range []string{"203.0.113.7", "100.64.0.1", "10.0.0.1", "::1", "2001:db8::1", "x"} {
		f.Add(ip)
	}
	f.Fuzz(func(t *testing.T, ip string) {
		if IsPublic(ip) && IsTailnet(ip) {
			t.Fatalf("%q is both public and a tailnet address", ip)
		}
		if IsPublic(ip) && net.ParseIP(ip) == nil {
			t.Fatalf("%q isn't an address", ip)
		}
	})
}
