package caddy

import (
	"strings"
	"testing"
)

func TestPublicSiteUsesPort443Alone(t *testing.T) {
	out, err := Render("/data", []Site{{Host: "app.example.com", Upstream: "127.0.0.1:8080", Block: []string{"/admin"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://app.example.com {", "disable_http_challenge", "disable_redirects", "path /admin /admin/*", "reverse_proxy 127.0.0.1:8080"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestLocalAndFileCertificateSites(t *testing.T) {
	out, err := Render("/data", []Site{
		{Host: "localhost", Port: 8443, Bind: "127.0.0.1", Internal: true, Upstream: "127.0.0.1:1"},
		{Host: "app.example.com", Port: 8443, CertFile: "/c.crt", KeyFile: "/c.key", Upstream: "127.0.0.1:1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://localhost:8443 {", "bind 127.0.0.1", "tls internal", `tls "/c.crt" "/c.key"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestBadNamesNeverReachTheCaddyfile(t *testing.T) {
	for _, bad := range []string{"", "a b.com", "x.com\n}", "--x.com", "*.example.com"} {
		if _, err := Render("/d", []Site{{Host: bad, Upstream: "127.0.0.1:1"}}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestSetupGateClosesSignupsToStrangers(t *testing.T) {
	out, err := Render("/data", []Site{{Host: "app.example.com", Upstream: "127.0.0.1:1", SetupToken: "abc123", SetupPaths: []string{"/signup"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"query setup=abc123", "path /signup /signup/*", "not header Cookie *ezsetup=abc123*", "respond @signup 403", "HttpOnly"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

func TestBadSetupGatesAreRefused(t *testing.T) {
	for _, s := range []Site{
		{Host: "a.example.com", Upstream: "x:1", SetupToken: "abc", SetupPaths: nil},
		{Host: "a.example.com", Upstream: "x:1", SetupToken: "a b", SetupPaths: []string{"/s"}},
		{Host: "a.example.com", Upstream: "x:1", SetupToken: "a\n}", SetupPaths: []string{"/s"}},
	} {
		if _, err := Render("/d", []Site{s}); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}
