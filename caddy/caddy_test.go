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
