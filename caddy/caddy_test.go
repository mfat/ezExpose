package caddy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	out, err := Render("/data", []Site{{Host: "app.example.com", Upstream: "127.0.0.1:1", SetupToken: token, SetupPaths: []string{"/signup"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"query setup=" + token + "", "path /signup /signup/*", "not header Cookie *ezsetup=" + token + "*", "respond @signup 403", "HttpOnly"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
}

const token = "0123456789abcdef0123456789abcdef"

func TestBadSetupGatesAreRefused(t *testing.T) {
	for _, s := range []Site{
		{Host: "a.example.com", Upstream: "127.0.0.1:1", SetupToken: token, SetupPaths: nil},
		{Host: "a.example.com", Upstream: "127.0.0.1:1", SetupToken: "abc123", SetupPaths: []string{"/s"}},
		{Host: "a.example.com", Upstream: "127.0.0.1:1", SetupToken: token + " b", SetupPaths: []string{"/s"}},
		{Host: "a.example.com", Upstream: "127.0.0.1:1", SetupToken: token + "\n}", SetupPaths: []string{"/s"}},
	} {
		if _, err := Render("/d", []Site{s}); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}

func TestOnlyFieldsReachTheCaddyfile(t *testing.T) {
	good := Site{Host: "a.example.com", Upstream: "127.0.0.1:8080"}
	bad := map[string]func(*Site){
		"upstream directive": func(s *Site) { s.Upstream = "127.0.0.1:8080\n\tredir https://evil.example" },
		"upstream space":     func(s *Site) { s.Upstream = "127.0.0.1:8080 10.0.0.1:80" },
		"upstream path":      func(s *Site) { s.Upstream = "http://127.0.0.1:8080/x" },
		"upstream scheme":    func(s *Site) { s.Upstream = "unix//run/app.sock" },
		"upstream no port":   func(s *Site) { s.Upstream = "127.0.0.1" },
		"upstream port":      func(s *Site) { s.Upstream = "127.0.0.1:70000" },
		"empty upstream":     func(s *Site) { s.Upstream = "" },
		"port":               func(s *Site) { s.Port = 70000 },
		"bind":               func(s *Site) { s.Bind = "0.0.0.0\n\tbind ::" },
		"bind name":          func(s *Site) { s.Bind = "localhost" },
		"cert without key":   func(s *Site) { s.CertFile = "/c.crt" },
		"key without cert":   func(s *Site) { s.KeyFile = "/c.key" },
		"both tls modes":     func(s *Site) { s.Internal, s.CertFile, s.KeyFile = true, "/c", "/k" },
		"cert newline":       func(s *Site) { s.CertFile, s.KeyFile = "/c\n}", "/k" },
		"block space":        func(s *Site) { s.Block = []string{"/admin /"} },
		"block brace":        func(s *Site) { s.Block = []string{"/admin}"} },
		"block wildcard":     func(s *Site) { s.Block = []string{"/admin*"} },
		"block root":         func(s *Site) { s.Block = []string{"/"} },
		"block relative":     func(s *Site) { s.Block = []string{"admin"} },
		"setup path":         func(s *Site) { s.SetupToken, s.SetupPaths = token, []string{"/s\n}"} },
	}
	for name, change := range bad {
		s := good
		change(&s)
		if out, err := Render("/d", []Site{s}); err == nil {
			t.Errorf("%s was accepted:\n%s", name, out)
		}
	}
	for _, upstream := range []string{"127.0.0.1:8080", "[::1]:8080", "app.internal.example:80", "http://127.0.0.1:8080", "https://10.0.0.5:8443"} {
		s := good
		s.Upstream = upstream
		if _, err := Render("/d", []Site{s}); err != nil {
			t.Errorf("%s: %v", upstream, err)
		}
	}
	s := good
	s.Bind = "::1"
	if _, err := Render("/d", []Site{s}); err != nil {
		t.Errorf("IPv6 bind: %v", err)
	}
}

// pinnedCaddy is the version CI installs. Older ones lack options we use.
const pinnedCaddy = "v2.11.7"

// TestRealCaddyAcceptsTheOutput runs every kind of site through Caddy's own
// parser. CI installs the pinned Caddy; elsewhere it's skipped without it.
func TestRealCaddyAcceptsTheOutput(t *testing.T) {
	bin, err := exec.LookPath("caddy")
	if err != nil {
		t.Skip("caddy isn't installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if v, _ := exec.CommandContext(ctx, bin, "version").Output(); !strings.HasPrefix(string(v), pinnedCaddy+" ") {
		t.Skipf("found Caddy %s, want %s", strings.TrimSpace(string(v)), pinnedCaddy)
	}
	dir := t.TempDir()
	out, err := Render(filepath.Join(dir, "data"), []Site{
		{Host: "app.example.com", Upstream: "127.0.0.1:8080", Block: []string{"/admin"},
			SetupToken: token, SetupPaths: []string{"/signup", "/api/register"}},
		{Host: "localhost", Port: 8443, Bind: "127.0.0.1", Internal: true, Upstream: "http://[::1]:8081"},
		{Host: "lan.example.com", Port: 8443, CertFile: "/c.crt", KeyFile: "/c.key", Upstream: "127.0.0.1:8082"},
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(file, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "adapt", "--config", file, "--adapter", "caddyfile")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("caddy refused it: %v\n%s\n%s", err, msg, out)
	}
}
