package caddy

import (
	"strings"
	"testing"
)

// directives are the only things a line of the Caddyfile may start with.
var directives = []string{"{", "}", "admin ", "persist_config ", "skip_install_trust", "auto_https ", "storage ",
	"root ", "https://", "bind ", "tls", "issuer ", "disable_http_challenge", "@block", "respond ",
	"@setuplink ", "header ", "redir ", "@signup ", "path ", "not ", "reverse_proxy "}

// FuzzRenderCanOnlyFillFields throws arbitrary text at every field. Whatever
// Render accepts must still be one site, with balanced braces and only the
// directives Render writes: nothing a field holds can add to the config.
func FuzzRenderCanOnlyFillFields(f *testing.F) {
	f.Add("app.example.com", "127.0.0.1:8080", "", "/admin", "", "/signup")
	f.Add("app.example.com", "127.0.0.1:8080\n\tredir https://evil.example", "0.0.0.0\nbind ::", "/a}", "/c\n}", "/s s")
	f.Add("a.example.com", "http://[::1]:8081", "::1", "/x/y", "/c.crt", "/api/register")
	f.Add("localhost", "https://10.0.0.5:8443", "127.0.0.1", "/admin*", "\"/c\"", "/")
	f.Fuzz(func(t *testing.T, host, upstream, bind, block, cert, setupPath string) {
		s := Site{Host: host, Upstream: upstream, Bind: bind, Block: []string{block},
			SetupToken: "0123456789abcdef", SetupPaths: []string{setupPath}}
		if cert != "" {
			s.CertFile, s.KeyFile = cert, cert+".key"
		}
		out, err := Render("/data", []Site{s})
		if err != nil {
			return
		}
		if strings.Count(out, "{") != strings.Count(out, "}") {
			t.Fatalf("unbalanced braces:\n%s", out)
		}
		if n := strings.Count(out, "\nhttps://"); n != 1 {
			t.Fatalf("%d sites from one:\n%s", n, out)
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			known := false
			for _, d := range directives {
				if strings.HasPrefix(line, d) {
					known = true
					break
				}
			}
			if !known {
				t.Fatalf("a field became a directive: %q\n%s", line, out)
			}
		}
	})
}
