// Package caddy renders the Caddyfile that puts local services behind HTTPS.
package caddy

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// A Site is one address in front of one local service.
type Site struct {
	Host     string // a public name, or localhost
	Port     int    // 0 means 443
	Upstream string // such as 127.0.0.1:8080
	Bind     string // an address to listen on, or "" for every interface
	Internal bool   // use Caddy's private certificate authority
	CertFile string // a certificate from elsewhere, such as lego
	KeyFile  string
	Block    []string // paths the site must never serve, such as /admin

	// SetupToken and SetupPaths keep an app closed to strangers before its first
	// account: SetupPaths answer 403 unless the browser came through /?setup=TOKEN,
	// which sets a cookie. An interrupted setup stays closed. Clear the token once
	// the first account exists.
	SetupToken string
	SetupPaths []string // such as /signup and /api/register
}

// The name reaches the Caddyfile, so only a plain hostname gets through.
var validHost = regexp.MustCompile(`^(localhost|([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})$`)

var validToken = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// ValidHost reports whether host is safe to use as a site name.
func ValidHost(host string) bool { return validHost.MatchString(host) }

// Render writes the Caddyfile. Port 80 stays closed: Let's Encrypt can check over
// 443 alone, and that's one open port fewer.
func Render(storage string, sites []Site) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, `{
	admin off
	persist_config off
	skip_install_trust
	auto_https disable_redirects
	storage file_system {
		root %q
	}
}
`, storage)
	for _, s := range sites {
		if !ValidHost(s.Host) {
			return "", fmt.Errorf("%q isn't a host name", s.Host)
		}
		if s.Upstream == "" {
			return "", errors.New("a site needs an upstream")
		}
		if s.SetupToken != "" && (!validToken.MatchString(s.SetupToken) || len(s.SetupPaths) == 0) {
			return "", errors.New("a setup token must be letters and digits, and needs setup paths")
		}
		fmt.Fprintf(&b, "\nhttps://%s", s.Host)
		if s.Port != 0 {
			fmt.Fprintf(&b, ":%d", s.Port)
		}
		b.WriteString(" {\n")
		if s.Bind != "" {
			fmt.Fprintf(&b, "\tbind %s\n", s.Bind)
		}
		switch {
		case s.Internal:
			b.WriteString("\ttls internal\n")
		case s.CertFile != "":
			fmt.Fprintf(&b, "\ttls %q %q\n", s.CertFile, s.KeyFile)
		default:
			b.WriteString("\ttls {\n\t\tissuer acme {\n\t\t\tdisable_http_challenge\n\t\t}\n\t}\n")
		}
		for i, path := range s.Block {
			fmt.Fprintf(&b, "\t@block%d path %s %s/*\n\trespond @block%d 404\n", i, path, path, i)
		}
		writeSetupGate(&b, s)
		fmt.Fprintf(&b, "\treverse_proxy %s\n}\n", s.Upstream)
	}
	return b.String(), nil
}

func writeSetupGate(b *strings.Builder, s Site) {
	if s.SetupToken == "" {
		return
	}
	fmt.Fprintf(b, "\t@setuplink query setup=%s\n", s.SetupToken)
	fmt.Fprintf(b, "\theader @setuplink Set-Cookie \"ezsetup=%s; Path=/; Secure; HttpOnly; SameSite=Strict\"\n", s.SetupToken)
	b.WriteString("\tredir @setuplink / 302\n\t@signup {\n\t\tpath")
	for _, path := range s.SetupPaths {
		fmt.Fprintf(b, " %s %s/*", path, path)
	}
	fmt.Fprintf(b, "\n\t\tnot header Cookie *ezsetup=%s*\n\t}\n\trespond @signup 403\n", s.SetupToken)
}
