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
}

// The name reaches the Caddyfile, so only a plain hostname gets through.
var validHost = regexp.MustCompile(`^(localhost|([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})$`)

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
		fmt.Fprintf(&b, "\treverse_proxy %s\n}\n", s.Upstream)
	}
	return b.String(), nil
}
