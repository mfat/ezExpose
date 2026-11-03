// Package caddy renders the Caddyfile that puts local services behind HTTPS.
package caddy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
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

// A setup token is a password in a link, so it has to be long enough not to guess.
var validToken = regexp.MustCompile(`^[a-zA-Z0-9]{16,}$`)

// Paths are matched literally: no spaces, quotes, braces or wildcards.
var validPath = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)

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
		if err := s.check(); err != nil {
			return "", err
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

// check refuses anything that could add to the Caddyfile instead of filling a field.
func (s Site) check() error {
	if !ValidHost(s.Host) {
		return fmt.Errorf("%q isn't a host name", s.Host)
	}
	if s.Port < 0 || s.Port > 65535 {
		return fmt.Errorf("%d isn't a port", s.Port)
	}
	if err := checkUpstream(s.Upstream); err != nil {
		return err
	}
	if s.Bind != "" && net.ParseIP(s.Bind) == nil {
		return fmt.Errorf("%q isn't an address to listen on", s.Bind)
	}
	if (s.CertFile == "") != (s.KeyFile == "") {
		return errors.New("a certificate file needs its key file, and the other way round")
	}
	if s.Internal && s.CertFile != "" {
		return errors.New("a site uses either Caddy's own certificates or files, not both")
	}
	for _, f := range []string{s.CertFile, s.KeyFile} {
		if strings.ContainsFunc(f, isControl) {
			return fmt.Errorf("%q isn't a file name", f)
		}
	}
	if s.SetupToken != "" && (!validToken.MatchString(s.SetupToken) || len(s.SetupPaths) == 0) {
		return errors.New("a setup token must be at least 16 letters and digits, and needs setup paths")
	}
	for _, path := range append(append([]string{}, s.Block...), s.SetupPaths...) {
		if !validPath.MatchString(path) || strings.Contains(path, "//") || path == "/" {
			return fmt.Errorf("%q isn't a path to match", path)
		}
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// checkUpstream accepts host:port, optionally with http:// or https:// in front.
func checkUpstream(upstream string) error {
	bad := fmt.Errorf("%q isn't an upstream such as 127.0.0.1:8080", upstream)
	rest := upstream
	if scheme, after, ok := strings.Cut(upstream, "://"); ok {
		if scheme != "http" && scheme != "https" {
			return bad
		}
		rest = after
	}
	if u, err := url.Parse("http://" + rest); err != nil || u.Host != rest {
		return bad
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil || host == "" {
		return bad
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return bad
	}
	if net.ParseIP(host) == nil && !ValidHost(host) {
		return bad
	}
	return nil
}
