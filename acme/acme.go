// Package acme gets real certificates over the DNS challenge, so no ports need to
// be open. Official Caddy has no DNS plugins, so lego does the work and Caddy just
// serves the files.
package acme

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mfat/ezExpose/fetch"
)

// Issuer gets and renews one host's certificate through Cloudflare.
type Issuer struct {
	Tools     string // where the pinned lego is kept
	Data      string // lego's account and certificates
	TokenFile string // an owner-only file holding the Cloudflare token
	Force     bool   // renew even if it isn't due, for testing renewal
	Report    fetch.Report
}

// CertFile and KeyFile are where lego leaves a host's certificate.
func (i Issuer) CertFile(host string) string {
	return filepath.Join(i.Data, "certificates", host+".crt")
}
func (i Issuer) KeyFile(host string) string {
	return filepath.Join(i.Data, "certificates", host+".key")
}

// Args waits a fixed time instead of letting lego look for the record itself.
// Networks that intercept DNS answer that lookup with a stale "no such name", so
// it could never succeed. Let's Encrypt checks from outside, and Cloudflare is quick.
func (i Issuer) Args(host string) []string {
	args := []string{"run", "--accept-tos", "--dns", "cloudflare", "--dns.propagation.wait", "30s",
		"--domains", host, "--path", i.Data, "--log.format", "text"}
	if i.Force {
		args = append(args, "--renew-force")
	}
	return args
}

// Issue gets or renews the certificate. lego reads the token from its file, so it
// never shows up in a process list. lego 5's run does both: with a certificate
// already there, it only renews when about a third of its lifetime is left.
func (i Issuer) Issue(ctx context.Context, host string) error {
	if err := OwnerOnly(i.TokenFile); err != nil {
		return err
	}
	lego, err := fetch.Install(ctx, i.Tools, fetch.Lego, i.Report)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, lego, i.Args(host)...)
	cmd.Env = append(os.Environ(), "CLOUDFLARE_DNS_API_TOKEN_FILE="+i.TokenFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("the certificate request failed: %w\n%s", err, lastLines(out, 5))
	}
	return nil
}

func lastLines(out []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// OwnerOnly refuses a token file that other users could read or change, or a
// link that could lead anywhere.
func OwnerOnly(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("the Cloudflare token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("the Cloudflare token file %s isn't a plain file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("other users can read the Cloudflare token in %s. Run: chmod 600 %s", path, path)
	}
	return nil
}
