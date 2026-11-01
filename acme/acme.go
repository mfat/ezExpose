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
	"runtime"
	"strings"

	"github.com/mfat/ezExpose/fetch"
)

// Issuer gets and renews one host's certificate through Cloudflare.
type Issuer struct {
	Tools     string // where the pinned lego is kept
	Data      string // lego's account and certificates
	TokenFile string // an owner-only file holding the Cloudflare token
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
	return []string{"run", "--accept-tos", "--dns", "cloudflare", "--dns.propagation.wait", "30s",
		"--domains", host, "--path", i.Data, "--log.format", "text"}
}

// Issue gets or renews the certificate. lego reads the token from its file, so it
// never shows up in a process list. Run again, it only acts when renewal is due.
func (i Issuer) Issue(ctx context.Context, host string) error {
	lego, err := i.fetchLego(ctx)
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

// fetchLego downloads the pinned lego the first time. The folder only appears
// once complete and verified, so finding it is proof enough.
func (i Issuer) fetchLego(ctx context.Context) (string, error) {
	final := filepath.Join(i.Tools, "lego-"+fetch.LegoVersion)
	binary := filepath.Join(final, "lego")
	if _, err := os.Stat(final); err == nil {
		return binary, nil
	}
	url, sum, err := fetch.LegoRelease(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(i.Tools, 0o700); err != nil {
		return "", err
	}
	staged, err := os.MkdirTemp(i.Tools, ".download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staged)
	if err := fetch.ExtractLego(ctx, url, sum, staged, i.Report); err != nil {
		return "", fmt.Errorf("downloading lego: %w", err)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return "", err
	}
	return binary, os.Rename(staged, final)
}
