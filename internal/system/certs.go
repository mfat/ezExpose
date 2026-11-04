package system

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mfat/ezExpose/acme"
	"github.com/mfat/ezExpose/cloudflare"
	"github.com/mfat/ezExpose/fetch"
	"github.com/mfat/ezExpose/internal/manager"
)

// TokenFile is where the Cloudflare token is kept, readable only by its owner.
func TokenFile(dir string) string { return filepath.Join(dir, "cloudflare-token") }

// SaveToken stores a Cloudflare token for later runs.
func SaveToken(dir, token string) error {
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("that doesn't look like a Cloudflare token")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := TokenFile(dir) + ".new"
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, TokenFile(dir))
}

// DNS returns the manager's Cloudflare client for an install.
func DNS(dir string) func(install string) (manager.DNS, error) {
	return func(install string) (manager.DNS, error) {
		raw, err := os.ReadFile(TokenFile(dir))
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no Cloudflare token yet. Create one here, then save it with "+
				"ezexpose cloudflare-token:\n  %s", cloudflare.TokenURL)
		}
		if err != nil {
			return nil, err
		}
		c, err := cloudflare.New(strings.TrimSpace(string(raw)), install)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

// Certs gets certificates with lego, through Cloudflare.
type Certs struct {
	Dir    string
	Report fetch.Report
}

func (c Certs) issuer(force bool) acme.Issuer {
	return acme.Issuer{Tools: filepath.Join(c.Dir, "tools"), Data: filepath.Join(c.Dir, "lego"),
		TokenFile: TokenFile(c.Dir), Force: force, Report: c.Report}
}

// Issue implements manager.Certs.
func (c Certs) Issue(ctx context.Context, host string, force bool) error {
	return c.issuer(force).Issue(ctx, host)
}

// Files implements manager.Certs.
func (c Certs) Files(host string) (string, string) {
	i := c.issuer(false)
	return i.CertFile(host), i.KeyFile(host)
}

// Fingerprint implements manager.Certs.
func (c Certs) Fingerprint(host string) string {
	cert, _ := c.Files(host)
	raw, err := os.ReadFile(cert)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Expires implements manager.Certs.
func (c Certs) Expires(host string) (time.Time, error) {
	cert, _ := c.Files(host)
	raw, err := os.ReadFile(cert)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return time.Time{}, errors.New("the certificate file is damaged")
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.NotAfter, nil
}

// Delete implements manager.Certs: every file lego keeps for host.
func (c Certs) Delete(host string) error {
	cert, _ := c.Files(host)
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(cert), host+".*"))
	if err != nil {
		return err
	}
	for _, path := range matches {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

const (
	renewUnit  = "ezexpose-renew.service"
	renewTimer = "ezexpose-renew.timer"
)

// Renewal runs ezexpose renew twice a day. lego only renews when it's due.
type Renewal struct {
	Dir     string
	Self    string // this program
	Systemd Systemd
}

// Enable implements manager.Renewal.
func (r Renewal) Enable(ctx context.Context) error {
	if err := r.Systemd.Available(ctx); err != nil {
		return err
	}
	units := map[string]string{
		renewUnit: fmt.Sprintf(`[Unit]
Description=ezExpose certificate renewal
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Environment=EZEXPOSE_HOME=%s
ExecStart="%s" renew
`, r.Dir, r.Self),
		renewTimer: `[Unit]
Description=ezExpose certificate renewal

[Timer]
OnCalendar=*-*-* 03,15:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
`,
	}
	if err := r.Systemd.Write(ctx, units); err != nil {
		return err
	}
	r.Systemd.KeepRunning(ctx)
	return r.Systemd.Run(ctx, "enable", "--now", renewTimer)
}

// Disable implements manager.Renewal.
func (r Renewal) Disable(ctx context.Context) error {
	return r.Systemd.Delete(ctx, renewTimer, renewUnit)
}
