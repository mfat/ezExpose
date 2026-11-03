package acme

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCertificatesDontDependOnLocalDNS(t *testing.T) {
	args := strings.Join(Issuer{Data: "/data"}.Args("vault.example.com"), " ")
	if !strings.Contains(args, "--dns.propagation.wait 30s") {
		t.Fatalf("a network that intercepts DNS would break this: %s", args)
	}
}

func TestCertificatePaths(t *testing.T) {
	i := Issuer{Data: "/data"}
	if i.CertFile("a.example.com") != "/data/certificates/a.example.com.crt" ||
		i.KeyFile("a.example.com") != "/data/certificates/a.example.com.key" {
		t.Fatal(i.CertFile("a.example.com"))
	}
}

func TestForceRenewsEarly(t *testing.T) {
	if args := strings.Join(Issuer{Force: true}.Args("a.example.com"), " "); !strings.Contains(args, "--renew-force") {
		t.Fatal(args)
	}
	if args := strings.Join(Issuer{}.Args("a.example.com"), " "); strings.Contains(args, "--renew-force") {
		t.Fatal(args)
	}
}

func TestTheTokenFileMustBeOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	i := Issuer{Tools: filepath.Join(dir, "tools"), Data: dir, TokenFile: token}
	if err := i.Issue(context.Background(), "a.example.com"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(i.Tools); err == nil {
		t.Fatal("went on to fetch lego")
	}
	for _, bad := range []string{filepath.Join(dir, "missing"), dir} {
		if err := ownerOnly(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if err := os.Chmod(token, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ownerOnly(token); err != nil {
		t.Fatal(err)
	}
}
