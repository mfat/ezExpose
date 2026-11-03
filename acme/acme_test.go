package acme

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mfat/ezExpose/fetch"
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

func TestADamagedCachedLegoIsNotTrusted(t *testing.T) {
	dir := t.TempDir()
	scripts := map[string]string{
		"pinned":  "#!/bin/sh\necho lego version " + fetch.LegoVersion + " linux/amd64\n",
		"other":   "#!/bin/sh\necho lego version 4.0.0 linux/amd64\n",
		"crashes": "#!/bin/sh\nexit 1\n",
		"garbage": "\x7fELF\x00\x00 cut short",
	}
	for name, body := range scripts {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := works(context.Background(), path); got != (name == "pinned") {
			t.Errorf("%s: works = %v", name, got)
		}
	}
	if works(context.Background(), filepath.Join(dir, "missing")) {
		t.Error("a missing lego works")
	}
}
