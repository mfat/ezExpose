package system

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCert(t *testing.T, path string, expires time.Time) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a.example.com"},
		NotBefore: time.Now(), NotAfter: expires}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateFiles(t *testing.T) {
	c := Certs{Dir: t.TempDir()}
	if c.Fingerprint("a.example.com") != "" {
		t.Fatal("a fingerprint with no certificate")
	}
	cert, key := c.Files("a.example.com")
	expires := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	writeCert(t, cert, expires)
	_ = os.WriteFile(key, []byte("key"), 0o600)
	other, _ := c.Files("b.example.com")
	writeCert(t, other, expires)
	first := c.Fingerprint("a.example.com")
	if got, err := c.Expires("a.example.com"); err != nil || !got.Equal(expires.UTC()) {
		t.Fatalf("%v, %v", got, err)
	}
	writeCert(t, cert, expires)
	if c.Fingerprint("a.example.com") == first {
		t.Fatal("a new certificate has the old fingerprint")
	}
	if err := c.Delete("a.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{cert, key} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s survived", f)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("deleted another name's certificate")
	}
}

func TestATokenWithSpacesIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"", "  ", "two words"} {
		if SaveToken(dir, bad) == nil {
			t.Errorf("%q was saved", bad)
		}
	}
	if _, err := DNS(dir)("0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "Edit zone DNS") {
		t.Fatalf("a client without a token, or no steps: %v", err)
	}
	if err := SaveToken(dir, "tok123\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := DNS(dir)("0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(TokenFile(dir), 0o644)
	if _, err := DNS(dir)("0123456789abcdef"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("a token others can read was used: %v", err)
	}
}
