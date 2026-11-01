package acme

import (
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
