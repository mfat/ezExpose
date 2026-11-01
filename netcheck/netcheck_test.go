package netcheck

import (
	"errors"
	"strings"
	"syscall"
	"testing"
)

func TestIsPublic(t *testing.T) {
	cases := map[string]bool{
		"203.0.113.7": true, "198.51.100.20": true, "192.168.1.20": false, "10.0.0.5": false,
		"172.16.0.1": false, "100.64.0.1": false, "127.0.0.1": false, "": false,
	}
	for ip, want := range cases {
		if got := IsPublic(ip); got != want {
			t.Errorf("%q: got %v", ip, got)
		}
	}
}

func TestTraceIP(t *testing.T) {
	if ip, err := traceIP("h=1.1.1.1\nip=203.0.113.7\nloc=US\n"); err != nil || ip != "203.0.113.7" {
		t.Fatalf("%q, %v", ip, err)
	}
	if _, err := traceIP("nothing"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestPort443SaysWhatToDo(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"free":          {nil, ""},
		"no permission": {syscall.EACCES, "sudo tee"},
		"in use":        {syscall.EADDRINUSE, "using port 443"},
		"other":         {errors.New("odd"), "odd"},
	}
	for name, tc := range cases {
		got := Port443(func() error { return tc.err })
		if (tc.want == "" && got != "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q", name, got)
		}
	}
}

func TestDNSMustPointOnlyHere(t *testing.T) {
	const ip = "203.0.113.7"
	none := func(string) bool { return false }
	cases := map[string]struct {
		found []string
		want  string
	}{
		"right":      {[]string{ip}, ""},
		"elsewhere":  {[]string{"198.51.100.1"}, "add this record"},
		"stray a":    {[]string{ip, "198.51.100.9"}, "also points to 198.51.100.9"},
		"stray aaaa": {[]string{ip, "2001:db8::1"}, "also points to 2001:db8::1"},
	}
	for name, tc := range cases {
		got := DNSProblem("app.example.com", ip, tc.found, none)
		if (tc.want == "" && got != "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q", name, got)
		}
	}
	mine := func(a string) bool { return a == "2001:db8::1" }
	if got := DNSProblem("app.example.com", ip, []string{ip, "2001:db8::1"}, mine); got != "" {
		t.Errorf("rejected this machine's own IPv6 address: %q", got)
	}
}
