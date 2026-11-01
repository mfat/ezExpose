package tailscale

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fake(out string, err error) CLI {
	return CLI{run: func(context.Context, ...string) ([]byte, error) { return []byte(out), err }}
}

func TestLookupReturnsTheNameWithoutItsTrailingDot(t *testing.T) {
	c := fake(`{"BackendState":"Running","CertDomains":["box.tail1.ts.net"],"Self":{"DNSName":"box.tail1.ts.net."}}`, nil)
	host, err := c.Lookup(context.Background())
	if err != nil || host != "box.tail1.ts.net" {
		t.Fatalf("got %q, %v", host, err)
	}
}

func TestLookupSaysWhatToFix(t *testing.T) {
	cases := map[string]struct{ out, want string }{
		"logged out": {`{"BackendState":"NeedsLogin"}`, "tailscale up"},
		"no name":    {`{"BackendState":"Running","Self":{"DNSName":""}}`, "MagicDNS"},
		"no https":   {`{"BackendState":"Running","Self":{"DNSName":"box.tail1.ts.net."}}`, "Turn on HTTPS"},
	}
	for name, tc := range cases {
		_, err := fake(tc.out, nil).Lookup(context.Background())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestProxyingTellsOursFromSomeoneElses(t *testing.T) {
	host := "box.tail1.ts.net"
	cases := map[string]struct{ out, want string }{
		"free":   {`{}`, ""},
		"proxy":  {`{"Web":{"box.tail1.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:18443"}}}}}`, "http://127.0.0.1:18443"},
		"files":  {`{"Web":{"box.tail1.ts.net:443":{"Handlers":{"/":{"Path":"/srv"}}}}}`, "something else"},
		"shared": {`{"Web":{"box.tail1.ts.net:443":{"Handlers":{"/":{"Proxy":"x"},"/a":{"Proxy":"y"}}}}}`, "something else"},
	}
	for name, tc := range cases {
		got, err := fake(tc.out, nil).Proxying(context.Background(), host)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
}

func TestServeExplainsTheOperatorStep(t *testing.T) {
	err := fake("Access denied: serve config denied", errors.New("exit status 1")).Serve(context.Background(), "http://x")
	if err == nil || !strings.Contains(err.Error(), "--operator") {
		t.Fatalf("got %v", err)
	}
}

func TestStopServingOnlyFreesOurPort(t *testing.T) {
	var got []string
	c := CLI{run: func(_ context.Context, args ...string) ([]byte, error) {
		got = args
		return nil, nil
	}}
	if err := c.StopServing(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "serve --https=443 off" {
		t.Fatalf("ran: %v", got)
	}
}
