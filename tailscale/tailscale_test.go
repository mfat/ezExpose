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
		got, err := fake(tc.out, nil).Proxying(context.Background(), host, 443)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
}

const (
	box  = "box.tail1.ts.net"
	ours = "http://127.0.0.1:8080"
)

func route(target string) string {
	return `{"Web":{"box.tail1.ts.net:443":{"Handlers":{"/":{"Proxy":"` + target + `"}}}}}`
}

// daemon is a stand-in tailscaled that records the commands that change things.
type daemon struct {
	status  string
	changes []string
	fail    error
}

func (d *daemon) cli() CLI {
	return CLI{run: func(_ context.Context, args ...string) ([]byte, error) {
		cmd := strings.Join(args, " ")
		if cmd == "serve status --json" {
			return []byte(d.status), nil
		}
		if d.fail != nil {
			return []byte("Access denied: serve config denied"), d.fail
		}
		d.changes = append(d.changes, cmd)
		switch {
		case strings.HasSuffix(cmd, " off"):
			d.status = `{}`
		case strings.HasPrefix(cmd, "serve --bg"):
			d.status = route(args[len(args)-1])
		}
		return nil, nil
	}}
}

func TestServeExplainsTheOperatorStep(t *testing.T) {
	d := &daemon{status: `{}`, fail: errors.New("exit status 1")}
	err := d.cli().Serve(context.Background(), box, 443, ours)
	if err == nil || !strings.Contains(err.Error(), "--operator") {
		t.Fatalf("got %v", err)
	}
}

func TestServeTakesAFreePortAndIsSafeToRepeat(t *testing.T) {
	d := &daemon{status: `{}`}
	for range 2 {
		if err := d.cli().Serve(context.Background(), box, 443, ours); err != nil {
			t.Fatal(err)
		}
	}
	if len(d.changes) != 1 || d.changes[0] != "serve --bg --https=443 "+ours {
		t.Fatalf("ran: %v", d.changes)
	}
}

func TestNeverTouchesSomeoneElsesRoute(t *testing.T) {
	foreign := map[string]string{
		"other proxy": route("http://127.0.0.1:3000"),
		"files":       `{"Web":{"box.tail1.ts.net:443":{"Handlers":{"/":{"Path":"/srv"}}}}}`,
		"shared":      `{"Web":{"box.tail1.ts.net:443":{"Handlers":{"/":{"Proxy":"` + ours + `"},"/a":{"Proxy":"y"}}}}}`,
	}
	for name, status := range foreign {
		d := &daemon{status: status}
		if err := d.cli().Serve(context.Background(), box, 443, ours); !errors.Is(err, ErrNotOurs) {
			t.Errorf("%s: serve got %v", name, err)
		}
		if err := d.cli().Close(context.Background(), box, 443, ours); !errors.Is(err, ErrNotOurs) {
			t.Errorf("%s: close got %v", name, err)
		}
		if len(d.changes) != 0 || d.status != status {
			t.Errorf("%s: changed someone else's route: %v", name, d.changes)
		}
	}
}

func TestCloseConfirmsItReallyStopped(t *testing.T) {
	d := &daemon{status: route(ours)}
	if err := d.cli().Close(context.Background(), box, 443, ours); err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.changes, ";") != "serve --https=443 off" {
		t.Fatalf("ran: %v", d.changes)
	}
	// Already closed is fine, and changes nothing.
	if err := d.cli().Close(context.Background(), box, 443, ours); err != nil || len(d.changes) != 1 {
		t.Fatalf("second close: %v, %v", err, d.changes)
	}
}

func TestCloseReportsARouteThatSurvived(t *testing.T) {
	stuck := CLI{run: func(_ context.Context, args ...string) ([]byte, error) {
		if args[1] == "status" {
			return []byte(route(ours)), nil
		}
		return nil, nil
	}}
	if err := stuck.Close(context.Background(), box, 443, ours); err == nil {
		t.Error("claimed closed while Tailscale still forwards")
	}
	d := &daemon{status: route(ours), fail: errors.New("exit status 1")}
	if err := d.cli().Close(context.Background(), box, 443, ours); err == nil {
		t.Error("a failed stop looked fine")
	}
}

func TestEachPortIsSeparate(t *testing.T) {
	d := &daemon{status: route("http://127.0.0.1:3000")}
	if err := d.cli().Serve(context.Background(), box, 8443, ours); err != nil {
		t.Fatal(err)
	}
	if len(d.changes) != 1 || d.changes[0] != "serve --bg --https=8443 "+ours {
		t.Fatalf("ran: %v", d.changes)
	}
}
