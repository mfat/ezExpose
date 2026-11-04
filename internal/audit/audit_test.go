package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/tailscale"
)

const box = "box.tail1.ts.net"

// readOnly returns command runners that fail the test on anything but a read.
func readOnly(t *testing.T, serveStatus string, dockerPS string) (tailscale.CLI, func(context.Context, ...string) ([]byte, error)) {
	t.Helper()
	ts := tailscale.NewWith(func(_ context.Context, args ...string) ([]byte, error) {
		if strings.Join(args, " ") != "serve status --json" {
			t.Errorf("the audit ran tailscale %v", args)
		}
		return []byte(serveStatus), nil
	})
	docker := func(_ context.Context, args ...string) ([]byte, error) {
		if len(args) == 0 || args[0] != "ps" {
			t.Errorf("the audit ran docker %v", args)
		}
		return []byte(dockerPS), nil
	}
	return ts, docker
}

func scenario(t *testing.T) Sources {
	ts, docker := readOnly(t, `{
	  "Web": {
	    "box.tail1.ts.net:443":   {"Handlers": {"/": {"Proxy": "http://127.0.0.1:18443"}}},
	    "box.tail1.ts.net:8443":  {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}},
	    "box.tail1.ts.net:10000": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}}
	  },
	  "AllowFunnel": {"box.tail1.ts.net:10000": true}
	}`, "photos\t0.0.0.0:9000->9000/tcp, [::]:9000->9000/tcp\nquiet\t\n")
	owned := []state.Exposure{
		{ID: "exp_1", Backend: "127.0.0.1:8080", Access: state.Private, Host: box, Port: 8443, Status: state.Active,
			Resources: []state.Resource{{Kind: state.TailscaleRoute, Ref: box + ":8443", Target: "http://127.0.0.1:8080", Owned: true, Done: true}}},
		{ID: "exp_2", Backend: "127.0.0.1:9000", Access: state.Public, Host: "photos.example.com", Port: 443, Status: state.Active},
		{ID: "exp_3", Backend: "127.0.0.1:7777", Access: state.Public, Host: "gone.example.com", Port: 443, Status: state.Degraded, Error: "nothing answers"},
	}
	return Sources{
		Owned: func() ([]state.Exposure, error) { return owned, nil },
		Listeners: func() ([]Listener, int, error) {
			return []Listener{
				{Address: "0.0.0.0", Port: 8080, Process: "jellyfin", PID: 10},
				{Address: "0.0.0.0", Port: 443, Process: "nginx", PID: 11},
				{Address: "0.0.0.0", Port: 9000},
				{Address: "203.0.113.7", Port: 443, Process: "caddy", PID: 12},
			}, 1, nil
		},
		Routes:     ts.Routes,
		Containers: func(ctx context.Context) ([]Container, error) { return Containers(ctx, docker) },
		CaddyPID:   func(context.Context) int { return 12 },
	}
}

func codes(r Report) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Findings {
		if _, seen := out[f.Code]; !seen {
			out[f.Code] = f
		}
	}
	return out
}

func TestTheAuditSeesWhoseEverythingIs(t *testing.T) {
	r := Run(context.Background(), scenario(t), time.Now())
	owner := map[int]Ownership{}
	for _, route := range r.Routes {
		owner[route.Port] = route.Ownership
	}
	if owner[8443] != Ours || owner[443] != External || owner[10000] != External {
		t.Fatalf("routes: %+v", r.Routes)
	}
	listening := map[string]Port{}
	for _, p := range r.Listening {
		listening[p.Process+"/"+p.Address] = p
	}
	if listening["caddy/203.0.113.7"].Ownership != Ours || listening["nginx/0.0.0.0"].Ownership != External ||
		listening["/0.0.0.0"].Ownership != Unknown || listening["/0.0.0.0"].Container != "photos" {
		t.Fatalf("listening: %+v", r.Listening)
	}
	if len(r.Containers) != 1 || r.Containers[0].Name != "photos" || len(r.Containers[0].Published) != 2 {
		t.Fatalf("containers: %+v", r.Containers)
	}
}

func TestTheAuditSaysWhatMatters(t *testing.T) {
	r := Run(context.Background(), scenario(t), time.Now())
	got := codes(r)
	for code, want := range map[string]string{
		"port_443_taken":             "nginx",
		"tailscale_funnel":           "whole internet",
		"backend_down":               "127.0.0.1:7777",
		"exposure_not_active":        "exp_3",
		"backend_reachable_directly": "127.0.0.1 only",
		"names_hidden":               "1 program belongs",
	} {
		if !strings.Contains(got[code].Message, want) {
			t.Errorf("%s: %q", code, got[code].Message)
		}
	}
	if r.Findings[0].Severity != Blocking {
		t.Errorf("the blocking finding isn't first: %+v", r.Findings[0])
	}
	var container bool
	for _, f := range r.Findings {
		if f.Code == "backend_reachable_directly" && f.About == "exp_2" && strings.Contains(f.Message, "photos container") {
			container = true
		}
	}
	if !container {
		t.Errorf("no Docker advice: %+v", r.Findings)
	}
}

func TestARouteSetUpByHandIsNeverOurs(t *testing.T) {
	route := tailscale.Route{Host: box, Port: 8443, Path: "/", Proxy: "http://127.0.0.1:8080"}
	pending := []state.Exposure{{Resources: []state.Resource{{Kind: state.TailscaleRoute, Ref: box + ":8443", Target: "http://127.0.0.1:8080"}}}}
	other := []state.Exposure{{Resources: []state.Resource{{Kind: state.TailscaleRoute, Ref: box + ":8443", Target: "http://127.0.0.1:9", Done: true}}}}
	for name, owned := range map[string][]state.Exposure{"no record": nil, "only pending": pending, "different target": other} {
		if got := routeOwner(route, owned); got != External {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestAFailedPartIsNeverNothingFound(t *testing.T) {
	src := scenario(t)
	src.Routes = func(context.Context) ([]tailscale.Route, error) { return nil, errors.New("tailscaled isn't running") }
	src.Containers = func(context.Context) ([]Container, error) { return nil, ErrNoDocker }
	r := Run(context.Background(), src, time.Now())
	status := map[string]string{}
	for _, d := range r.Detectors {
		status[d.ID] = d.Status
	}
	if status["tailscale"] != "failed" || status["docker"] != "skipped" || status["listening"] != "partial" || status["ezexpose"] != "complete" {
		t.Fatalf("%+v", r.Detectors)
	}
	if !strings.Contains(codes(r)["look_failed"].Message, "tailscaled isn't running") {
		t.Fatalf("%+v", r.Findings)
	}
	if len(r.Listening) == 0 || len(r.Exposures) == 0 {
		t.Fatal("one failed part hid the rest")
	}
}

func TestDockerPortsAreRead(t *testing.T) {
	got := parseContainers("web\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp, 127.0.0.1:5432->5432/tcp, 53/udp, 0.0.0.0:6000-6001->6000-6001/tcp\nidle\t\n")
	if len(got) != 1 || len(got[0].Published) != 3 {
		t.Fatalf("%+v", got)
	}
	if p := got[0].Published[2]; p.Address != "127.0.0.1" || p.Port != 5432 || p.Everywhere() || !got[0].Published[1].Everywhere() {
		t.Fatalf("%+v", got[0].Published)
	}
	denied := func(context.Context, ...string) ([]byte, error) {
		return []byte("permission denied while trying to connect to the Docker daemon socket"), errors.New("exit status 1")
	}
	if _, err := Containers(context.Background(), denied); !errors.Is(err, ErrNoDocker) {
		t.Fatalf("%v", err)
	}
}
