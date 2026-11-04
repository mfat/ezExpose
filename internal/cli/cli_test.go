package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mfat/ezExpose/internal/manager"
	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/internal/system"
)

func app(t *testing.T, input string) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	var out, errs bytes.Buffer
	return &App{
		Out: &out, Err: &errs, In: bufio.NewReader(strings.NewReader(input)), Dir: dir,
		Manager: &manager.Manager{Store: state.Store{Dir: dir}},
		Version: "test",
		Doctor: func(context.Context) []Check {
			return []Check{{Name: "Tailscale", For: "private", OK: false, Detail: "off"}}
		},
	}, &out, &errs
}

// envelope returns the result: the last line.
func envelope(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	if got["schema"] != float64(Schema) || got["event"] != "result" {
		t.Fatalf("no schema: %s", raw)
	}
	return got
}

func TestExitCodes(t *testing.T) {
	a, _, _ := app(t, "")
	if code := a.Run(context.Background(), []string{"nonsense"}); code != 2 {
		t.Errorf("unknown command: %d", code)
	}
	if code := a.Run(context.Background(), []string{"status", "--bogus"}); code != 2 {
		t.Errorf("unknown flag: %d", code)
	}
	if code := a.Run(context.Background(), []string{"remove"}); code != 2 {
		t.Errorf("remove without an ID: %d", code)
	}
	if code := a.Run(context.Background(), []string{"status"}); code != 0 {
		t.Errorf("status: %d", code)
	}
}

func TestErrorsCarryACode(t *testing.T) {
	a, out, _ := app(t, "")
	if code := a.Run(context.Background(), []string{"apply", "--json", "--backend", "nope", "--access", "private"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	got := envelope(t, out.Bytes())
	if got["ok"] != false || got["error"].(map[string]any)["code"] != string(manager.Invalid) {
		t.Fatalf("%s", out)
	}
}

func TestStatusJSONIsAnEmptyList(t *testing.T) {
	a, out, _ := app(t, "")
	a.Run(context.Background(), []string{"status", "--json"})
	if got := envelope(t, out.Bytes()); got["ok"] != true || len(got["exposures"].([]any)) != 0 {
		t.Fatalf("%s", out)
	}
}

func TestUnknownIDIsNotFound(t *testing.T) {
	a, out, _ := app(t, "")
	a.Run(context.Background(), []string{"status", "--json", "exp_none"})
	if envelope(t, out.Bytes())["error"].(map[string]any)["code"] != string(manager.NotFound) {
		t.Fatalf("%s", out)
	}
}

func TestRemoveWithoutAPersonNeedsYes(t *testing.T) {
	a, out, _ := app(t, "")
	a.Run(context.Background(), []string{"remove", "--json", "exp_1"})
	if envelope(t, out.Bytes())["error"].(map[string]any)["code"] != string(manager.NeedsConfirmation) {
		t.Fatalf("%s", out)
	}
}

func TestTokenIsSavedPrivately(t *testing.T) {
	a, out, _ := app(t, "abcdefgh1234\n")
	if code := a.Run(context.Background(), []string{"cloudflare-token"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "…1234") || strings.Contains(out.String(), "abcdefgh") {
		t.Fatalf("shown: %s", out)
	}
	info, err := os.Stat(system.TokenFile(a.Dir))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v, %v", info, err)
	}
	bad, _, _ := app(t, "two words\n")
	if code := bad.Run(context.Background(), []string{"cloudflare-token"}); code != 1 {
		t.Fatalf("accepted a bad token: %d", code)
	}
}

func TestDoctorFailsWhenNothingIsReady(t *testing.T) {
	a, out, _ := app(t, "")
	a.Doctor = func(context.Context) []Check {
		return []Check{{Name: "Linux", For: "all", OK: false}}
	}
	if code := a.Run(context.Background(), []string{"doctor", "--json"}); code != 1 {
		t.Fatalf("exit %d: %s", code, out)
	}
	b, out2, _ := app(t, "")
	if code := b.Run(context.Background(), []string{"doctor", "--json"}); code != 0 {
		t.Fatalf("public and lan are still ready: %d %s", code, out2)
	}
}

func TestVersionTellsAnAppWhatItCanDo(t *testing.T) {
	a, out, _ := app(t, "")
	a.Tailscale = func(context.Context) (string, error) { return "1.50.0", nil }
	a.Run(context.Background(), []string{"version", "--json"})
	got := envelope(t, out.Bytes())
	ts := got["tailscale"].(map[string]any)
	if got["version"] != "test" || ts["ok"] != false || ts["installed"] != "1.50.0" || len(got["commands"].([]any)) == 0 {
		t.Fatalf("%s", out)
	}
}

// deadNet is a network where nothing answers.
type deadNet struct{ manager.Net }

func (deadNet) Dial(context.Context, string) error { return errors.New("connection refused") }

func TestProgressBecomesEventsWithJSON(t *testing.T) {
	a, out, errs := app(t, "")
	a.Progress = NewProgress(a.Err)
	a.Manager.Log, a.Manager.Net = a.Progress, deadNet{}
	a.Run(context.Background(), []string{"apply", "--json", "--backend", "127.0.0.1:1", "--access", "lan", "--host", "a.example.com", "--yes"})
	fmt.Fprintln(a.Progress, "a step")
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var last map[string]any
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	if last["event"] != "progress" || last["message"] != "a step" || errs.Len() != 0 {
		t.Fatalf("stdout %q, stderr %q", out, errs)
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("not one JSON object per line: %q", line)
		}
	}
	b, _, errs2 := app(t, "")
	b.Progress = NewProgress(b.Err)
	b.Run(context.Background(), []string{"status"})
	fmt.Fprintln(b.Progress, "for people")
	if !strings.Contains(errs2.String(), "for people") {
		t.Fatalf("without --json, progress goes to stderr: %q", errs2)
	}
}

func TestPlanFileRoundTrip(t *testing.T) {
	a, out, _ := app(t, "")
	path := filepath.Join(t.TempDir(), "plan.json")
	if code := a.Run(context.Background(), []string{"plan", "--backend", "127.0.0.1:1", "--access", "lan", "--host", "a.example.com", "--out", path}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "--plan-file") {
		t.Fatalf("%s", out)
	}
	p, err := readPlan(path)
	if err != nil || p.Request.Host != "a.example.com" || p.Exposure.Port != 8443 {
		t.Fatalf("%+v, %v", p, err)
	}
	b, _, _ := app(t, "")
	if code := b.Run(context.Background(), []string{"apply", "--plan-file", path, "--host", "b.example.com"}); code != 2 {
		t.Fatalf("settings beside a plan file: exit %d", code)
	}
	_ = os.WriteFile(path, []byte(`{"schema":99,"plan":{}}`), 0o600)
	if _, err := readPlan(path); err == nil {
		t.Fatal("a plan from another schema was read")
	}
}

// results counts the result objects on stdout: there must be exactly one.
func results(t *testing.T, out string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		if obj["event"] == "result" {
			n++
		}
	}
	return n
}

func TestEveryJSONRunEndsWithExactlyOneResult(t *testing.T) {
	runs := map[string][]string{
		"doctor, nothing ready": {"doctor", "--json"},
		"unknown flag":          {"status", "--json", "--bogus"},
		"unknown command":       {"bogus", "--json"},
		"missing ID":            {"remove", "--json"},
		"bad request":           {"apply", "--json", "--backend", "nope", "--access", "private"},
		"status":                {"status", "--json"},
	}
	for name, args := range runs {
		a, out, errs := app(t, "")
		a.Doctor = func(context.Context) []Check { return []Check{{Name: "Linux", For: "all"}} }
		code := a.Run(context.Background(), args)
		if n := results(t, out.String()); n != 1 {
			t.Errorf("%s: %d results:\n%s", name, n, out)
		}
		if errs.Len() != 0 {
			t.Errorf("%s: text on stderr with --json: %q", name, errs)
		}
		got := envelope(t, out.Bytes())
		if (code == 0) != (got["ok"] == true) {
			t.Errorf("%s: exit %d but ok=%v", name, code, got["ok"])
		}
		if code == 2 && got["error"].(map[string]any)["code"] != string(manager.Usage) {
			t.Errorf("%s: %s", name, out)
		}
	}
}

func TestReconcileSaysWhenSomethingNeedsAttention(t *testing.T) {
	a, out, _ := app(t, "")
	st, _ := a.Manager.Store.Load()
	st.Exposures = []state.Exposure{{ID: "exp_1", Backend: "127.0.0.1:1", Access: state.Private, Host: "box.example.ts.net",
		Port: 443, Status: state.Failed, Error: "earlier failure",
		Resources: []state.Resource{{Kind: state.TailscaleRoute, Ref: "box:443", Done: true, Owned: true}}}}
	if err := a.Manager.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if code := a.Run(context.Background(), []string{"reconcile", "--json"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	got := envelope(t, out.Bytes())
	if results(t, out.String()) != 1 || got["error"].(map[string]any)["code"] != string(manager.NeedsAttention) ||
		len(got["exposures"].([]any)) != 1 {
		t.Fatalf("%s", out)
	}
}

func TestJSONNeverAsksEvenInATerminal(t *testing.T) {
	a, out, errs := app(t, "y\n")
	a.Terminal = true
	a.Run(context.Background(), []string{"remove", "--json", "exp_1"})
	if envelope(t, out.Bytes())["error"].(map[string]any)["code"] != string(manager.NeedsConfirmation) || errs.Len() != 0 {
		t.Fatalf("stdout %s, stderr %q", out, errs)
	}
}
