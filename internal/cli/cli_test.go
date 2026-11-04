package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
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

func envelope(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	if got["schema"] != float64(Schema) {
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
