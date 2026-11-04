package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestANewRecordGetsAnInstallID(t *testing.T) {
	st, err := Store{Dir: t.TempDir()}.Load()
	if err != nil || st.Version != Version || len(st.Install) != 32 {
		t.Fatalf("%+v, %v", st, err)
	}
}

func TestSaveAndLoad(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "nested")}
	st, _ := s.Load()
	st.Exposures = []Exposure{{ID: "exp_1", Backend: "127.0.0.1:8080", Access: Private,
		Resources: []Resource{{Kind: TailscaleRoute, Ref: "box:443", Owned: true}}}}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil || got.Install != st.Install || got.Find("exp_1").Resource(TailscaleRoute) == nil {
		t.Fatalf("%+v, %v", got, err)
	}
	info, _ := os.Stat(s.file())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("readable by others: %v", info.Mode())
	}
}

func TestTheOldRecordIsKept(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	st, _ := s.Load()
	st.Zone = "first"
	_ = s.Save(st)
	st.Zone = "second"
	_ = s.Save(st)
	raw, _ := os.ReadFile(s.backup())
	if !strings.Contains(string(raw), "first") {
		t.Fatalf("backup: %s", raw)
	}
	leftovers, _ := filepath.Glob(filepath.Join(s.Dir, ".state-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
}

func TestADamagedOrNewerRecordIsNeverOverwritten(t *testing.T) {
	for name, body := range map[string]string{
		"damaged": `{"version":1,"install":`,
		"newer":   `{"version":99,"install":"abc"}`,
		"foreign": `{"something":"else"}`,
	} {
		s := Store{Dir: t.TempDir()}
		_ = os.WriteFile(s.file(), []byte(body), 0o600)
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s: %v", name, err)
		}
		if raw, _ := os.ReadFile(s.file()); string(raw) != body {
			t.Errorf("%s: changed", name)
		}
	}
}

func TestOnlyOneCommandAtATime(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	unlock, err := s.Lock(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock(200 * time.Millisecond); err != ErrBusy {
		t.Fatalf("second lock: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		unlock()
	}()
	again, err := s.Lock(5 * time.Second)
	if err != nil {
		t.Fatalf("waiting didn't get the lock: %v", err)
	}
	again()
}

func TestURL(t *testing.T) {
	for want, e := range map[string]Exposure{
		"https://a.example.com":      {Host: "a.example.com", Port: 443},
		"https://a.example.com:8443": {Host: "a.example.com", Port: 8443},
	} {
		if e.URL() != want {
			t.Errorf("got %s, want %s", e.URL(), want)
		}
	}
}
