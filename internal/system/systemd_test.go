package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystemd keeps units running until told to stop them.
func fakeSystemd(t *testing.T, stopFails bool) (Systemd, map[string]bool) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	running := map[string]bool{}
	s := Systemd{systemctl: func(_ context.Context, args ...string) error {
		switch args[0] {
		case "disable":
			if stopFails {
				return errors.New("Failed to stop: access denied")
			}
			running[args[len(args)-1]] = false
		case "is-active":
			if !running[args[len(args)-1]] {
				return errors.New("inactive")
			}
		case "enable":
			running[args[len(args)-1]] = true
		}
		return nil
	}}
	return s, running
}

func TestAUnitThatWontStopIsKept(t *testing.T) {
	s, running := fakeSystemd(t, true)
	if err := s.Write(context.Background(), map[string]string{"x.service": "[Unit]\n"}); err != nil {
		t.Fatal(err)
	}
	running["x.service"] = true
	err := s.Delete(context.Background(), "x.service")
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("got %v", err)
	}
	dir, _ := s.UnitDir()
	if _, err := os.Stat(filepath.Join(dir, "x.service")); err != nil {
		t.Fatal("deleted the file of a unit that's still running")
	}
}

func TestDeleteStopsThenRemoves(t *testing.T) {
	s, running := fakeSystemd(t, false)
	_ = s.Write(context.Background(), map[string]string{"x.service": "[Unit]\n"})
	running["x.service"] = true
	if err := s.Delete(context.Background(), "x.service", "never-there.service"); err != nil {
		t.Fatal(err)
	}
	dir, _ := s.UnitDir()
	if _, err := os.Stat(filepath.Join(dir, "x.service")); !os.IsNotExist(err) {
		t.Fatal("file survived")
	}
	if running["x.service"] {
		t.Fatal("still running")
	}
}
