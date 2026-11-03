package fetch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestADamagedCachedToolIsNotTrusted(t *testing.T) {
	lego, _ := Lego("amd64")
	dir := t.TempDir()
	scripts := map[string]string{
		"pinned":  "#!/bin/sh\necho lego version " + LegoVersion + " linux/amd64\n",
		"other":   "#!/bin/sh\necho lego version 4.0.0 linux/amd64\n",
		"crashes": "#!/bin/sh\nexit 1\n",
		"garbage": "\x7fELF\x00\x00 cut short",
	}
	for name, body := range scripts {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		if got := lego.Works(context.Background(), path); got != (name == "pinned") {
			t.Errorf("%s: works = %v", name, got)
		}
	}
	if lego.Works(context.Background(), filepath.Join(dir, "missing")) {
		t.Error("a missing lego works")
	}
}

func TestEveryArchitectureIsPinned(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, pick := range []func(string) (Tool, error){Lego, Caddy} {
			if tool, err := pick(arch); err != nil || tool.Sum == "" {
				t.Errorf("%s: %v", arch, err)
			}
		}
	}
	if _, err := Caddy("386"); err == nil {
		t.Error("an unpinned architecture was accepted")
	}
}
