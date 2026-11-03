package fetch

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// LegoVersion and CaddyVersion are the tested releases. Each is pinned by checksum.
const (
	LegoVersion  = "5.6.0"
	CaddyVersion = "2.11.7"
)

var legoSHA256 = map[string]string{
	"amd64": "f02fc11b6f56b97e387fa7caa0268f86f5a336953b22458e6430e4651fea439a",
	"arm64": "34d87a6552d69390c4a4560237045c47713a8e148d899e16db0e97040894ed1f",
}

var caddySHA512 = map[string]string{
	"amd64": "a7a433a1b133efc3c8d10eb0b99d52a24b5ef5c322dc77f5282182b1c0402139ab83f3a99f0c52409df77d20123fb0b523edad8a66d8f5e49136197bf61ef0e7",
	"arm64": "3db36ba90c7a6e8dda40ee3dd71fa08844c76b5fb08f61b31e5e78d2ed38e71c51dc7baed875e50d1ca1279196e84302967237386ae87c91ae9f2aaceada682e",
}

// A Tool is one pinned release binary.
type Tool struct {
	Name        string
	Version     string
	URL         string
	Sum         string
	newHash     func() hash.Hash
	versionArgs []string
}

// Lego returns the pinned lego for arch.
func Lego(arch string) (Tool, error) {
	sum, ok := legoSHA256[arch]
	if !ok {
		return Tool{}, fmt.Errorf("no lego build pinned for %s", arch)
	}
	return Tool{Name: "lego", Version: LegoVersion, Sum: sum, newHash: sha256.New, versionArgs: []string{"--version"},
		URL: fmt.Sprintf("https://github.com/go-acme/lego/releases/download/v%[1]s/lego_v%[1]s_linux_%[2]s.tar.gz",
			LegoVersion, arch)}, nil
}

// Caddy returns the pinned Caddy for arch. Its releases publish SHA-512.
func Caddy(arch string) (Tool, error) {
	sum, ok := caddySHA512[arch]
	if !ok {
		return Tool{}, fmt.Errorf("no Caddy build pinned for %s", arch)
	}
	return Tool{Name: "caddy", Version: CaddyVersion, Sum: sum, newHash: sha512.New, versionArgs: []string{"version"},
		URL: fmt.Sprintf("https://github.com/caddyserver/caddy/releases/download/v%[1]s/caddy_%[1]s_linux_%[2]s.tar.gz",
			CaddyVersion, arch)}, nil
}

// Install returns the path of the tool for this machine under dir, downloading
// it the first time. The folder only appears once complete and verified, but
// files can still go missing or get damaged later, so a copy that doesn't answer
// with its version is fetched again.
func Install(ctx context.Context, dir string, pick func(arch string) (Tool, error), report Report) (string, error) {
	t, err := pick(runtime.GOARCH)
	if err != nil {
		return "", err
	}
	final := filepath.Join(dir, t.Name+"-"+t.Version)
	binary := filepath.Join(final, t.Name)
	if t.Works(ctx, binary) {
		return binary, nil
	}
	if err := os.RemoveAll(final); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	staged, err := os.MkdirTemp(dir, ".download-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staged)
	if err := t.Extract(ctx, staged, report); err != nil {
		return "", fmt.Errorf("downloading %s: %w", t.Name, err)
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return "", err
	}
	return binary, os.Rename(staged, final)
}

// Works reports whether binary runs and is this tool's pinned version.
func (t Tool) Works(ctx context.Context, binary string) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, t.versionArgs...).Output()
	return err == nil && strings.Contains(string(out), t.Version)
}

// Extract downloads the release tarball, checks it against the pinned checksum
// and writes only the binary into dest.
func (t Tool) Extract(ctx context.Context, dest string, report Report) error {
	open := func(ctx context.Context, offset int64) (*http.Response, error) {
		req, err := rangeRequest(ctx, t.URL, offset)
		if err != nil {
			return nil, err
		}
		return http.DefaultClient.Do(req)
	}
	f, err := download(ctx, open, func(r io.Reader) error {
		h := t.newHash()
		if _, err := io.Copy(h, r); err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != t.Sum {
			return fmt.Errorf("%s checksum mismatch: got %s", t.Name, got)
		}
		return nil
	}, report)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s tarball holds no binary", t.Name)
		}
		if err != nil {
			return err
		}
		if hdr.Name == t.Name && hdr.Typeflag == tar.TypeReg {
			return writeFile(filepath.Join(dest, t.Name), tr, 0o755)
		}
	}
}

func writeFile(dst string, r io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
