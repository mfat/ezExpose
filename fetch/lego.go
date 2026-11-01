package fetch

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// LegoVersion is the tested lego. Each release pins exact content by digest.
const LegoVersion = "5.6.0"

var legoSHA256 = map[string]string{
	"amd64": "f02fc11b6f56b97e387fa7caa0268f86f5a336953b22458e6430e4651fea439a",
	"arm64": "34d87a6552d69390c4a4560237045c47713a8e148d899e16db0e97040894ed1f",
}

// LegoRelease returns the download URL and checksum for arch.
func LegoRelease(arch string) (url, sha256sum string, err error) {
	sha256sum, ok := legoSHA256[arch]
	if !ok {
		return "", "", fmt.Errorf("no lego build pinned for %s", arch)
	}
	url = fmt.Sprintf("https://github.com/go-acme/lego/releases/download/v%[1]s/lego_v%[1]s_linux_%[2]s.tar.gz",
		LegoVersion, arch)
	return url, sha256sum, nil
}

// ExtractLego downloads a release tarball, checks it against the pinned SHA-256
// and writes only the lego binary into dest.
func ExtractLego(ctx context.Context, url, sum, dest string, report Report) error {
	open := func(ctx context.Context, offset int64) (*http.Response, error) {
		req, err := rangeRequest(ctx, url, offset)
		if err != nil {
			return nil, err
		}
		return http.DefaultClient.Do(req)
	}
	f, err := download(ctx, open, func(r io.Reader) error {
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			return err
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != sum {
			return fmt.Errorf("lego checksum mismatch: got %s", got)
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
			return errors.New("lego tarball holds no binary")
		}
		if err != nil {
			return err
		}
		if hdr.Name == "lego" && hdr.Typeflag == tar.TypeReg {
			return writeFile(filepath.Join(dest, "lego"), tr, 0o755)
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
