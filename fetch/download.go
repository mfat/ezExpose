package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Report receives the running total of bytes received. It may be nil.
type Report func(received int64)

const maxFailures = 5

// maxAttempts bounds a download that keeps delivering a little and dropping, which
// would otherwise never count as failing.
const maxAttempts = 200

// stallTimeout gives up on a connection that stops delivering. Slow is fine.
var stallTimeout = 45 * time.Second

// retryDelay is the base wait between attempts.
var retryDelay = time.Second

type openFunc func(ctx context.Context, offset int64) (*http.Response, error)

// download fetches into an unlinked temp file, so a partial or tampered file
// can never be found afterwards, and returns it positioned at the start.
//
// CDNs drop long transfers, so a dropped connection resumes from where it got
// to, and only attempts that deliver nothing count as failures. On a slow line
// that is what makes a large layer possible at all. verify sees the whole file.
func download(ctx context.Context, open openFunc, verify func(io.Reader) error, report Report) (*os.File, error) {
	f, err := os.CreateTemp("", "ezexpose-download-")
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name())
	if err := fetchAll(ctx, f, open, verify, report); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func fetchAll(ctx context.Context, f *os.File, open openFunc, verify func(io.Reader) error, report Report) error {
	var last error
	failures := 0
	for attempt := 0; failures < maxFailures; attempt++ {
		if attempt == maxAttempts {
			return fmt.Errorf("download: gave up after %d attempts: %w", attempt, last)
		}
		if failures > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay << (failures - 1)):
			}
		}
		received, err := fetchFrom(ctx, f, open, report)
		if err == nil {
			if err = checkFile(f, verify); err == nil {
				return nil
			}
			// Complete but wrong: resuming could only preserve the bad bytes.
			if truncErr := f.Truncate(0); truncErr != nil {
				return truncErr
			}
			received = 0
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		last = err
		if received > 0 {
			failures = 0
		} else {
			failures++
		}
	}
	return last
}

func checkFile(f *os.File, verify func(io.Reader) error) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := verify(f); err != nil {
		return err
	}
	_, err := f.Seek(0, io.SeekStart)
	return err
}

// fetchFrom appends to f from its current size, returning the bytes this
// attempt delivered.
func fetchFrom(ctx context.Context, f *os.File, open openFunc, report Report) (int64, error) {
	offset, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stalled := time.AfterFunc(stallTimeout, cancel)
	defer stalled.Stop()

	resp, err := open(ctx, offset)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusPartialContent:
		// Bytes from anywhere else would be appended in the wrong place.
		if start, ok := rangeStart(resp.Header.Get("Content-Range")); !ok || start != offset {
			if err := f.Truncate(0); err != nil {
				return 0, err
			}
			return 0, fmt.Errorf("download: asked for byte %d, got range %q", offset, resp.Header.Get("Content-Range"))
		}
	case http.StatusOK:
		// This server ignored the range, so it is sending the file from the top.
		if err := f.Truncate(0); err != nil {
			return 0, err
		}
		if offset, err = f.Seek(0, io.SeekStart); err != nil {
			return 0, err
		}
	case http.StatusRequestedRangeNotSatisfiable:
		return 0, nil // we already hold every byte; verification decides
	default:
		return 0, fmt.Errorf("download: %s", resp.Status)
	}

	var delivered int64
	buf := make([]byte, 64*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			stalled.Reset(stallTimeout)
			if _, err := f.Write(buf[:n]); err != nil {
				return delivered, err
			}
			delivered += int64(n)
			if report != nil {
				report(offset + delivered)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return delivered, nil
		}
		if readErr != nil {
			return delivered, readErr
		}
	}
}

func rangeRequest(ctx context.Context, url string, offset int64) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	return req, nil
}

// rangeStart reads the first byte from a Content-Range such as "bytes 100-199/200".
func rangeStart(header string) (int64, bool) {
	spec, ok := strings.CutPrefix(header, "bytes ")
	if !ok {
		return 0, false
	}
	first, _, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, false
	}
	start, err := strconv.ParseInt(first, 10, 64)
	return start, err == nil && start >= 0
}
