package fetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fastRetries(t *testing.T) {
	t.Helper()
	old := retryDelay
	retryDelay = time.Millisecond
	t.Cleanup(func() { retryDelay = old })
}

func openURL(url string) openFunc {
	return func(ctx context.Context, offset int64) (*http.Response, error) {
		req, err := rangeRequest(ctx, url, offset)
		if err != nil {
			return nil, err
		}
		return http.DefaultClient.Do(req)
	}
}

func accept(want []byte) func(io.Reader) error {
	return func(r io.Reader) error {
		got, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return errors.New("content mismatch")
		}
		return nil
	}
}

// A CDN that cuts every connection after a fixed number of bytes.
func droppingServer(t *testing.T, body []byte, perConnection int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := 0
		if v := r.Header.Get("Range"); v != "" {
			start, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(v, "bytes="), "-"))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(body)-1, len(body)))
			w.Header().Set("Content-Length", strconv.Itoa(len(body)-start))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		}
		end := min(start+perConnection, len(body))
		w.Write(body[start:end])
		w.(http.Flusher).Flush()
		if end < len(body) {
			panic(http.ErrAbortHandler)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDroppedConnectionsResumeInsteadOfStartingOver(t *testing.T) {
	fastRetries(t)
	body := bytes.Repeat([]byte("vault"), 20000)
	// Far more drops than maxFailures: only a fruitless attempt may count.
	srv := droppingServer(t, body, len(body)/(maxFailures*4))
	f, err := download(context.Background(), openURL(srv.URL), accept(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, _ := io.ReadAll(f)
	if !bytes.Equal(got, body) {
		t.Fatalf("got %d bytes, want %d", len(got), len(body))
	}
}

func TestServerThatIgnoresRangesStartsClean(t *testing.T) {
	fastRetries(t)
	body := []byte(strings.Repeat("x", 4096))
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if calls == 1 {
			w.Write(body[:100])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		w.Write(body)
	}))
	defer srv.Close()
	f, err := download(context.Background(), openURL(srv.URL), accept(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestWrongContentIsRefusedNotResumed(t *testing.T) {
	fastRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			t.Error("resumed after a failed verification")
		}
		w.Write([]byte("tampered"))
	}))
	defer srv.Close()
	_, err := download(context.Background(), openURL(srv.URL), accept([]byte("genuine")), nil)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestDeadServerGivesUp(t *testing.T) {
	fastRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	if _, err := download(context.Background(), openURL(srv.URL), accept(nil), nil); err == nil {
		t.Fatal("expected a failure")
	}
}

func TestStalledConnectionIsAbandonedAndResumed(t *testing.T) {
	fastRetries(t)
	old := stallTimeout
	stallTimeout = 50 * time.Millisecond
	defer func() { stallTimeout = old }()
	body := []byte(strings.Repeat("y", 2048))
	release := make(chan struct{})
	defer close(release)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write(body[:100])
			w.(http.Flusher).Flush()
			<-release // goes silent without closing
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 100-%d/%d", len(body)-1, len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)-100))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body[100:])
	}))
	defer srv.CloseClientConnections()
	f, err := download(context.Background(), openURL(srv.URL), accept(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestReportCountsTheWholeFileAcrossResumes(t *testing.T) {
	fastRetries(t)
	body := bytes.Repeat([]byte("z"), 10000)
	srv := droppingServer(t, body, 3000)
	var last int64
	f, err := download(context.Background(), openURL(srv.URL), accept(body), func(n int64) { last = n })
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if last != int64(len(body)) {
		t.Fatalf("reported %d", last)
	}
}

func TestAResumeFromTheWrongPlaceIsThrownAway(t *testing.T) {
	fastRetries(t)
	body := bytes.Repeat([]byte("vault"), 2000)
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Header.Get("Range"))
		switch len(requests) {
		case 1: // drops after 100 bytes
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write(body[:100])
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		case 2: // the wrong range: appending it would corrupt the file
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(body)
		default:
			w.Write(body)
		}
	}))
	t.Cleanup(srv.Close)
	f, err := download(context.Background(), openURL(srv.URL), accept(body), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got, _ := io.ReadAll(f); !bytes.Equal(got, body) {
		t.Fatal("wrong content")
	}
	if strings.Join(requests, ",") != ",bytes=100-," {
		t.Fatalf("requests: %q", requests)
	}
}

func TestRangeStart(t *testing.T) {
	cases := map[string]int64{"bytes 100-199/200": 100, "bytes 0-9/*": 0}
	for header, want := range cases {
		if got, ok := rangeStart(header); !ok || got != want {
			t.Errorf("%q: %d, %v", header, got, ok)
		}
	}
	for _, bad := range []string{"", "bytes */200", "items 1-2/3", "bytes -5-9/10", "bytes x-9/10"} {
		if _, ok := rangeStart(bad); ok {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestADownloadThatNeverFinishesGivesUp(t *testing.T) {
	fastRetries(t)
	// Every attempt delivers one more byte and drops, so it never counts as failing.
	srv := droppingServer(t, bytes.Repeat([]byte("v"), 10*maxAttempts), 1)
	if _, err := download(context.Background(), openURL(srv.URL), accept(nil), nil); err == nil ||
		!strings.Contains(err.Error(), "gave up") {
		t.Fatalf("got %v", err)
	}
}
