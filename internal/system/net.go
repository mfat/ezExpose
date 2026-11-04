package system

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/mfat/ezExpose/netcheck"
)

// Net implements manager.Net.
type Net struct{}

func (Net) PublicIP(ctx context.Context) (string, error) { return netcheck.PublicIP(ctx) }
func (Net) LocalIP() string                              { return netcheck.LocalIP() }
func (Net) Resolve(ctx context.Context, host string) ([]string, error) {
	return netcheck.Resolve(ctx, host)
}
func (Net) OnThisMachine(addr string) bool { return netcheck.OnThisMachine(addr) }

// Listen checks addr can be listened on, and lets it go again.
func (Net) Listen(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return l.Close()
}

// Dial checks something answers at addr.
func (Net) Dial(ctx context.Context, addr string) error {
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

var client = &http.Client{
	Timeout: 10 * time.Second,
	// A login page redirecting is still an answer.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Get fetches url with the certificates this machine trusts.
func (Net) Get(ctx context.Context, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
