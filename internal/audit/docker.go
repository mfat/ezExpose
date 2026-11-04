package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// A Container is a running Docker container with ports published on this machine.
type Container struct {
	Name      string      `json:"name"`
	Published []Published `json:"published"`
}

// Published is one port Docker opens on this machine for a container.
type Published struct {
	Address       string `json:"address"` // 0.0.0.0 and :: mean every address
	Port          int    `json:"port"`
	ContainerPort int    `json:"container_port"`
}

// Everywhere reports whether Docker publishes it on every address.
func (p Published) Everywhere() bool {
	ip := net.ParseIP(p.Address)
	return ip != nil && ip.IsUnspecified()
}

// ErrNoDocker means Docker isn't installed, or this user can't use it. Neither
// is a problem worth more than a note.
var ErrNoDocker = errors.New("docker isn't available to this user")

// Containers asks Docker which containers publish ports. It only lists: it uses
// docker ps and nothing else, and never sudo.
func Containers(ctx context.Context, run func(ctx context.Context, args ...string) ([]byte, error)) ([]Container, error) {
	out, err := run(ctx, "ps", "--format", "{{.Names}}\t{{.Ports}}")
	if err != nil {
		text := strings.ToLower(string(out))
		if strings.Contains(text, "permission denied") || strings.Contains(text, "cannot connect") ||
			errors.Is(err, errNotInstalled) {
			return nil, ErrNoDocker
		}
		return nil, fmt.Errorf("docker ps: %v", strings.TrimSpace(string(out)))
	}
	return parseContainers(string(out)), nil
}

var errNotInstalled = errors.New("not installed")

// parseContainers reads lines such as
// "jellyfin\t0.0.0.0:8096->8096/tcp, [::]:8096->8096/tcp, 1900/udp".
func parseContainers(out string) []Container {
	var found []Container
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		name, ports, ok := strings.Cut(line, "\t")
		if !ok || name == "" {
			continue
		}
		c := Container{Name: name}
		for _, mapping := range strings.Split(ports, ",") {
			host, inside, ok := strings.Cut(strings.TrimSpace(mapping), "->")
			if !ok || !strings.HasSuffix(inside, "/tcp") {
				continue // not published, or not TCP
			}
			addr, portText, err := net.SplitHostPort(host)
			if err != nil {
				continue
			}
			port, err1 := strconv.Atoi(portText)
			cport, err2 := strconv.Atoi(strings.TrimSuffix(inside, "/tcp"))
			if err1 != nil || err2 != nil {
				continue // a range such as 8000-8010; rare, and left out
			}
			c.Published = append(c.Published, Published{Address: addr, Port: port, ContainerPort: cport})
		}
		if len(c.Published) > 0 {
			found = append(found, c)
		}
	}
	return found
}
