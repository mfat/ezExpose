package audit

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A Listener is a TCP port something on this machine is waiting on.
type Listener struct {
	Address string `json:"address"` // such as 127.0.0.1, 0.0.0.0 or ::
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"` // the program, when this user may see it
	PID     int    `json:"pid,omitempty"`
}

// Everywhere reports whether the listener takes connections on every address,
// not just this machine's own.
func (l Listener) Everywhere() bool {
	ip := net.ParseIP(l.Address)
	return ip != nil && ip.IsUnspecified()
}

// Local reports whether only programs on this machine can reach it.
func (l Listener) Local() bool {
	ip := net.ParseIP(l.Address)
	return ip != nil && ip.IsLoopback()
}

// maxProcesses bounds the walk through /proc on a very busy machine.
const maxProcesses = 20000

// Listeners reads the kernel's socket tables under proc (normally /proc). It
// runs nothing and asks for no extra permission: a program another user runs is
// left unnamed, and hidden counts how many.
func Listeners(proc string) (found []Listener, hidden int, err error) {
	byInode := map[string]*Listener{}
	var order []string
	for _, table := range []string{"net/tcp", "net/tcp6"} {
		f, err := os.Open(filepath.Join(proc, table))
		if err != nil {
			if table == "net/tcp6" && os.IsNotExist(err) {
				continue // IPv6 is off
			}
			return nil, 0, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // the header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" { // 0A is LISTEN
				continue
			}
			addr, port, err := decodeAddress(fields[1])
			if err != nil {
				continue
			}
			inode := fields[9]
			if _, seen := byInode[inode]; !seen {
				order = append(order, inode)
			}
			byInode[inode] = &Listener{Address: addr, Port: port}
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			return nil, 0, err
		}
	}
	attribute(proc, byInode)
	for _, inode := range order {
		l := *byInode[inode]
		if l.Process == "" {
			hidden++
		}
		found = append(found, l)
	}
	return found, hidden, nil
}

// decodeAddress turns the kernel's "0100007F:1F90" into 127.0.0.1 and 8080.
// Addresses are stored as 32-bit words in the machine's byte order, which is
// little-endian on every architecture ezExpose supports.
func decodeAddress(field string) (string, int, error) {
	hexAddr, hexPort, ok := strings.Cut(field, ":")
	if !ok {
		return "", 0, fmt.Errorf("bad address %q", field)
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, fmt.Errorf("bad address %q", field)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", field)
	}
	ip := net.IP(raw)
	if v4 := ip.To4(); v4 != nil && len(raw) == 16 && !ip.IsUnspecified() {
		ip = v4 // an IPv4 address seen through an IPv6 socket
	}
	return ip.String(), int(port), nil
}

// attribute names the program behind each socket, where this user may look.
func attribute(proc string, byInode map[string]*Listener) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return
	}
	remaining := len(byInode)
	for i, entry := range entries {
		if remaining == 0 || i >= maxProcesses {
			return
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join(proc, entry.Name(), "fd"))
		if err != nil {
			continue // another user's program
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(proc, entry.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			l := byInode[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")]
			if l == nil || l.Process != "" {
				continue
			}
			comm, _ := os.ReadFile(filepath.Join(proc, entry.Name(), "comm"))
			l.Process, l.PID = strings.TrimSpace(string(comm)), pid
			remaining--
		}
	}
}
