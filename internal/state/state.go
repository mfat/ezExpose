// Package state keeps ezExpose's record of what it owns. Anything not in this
// record is never changed, so the record is written before every change and
// replaced in one step, never half-written.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Version is the schema this build writes. An older file is upgraded on load;
// a newer one is refused, so an older ezExpose never drops what it can't read.
const Version = 1

// Access is how an exposure is reached.
type Access string

const (
	Private Access = "private" // over Tailscale, from your own devices
	Public  Access = "public"  // from the internet, with your own domain on port 443
	LAN     Access = "lan"     // a real certificate on your home network, through Cloudflare
)

// Status is where an exposure stands.
type Status string

const (
	Applying Status = "applying" // being set up, or interrupted while it was
	Active   Status = "active"   // set up and checked
	Removing Status = "removing" // being taken down, or interrupted while it was
	Degraded Status = "degraded" // set up, but the last check found something wrong
	Failed   Status = "failed"   // setting up stopped with an error
	Unknown  Status = "unknown"  // it couldn't be checked
)

// Kind is a type of resource on the machine or elsewhere.
type Kind string

const (
	TailscaleRoute Kind = "tailscale-route"
	DNSRecord      Kind = "dns-record"
	Certificate    Kind = "certificate"
	CaddySite      Kind = "caddy-site"
)

// A Resource is one thing an exposure needs. It's saved as pending before it's
// changed, so after a crash recovery knows what might exist.
type Resource struct {
	Kind   Kind   `json:"kind"`
	Ref    string `json:"ref"`              // what identifies it, such as host:port
	Target string `json:"target,omitempty"` // what it points at, such as a URL or address
	Owned  bool   `json:"owned"`            // false when it already existed and only gets used
	Done   bool   `json:"done"`             // false while the change may or may not have happened
}

// An Exposure is one local app made reachable one way.
type Exposure struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Backend string `json:"backend"` // such as 127.0.0.1:8080
	Access  Access `json:"access"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	// Cloudflare is true when ezExpose keeps the DNS record, not the person.
	Cloudflare bool       `json:"cloudflare,omitempty"`
	Status     Status     `json:"status,omitempty"`
	Resources  []Resource `json:"resources"`
	Created    time.Time  `json:"created,omitzero"`
	Checked    time.Time  `json:"checked,omitzero"`
	Error      string     `json:"error,omitempty"`
}

// URL is the address people use.
func (e Exposure) URL() string {
	if e.Port == 443 || e.Port == 0 {
		return "https://" + e.Host
	}
	return fmt.Sprintf("https://%s:%d", e.Host, e.Port)
}

// Resource returns the exposure's resource of kind, if it has one.
func (e *Exposure) Resource(kind Kind) *Resource {
	for i := range e.Resources {
		if e.Resources[i].Kind == kind {
			return &e.Resources[i]
		}
	}
	return nil
}

// Drop removes the exposure's resource of kind.
func (e *Exposure) Drop(kind Kind) {
	kept := e.Resources[:0]
	for _, r := range e.Resources {
		if r.Kind != kind {
			kept = append(kept, r)
		}
	}
	e.Resources = kept
}

// State is everything ezExpose owns on this machine.
type State struct {
	Version int    `json:"version"`
	Install string `json:"install"` // marks this install's DNS records
	Zone    string `json:"cloudflare_zone,omitempty"`
	// Exposures are kept in the order they were made.
	Exposures []Exposure `json:"exposures"`
}

// Find returns the exposure with id, or nil.
func (s *State) Find(id string) *Exposure {
	for i := range s.Exposures {
		if s.Exposures[i].ID == id {
			return &s.Exposures[i]
		}
	}
	return nil
}

// Delete forgets the exposure with id.
func (s *State) Delete(id string) {
	kept := s.Exposures[:0]
	for _, e := range s.Exposures {
		if e.ID != id {
			kept = append(kept, e)
		}
	}
	s.Exposures = kept
}

// NewID returns a short random ID with prefix.
func NewID(prefix string, size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

// Store is the folder holding the record.
type Store struct{ Dir string }

// DefaultDir is /var/lib/ezexpose for root, or the user's state folder.
func DefaultDir() (string, error) {
	if dir := os.Getenv("EZEXPOSE_HOME"); dir != "" {
		return dir, nil
	}
	if os.Geteuid() == 0 {
		return "/var/lib/ezexpose", nil
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "ezexpose"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "ezexpose"), nil
}

func (s Store) file() string   { return filepath.Join(s.Dir, "state.json") }
func (s Store) backup() string { return filepath.Join(s.Dir, "state.json.prev") }

// Load reads the record, or starts a new one if there's none yet.
func (s Store) Load() (State, error) {
	raw, err := os.ReadFile(s.file())
	if errors.Is(err, os.ErrNotExist) {
		install, err := NewID("", 16)
		return State{Version: Version, Install: install}, err
	}
	if err != nil {
		return State{}, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, fmt.Errorf("%s is damaged (%v). The previous version is in %s; "+
			"nothing was changed", s.file(), err, s.backup())
	}
	switch {
	case st.Version > Version:
		return State{}, fmt.Errorf("%s was written by a newer ezExpose (version %d). Update ezExpose; "+
			"nothing was changed", s.file(), st.Version)
	case st.Version < 1 || st.Install == "":
		return State{}, fmt.Errorf("%s isn't an ezExpose record; nothing was changed", s.file())
	}
	return st, nil
}

// Save replaces the record in one step. The old one is kept beside it.
func (s Store) Save(st State) error {
	st.Version = Version
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(s.file(), s.backup()+".new"); err == nil {
		if err := os.Rename(s.backup()+".new", s.backup()); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp.Name(), s.file()); err != nil {
		return err
	}
	return syncDir(s.Dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ErrBusy means another ezExpose command holds the lock.
var ErrBusy = errors.New("another ezExpose command is running. Try again when it's finished")

// Lock takes the machine-wide lock, waiting up to wait. The kernel drops it if
// the process dies, so a crash can never leave it stuck.
func (s Store) Lock(wait time.Duration) (unlock func(), err error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || !time.Now().Before(deadline) {
			f.Close()
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, ErrBusy
			}
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
}
