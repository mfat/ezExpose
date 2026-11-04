package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
)

// Progress is where progress and warnings go: stderr for people, or events on
// stdout with --json. Everything that reports progress writes here, so the
// choice is made once, when the command line is read.
type Progress struct {
	mu sync.Mutex
	w  io.Writer
}

// NewProgress starts out writing to w.
func NewProgress(w io.Writer) *Progress { return &Progress{w: w} }

func (p *Progress) set(w io.Writer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.w = w
}

func (p *Progress) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w == nil {
		return len(b), nil
	}
	return p.w.Write(b)
}

// events turns lines of text into progress events, one JSON object per line.
type events struct {
	mu      sync.Mutex
	out     io.Writer
	partial []byte
}

func (e *events) Write(b []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.partial = append(e.partial, b...)
	for {
		i := bytes.IndexByte(e.partial, '\n')
		if i < 0 {
			return len(b), nil
		}
		line := strings.TrimSpace(string(e.partial[:i]))
		e.partial = e.partial[i+1:]
		if line == "" {
			continue
		}
		raw, _ := json.Marshal(map[string]any{"schema": Schema, "event": "progress", "message": line})
		if _, err := e.out.Write(append(raw, '\n')); err != nil {
			return len(b), err
		}
	}
}
