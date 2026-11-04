// Package cli is the ezexpose command. Results go to stdout, as text for people
// or, with --json, as one versioned JSON object for scripts and apps. Progress
// and warnings go to stderr.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mfat/ezExpose/internal/manager"
	"github.com/mfat/ezExpose/internal/state"
	"github.com/mfat/ezExpose/internal/system"
)

// Schema is the version of the JSON output. Fields may be added within a
// version; anything else changing means a new one.
const Schema = 1

// App is one run of the command.
type App struct {
	Out, Err io.Writer
	In       *bufio.Reader
	Dir      string
	Manager  *manager.Manager
	Version  string
	// Terminal is true when a person can answer questions.
	Terminal bool
	// Doctor checks the machine.
	Doctor func(ctx context.Context) []Check
	// ReadSecret reads a line without showing it.
	ReadSecret func() (string, error)
	// Logs shows recent service output.
	Logs func(ctx context.Context, lines int) error

	json bool
}

const usage = `ezExpose puts apps you already run behind real HTTPS.

Usage:
  ezexpose doctor                  Check this machine is ready
  ezexpose plan  --backend ADDR --access private|public|lan [--host NAME]
                                   Show what apply would do, changing nothing
  ezexpose apply --backend ADDR --access private|public|lan [--host NAME]
                                   Expose an app, or check and repair it
  ezexpose status [ID]             Show what's exposed
  ezexpose remove ID               Take an exposure down
  ezexpose reconcile               Check everything, and finish interrupted work
  ezexpose renew [--force]         Renew certificates that are due
  ezexpose cloudflare-token        Save a Cloudflare token for DNS and certificates
  ezexpose logs                    Show Caddy's and renewal's recent output
  ezexpose version

Access:
  private  Over Tailscale, for your own devices. Nothing is opened to the internet.
  public   From anywhere, with your own domain on port 443. Anyone can reach the app,
           so it needs its own login.
  lan      A real certificate on your home network, through Cloudflare. --address points
           the name somewhere else on this machine, such as its Tailscale address, so
           only your tailnet devices can reach it.

Add --json for machine-readable output.
`

// Run runs args and returns the exit code: 0 done, 1 failed, 2 used wrongly.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.Out, usage)
		return 0
	}
	commands := map[string]func(context.Context, []string) error{
		"doctor":           a.doctor,
		"plan":             a.plan,
		"apply":            a.apply,
		"status":           a.status,
		"remove":           a.remove,
		"reconcile":        a.reconcile,
		"renew":            a.renew,
		"cloudflare-token": a.cloudflareToken,
		"logs":             a.logs,
		"version":          a.version,
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(a.Err, "ezexpose: unknown command %q. See: ezexpose help\n", args[0])
		return 2
	}
	err := cmd(ctx, args[1:])
	var bad usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &bad):
		fmt.Fprintf(a.Err, "ezexpose %s: %v\n", args[0], err)
		return 2
	case a.json:
		a.emit(map[string]any{"error": map[string]string{"code": string(manager.CodeOf(err)), "message": err.Error()}}, false)
	default:
		fmt.Fprintf(a.Err, "✗ %v\n", err)
	}
	return 1
}

type usageError struct{ error }

func (a *App) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&a.json, "json", false, "machine-readable output")
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	return nil
}

// emit writes the JSON envelope.
func (a *App) emit(payload map[string]any, ok bool) {
	payload["schema"], payload["ok"] = Schema, ok
	enc := json.NewEncoder(a.Out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func (a *App) confirm(question string, yes bool) (bool, error) {
	if !a.Terminal {
		return false, nil
	}
	hint := "[y/N]"
	if yes {
		hint = "[Y/n]"
	}
	fmt.Fprintf(a.Err, "%s %s ", question, hint)
	line, err := a.In.ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return yes, nil
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func requestFlags(fs *flag.FlagSet) *manager.Request {
	r := &manager.Request{}
	fs.StringVar(&r.Backend, "backend", "", "the app's address, such as 127.0.0.1:8080")
	fs.Func("access", "private, public or lan", func(v string) error { r.Access = state.Access(v); return nil })
	fs.StringVar(&r.Host, "host", "", "your domain name, for public and lan")
	fs.IntVar(&r.Port, "port", 0, "the port people use; picked for you if left out")
	fs.StringVar(&r.Name, "name", "", "a name to remember it by")
	fs.BoolVar(&r.Cloudflare, "cloudflare", false, "create the public DNS record through Cloudflare")
	fs.StringVar(&r.Address, "address", "", "for lan: point the name here, such as this machine's Tailscale address")
	return r
}

func (a *App) plan(ctx context.Context, args []string) error {
	fs := a.flags("plan")
	r := requestFlags(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	p, err := a.Manager.Plan(ctx, *r)
	if err != nil {
		return err
	}
	if a.json {
		a.emit(map[string]any{"plan": p}, true)
		return nil
	}
	a.showPlan(p)
	return nil
}

func (a *App) showPlan(p manager.Plan) {
	w := a.Out
	if a.json {
		w = a.Err
	}
	fmt.Fprintf(w, "Address: %s\n", planURL(p.Exposure))
	for i, step := range p.Steps {
		fmt.Fprintf(w, "  %d. %s\n", i+1, step)
	}
}

func planURL(e state.Exposure) string {
	if e.Host == "" {
		return "(your tailnet name)"
	}
	return e.URL()
}

func (a *App) apply(ctx context.Context, args []string) error {
	fs := a.flags("apply")
	r := requestFlags(fs)
	yes := fs.Bool("yes", false, "don't ask; for public access, confirm the app has its own login")
	if err := parse(fs, args); err != nil {
		return err
	}
	p, err := a.Manager.Plan(ctx, *r)
	if err != nil {
		return err
	}
	if !*yes {
		a.showPlan(p)
		question, def := "Continue?", true
		if r.Access == state.Public && !p.Existing {
			question, def = "Anyone on the internet will be able to reach this app, so it needs its own login. Continue?", false
		}
		ok, err := a.confirm(question, def)
		if err != nil {
			return err
		}
		if !ok {
			if !a.Terminal {
				return &manager.Error{Code: manager.NeedsConfirmation, Err: errors.New("nothing was changed. Add --yes to go ahead without asking")}
			}
			fmt.Fprintln(a.Err, "Nothing was changed.")
			return nil
		}
	}
	r.Confirmed = true
	e, err := a.Manager.Apply(ctx, *r)
	if err != nil {
		return err
	}
	if a.json {
		a.emit(map[string]any{"exposure": e}, true)
		return nil
	}
	if e.Status == state.Active {
		fmt.Fprintf(a.Out, "✓ %s now reaches %s  (%s)\n", e.URL(), e.Backend, e.ID)
	} else {
		fmt.Fprintf(a.Out, "⚠ %s is set up, but: %s\n", e.URL(), e.Error)
	}
	switch e.Access {
	case state.Private:
		fmt.Fprintln(a.Out, "  Only your own devices on Tailscale can open it.")
	case state.Public:
		fmt.Fprintln(a.Out, "  Anyone on the internet can open it. The certificate renews by itself.")
	case state.LAN:
		fmt.Fprintln(a.Out, "  It works on your home network. The certificate renews twice a day when due.")
	}
	return nil
}

func (a *App) status(ctx context.Context, args []string) error {
	fs := a.flags("status")
	if err := parse(fs, args); err != nil {
		return err
	}
	list, err := a.Manager.List()
	if err != nil {
		return err
	}
	if id := fs.Arg(0); id != "" {
		for _, e := range list {
			if e.ID == id {
				return a.showList([]state.Exposure{e})
			}
		}
		return &manager.Error{Code: manager.NotFound, Err: fmt.Errorf("there's no exposure %s", id)}
	}
	return a.showList(list)
}

func (a *App) showList(list []state.Exposure) error {
	if list == nil {
		list = []state.Exposure{}
	}
	if a.json {
		a.emit(map[string]any{"exposures": list}, true)
		return nil
	}
	if len(list) == 0 {
		fmt.Fprintln(a.Out, "Nothing is exposed. See: ezexpose help")
		return nil
	}
	for _, e := range list {
		mark := map[state.Status]string{state.Active: "●", state.Degraded: "⚠", state.Failed: "✗"}[e.Status]
		if mark == "" {
			mark = "○"
		}
		fmt.Fprintf(a.Out, "%s %-13s %-8s %-40s → %s  %s\n", mark, e.ID, e.Access, e.URL(), e.Backend, e.Status)
		if e.Error != "" {
			fmt.Fprintf(a.Out, "    %s\n", e.Error)
		}
		if !e.Checked.IsZero() {
			fmt.Fprintf(a.Out, "    checked %s\n", e.Checked.Local().Format(time.DateTime))
		}
	}
	return nil
}

func (a *App) remove(ctx context.Context, args []string) error {
	fs := a.flags("remove")
	yes := fs.Bool("yes", false, "don't ask")
	if err := parse(fs, args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return usageError{errors.New("which one? See: ezexpose status")}
	}
	if !*yes {
		ok, err := a.confirm("Take "+id+" down?", true)
		if err != nil {
			return err
		}
		if !ok {
			if !a.Terminal {
				return &manager.Error{Code: manager.NeedsConfirmation, Err: errors.New("nothing was changed. Add --yes to go ahead without asking")}
			}
			fmt.Fprintln(a.Err, "Nothing was changed.")
			return nil
		}
	}
	if err := a.Manager.Remove(ctx, id); err != nil {
		return err
	}
	if a.json {
		a.emit(map[string]any{"removed": id}, true)
		return nil
	}
	fmt.Fprintf(a.Out, "✓ %s removed\n", id)
	return nil
}

func (a *App) reconcile(ctx context.Context, args []string) error {
	fs := a.flags("reconcile")
	if err := parse(fs, args); err != nil {
		return err
	}
	list, err := a.Manager.Reconcile(ctx)
	if err != nil {
		return err
	}
	return a.showList(list)
}

func (a *App) renew(ctx context.Context, args []string) error {
	fs := a.flags("renew")
	force := fs.Bool("force", false, "renew even if it isn't due")
	if err := parse(fs, args); err != nil {
		return err
	}
	renewed, err := a.Manager.Renew(ctx, *force)
	if err != nil {
		return err
	}
	if a.json {
		if renewed == nil {
			renewed = []string{}
		}
		a.emit(map[string]any{"renewed": renewed}, true)
		return nil
	}
	if len(renewed) == 0 {
		fmt.Fprintln(a.Out, "Nothing was due.")
	}
	for _, host := range renewed {
		fmt.Fprintf(a.Out, "✓ Renewed %s\n", host)
	}
	return nil
}

func (a *App) cloudflareToken(_ context.Context, args []string) error {
	fs := a.flags("cloudflare-token")
	if err := parse(fs, args); err != nil {
		return err
	}
	var token string
	var err error
	if a.Terminal {
		fmt.Fprintln(a.Err, "Paste the token and press Enter. It isn't shown while you paste.")
		token, err = a.ReadSecret()
	} else {
		token, err = a.In.ReadString('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
	}
	if err != nil {
		return err
	}
	if err := system.SaveToken(a.Dir, token); err != nil {
		return &manager.Error{Code: manager.Invalid, Err: err}
	}
	token = strings.TrimSpace(token)
	if a.json {
		a.emit(map[string]any{"saved": true}, true)
		return nil
	}
	fmt.Fprintf(a.Out, "✓ Token saved, ending …%s\n", token[max(0, len(token)-4):])
	return nil
}

func (a *App) logs(ctx context.Context, args []string) error {
	fs := a.flags("logs")
	lines := fs.Int("n", 50, "how many lines")
	if err := parse(fs, args); err != nil {
		return err
	}
	return a.Logs(ctx, *lines)
}

func (a *App) version(_ context.Context, args []string) error {
	fs := a.flags("version")
	if err := parse(fs, args); err != nil {
		return err
	}
	if a.json {
		a.emit(map[string]any{"version": a.Version}, true)
		return nil
	}
	fmt.Fprintf(a.Out, "ezExpose %s\n", a.Version)
	return nil
}
