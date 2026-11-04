package manager

import (
	"errors"
	"fmt"
)

// Code names a kind of failure, so scripts and apps don't have to read messages.
type Code string

const (
	Invalid           Code = "invalid"            // the request itself is wrong
	NotFound          Code = "not_found"          // no exposure with that ID
	Busy              Code = "busy"               // another command holds the lock
	BadRecord         Code = "bad_record"         // the record is damaged or newer
	NeedsConfirmation Code = "needs_confirmation" // public access wasn't confirmed
	BackendDown       Code = "backend_down"       // nothing answers at the app's address
	NotOurs           Code = "not_ours"           // something else is in the way, and was left alone
	TailscaleNotReady Code = "tailscale"          // Tailscale is missing, off or needs a setting
	NoCloudflare      Code = "cloudflare"         // no token, or it can't see the domain
	DNSNotReady       Code = "dns"                // the name doesn't point here yet
	PortUnavailable   Code = "port"               // the port is taken or needs permission
	CertificateFailed Code = "certificate"        // no trusted certificate
	PlanChanged       Code = "plan_changed"       // the machine changed since the plan was made
	NeedsAttention    Code = "needs_attention"    // reconcile found something not working
	Usage             Code = "usage"              // the command was used wrongly
	Failed            Code = "failed"             // anything else
)

// Error is a failure with a code.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func errorf(code Code, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}

// wrap gives err a code, unless it's nil or already has one.
func wrap(code Code, err error) error {
	if err == nil {
		return nil
	}
	var coded *Error
	if errors.As(err, &coded) {
		return err
	}
	return &Error{Code: code, Err: err}
}

// CodeOf returns err's code, or Failed.
func CodeOf(err error) Code {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Code
	}
	return Failed
}
