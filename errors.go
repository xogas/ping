//go:build linux

package ping

import "errors"

var (
	// ErrTimeout indicates that a reply was not received within the per-seq timeout window.
	ErrTimeout = errors.New("ping: timeout waiting for reply")

	// ErrInvalidAddr indicates that the target address could not be resolved.
	ErrInvalidAddr = errors.New("ping: invalid or unresolvable address")

	// ErrSendFailed indicates that consecutive send failures reached the threshold.
	ErrSendFailed = errors.New("ping: consecutive send failures exceeded threshold")

	// ErrRecvFailed indicates an unrecoverable receive error (e.g. connection closed).
	ErrRecvFailed = errors.New("ping: unrecoverable receive error")

	// ErrInvalidState indicates an illegal state transition (e.g. concurrent or repeated Run).
	ErrInvalidState = errors.New("ping: invalid state transition")
)
