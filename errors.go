//go:build unix

package ping

import "errors"

// Sentinel errors returned by the ping library.
var (
	ErrTimeout      = errors.New("ping: timeout waiting for reply")
	ErrInvalidAddr  = errors.New("ping: invalid or unresolvable address")
	ErrSendFailed   = errors.New("ping: consecutive send failures exceeded threshold")
	ErrInvalidState = errors.New("ping: invalid state transition")
)
