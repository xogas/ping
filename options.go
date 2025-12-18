//go:build linux

package ping

import "time"

// options holds the configurable parameters for a Pinger.
// Users set these via the functional Options pattern.
type options struct {
	count      int
	size       int
	interval   time.Duration
	timeout    time.Duration
	ttl        int
	privileged bool
	logger     Logger
}

type Option func(*options)

// defaultOptions returns a sensible set of defaults.
func defaultOptions() options {
	return options{
		count:      0, // 0 means infinite
		size:       56,
		interval:   time.Second,
		timeout:    5 * time.Second,
		ttl:        64,
		privileged: false,
		logger:     NoopLogger{},
	}
}

// WithCount sets the number of echo requests to send.
func WithCount(count int) Option {
	return func(o *options) {
		if count >= 0 {
			o.count = count
		}
	}
}

// WithSize sets the size of the ICMP payload in bytes.
func WithSize(size int) Option {
	return func(o *options) {
		if size > 0 {
			o.size = size
		}
	}
}

// WithInterval sets the interval between sending each echo request.
func WithInterval(interval time.Duration) Option {
	return func(o *options) {
		if interval > 0 {
			o.interval = interval
		}
	}
}

// WithTimeout sets the timeout for each echo request.
func WithTimeout(timeout time.Duration) Option {
	return func(o *options) {
		if timeout > 0 {
			o.timeout = timeout
		}
	}
}

// WithTTL sets the Time-To-Live (TTL) for the ICMP packets.
func WithTTL(ttl int) Option {
	return func(o *options) {
		if ttl > 0 && ttl <= 255 {
			o.ttl = ttl
		}
	}
}

// WithPrivileged sets whether to use privileged raw sockets (requires admin/root).
func WithPrivileged(privileged bool) Option {
	return func(o *options) {
		o.privileged = privileged
	}
}

// WithLogger sets a custom logger for the Pinger.
func WithLogger(logger Logger) Option {
	return func(o *options) {
		if logger != nil {
			o.logger = logger
		}
	}
}
