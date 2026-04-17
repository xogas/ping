//go:build linux

package ping

import (
	"context"
	"fmt"
	"net"
)

// resolve resolves a hostname or IP string to a net.IPAddr.
// It automatically detects IPv4/IPv6 and supports context cancellation
// via net.Resolver.
func resolve(ctx context.Context, host string) (*net.IPAddr, error) {
	// First try to parse as a literal IP address to avoid unnecessary DNS lookup.
	if ip := net.ParseIP(host); ip != nil {
		return &net.IPAddr{IP: ip}, nil
	}

	// Perform DNS resolution with context support.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAddr, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses found for %s", ErrInvalidAddr, host)
	}

	// Prefer IPv4 if available.
	for _, ip := range ips {
		if isIPv4(ip.IP) {
			return &ip, nil
		}
	}

	// Fall back to the first address (IPv6).
	return &ips[0], nil
}

// isIPv4 reports whether addr is an IPv4 address.
func isIPv4(addr net.IP) bool {
	return addr.To4() != nil
}
