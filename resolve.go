//go:build unix

package ping

import (
	"context"
	"fmt"
	"net"
)

func resolve(ctx context.Context, host string) (*net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.IPAddr{IP: ip}, nil
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAddr, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses found for %s", ErrInvalidAddr, host)
	}

	// Prefer IPv4 if available.
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return &ip, nil
		}
	}

	return &ips[0], nil
}
