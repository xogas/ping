//go:build unix

package ping

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// EchoReply represents a received ICMP Echo Reply.
type EchoReply struct {
	Seq  uint16
	RTT  time.Duration
	TTL  int
	Size int
	Addr net.Addr
}

// recvEchoReply reads and parses an ICMP Echo Reply from conn.
func recvEchoReply(conn *packetConn, id int, dst *net.IPAddr, privileged bool, buf []byte) (*EchoReply, error) {
	n, ttl, addr, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	// IANA protocol numbers: ICMP=1, ICMPv6=58.
	proto := 58
	if conn.ipv4 {
		proto = 1
	}

	msg, err := icmp.ParseMessage(proto, buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parse ICMP message: %w", err)
	}

	echo, err := validateReply(msg, id, dst, addr, privileged)
	if err != nil {
		return nil, fmt.Errorf("validate reply: %w", err)
	}

	return buildEchoReply(echo, ttl, addr), nil
}

// Narrowing conversions are safe: ICMP seq is 16-bit by protocol;
// UnixNano timestamps fit int64 through year 2262.
func buildEchoReply(echo *icmp.Echo, ttl int, addr net.Addr) *EchoReply {
	reply := &EchoReply{
		Seq:  uint16(echo.Seq), //nolint:gosec
		TTL:  ttl,
		Size: len(echo.Data),
		Addr: addr,
	}

	if len(echo.Data) >= 8 {
		ns := binary.BigEndian.Uint64(echo.Data[:8])
		sentAt := time.Unix(0, int64(ns)) //nolint:gosec
		reply.RTT = max(time.Since(sentAt), 0)
	}

	return reply
}

func addrIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	default:
		return nil
	}
}

// validateReply checks whether an ICMP message is a valid Echo Reply.
//
// In privileged mode the ICMP Identifier is validated against the session ID.
// In unprivileged mode the ID check is skipped --- the kernel rewrites it,
// but the UDP port provides sufficient isolation.
func validateReply(msg *icmp.Message, id int, dst *net.IPAddr, from net.Addr, privileged bool) (*icmp.Echo, error) {
	switch msg.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
	default:
		return nil, fmt.Errorf("unexpected ICMP type %v", msg.Type)
	}

	if msg.Code != 0 {
		return nil, fmt.Errorf("unexpected ICMP code %d", msg.Code)
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, fmt.Errorf("expected ICMP Echo body, got %T", msg.Body)
	}

	if privileged && echo.ID != id {
		return nil, fmt.Errorf("ICMP ID mismatch: got %d, want %d", echo.ID, id)
	}

	if dst != nil {
		fromIP := addrIP(from)
		if fromIP != nil && !fromIP.Equal(dst.IP) {
			return nil, fmt.Errorf("source address mismatch: got %v, want %v", fromIP, dst.IP)
		}
	}

	return echo, nil
}
