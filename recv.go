//go:build linux

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
	Seq  uint16        // Sequence number (16-bit, wraps around)
	RTT  time.Duration // Round-trip time (0 on timeout)
	TTL  int           // Reply TTL / HopLimit (0 if unavailable)
	Size int           // Reply payload size in bytes (0 on timeout)
	Addr net.Addr      // Reply source address (nil on timeout)
}

// recvEchoReply reads and parses an ICMP Echo Reply from conn.
// It validates the reply, extracts the send timestamp from the payload to compute RTT,
// and returns a populated EchoReply.
func recvEchoReply(conn packetConn, id int, dst *net.IPAddr, isIPv4 bool, privileged bool, buf []byte) (*EchoReply, error) {
	n, ttl, addr, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}

	var proto int
	if isIPv4 {
		proto = 1 // IANA ICMP
	} else {
		proto = 58 // IANA ICMPv6
	}

	msg, err := icmp.ParseMessage(proto, buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parse ICMP message: %w", err)
	}

	seq, err := validateReply(msg, id, dst, addr, privileged)
	if err != nil {
		return nil, err
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return nil, fmt.Errorf("unexpected ICMP body type: %T", msg.Body)
	}

	reply := &EchoReply{
		Seq:  seq,
		TTL:  ttl,
		Size: len(echo.Data),
		Addr: addr,
	}

	// Extract send timestamp from payload to compute RTT.
	if len(echo.Data) >= 8 {
		nsec := binary.BigEndian.Uint64(echo.Data[:8])
		sentAt := time.Unix(0, int64(nsec))
		reply.RTT = time.Since(sentAt)
		if reply.RTT < 0 {
			reply.RTT = 0
		}
	}

	return reply, nil
}

// validateReply checks whether an ICMP message is a valid Echo Reply for the current session.
// In privileged mode: validates Type + Code + ID + source address.
// In unprivileged mode: validates Type + Code + source address (skips ID check,
// since the kernel overwrites it; UDP port provides isolation).
// Returns the parsed Seq for the caller; Seq validity (pending table lookup) is handled by the run loop.
func validateReply(msg *icmp.Message, id int, dst *net.IPAddr, from net.Addr, privileged bool) (seq uint16, err error) {
	// Validate Type and Code.
	switch msg.Type {
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		// Valid Echo Reply type.
	default:
		return 0, fmt.Errorf("unexpected ICMP type: %v", msg.Type)
	}

	if msg.Code != 0 {
		return 0, fmt.Errorf("unexpected ICMP code: %d", msg.Code)
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		return 0, fmt.Errorf("unexpected ICMP body type: %T", msg.Body)
	}

	// Validate Identifier in privileged mode (user-space fallback check;
	// BPF already filters in kernel, but we double-check here).
	if privileged && echo.ID != id {
		return 0, fmt.Errorf("ICMP ID mismatch: got %d, want %d", echo.ID, id)
	}

	// Validate source address matches the destination we pinged.
	if dst != nil {
		fromIP := addrToIP(from)
		if fromIP != nil && !fromIP.Equal(dst.IP) {
			return 0, fmt.Errorf("source address mismatch: got %v, want %v", fromIP, dst.IP)
		}
	}

	return uint16(echo.Seq), nil
}

// addrToIP extracts the IP from a net.Addr.
func addrToIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	default:
		return nil
	}
}
