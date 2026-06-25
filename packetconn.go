//go:build unix

package ping

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// packetConn wraps an ICMP connection with IPv4/IPv6 support.
type packetConn struct {
	conn    *icmp.PacketConn
	rawConn syscall.RawConn
	ipv4    bool
}

func newPacketConn(isIPv4 bool, opts *options) (*packetConn, error) {
	network, addr := icmpNetwork(isIPv4, opts.privileged)

	c, err := icmp.ListenPacket(network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s on %s: %w", network, addr, err)
	}

	sc, err := getRawConn(c)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	pc := &packetConn{
		conn:    c,
		rawConn: sc,
		ipv4:    isIPv4,
	}

	if err := configureSocket(pc, opts); err != nil {
		_ = c.Close()
		return nil, err
	}

	return pc, nil
}

func (c *packetConn) ReadFrom(b []byte) (n int, ttl int, addr net.Addr, err error) {
	if c.ipv4 {
		var cm *ipv4.ControlMessage
		n, cm, addr, err = c.conn.IPv4PacketConn().ReadFrom(b)
		if cm != nil {
			ttl = cm.TTL
		}
		return
	}

	var cm *ipv6.ControlMessage
	n, cm, addr, err = c.conn.IPv6PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.HopLimit
	}
	return
}

func (c *packetConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	return c.conn.WriteTo(b, dst)
}

func (c *packetConn) Close() error {
	return c.conn.Close()
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *packetConn) SetTTL(ttl int) error {
	if c.ipv4 {
		return c.conn.IPv4PacketConn().SetTTL(ttl)
	}
	return c.conn.IPv6PacketConn().SetHopLimit(ttl)
}

func (c *packetConn) EnableTTLControlMessage() error {
	if c.ipv4 {
		return c.conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	}
	return c.conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
}

func (c *packetConn) SetBroadcast(v bool) error {
	val := 0
	if v {
		val = 1
	}
	var sErr error
	err := c.rawConn.Control(func(fd uintptr) {
		sErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, val)
	})
	if err != nil {
		return err
	}
	return sErr
}

func icmpNetwork(isIPv4, privileged bool) (network, addr string) {
	if isIPv4 {
		if privileged {
			return "ip4:icmp", "0.0.0.0"
		}
		return "udp4", "0.0.0.0"
	}
	if privileged {
		return "ip6:ipv6-icmp", "::"
	}
	return "udp6", "::"
}

func getRawConn(c *icmp.PacketConn) (syscall.RawConn, error) {
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}

	if scc, ok := c.IPv4PacketConn().PacketConn.(syscallConner); ok {
		return scc.SyscallConn()
	}
	if scc, ok := c.IPv6PacketConn().PacketConn.(syscallConner); ok {
		return scc.SyscallConn()
	}
	return nil, fmt.Errorf("underlying connection does not support SyscallConn")
}

func configureSocket(pc *packetConn, opts *options) error {
	if err := pc.SetTTL(opts.ttl); err != nil {
		return fmt.Errorf("set TTL: %w", err)
	}
	if err := pc.EnableTTLControlMessage(); err != nil {
		return fmt.Errorf("enable TTL control message: %w", err)
	}
	if opts.broadcast {
		if err := pc.SetBroadcast(true); err != nil {
			return fmt.Errorf("set SO_BROADCAST: %w", err)
		}
	}
	return nil
}
