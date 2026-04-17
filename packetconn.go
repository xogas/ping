//go:build linux

package ping

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// packetConn abstracts the ICMP connection capabilities.
// send.go and recv.go depend only on this interface.
type packetConn interface {
	// WriteTo sends an ICMP packet to the destination address.
	WriteTo(b []byte, dst net.Addr) (int, error)

	// ReadFrom reads an ICMP packet, returning byte count, TTL/HopLimit, source address, and error.
	ReadFrom(b []byte) (n int, ttl int, addr net.Addr, err error)

	// SetReadDeadline sets the read timeout.
	SetReadDeadline(t time.Time) error

	// SetTTL sets the IP TTL / Hop Limit.
	SetTTL(ttl int) error

	// SetMark sets the SO_MARK socket option.
	SetMark(mark int) error

	// SetDoNotFragment sets the DF bit to prohibit IP fragmentation.
	SetDoNotFragment(v bool) error

	// SetBroadcast sets SO_BROADCAST to allow sending to broadcast addresses.
	SetBroadcast(v bool) error

	// SetICMPFilter sets ICMP_FILTER (IPv4) or ICMPV6_FILTER (IPv6)
	// to only pass through Echo Reply at the kernel level.
	SetICMPFilter() error

	// EnableTTLControlMessage enables ControlMessage to read TTL/HopLimit.
	EnableTTLControlMessage() error

	// Close closes the underlying connection.
	Close() error
}

// listenNetwork returns the network string for icmp.ListenPacket based on
// IP version and privilege mode.
func listenNetwork(isIPv4 bool, privileged bool) string {
	if isIPv4 {
		if privileged {
			return "ip4:icmp"
		}
		return "udp4"
	}
	if privileged {
		return "ip6:ipv6-icmp"
	}
	return "udp6"
}

// listenAddr returns the listen address.
// IPv4 -> "0.0.0.0", IPv6 -> "::".
func listenAddr(isIPv4 bool) string {
	if isIPv4 {
		return "0.0.0.0"
	}
	return "::"
}

// packetConnImpl is the Linux implementation of packetConn.
type packetConnImpl struct {
	conn    *icmp.PacketConn // Underlying ICMP connection
	rawConn syscall.RawConn  // Obtained via SyscallConn() for safe fd access
	ipv4    bool             // Whether this is an IPv4 connection
}

// newPacketConn creates an ICMP connection, obtains a RawConn via SyscallConn(),
// sets TTL, enables TTL/HopLimit ControlMessage, attaches ICMP_FILTER/ICMPV6_FILTER
// and BPF filter (privileged mode only), and configures SO_MARK / DF / SO_BROADCAST.
func newPacketConn(isIPv4 bool, id int, opts *options) (packetConn, error) {
	network := listenNetwork(isIPv4, opts.privileged)
	addr := listenAddr(isIPv4)

	c, err := icmp.ListenPacket(network, addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s on %s: %w", network, addr, err)
	}

	// Obtain RawConn for setsockopt operations.
	// icmp.PacketConn embeds net.PacketConn which on Linux implements
	// the SyscallConn interface.
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}

	var sc syscall.RawConn
	if scc, ok := c.IPv4PacketConn().PacketConn.(syscallConner); ok {
		sc, err = scc.SyscallConn()
	} else if scc, ok := c.IPv6PacketConn().PacketConn.(syscallConner); ok {
		sc, err = scc.SyscallConn()
	} else {
		_ = c.Close()
		return nil, fmt.Errorf("underlying connection does not support SyscallConn")
	}
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("obtain syscall conn: %w", err)
	}

	pc := &packetConnImpl{
		conn:    c,
		rawConn: sc,
		ipv4:    isIPv4,
	}

	// Set TTL.
	if err := pc.SetTTL(opts.ttl); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("set TTL: %w", err)
	}

	// Enable TTL/HopLimit ControlMessage for reading.
	if err := pc.EnableTTLControlMessage(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("enable TTL control message: %w", err)
	}

	// Privileged mode: attach ICMP_FILTER and BPF.
	if opts.privileged {
		if err := pc.SetICMPFilter(); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("set ICMP filter: %w", err)
		}
		if err := attachBPF(sc, id, isIPv4); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("attach BPF: %w", err)
		}
	}

	// Optional socket options.
	if opts.mark != 0 {
		if err := pc.SetMark(opts.mark); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("set SO_MARK: %w", err)
		}
	}
	if opts.dontFragment {
		if err := pc.SetDoNotFragment(true); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("set DF: %w", err)
		}
	}
	if opts.broadcast {
		if err := pc.SetBroadcast(true); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("set SO_BROADCAST: %w", err)
		}
	}

	return pc, nil
}

func (c *packetConnImpl) WriteTo(b []byte, dst net.Addr) (int, error) {
	return c.conn.WriteTo(b, dst)
}

func (c *packetConnImpl) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *packetConnImpl) Close() error {
	return c.conn.Close()
}

func (c *packetConnImpl) ReadFrom(b []byte) (n int, ttl int, addr net.Addr, err error) {
	if c.ipv4 {
		var cm *ipv4.ControlMessage
		n, cm, addr, err = c.conn.IPv4PacketConn().ReadFrom(b)
		if cm != nil {
			ttl = cm.TTL
		}
	} else {
		var cm *ipv6.ControlMessage
		n, cm, addr, err = c.conn.IPv6PacketConn().ReadFrom(b)
		if cm != nil {
			ttl = cm.HopLimit
		}
	}
	return
}

func (c *packetConnImpl) SetTTL(ttl int) error {
	if c.ipv4 {
		return c.conn.IPv4PacketConn().SetTTL(ttl)
	}
	return c.conn.IPv6PacketConn().SetHopLimit(ttl)
}

func (c *packetConnImpl) EnableTTLControlMessage() error {
	if c.ipv4 {
		return c.conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	}
	return c.conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
}

func (c *packetConnImpl) SetMark(mark int) error {
	const soMark = 36 // SO_MARK on Linux
	var sErr error
	err := c.rawConn.Control(func(fd uintptr) {
		sErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soMark, mark)
	})
	if err != nil {
		return err
	}
	return sErr
}

func (c *packetConnImpl) SetDoNotFragment(v bool) error {
	var sErr error
	err := c.rawConn.Control(func(fd uintptr) {
		if c.ipv4 {
			val := 0 // IP_PMTUDISC_DONT
			if v {
				val = 2 // IP_PMTUDISC_DO
			}
			sErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, val)
		} else {
			val := 0
			if v {
				val = 1
			}
			const ipv6DontFrag = 62 // IPV6_DONTFRAG on Linux
			sErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6DontFrag, val)
		}
	})
	if err != nil {
		return err
	}
	return sErr
}

func (c *packetConnImpl) SetBroadcast(v bool) error {
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

func (c *packetConnImpl) SetICMPFilter() error {
	var sErr error
	err := c.rawConn.Control(func(fd uintptr) {
		if c.ipv4 {
			// ICMP_FILTER: only allow Echo Reply (Type 0).
			// The filter is a bitmask where bit N means "block type N".
			// We block all types, then unblock type 0 (Echo Reply).
			const (
				solRAW     = 255 // SOL_RAW
				icmpFilter = 1   // ICMP_FILTER
			)
			// Block all: set all bits to 1.
			var filter [4]byte
			filter[0] = 0xFF
			filter[1] = 0xFF
			filter[2] = 0xFF
			filter[3] = 0xFF
			// Unblock Echo Reply (type 0): clear bit 0.
			filter[0] &^= 1 << 0
			sErr = setsockopt(int(fd), solRAW, icmpFilter, unsafe.Pointer(&filter[0]), 4)
		} else {
			// ICMPV6_FILTER: only allow Echo Reply (Type 129).
			const (
				icmpV6Filter = 1 // ICMPV6_FILTER
			)
			// The ICMPv6 filter is 256 bits (32 bytes).
			// Bit N set means "pass type N".
			var filter [32]byte
			// Set bit 129 to pass Echo Reply.
			filter[129/8] |= 1 << (129 % 8)
			sErr = setsockopt(int(fd), syscall.IPPROTO_ICMPV6, icmpV6Filter, unsafe.Pointer(&filter[0]), 32)
		}
	})
	if err != nil {
		return err
	}
	return sErr
}

// setsockopt is a thin wrapper around syscall.Syscall6 for setsockopt.
func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	_, _, err := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		vallen,
		0,
	)
	if err != 0 {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

// attachBPF constructs a BPF program that filters ICMP Echo Reply by Identifier
// and attaches it to the socket via SO_ATTACH_FILTER.
// Only called in privileged mode; unprivileged mode uses UDP port isolation.
func attachBPF(rc syscall.RawConn, id int, isIPv4 bool) error {
	// BPF instructions:
	// 1. Load ICMP Type byte
	// 2. Compare with Echo Reply type; if not match, reject
	// 3. Load ICMP Identifier (2 bytes)
	// 4. Compare with our ID; if not match, reject
	// 5. Accept

	var replyType uint32
	var typeOffset, idOffset uint32

	if isIPv4 {
		replyType = 0   // Echo Reply
		typeOffset = 20 // ICMP type at offset 20 (after 20-byte IPv4 header)
		idOffset = 24   // ICMP identifier at offset 24 (20 + 4)
	} else {
		replyType = 129 // ICMPv6 Echo Reply
		typeOffset = 0  // IPv6 raw socket does not include IPv6 header
		idOffset = 4
	}

	rawInstructions, err := bpf.Assemble([]bpf.Instruction{
		// Load ICMP Type (1 byte at offset typeOffset).
		bpf.LoadAbsolute{Off: typeOffset, Size: 1},
		// If Type != Echo Reply, jump to reject.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: replyType, SkipTrue: 0, SkipFalse: 3},
		// Load ICMP Identifier (2 bytes at offset idOffset).
		bpf.LoadAbsolute{Off: idOffset, Size: 2},
		// If ID != our ID, jump to reject.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(id), SkipTrue: 0, SkipFalse: 1},
		// Accept: return max packet size.
		bpf.RetConstant{Val: 0xFFFF},
		// Reject: return 0.
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		return fmt.Errorf("assemble BPF: %w", err)
	}

	var sErr error
	err = rc.Control(func(fd uintptr) {
		prog := syscall.SockFprog{
			Len:    uint16(len(rawInstructions)),
			Filter: (*syscall.SockFilter)(unsafe.Pointer(&rawInstructions[0])),
		}
		sErr = setsockopt(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_ATTACH_FILTER,
			unsafe.Pointer(&prog),
			unsafe.Sizeof(prog),
		)
	})
	if err != nil {
		return err
	}
	return sErr
}
