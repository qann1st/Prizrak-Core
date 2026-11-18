//go:build windows && amd64 && with_zapret2

package zapret2

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/internal/windivert"
)

type Engine struct {
	cfg   *config
	wd    *windivert.Divert
	mu    sync.Mutex
	guest *guest
}

func New(o *Option) (*Engine, error) {
	cfg, err := parse(o)
	if err != nil {
		return nil, err
	}
	g, err := newGuest(cfg)
	if err != nil {
		return nil, err
	}
	wd, err := windivert.Load()
	if err == nil {
		var probe syscall.Handle
		probe, err = wd.Open("false")
		if err == nil {
			err = wd.Close(probe)
		}
	}
	if err != nil {
		g.close()
		return nil, fmt.Errorf("zapret2 WinDivert: %w (run as Administrator with WinDivert.dll and WinDivert64.sys next to the exe)", err)
	}
	e := &Engine{cfg: cfg, wd: wd, guest: g}
	runtime.SetFinalizer(e, func(e *Engine) { e.guest.close() })
	return e, nil
}

func (e *Engine) RegisterTCP(c net.Conn) (net.Conn, error) {
	remote, rok := c.RemoteAddr().(*net.TCPAddr)
	local, lok := c.LocalAddr().(*net.TCPAddr)
	if !rok || !lok || !e.cfg.tcp[remote.AddrPort().Port()] {
		return c, nil
	}
	f, err := e.attach(local.AddrPort(), remote.AddrPort(), true)
	if err != nil {
		return c, err
	}
	return &tcpConn{Conn: c, flow: f}, nil
}

func (e *Engine) RegisterUDP(c net.PacketConn, remote netip.AddrPort) (net.PacketConn, error) {
	local, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || !remote.IsValid() || !e.cfg.udp[remote.Port()] {
		return c, nil
	}
	f, err := e.attach(local.AddrPort(), remote, false)
	if err != nil {
		return c, err
	}
	return &udpConn{PacketConn: c, flow: f}, nil
}

func (e *Engine) attach(local, remote netip.AddrPort, tcp bool) (*capture, error) {
	local = netip.AddrPortFrom(local.Addr().Unmap().WithZone(""), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap().WithZone(""), remote.Port())
	flow := socketFlow{local: local, remote: remote, tcp: tcp}
	handle, err := e.wd.Open(flowFilter(flow))
	if err != nil {
		return nil, fmt.Errorf("open connection capture: %w", err)
	}
	f := &capture{socketFlow: flow, engine: e, handle: handle}
	go f.loop()
	return f, nil
}

func flowFilter(f socketFlow) string {
	proto := "udp"
	if f.tcp {
		proto = "tcp"
	}
	ip := "ipv6"
	if f.remote.Addr().Is4() {
		ip = "ip"
	}
	out := []string{"outbound", fmt.Sprintf("%s.DstAddr == %s", ip, f.remote.Addr()),
		fmt.Sprintf("%s.SrcPort == %d", proto, f.local.Port()), fmt.Sprintf("%s.DstPort == %d", proto, f.remote.Port())}
	in := []string{"inbound", fmt.Sprintf("%s.SrcAddr == %s", ip, f.remote.Addr()),
		fmt.Sprintf("%s.DstPort == %d", proto, f.local.Port()), fmt.Sprintf("%s.SrcPort == %d", proto, f.remote.Port())}
	if !f.local.Addr().IsUnspecified() {
		out = append(out, fmt.Sprintf("%s.SrcAddr == %s", ip, f.local.Addr()))
		in = append(in, fmt.Sprintf("%s.DstAddr == %s", ip, f.local.Addr()))
	}
	return fmt.Sprintf("%s and %s and ((%s) or (%s))", ip, proto, strings.Join(out, " and "), strings.Join(in, " and "))
}

type capture struct {
	socketFlow
	engine *Engine
	handle syscall.Handle
	once   sync.Once
}

func (f *capture) loop() {
	defer f.close()
	var address windivert.Address
	buf := make([]byte, packetLimit)
	wd := f.engine.wd
	for {
		n, err := wd.Recv(f.handle, buf, &address)
		if err != nil {
			return
		}
		original := buf[:n]
		outbound := address.Outbound()
		result := packetResult{keep: true}
		if !address.Impostor() && f.matchesPacket(original, outbound) {
			src, dst, _, _ := packetEndpoints(original)
			accept := func(packet []byte) bool {
				from, to, tcp, ok := packetEndpoints(packet)
				return ok && from == src && to == dst && tcp == f.tcp
			}
			result = f.process(original, outbound, accept)
		}
		crafted := address
		crafted.MarkRebuilt(original[0]>>4 == 6, f.tcp)
		for _, packet := range result.packets {
			if err := wd.Send(f.handle, packet, &crafted); err != nil {
				log.Debugln("[zapret2] reinject: %v", err)
				result.keep = true
				break
			}
		}
		if result.keep {
			if err := wd.Send(f.handle, original, &address); err != nil {
				log.Debugln("[zapret2] pass connection packet: %v", err)
			}
		}
	}
}

func (f *capture) process(packet []byte, outbound bool, accept func([]byte) bool) packetResult {
	e := f.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.guest.mod.IsClosed() {
		return packetResult{keep: true}
	}
	result, err := e.guest.process(packet, outbound, accept)
	if err != nil {
		log.Warnln("[zapret2] strategy: %v", err)
		return packetResult{keep: true}
	}
	return result
}

func (f *capture) close() {
	f.once.Do(func() { _ = f.engine.wd.Close(f.handle) })
}

type tcpConn struct {
	net.Conn
	flow *capture
}

func (c *tcpConn) Close() error  { c.flow.close(); return c.Conn.Close() }
func (c *tcpConn) Upstream() any { return c.Conn }
func (c *tcpConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}
func (c *tcpConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

type udpConn struct {
	net.PacketConn
	flow *capture
}

func (c *udpConn) Close() error  { c.flow.close(); return c.PacketConn.Close() }
func (c *udpConn) Upstream() any { return c.PacketConn }
