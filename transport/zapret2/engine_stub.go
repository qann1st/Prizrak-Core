//go:build !windows || !amd64 || !with_zapret2

package zapret2

import (
	"net"
	"net/netip"
)

type Engine struct{}

func New(o *Option) (*Engine, error) {
	if _, err := parse(o); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

func (*Engine) RegisterTCP(c net.Conn) (net.Conn, error) { return c, nil }

func (*Engine) RegisterUDP(c net.PacketConn, remote netip.AddrPort) (net.PacketConn, error) {
	return c, nil
}
