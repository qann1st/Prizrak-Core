//go:build with_zapret2

package zapret2

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func TestGuestLoadsOriginalLuaAndProcessesUDP(t *testing.T) {
	cfg, err := parse(&Option{UDPPorts: []int{443}, Options: []string{
		"--blob=sample:0x01020304",
		"--filter-udp=443",
		"--payload=all",
		"--lua-desync=fake:blob=sample:payload=all",
	}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGuest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()

	flow := socketFlow{local: netip.MustParseAddrPort("192.0.2.10:50000"),
		remote: netip.MustParseAddrPort("198.51.100.10:443")}
	packet := []byte{
		0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 10, 198, 51, 100, 10,
		0xc3, 0x50, 0x01, 0xbb, 0, 12, 0, 0, 9, 9, 9, 9,
	}
	result, err := g.process(packet, true, func(output []byte) bool { return flow.matchesPacket(output, true) })
	if err != nil {
		t.Fatal(err)
	}
	if !result.keep || len(result.packets) != 1 || !bytes.HasSuffix(result.packets[0], []byte{1, 2, 3, 4}) {
		t.Fatalf("unexpected result from upstream Lua: %+v", result)
	}
	binary.BigEndian.PutUint16(packet[22:24], 444)
	result, err = g.process(packet, true, func([]byte) bool { return true })
	if err != nil || !result.keep || len(result.packets) != 0 {
		t.Fatalf("non-matching profile: %+v, %v", result, err)
	}
}

func TestGuestReportsLuaConfigurationError(t *testing.T) {
	cfg, err := parse(&Option{TCPPorts: []int{443}, Options: []string{
		"--lua-desync=unknown_test_function",
	}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGuest(cfg)
	if err == nil {
		g.close()
		t.Fatal("invalid Lua strategy was accepted")
	}
	if !strings.Contains(err.Error(), "unknown_test_function") {
		t.Fatal(err)
	}
}

func TestGuestRunsUpstreamTCPSplit(t *testing.T) {
	cfg, err := parse(&Option{TCPPorts: []int{443}, Options: []string{
		"--filter-tcp=443", "--payload=all", "--lua-desync=multisplit:pos=2:payload=all",
	}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGuest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	packet := []byte{
		0x45, 0, 0, 45, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 10, 198, 51, 100, 10,
		0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 100, 0, 0, 0, 200, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0,
		'a', 'b', 'c', 'd', 'e',
	}
	flow := socketFlow{local: netip.MustParseAddrPort("192.0.2.10:50000"),
		remote: netip.MustParseAddrPort("198.51.100.10:443"), tcp: true}
	result, err := g.process(packet, true, func(output []byte) bool { return flow.matchesPacket(output, true) })
	if err != nil {
		t.Fatal(err)
	}
	if result.keep || len(result.packets) != 2 ||
		!bytes.HasSuffix(result.packets[0], []byte("ab")) || !bytes.HasSuffix(result.packets[1], []byte("cde")) {
		t.Fatalf("unexpected TCP split: %+v", result)
	}
}
