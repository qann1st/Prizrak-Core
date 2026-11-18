//go:build windows && amd64 && with_zapret2

package zapret2

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestEmbeddedWindowsUDPLoopback(t *testing.T) {
	if os.Getenv("PRIZRAK_ZAPRET2_WIN_SMOKE") != "1" {
		t.Skip("requires the bundled WinDivert driver and elevated privileges")
	}
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	remote := target.LocalAddr().(*net.UDPAddr)
	e, err := New(&Option{UDPPorts: []int{remote.Port}, Options: []string{
		"--blob=sample:0x01020304",
		fmt.Sprintf("--filter-udp=%d", remote.Port),
		"--payload=all",
		"--lua-desync=fake:blob=sample:payload=all",
	}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	wrapped, err := e.RegisterUDP(client, remote.AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer wrapped.Close()
	if _, err := wrapped.WriteTo([]byte("original"), remote); err != nil {
		t.Fatal(err)
	}
	if err := target.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	gotOriginal, gotGuestOutput := false, false
	for i := 0; i < 2; i++ {
		var buf [256]byte
		n, _, err := target.ReadFromUDP(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		gotOriginal = gotOriginal || string(buf[:n]) == "original"
		gotGuestOutput = gotGuestOutput || bytes.Equal(buf[:n], []byte{1, 2, 3, 4})
	}
	if !gotOriginal || !gotGuestOutput {
		t.Fatal("expected original and zapret2-generated datagrams on the loopback socket")
	}
}
