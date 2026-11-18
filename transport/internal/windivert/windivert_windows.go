//go:build windows

package windivert

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	windivertLayerNetwork     = 0
	windivertParamQueueLength = 0
	windivertParamQueueSize   = 2

	// One WinDivert handle is opened per flow, so its kernel queues must be
	// small: the default 4 MB queue per handle adds up fast.
	windivertQueueLength = 512
	windivertQueueSize   = 256 * 1024
)

// windivertAddress mirrors WINDIVERT_ADDRESS from windivert.h. The bitfield
// word is kept opaque: it is copied from the received packet and reused when
// the crafted packet is injected.
type Address struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Data      [64]byte
}

func (a *Address) MarkCrafted(ipv6, tcp bool) {
	a.Flags |= 1 << 17 // Outbound
	a.MarkRebuilt(ipv6, tcp)
}

func (a *Address) MarkRebuilt(ipv6, tcp bool) {
	a.Flags &^= 7 << 21
	if !ipv6 {
		a.Flags |= 1 << 21 // IPChecksum
	}
	if tcp {
		a.Flags |= 1 << 22 // TCPChecksum
	} else {
		a.Flags |= 1 << 23 // UDPChecksum
	}
}

func (a *Address) Outbound() bool { return a.Flags&(1<<17) != 0 }

func (a *Address) Impostor() bool { return a.Flags&(1<<19) != 0 }

type Divert struct {
	dll     *syscall.LazyDLL
	openFn  *syscall.LazyProc
	recvFn  *syscall.LazyProc
	sendFn  *syscall.LazyProc
	shutFn  *syscall.LazyProc
	closeFn *syscall.LazyProc
	paramFn *syscall.LazyProc
}

func Load() (*Divert, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	dll := syscall.NewLazyDLL(filepath.Join(filepath.Dir(executable), "WinDivert.dll"))
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("load WinDivert.dll: %w (put WinDivert.dll and WinDivert64.sys next to the exe)", err)
	}
	w := &Divert{
		dll:     dll,
		openFn:  dll.NewProc("WinDivertOpen"),
		recvFn:  dll.NewProc("WinDivertRecv"),
		sendFn:  dll.NewProc("WinDivertSend"),
		shutFn:  dll.NewProc("WinDivertShutdown"),
		closeFn: dll.NewProc("WinDivertClose"),
		paramFn: dll.NewProc("WinDivertSetParam"),
	}
	for _, p := range []*syscall.LazyProc{w.openFn, w.recvFn, w.sendFn, w.shutFn, w.closeFn, w.paramFn} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("WinDivert.dll: %s: %w", p.Name, err)
		}
	}
	return w, nil
}

func winErr(err error) error {
	if err != nil && err != syscall.Errno(0) {
		return err
	}
	return syscall.GetLastError()
}

func (w *Divert) Open(filter string) (syscall.Handle, error) {
	fp, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r1, _, e := w.openFn.Call(
		uintptr(unsafe.Pointer(fp)),
		windivertLayerNetwork,
		0,
		0,
	)
	runtime.KeepAlive(fp)
	if r1 == 0 || r1 == uintptr(syscall.InvalidHandle) {
		return 0, winErr(e)
	}
	h := syscall.Handle(r1)
	// Keep per-flow kernel queues small: the default 4 MB queue per handle
	// multiplied by every intercepted connection is significant memory.
	_, _, _ = w.paramFn.Call(uintptr(h), windivertParamQueueLength, windivertQueueLength)
	_, _, _ = w.paramFn.Call(uintptr(h), windivertParamQueueSize, windivertQueueSize)
	return h, nil
}

func (w *Divert) Recv(h syscall.Handle, buf []byte, addr *Address) (int, error) {
	var n uint32
	r1, _, e := w.recvFn.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
		uintptr(unsafe.Pointer(addr)),
	)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(addr)
	if r1 == 0 {
		return 0, winErr(e)
	}
	if n == 0 || int(n) > len(buf) {
		return 0, fmt.Errorf("WinDivertRecv length %d", n)
	}
	return int(n), nil
}

func (w *Divert) Send(h syscall.Handle, data []byte, addr *Address) error {
	if len(data) == 0 {
		return nil
	}
	var n uint32
	r1, _, e := w.sendFn.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&n)),
		uintptr(unsafe.Pointer(addr)),
	)
	runtime.KeepAlive(data)
	runtime.KeepAlive(addr)
	if r1 == 0 {
		return winErr(e)
	}
	return nil
}

func (w *Divert) Close(h syscall.Handle) error {
	_, _, _ = w.shutFn.Call(uintptr(h), 3) // WINDIVERT_SHUTDOWN_BOTH
	r1, _, e := w.closeFn.Call(uintptr(h))
	if r1 == 0 {
		return winErr(e)
	}
	return nil
}
