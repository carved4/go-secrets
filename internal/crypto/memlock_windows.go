//go:build windows

package crypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func LockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	addr := uintptr(unsafe.Pointer(&b[0]))
	size := uintptr(len(b))

	return windows.VirtualLock(addr, size)
}

func UnlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	addr := uintptr(unsafe.Pointer(&b[0]))
	size := uintptr(len(b))

	return windows.VirtualUnlock(addr, size)
}

func ZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
