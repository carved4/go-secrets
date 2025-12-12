//go:build linux || darwin

package crypto

import (
	"golang.org/x/sys/unix"
)

func LockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	return unix.Mlock(b)
}

func UnlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	return unix.Munlock(b)
}

func ZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
