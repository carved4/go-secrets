//go:build windows

package privileges

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type tokenElevation struct {
	TokenIsElevated uint32
}

func IsElevated() (bool, error) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	var elevation tokenElevation
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	if err != nil {
		return false, fmt.Errorf("failed to get token information: %w", err)
	}

	return elevation.TokenIsElevated != 0, nil
}

func RequireElevated() error {
	elevated, err := IsElevated()
	if err != nil {
		return fmt.Errorf("failed to check elevation: %w", err)
	}
	if !elevated {
		return fmt.Errorf("this operation requires administrator privileges. Please run as administrator")
	}
	return nil
}
