//go:build linux || darwin

package privileges

import (
	"fmt"
	"os"
)

func IsElevated() (bool, error) {
	return os.Geteuid() == 0, nil
}

func RequireElevated() error {
	elevated, err := IsElevated()
	if err != nil {
		return fmt.Errorf("failed to check privileges: %w", err)
	}
	if !elevated {
		return fmt.Errorf("this operation requires root privileges. Please run with sudo")
	}
	return nil
}
