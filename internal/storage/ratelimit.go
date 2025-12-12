package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RateLimit struct {
	FailedAttempts int       `json:"failed_attempts"`
	LockedUntil    time.Time `json:"locked_until"`
}

func getRateLimitPath() string {
	vaultDir := GetVaultDir()
	return filepath.Join(vaultDir, "ratelimit.json")
}

func LoadRateLimit() (*RateLimit, error) {
	path := getRateLimitPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &RateLimit{}, nil
		}
		return nil, err
	}

	var rl RateLimit
	if err := json.Unmarshal(data, &rl); err != nil {
		return nil, err
	}

	return &rl, nil
}

func SaveRateLimit(rl *RateLimit) error {
	path := getRateLimitPath()
	data, err := json.MarshalIndent(rl, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func CheckRateLimit() error {
	rl, err := LoadRateLimit()
	if err != nil {
		return err
	}

	if !rl.LockedUntil.IsZero() && time.Now().Before(rl.LockedUntil) {
		remaining := time.Until(rl.LockedUntil).Round(time.Second)
		return fmt.Errorf("vault locked due to too many failed attempts. try again in %v", remaining)
	}

	if time.Now().After(rl.LockedUntil) {
		rl.FailedAttempts = 0
		rl.LockedUntil = time.Time{}
		SaveRateLimit(rl)
	}

	return nil
}

func RecordFailedAttempt() error {
	rl, err := LoadRateLimit()
	if err != nil {
		return err
	}

	rl.FailedAttempts++

	if rl.FailedAttempts >= 10 {
		rl.LockedUntil = time.Now().Add(5 * time.Minute)
	}

	return SaveRateLimit(rl)
}

func ResetRateLimit() error {
	rl := &RateLimit{
		FailedAttempts: 0,
		LockedUntil:    time.Time{},
	}
	return SaveRateLimit(rl)
}
