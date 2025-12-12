//go:build linux
// +build linux

package keyring

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/jsipprell/keyctl"
)

func StoreEncryptedMasterKey(encryptedKey []byte, salt []byte) error {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		log.Println("failed to access session keyring")
		return fmt.Errorf("failed to access kernel keyring: %w", err)
	}

	keyring.SetDefaultTimeout(0) // No timeout - persist until reboot

	encryptedKeyHex := hex.EncodeToString(encryptedKey)
	saltHex := hex.EncodeToString(salt)

	// Store encrypted master key
	_, err = keyring.Add("secrets-manager:encrypted_master_key", []byte(encryptedKeyHex))
	if err != nil {
		log.Println("failed to store encrypted master key in kernel keyring")
		return fmt.Errorf("failed to store encrypted master key: %w", err)
	}

	// Store salt
	_, err = keyring.Add("secrets-manager:salt", []byte(saltHex))
	if err != nil {
		log.Println("failed to store salt in kernel keyring")
		return fmt.Errorf("failed to store salt: %w", err)
	}

	return nil
}

func LoadEncryptedMasterKey() (encryptedKey []byte, salt []byte, err error) {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		log.Println("failed to access session keyring")
		return nil, nil, fmt.Errorf("failed to access kernel keyring: %w", err)
	}

	// Load encrypted master key
	keyID, err := keyring.Search("secrets-manager:encrypted_master_key")
	if err != nil {
		log.Println("failed to find encrypted master key in kernel keyring")
		return nil, nil, fmt.Errorf("encrypted master key not found in keyring: %w", err)
	}

	encryptedKeyHex, err := keyID.Get()
	if err != nil {
		log.Println("failed to get encrypted master key from kernel keyring")
		return nil, nil, fmt.Errorf("failed to retrieve encrypted master key: %w", err)
	}

	// Load salt
	saltID, err := keyring.Search("secrets-manager:salt")
	if err != nil {
		log.Println("failed to find salt in kernel keyring")
		return nil, nil, fmt.Errorf("salt not found in keyring: %w", err)
	}

	saltHex, err := saltID.Get()
	if err != nil {
		log.Println("failed to get salt from kernel keyring")
		return nil, nil, fmt.Errorf("failed to retrieve salt: %w", err)
	}

	// Decode from hex
	encryptedKeyBytes, err := hex.DecodeString(string(encryptedKeyHex))
	if err != nil {
		log.Println("failed to decode encrypted master key from hex")
		return nil, nil, fmt.Errorf("failed to decode encrypted master key: %w", err)
	}

	saltBytes, err := hex.DecodeString(string(saltHex))
	if err != nil {
		log.Println("failed to decode salt from hex")
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	return encryptedKeyBytes, saltBytes, nil
}

func DeleteMasterKey() error {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		return fmt.Errorf("failed to access kernel keyring: %w", err)
	}

	// Try to delete encrypted master key
	if keyID, err := keyring.Search("secrets-manager:encrypted_master_key"); err == nil {
		keyID.Unlink()
	}

	// Try to delete salt
	if saltID, err := keyring.Search("secrets-manager:salt"); err == nil {
		saltID.Unlink()
	}

	return nil
}
