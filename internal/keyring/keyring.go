package keyring

import (
	"encoding/hex"
	"fmt"
	"log"
	"runtime"
	"strings"

	"github.com/zalando/go-keyring"
)

func StoreEncryptedMasterKey(encryptedKey []byte, salt []byte) error {
	encryptedKeyHex := hex.EncodeToString(encryptedKey)
	saltHex := hex.EncodeToString(salt)
	if err := keyring.Set("secrets-manager", "encrypted_master_key", encryptedKeyHex); err != nil {
		log.Println("failed to store encrypted master key in keyring")
		return formatKeyringError(err)
	}
	if err := keyring.Set("secrets-manager", "salt", saltHex); err != nil {
		log.Println("failed to store salt in keyring")
		return formatKeyringError(err)
	}
	return nil
}

func LoadEncryptedMasterKey() (encryptedKey []byte, salt []byte, err error) {
	encryptedKeyHex, err := keyring.Get("secrets-manager", "encrypted_master_key")
	if err != nil {
		log.Println("failed to get master key from keyring")
		return nil, nil, err
	}
	saltHex, err := keyring.Get("secrets-manager", "salt")
	if err != nil {
		log.Println("failed to get salt from keyring")
		return nil, nil, err
	}
	encryptedKeyBytes, err := hex.DecodeString(encryptedKeyHex)
	if err != nil {
		log.Println("failed to decode encrypted master key to bytes")
		return nil, nil, err
	}
	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		log.Println("failed to decode salt to bytes")
		return nil, nil, err
	}
	return encryptedKeyBytes, saltBytes, nil
}

func DeleteMasterKey() error {
	keyring.Delete("secrets-manager", "encrypted_master_key")
	keyring.Delete("secrets-manager", "salt")
	return nil
}

func formatKeyringError(err error) error {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	if runtime.GOOS == "linux" && strings.Contains(errMsg, "failed to unlock correct collection") {
		return fmt.Errorf("keyring error: %w\n\nlinux troubleshooting:\n  1. ensure you're logged into a desktop session (gnome/kde/xfce)\n  2. install gnome-keyring: sudo apt install gnome-keyring\n  3. unlock your keyring: run 'seahorse' and create/unlock the default keyring\n  4. if using ssh/headless, set up gnome-keyring-daemon in your session", err)
	}

	return err
}
