//go:build !linux
// +build !linux

package keyring

import (
	"encoding/hex"
	"log"

	"github.com/zalando/go-keyring"
)

func StoreEncryptedMasterKey(encryptedKey []byte, salt []byte) error {
	encryptedKeyHex := hex.EncodeToString(encryptedKey)
	saltHex := hex.EncodeToString(salt)

	if err := keyring.Set("secrets-manager", "encrypted_master_key", encryptedKeyHex); err != nil {
		log.Println("failed to store encrypted master key in keyring")
		return err
	}
	if err := keyring.Set("secrets-manager", "salt", saltHex); err != nil {
		log.Println("failed to store salt in keyring")
		return err
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
