package keyring

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type KeyringData struct {
	EncryptedMasterKey string `json:"encrypted_master_key"`
	Salt               string `json:"salt"`
}

func GetVaultKeyringPath(vaultDir string) string {
	return filepath.Join(vaultDir, "keyring.json")
}

func StoreVaultKeyring(vaultDir string, encryptedKey []byte, salt []byte) error {
	keyringPath := GetVaultKeyringPath(vaultDir)
	
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	data := KeyringData{
		EncryptedMasterKey: hex.EncodeToString(encryptedKey),
		Salt:               hex.EncodeToString(salt),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keyring data: %w", err)
	}

	if err := os.WriteFile(keyringPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write keyring file: %w", err)
	}

	return nil
}

func LoadVaultKeyring(vaultDir string) (encryptedKey []byte, salt []byte, err error) {
	keyringPath := GetVaultKeyringPath(vaultDir)

	jsonData, err := os.ReadFile(keyringPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read keyring file: %w", err)
	}

	var data KeyringData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, nil, fmt.Errorf("failed to parse keyring data: %w", err)
	}

	encryptedKey, err = hex.DecodeString(data.EncryptedMasterKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode encrypted master key: %w", err)
	}

	salt, err = hex.DecodeString(data.Salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	return encryptedKey, salt, nil
}

func DeleteVaultKeyring(vaultDir string) error {
	keyringPath := GetVaultKeyringPath(vaultDir)
	if err := os.Remove(keyringPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete keyring file: %w", err)
	}
	return nil
}

func VaultKeyringExists(vaultDir string) bool {
	keyringPath := GetVaultKeyringPath(vaultDir)
	_, err := os.Stat(keyringPath)
	return err == nil
}

