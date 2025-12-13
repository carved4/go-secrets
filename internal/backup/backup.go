package backup

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/storage"
)

type ExportBlob struct {
	Version         string                            `json:"version"`
	ExportedAt      time.Time                         `json:"exported_at"`
	VaultID         string                            `json:"vault_id"`
	SecretsMetadata map[string]storage.SecretMetadata `json:"secrets_metadata"`
	MasterKey       string                            `json:"master_key"`
	Salt            string                            `json:"salt"`
	Nonce           string                            `json:"nonce"`
	Encrypted       bool                              `json:"encrypted"`
}

func ExportSecrets(password []byte) ([]byte, error) {
	vault, err := storage.LoadVault(storage.GetVaultPath())
	if err != nil {
		return nil, fmt.Errorf("failed to load vault: %w", err)
	}

	derivedKey, salt, err := crypto.DeriveKeyFromUserPass([]byte(password), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	blob := &ExportBlob{
		Version:         "1.0",
		ExportedAt:      time.Now(),
		VaultID:         vault.VaultID,
		SecretsMetadata: vault.SecretsMetadata,
		Encrypted:       true,
		Salt:            hex.EncodeToString(salt),
	}

	blobJSON, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal export blob: %w", err)
	}

	encryptedBlob, err := crypto.EncryptSecret(blobJSON, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt export blob: %w", err)
	}

	wrapper := map[string]string{
		"salt": hex.EncodeToString(salt),
		"data": hex.EncodeToString(encryptedBlob),
	}

	wrapperJSON, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapper: %w", err)
	}

	return wrapperJSON, nil
}

func ImportSecrets(encryptedBlob []byte, password []byte) (*ExportBlob, error) {
	var wrapper map[string]string
	if err := json.Unmarshal(encryptedBlob, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal wrapper: %w", err)
	}

	saltBytes, err := hex.DecodeString(wrapper["salt"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	encryptedData, err := hex.DecodeString(wrapper["data"])
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	derivedKey, _, err := crypto.DeriveKeyFromUserPass([]byte(password), saltBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	decryptedBlob, err := crypto.DecryptSecret(encryptedData, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt export blob - incorrect password: %w", err)
	}
	defer crypto.CleanupBytes(decryptedBlob)

	var blob ExportBlob
	if err := json.Unmarshal(decryptedBlob, &blob); err != nil {
		return nil, fmt.Errorf("failed to unmarshal export blob: %w", err)
	}

	return &blob, nil
}

func RestoreFromBlob(blob *ExportBlob) error {
	vault, err := storage.LoadVault(storage.GetVaultPath())
	if err != nil {
		return fmt.Errorf("failed to load current vault: %w", err)
	}

	for name, metadata := range blob.SecretsMetadata {
		vault.SecretsMetadata[name] = metadata
	}

	if err := storage.SaveVault(storage.GetVaultPath(), vault); err != nil {
		return fmt.Errorf("failed to save restored vault: %w", err)
	}

	return nil
}

func GetBackupDir() string {
	vaultDir := storage.GetVaultDir()
	return filepath.Join(vaultDir, "backups")
}

func GetBackupDirForVault(vaultDir string) string {
	return filepath.Join(vaultDir, "backups")
}

func CreateAutoBackup(password []byte) error {
	backupDir := GetBackupDir()
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	encryptedBlob, err := ExportSecrets(password)
	if err != nil {
		return fmt.Errorf("failed to export secrets: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("vault_backup_%s.enc", timestamp))

	if err := os.WriteFile(backupPath, encryptedBlob, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	if err := cleanOldBackups(backupDir, 10); err != nil {
		return fmt.Errorf("failed to clean old backups: %w", err)
	}

	return nil
}

func CreateAutoBackupForVault(vaultDir string, password []byte) error {
	backupDir := GetBackupDirForVault(vaultDir)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	encryptedBlob, err := ExportSecretsFromVault(vaultDir, password)
	if err != nil {
		return fmt.Errorf("failed to export secrets: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("vault_backup_%s.enc", timestamp))

	if err := os.WriteFile(backupPath, encryptedBlob, 0600); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	if err := cleanOldBackups(backupDir, 10); err != nil {
		return fmt.Errorf("failed to clean old backups: %w", err)
	}

	return nil
}

func ExportSecretsFromVault(vaultDir string, password []byte) ([]byte, error) {
	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load vault: %w", err)
	}

	derivedKey, salt, err := crypto.DeriveKeyFromUserPass([]byte(password), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	blob := &ExportBlob{
		Version:         "1.0",
		ExportedAt:      time.Now(),
		VaultID:         vault.VaultID,
		SecretsMetadata: vault.SecretsMetadata,
		Encrypted:       true,
		Salt:            hex.EncodeToString(salt),
	}

	blobJSON, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal export blob: %w", err)
	}

	encryptedBlob, err := crypto.EncryptSecret(blobJSON, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt export blob: %w", err)
	}

	wrapper := map[string]string{
		"salt": hex.EncodeToString(salt),
		"data": hex.EncodeToString(encryptedBlob),
	}

	wrapperJSON, err := json.MarshalIndent(wrapper, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal wrapper: %w", err)
	}

	return wrapperJSON, nil
}

func RestoreFromBlobToVault(blob *ExportBlob, vaultDir string) error {
	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load current vault: %w", err)
	}

	for name, metadata := range blob.SecretsMetadata {
		vault.SecretsMetadata[name] = metadata
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		return fmt.Errorf("failed to save restored vault: %w", err)
	}

	return nil
}

func cleanOldBackups(backupDir string, keepCount int) error {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return err
	}

	var backupFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".enc" {
			backupFiles = append(backupFiles, entry)
		}
	}

	if len(backupFiles) <= keepCount {
		return nil
	}

	type fileInfo struct {
		name    string
		modTime time.Time
	}

	var files []fileInfo
	for _, entry := range backupFiles {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{
			name:    entry.Name(),
			modTime: info.ModTime(),
		})
	}

	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[i].modTime.Before(files[j].modTime) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	for i := keepCount; i < len(files); i++ {
		backupPath := filepath.Join(backupDir, files[i].name)
		if err := os.Remove(backupPath); err != nil {
			return fmt.Errorf("failed to remove old backup %s: %w", files[i].name, err)
		}
	}

	return nil
}

func ListBackups() ([]string, error) {
	backupDir := GetBackupDir()
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var backups []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".enc" {
			backups = append(backups, entry.Name())
		}
	}

	return backups, nil
}
