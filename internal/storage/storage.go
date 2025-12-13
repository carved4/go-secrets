package storage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type SecretMetadata struct {
	EncryptedValue string    `json:"encrypted_value"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Vault struct {
	Secrets         map[string]string         `json:"secrets,omitempty"`
	SecretsMetadata map[string]SecretMetadata `json:"secrets_metadata,omitempty"`
	HMAC            string                    `json:"hmac"`
	VaultID         string                    `json:"vault_id,omitempty"`
}

func InitVault() error {
	vaultDir := GetVaultDir()
	vaultPath := GetVaultPath()

	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		log.Println("could not create vault directory", err)
		return err
	}

	vaultID := generateVaultID()
	vault := &Vault{
		SecretsMetadata: make(map[string]SecretMetadata),
		VaultID:         vaultID,
	}

	if err := SaveVault(vaultPath, vault); err != nil {
		return err
	}

	return nil
}
func GetVaultDir() string {
	if isWindows() {
		return filepath.Join(os.Getenv("ProgramData"), "secrets-manager", "vault")
	}
	return "/var/lib/secrets-manager"
}

func GetVaultPath() string {
	vaultDir := GetVaultDir()
	vaultPath := filepath.Join(vaultDir, "vault.json")
	return vaultPath
}

func GetGroupVaultPath() string {
	vaultDir := GetVaultDir()
	vaultPath := filepath.Join(vaultDir, "vault-group.json")
	return vaultPath
}

func GetVaultPathForMode(useGroup bool) string {
	if useGroup {
		return GetGroupVaultPath()
	}
	return GetVaultPath()
}

func GetVaultPathForVault(vaultDir string) string {
	return filepath.Join(vaultDir, "vault.json")
}

func LoadVaultFromDir(vaultDir string) (*Vault, error) {
	vaultPath := GetVaultPathForVault(vaultDir)
	return LoadVault(vaultPath)
}

func SaveVaultToDir(vaultDir string, vault *Vault) error {
	vaultPath := GetVaultPathForVault(vaultDir)
	return SaveVault(vaultPath, vault)
}

func InitVaultInDir(vaultDir string) error {
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		log.Println("could not create vault directory", err)
		return err
	}

	vaultID := generateVaultID()
	vault := &Vault{
		SecretsMetadata: make(map[string]SecretMetadata),
		VaultID:         vaultID,
	}

	vaultPath := GetVaultPathForVault(vaultDir)
	if err := SaveVault(vaultPath, vault); err != nil {
		return err
	}

	return nil
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}
func LoadVault(path string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var vault Vault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, err
	}

	// Migrate old format to new format with metadata
	if vault.Secrets != nil && vault.SecretsMetadata == nil {
		vault.SecretsMetadata = make(map[string]SecretMetadata)
		for name, encValue := range vault.Secrets {
			vault.SecretsMetadata[name] = SecretMetadata{
				EncryptedValue: encValue,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}
		}
		vault.Secrets = nil
	}

	if vault.SecretsMetadata == nil {
		vault.SecretsMetadata = make(map[string]SecretMetadata)
	}

	if vault.VaultID == "" {
		vault.VaultID = generateVaultID()
	}

	if vault.HMAC != "" {
		expectedHMAC := computeVaultHMAC(vault.SecretsMetadata, vault.VaultID)
		if vault.HMAC != expectedHMAC {
			return nil, fmt.Errorf("vault integrity check failed - possible tampering detected")
		}
	}

	return &vault, nil
}

func SaveVault(path string, vault *Vault) error {
	vault.HMAC = computeVaultHMAC(vault.SecretsMetadata, vault.VaultID)

	data, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		log.Printf("SaveVault: failed to marshal JSON: %v", err)
		return fmt.Errorf("failed to marshal vault: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("SaveVault: failed to write file %s: %v", path, err)
		return fmt.Errorf("failed to write vault file: %w", err)
	}
	return nil
}

func AddSecret(name string, encryptedValue []byte) error {
	return AddSecretWithMode(name, encryptedValue, false)
}

func AddSecretWithMode(name string, encryptedValue []byte, useGroup bool) error {
	vaultPath := GetVaultPathForMode(useGroup)

	vault, err := LoadVault(vaultPath)
	if err != nil {
		log.Printf("AddSecret: failed to load vault from %s: %v", vaultPath, err)
		return fmt.Errorf("failed to load vault: %w", err)
	}

	now := time.Now()
	existing, exists := vault.SecretsMetadata[name]
	if exists {
		vault.SecretsMetadata[name] = SecretMetadata{
			EncryptedValue: hex.EncodeToString(encryptedValue),
			CreatedAt:      existing.CreatedAt,
			UpdatedAt:      now,
		}
	} else {
		vault.SecretsMetadata[name] = SecretMetadata{
			EncryptedValue: hex.EncodeToString(encryptedValue),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
	}

	if err := SaveVault(vaultPath, vault); err != nil {
		log.Printf("AddSecret: failed to save vault to %s: %v", vaultPath, err)
		return fmt.Errorf("failed to save vault: %w", err)
	}
	return nil
}

func GetSecret(name string) ([]byte, error) {
	return GetSecretWithMode(name, false)
}

func GetSecretWithMode(name string, useGroup bool) ([]byte, error) {
	vaultPath := GetVaultPathForMode(useGroup)
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}

	metadata, exists := vault.SecretsMetadata[name]
	if !exists {
		return nil, fmt.Errorf("secret not found")
	}
	encryptedBytes, err := hex.DecodeString(metadata.EncryptedValue)

	return encryptedBytes, err
}

func ListSecrets() ([]string, error) {
	return ListSecretsWithMode(false)
}

func ListSecretsWithMode(useGroup bool) ([]string, error) {
	vaultPath := GetVaultPathForMode(useGroup)
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(vault.SecretsMetadata))
	for name := range vault.SecretsMetadata {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func DeleteSecret(name string) error {
	return DeleteSecretWithMode(name, false)
}

func DeleteSecretWithMode(name string, useGroup bool) error {
	vaultPath := GetVaultPathForMode(useGroup)
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return err
	}

	if _, exists := vault.SecretsMetadata[name]; !exists {
		return fmt.Errorf("secret '%s' not found", name)
	}

	delete(vault.SecretsMetadata, name)

	return SaveVault(vaultPath, vault)
}

func GenerateVaultID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Fatalf("could not generate vault ID: %v", err)
	}
	return hex.EncodeToString(b)
}

func generateVaultID() string {
	return GenerateVaultID()
}

func GetSecretMetadata(name string, useGroup bool) (*SecretMetadata, error) {
	vaultPath := GetVaultPathForMode(useGroup)
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}

	metadata, exists := vault.SecretsMetadata[name]
	if !exists {
		return nil, fmt.Errorf("secret not found")
	}

	return &metadata, nil
}

func GetAllSecretsMetadata(useGroup bool) (map[string]SecretMetadata, error) {
	vaultPath := GetVaultPathForMode(useGroup)
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}

	return vault.SecretsMetadata, nil
}

func ClearAllSecrets(useGroup bool) error {
	vaultPath := GetVaultPathForMode(useGroup)
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return err
	}

	vault.SecretsMetadata = make(map[string]SecretMetadata)
	return SaveVault(vaultPath, vault)
}

func computeVaultHMAC(secretsMetadata map[string]SecretMetadata, vaultID string) string {
	key := sha256.Sum256([]byte("vault-integrity-key-" + vaultID))
	h := hmac.New(sha256.New, key[:])

	names := make([]string, 0, len(secretsMetadata))
	for name := range secretsMetadata {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte(secretsMetadata[name].EncryptedValue))
	}

	return hex.EncodeToString(h.Sum(nil))
}
