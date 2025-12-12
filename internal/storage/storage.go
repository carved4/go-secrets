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
)

type Vault struct {
	Secrets map[string]string `json:"secrets"`
	HMAC    string            `json:"hmac"`
	VaultID string            `json:"vault_id,omitempty"`
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
		Secrets: make(map[string]string),
		VaultID: vaultID,
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
	if vault.Secrets == nil {
		vault.Secrets = make(map[string]string)
	}

	if vault.VaultID == "" {
		vault.VaultID = generateVaultID()
	}

	if vault.HMAC != "" {
		expectedHMAC := computeVaultHMAC(vault.Secrets, vault.VaultID)
		if vault.HMAC != expectedHMAC {
			return nil, fmt.Errorf("vault integrity check failed - possible tampering detected")
		}
	}

	return &vault, nil
}

func SaveVault(path string, vault *Vault) error {
	vault.HMAC = computeVaultHMAC(vault.Secrets, vault.VaultID)

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
	vaultPath := GetVaultPath()

	vault, err := LoadVault(vaultPath)
	if err != nil {
		log.Printf("AddSecret: failed to load vault from %s: %v", vaultPath, err)
		return fmt.Errorf("failed to load vault: %w", err)
	}

	vault.Secrets[name] = hex.EncodeToString(encryptedValue)

	if err := SaveVault(vaultPath, vault); err != nil {
		log.Printf("AddSecret: failed to save vault to %s: %v", vaultPath, err)
		return fmt.Errorf("failed to save vault: %w", err)
	}
	return nil
}

func GetSecret(name string) ([]byte, error) {
	vaultPath := GetVaultPath()
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}

	encryptedHex, exists := vault.Secrets[name]
	if !exists {
		return nil, fmt.Errorf("secret not found")
	}
	encryptedBytes, err := hex.DecodeString(encryptedHex)

	return encryptedBytes, err
}

func ListSecrets() ([]string, error) {
	vaultPath := GetVaultPath()
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(vault.Secrets))
	for name := range vault.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}
func DeleteSecret(name string) error {
	vaultPath := GetVaultPath()
	vault, err := LoadVault(vaultPath)
	if err != nil {
		return err
	}

	if _, exists := vault.Secrets[name]; !exists {
		return fmt.Errorf("secret '%s' not found", name)
	}

	delete(vault.Secrets, name)

	return SaveVault(vaultPath, vault)
}

func generateVaultID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Fatalf("could not generate vault ID: %v", err)
	}
	return hex.EncodeToString(b)
}

func computeVaultHMAC(secrets map[string]string, vaultID string) string {
	key := sha256.Sum256([]byte("vault-integrity-key-" + vaultID))
	h := hmac.New(sha256.New, key[:])

	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte(secrets[name]))
	}

	return hex.EncodeToString(h.Sum(nil))
}
