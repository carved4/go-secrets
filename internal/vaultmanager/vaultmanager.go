package vaultmanager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type VaultType string

const (
	VaultTypeSolo  VaultType = "solo"
	VaultTypeGroup VaultType = "group"
)

type VaultInfo struct {
	Name          string    `json:"name"`
	Type          VaultType `json:"type"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
	LegacyKeyring bool      `json:"legacy_keyring,omitempty"` // If true, uses old key derivation without vault context (for backwards compatibility)
}

type VaultConfig struct {
	ActiveVault string               `json:"active_vault"`
	Vaults      map[string]VaultInfo `json:"vaults"`
}

func GetVaultBaseDir() string {
	if isWindows() {
		return filepath.Join(os.Getenv("ProgramData"), "secrets-manager")
	}
	return "/var/lib/secrets-manager"
}

func GetVaultConfigPath() string {
	return filepath.Join(GetVaultBaseDir(), "vault-config.json")
}

func GetVaultDir(vaultName string) string {
	return filepath.Join(GetVaultBaseDir(), "vaults", vaultName)
}

func GetVaultPath(vaultName string) string {
	return filepath.Join(GetVaultDir(vaultName), "vault.json")
}

func GetVaultBackupDir(vaultName string) string {
	return filepath.Join(GetVaultDir(vaultName), "backups")
}

func GetVaultAuditPath(vaultName string) string {
	return filepath.Join(GetVaultDir(vaultName), "audit.json")
}

func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func LoadVaultConfig() (*VaultConfig, error) {
	configPath := GetVaultConfigPath()
	
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return &VaultConfig{
			ActiveVault: "default",
			Vaults:      make(map[string]VaultInfo),
		}, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault config: %w", err)
	}

	var config VaultConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse vault config: %w", err)
	}

	if config.Vaults == nil {
		config.Vaults = make(map[string]VaultInfo)
	}

	return &config, nil
}

func SaveVaultConfig(config *VaultConfig) error {
	configPath := GetVaultConfigPath()
	
	baseDir := filepath.Dir(configPath)
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vault config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write vault config: %w", err)
	}

	return nil
}

func GetActiveVault() (string, error) {
	config, err := LoadVaultConfig()
	if err != nil {
		return "", err
	}

	if config.ActiveVault == "" {
		return "default", nil
	}

	return config.ActiveVault, nil
}

func SetActiveVault(vaultName string) error {
	config, err := LoadVaultConfig()
	if err != nil {
		return err
	}

	if _, exists := config.Vaults[vaultName]; !exists {
		return fmt.Errorf("vault '%s' does not exist", vaultName)
	}

	config.ActiveVault = vaultName
	return SaveVaultConfig(config)
}

func CreateVault(name string, vaultType VaultType, description string) error {
	config, err := LoadVaultConfig()
	if err != nil {
		return err
	}

	if _, exists := config.Vaults[name]; exists {
		return fmt.Errorf("vault '%s' already exists", name)
	}

	vaultDir := GetVaultDir(name)
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	info := VaultInfo{
		Name:        name,
		Type:        vaultType,
		Description: description,
		CreatedAt:   time.Now(),
	}

	config.Vaults[name] = info
	
	if len(config.Vaults) == 1 {
		config.ActiveVault = name
	}

	return SaveVaultConfig(config)
}

func DeleteVault(name string) error {
	config, err := LoadVaultConfig()
	if err != nil {
		return err
	}

	if _, exists := config.Vaults[name]; !exists {
		return fmt.Errorf("vault '%s' does not exist", name)
	}

	if config.ActiveVault == name {
		return fmt.Errorf("cannot delete active vault - switch to another vault first")
	}

	vaultDir := GetVaultDir(name)
	if err := os.RemoveAll(vaultDir); err != nil {
		return fmt.Errorf("failed to delete vault directory: %w", err)
	}

	delete(config.Vaults, name)
	return SaveVaultConfig(config)
}

func ListVaults() ([]VaultInfo, error) {
	config, err := LoadVaultConfig()
	if err != nil {
		return nil, err
	}

	vaults := make([]VaultInfo, 0, len(config.Vaults))
	for _, info := range config.Vaults {
		vaults = append(vaults, info)
	}

	sort.Slice(vaults, func(i, j int) bool {
		return vaults[i].Name < vaults[j].Name
	})

	return vaults, nil
}

func VaultExists(name string) (bool, error) {
	config, err := LoadVaultConfig()
	if err != nil {
		return false, err
	}

	_, exists := config.Vaults[name]
	return exists, nil
}

func GetVaultInfo(name string) (*VaultInfo, error) {
	config, err := LoadVaultConfig()
	if err != nil {
		return nil, err
	}

	info, exists := config.Vaults[name]
	if !exists {
		return nil, fmt.Errorf("vault '%s' does not exist", name)
	}

	return &info, nil
}


