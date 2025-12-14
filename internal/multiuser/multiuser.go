package multiuser

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/storage"
)

type UserKeyShare struct {
	Username       string `json:"username"`
	EncryptedShare string `json:"encrypted_share"`
	Salt           string `json:"salt"`
}

type Group struct {
	Name         string   `json:"name"`
	Users        []string `json:"users"`
	SecretPrefix []string `json:"secret_prefix"`
}

type MasterKeyRotation struct {
	RotatedAt time.Time `json:"rotated_at"`
	RotatedBy string    `json:"rotated_by"`
}

type MultiUserVault struct {
	Version           string                  `json:"version"`
	Mode              string                  `json:"mode"`
	Secrets           map[string]string       `json:"secrets"`
	MasterKeyShare    map[string]UserKeyShare `json:"master_key_shares,omitempty"`
	Groups            map[string]Group        `json:"groups,omitempty"`
	HMAC              string                  `json:"hmac"`
	VaultID           string                  `json:"vault_id"`
	MasterKeyRotation *MasterKeyRotation      `json:"master_key_rotation,omitempty"`
}

func GetMultiUserVaultPath() string {
	return storage.GetGroupVaultPath()
}

func GetMultiUserVaultPathForVault(vaultDir string) string {
	return filepath.Join(vaultDir, "multiuser.json")
}

func LoadMultiUserVault(path string) (*MultiUserVault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var vault MultiUserVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, err
	}

	if vault.Secrets == nil {
		vault.Secrets = make(map[string]string)
	}
	if vault.MasterKeyShare == nil {
		vault.MasterKeyShare = make(map[string]UserKeyShare)
	}
	if vault.Groups == nil {
		vault.Groups = make(map[string]Group)
	}

	if vault.Mode == "" {
		vault.Mode = "single-user"
	}

	if vault.HMAC != "" {
		expectedHMAC := computeMultiUserVaultHMAC(&vault)
		if vault.HMAC != expectedHMAC {
			return nil, fmt.Errorf("vault integrity check failed - possible tampering detected")
		}
	}

	return &vault, nil
}

func SaveMultiUserVault(path string, vault *MultiUserVault) error {
	vault.HMAC = computeMultiUserVaultHMAC(vault)

	data, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vault: %w", err)
	}

	// Ensure vault directory exists
	vaultDir := filepath.Dir(path)
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}
	return nil
}

func computeMultiUserVaultHMAC(vault *MultiUserVault) string {
	key := sha256.Sum256([]byte("vault-integrity-key-" + vault.VaultID))
	h := hmac.New(sha256.New, key[:])

	// Hash secrets
	names := make([]string, 0, len(vault.Secrets))
	for name := range vault.Secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte(vault.Secrets[name]))
	}

	// Hash user shares
	users := make([]string, 0, len(vault.MasterKeyShare))
	for user := range vault.MasterKeyShare {
		users = append(users, user)
	}
	sort.Strings(users)
	for _, user := range users {
		share := vault.MasterKeyShare[user]
		h.Write([]byte(user))
		h.Write([]byte(share.EncryptedShare))
		h.Write([]byte(share.Salt))
	}

	// Hash groups
	groupNames := make([]string, 0, len(vault.Groups))
	for groupName := range vault.Groups {
		groupNames = append(groupNames, groupName)
	}
	sort.Strings(groupNames)
	for _, groupName := range groupNames {
		group := vault.Groups[groupName]
		h.Write([]byte(group.Name))
		for _, user := range group.Users {
			h.Write([]byte(user))
		}
		for _, prefix := range group.SecretPrefix {
			h.Write([]byte(prefix))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

func InitMultiUserVault(username string, password []byte, masterKey []byte) error {
	return InitMultiUserVaultInDir("", username, password, masterKey)
}

func InitMultiUserVaultInDir(vaultDir string, username string, password []byte, masterKey []byte) error {
	var vaultPath string
	if vaultDir == "" {
		vaultPath = GetMultiUserVaultPath()
	} else {
		vaultPath = GetMultiUserVaultPathForVault(vaultDir)
	}

	derivedKey, salt, err := crypto.DeriveKeyFromUserPass([]byte(password), nil)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	encryptedMasterKey, err := crypto.EncryptMasterKey(masterKey, derivedKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	vault := &MultiUserVault{
		Version: "2.0",
		Mode:    "multi-user",
		Secrets: make(map[string]string),
		MasterKeyShare: map[string]UserKeyShare{
			username: {
				Username:       username,
				EncryptedShare: hex.EncodeToString(encryptedMasterKey),
				Salt:           hex.EncodeToString(salt),
			},
		},
		Groups:  make(map[string]Group),
		VaultID: storage.GenerateVaultID(),
	}

	if err := SaveMultiUserVault(vaultPath, vault); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	return nil
}

func AddUserToVault(username string, password []byte, masterKey []byte) error {
	return AddUserToVaultInDir("", username, password, masterKey)
}

func AddUserToVaultInDir(vaultDir string, username string, password []byte, masterKey []byte) error {
	var vaultPath string
	if vaultDir == "" {
		vaultPath = GetMultiUserVaultPath()
	} else {
		vaultPath = GetMultiUserVaultPathForVault(vaultDir)
	}
	vault, err := LoadMultiUserVault(vaultPath)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	if vault.Mode != "multi-user" {
		return fmt.Errorf("vault is not in multi-user mode")
	}

	if _, exists := vault.MasterKeyShare[username]; exists {
		return fmt.Errorf("user %s already exists", username)
	}

	derivedKey, salt, err := crypto.DeriveKeyFromUserPass([]byte(password), nil)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	encryptedMasterKey, err := crypto.EncryptMasterKey(masterKey, derivedKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	vault.MasterKeyShare[username] = UserKeyShare{
		Username:       username,
		EncryptedShare: hex.EncodeToString(encryptedMasterKey),
		Salt:           hex.EncodeToString(salt),
	}

	if err := SaveMultiUserVault(vaultPath, vault); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	return nil
}

func GetMasterKeyForUser(username string, password []byte) ([]byte, error) {
	return GetMasterKeyForUserInDir("", username, password)
}

func GetMasterKeyForUserInDir(vaultDir string, username string, password []byte) ([]byte, error) {
	var vaultPath string
	if vaultDir == "" {
		vaultPath = GetMultiUserVaultPath()
	} else {
		vaultPath = GetMultiUserVaultPathForVault(vaultDir)
	}
	vault, err := LoadMultiUserVault(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load vault: %w", err)
	}

	if vault.Mode != "multi-user" {
		return nil, fmt.Errorf("vault is not in multi-user mode")
	}

	userShare, exists := vault.MasterKeyShare[username]
	if !exists {
		return nil, fmt.Errorf("user %s not found in vault", username)
	}

	saltBytes, err := hex.DecodeString(userShare.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	derivedKey, _, err := crypto.DeriveKeyFromUserPass([]byte(password), saltBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	encryptedMasterKey, err := hex.DecodeString(userShare.EncryptedShare)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted master key: %w", err)
	}

	masterKey, err := crypto.DecryptMasterKey(encryptedMasterKey, derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %w", err)
	}

	return masterKey, nil
}

func CreateGroup(groupName string, users []string, secretPrefixes []string) error {
	return CreateGroupInDir("", groupName, users, secretPrefixes)
}

func CreateGroupInDir(vaultDir string, groupName string, users []string, secretPrefixes []string) error {
	var vaultPath string
	if vaultDir == "" {
		vaultPath = GetMultiUserVaultPath()
	} else {
		vaultPath = GetMultiUserVaultPathForVault(vaultDir)
	}
	vault, err := LoadMultiUserVault(vaultPath)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	if vault.Mode != "multi-user" {
		return fmt.Errorf("vault is not in multi-user mode")
	}

	if _, exists := vault.Groups[groupName]; exists {
		return fmt.Errorf("group %s already exists", groupName)
	}

	for _, user := range users {
		if _, exists := vault.MasterKeyShare[user]; !exists {
			return fmt.Errorf("user %s does not exist in vault", user)
		}
	}

	vault.Groups[groupName] = Group{
		Name:         groupName,
		Users:        users,
		SecretPrefix: secretPrefixes,
	}

	if err := SaveMultiUserVault(vaultPath, vault); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	return nil
}

func UserCanAccessSecret(username string, secretName string) (bool, error) {
	return UserCanAccessSecretInDir("", username, secretName)
}

func UserCanAccessSecretInDir(vaultDir string, username string, secretName string) (bool, error) {
	var vaultPath string
	if vaultDir == "" {
		vaultPath = GetMultiUserVaultPath()
	} else {
		vaultPath = GetMultiUserVaultPathForVault(vaultDir)
	}
	vault, err := LoadMultiUserVault(vaultPath)
	if err != nil {
		return false, fmt.Errorf("failed to load vault: %w", err)
	}

	if vault.Mode != "multi-user" {
		return true, nil
	}

	for _, group := range vault.Groups {
		userInGroup := false
		for _, user := range group.Users {
			if user == username {
				userInGroup = true
				break
			}
		}

		if !userInGroup {
			continue
		}

		for _, prefix := range group.SecretPrefix {
			if len(secretName) >= len(prefix) && secretName[:len(prefix)] == prefix {
				return true, nil
			}
		}
	}

	return false, nil
}

func ListAccessibleSecrets(username string) ([]string, error) {
	return ListAccessibleSecretsInDir("", username)
}

func ListAccessibleSecretsInDir(vaultDir string, username string) ([]string, error) {
	var vaultPath string
	if vaultDir == "" {
		vaultPath = GetMultiUserVaultPath()
	} else {
		vaultPath = GetMultiUserVaultPathForVault(vaultDir)
	}
	vault, err := LoadMultiUserVault(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load vault: %w", err)
	}

	if vault.Mode != "multi-user" {
		names := make([]string, 0, len(vault.Secrets))
		for name := range vault.Secrets {
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}

	accessibleSecrets := make(map[string]bool)

	for _, group := range vault.Groups {
		userInGroup := false
		for _, user := range group.Users {
			if user == username {
				userInGroup = true
				break
			}
		}

		if !userInGroup {
			continue
		}

		for secretName := range vault.Secrets {
			for _, prefix := range group.SecretPrefix {
				if len(secretName) >= len(prefix) && secretName[:len(prefix)] == prefix {
					accessibleSecrets[secretName] = true
				}
			}
		}
	}

	names := make([]string, 0, len(accessibleSecrets))
	for name := range accessibleSecrets {
		names = append(names, name)
	}
	sort.Strings(names)

	return names, nil
}

func IsMultiUserMode() (bool, error) {
	return IsMultiUserModeInDir("")
}

func IsMultiUserModeInDir(vaultDir string) (bool, error) {
	var vaultPath string
	if vaultDir == "" {
		vaultPath = GetMultiUserVaultPath()
	} else {
		vaultPath = GetMultiUserVaultPathForVault(vaultDir)
	}
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		return false, nil
	}

	vault, err := LoadMultiUserVault(vaultPath)
	if err != nil {
		return false, err
	}

	return vault.Mode == "multi-user", nil
}
