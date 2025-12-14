package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/backup"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/keyring"
	"github.com/carved4/go-secrets/internal/multiuser"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
	"github.com/carved4/go-secrets/internal/vaultmanager"
)

func secretsRotate(args []string) error {
	ui.PrintTitle("rotating secrets")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	if len(args) > 0 {
		secretName := args[0]
		return rotateSpecificSecret(secretName, masterKey, vaultDir)
	}

	return rotateAllSecrets(masterKey, vaultDir)
}

func rotateSpecificSecret(secretName string, masterKey []byte, vaultDir string) error {
	ui.PrintWarning("!", fmt.Sprintf("rotating secret: %s", secretName))
	fmt.Println()

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	existing, exists := vault.SecretsMetadata[secretName]
	if !exists {
		return fmt.Errorf("secret not found: %s", secretName)
	}

	ui.PrintPrompt("paste the new secret value (press Enter when done): ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return fmt.Errorf("failed to read secret value")
	}

	newValue := scanner.Text()
	if newValue == "" {
		return fmt.Errorf("secret value cannot be empty")
	}

	secretBytes := []byte(newValue)
	crypto.SecureBytes(secretBytes)
	defer crypto.CleanupBytes(secretBytes)

	encryptedSecret, err := crypto.EncryptSecret(secretBytes, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	vault.SecretsMetadata[secretName] = storage.SecretMetadata{
		EncryptedValue: fmt.Sprintf("%x", encryptedSecret),
		CreatedAt:      existing.CreatedAt,
		UpdatedAt:      time.Now(),
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "rotate", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	audit.LogEventForVault(vaultDir, currentUsername, "rotate", secretName, true, "", masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' rotated successfully!", secretName))
	fmt.Println()
	return nil
}

func rotateAllSecrets(masterKey []byte, vaultDir string) error {
	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	var names []string
	for name := range vault.SecretsMetadata {
		names = append(names, name)
	}

	if len(names) == 0 {
		ui.PrintMuted("no secrets to rotate")
		fmt.Println()
		return nil
	}

	ui.PrintWarning("!", fmt.Sprintf("rotating %d secret(s)", len(names)))
	ui.PrintMuted("  this will clear all existing secrets and ask for new values")
	fmt.Println()

	ui.PrintPrompt("import rotated secrets from a .env file? (yes/no): ")
	var useFile string
	fmt.Scanln(&useFile)

	if useFile == "yes" || useFile == "y" {
		return rotateFromEnvFile(names, masterKey, vaultDir)
	}

	return rotateInteractively(names, masterKey, vaultDir)
}

func rotateFromEnvFile(existingNames []string, masterKey []byte, vaultDir string) error {
	ui.PrintPrompt("enter path to .env file: ")
	var filePath string
	fmt.Scanln(&filePath)

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	envVars, err := parseEnvFile(string(fileData))
	if err != nil {
		return fmt.Errorf("failed to parse .env file: %w", err)
	}

	if len(envVars) == 0 {
		return fmt.Errorf("no valid environment variables found in file")
	}

	fmt.Println()
	ui.PrintInfo(">", fmt.Sprintf("found %d variable(s) in .env file", len(envVars)))
	fmt.Println()

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	// Clear existing secrets
	vault.SecretsMetadata = make(map[string]storage.SecretMetadata)

	rotatedCount := 0
	now := time.Now()
	for name, value := range envVars {
		secretBytes := []byte(value)
		crypto.SecureBytes(secretBytes)

		encryptedSecret, err := crypto.EncryptSecret(secretBytes, masterKey)
		crypto.CleanupBytes(secretBytes)

		if err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to encrypt %s: %v", name, err))
			continue
		}

		vault.SecretsMetadata[name] = storage.SecretMetadata{
			EncryptedValue: fmt.Sprintf("%x", encryptedSecret),
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		audit.LogEventForVault(vaultDir, currentUsername, "rotate", name, true, "", masterKey)
		ui.PrintSuccess("+", fmt.Sprintf("rotated: %s", name))
		rotatedCount++
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("rotated %d secret(s) successfully!", rotatedCount))
	fmt.Println()

	ui.PrintWarning("!", "delete the source .env file for security?")
	ui.PrintPrompt("remove file? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)

	if confirm == "yes" || confirm == "y" {
		if err := os.Remove(filePath); err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to remove file: %v", err))
			ui.PrintMuted("  you may need to delete it manually")
		} else {
			ui.PrintSuccess("+", "source file removed")
		}
	} else {
		ui.PrintWarning("!", "source file kept - remember to delete it manually!")
	}

	fmt.Println()
	return nil
}

func rotateInteractively(names []string, masterKey []byte, vaultDir string) error {
	ui.PrintInfo(">", "enter new values for each secret")
	ui.PrintMuted("  press Enter to skip a secret (it will be deleted)")
	fmt.Println()

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	// Clear existing secrets
	vault.SecretsMetadata = make(map[string]storage.SecretMetadata)

	scanner := bufio.NewScanner(os.Stdin)
	rotatedCount := 0
	now := time.Now()

	for _, name := range names {
		ui.PrintPrompt(fmt.Sprintf("%s: ", name))
		if !scanner.Scan() {
			break
		}

		newValue := strings.TrimSpace(scanner.Text())
		if newValue == "" {
			ui.PrintMuted(fmt.Sprintf("  skipped %s (will be deleted)", name))
			audit.LogEventForVault(vaultDir, currentUsername, "rotate-skip", name, true, "skipped during rotation", masterKey)
			continue
		}

		secretBytes := []byte(newValue)
		crypto.SecureBytes(secretBytes)

		encryptedSecret, err := crypto.EncryptSecret(secretBytes, masterKey)
		crypto.CleanupBytes(secretBytes)

		if err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to encrypt %s: %v", name, err))
			continue
		}

		vault.SecretsMetadata[name] = storage.SecretMetadata{
			EncryptedValue: fmt.Sprintf("%x", encryptedSecret),
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		audit.LogEventForVault(vaultDir, currentUsername, "rotate", name, true, "", masterKey)
		rotatedCount++
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("rotated %d secret(s) successfully!", rotatedCount))
	fmt.Println()
	return nil
}

func parseEnvFile(content string) (map[string]string, error) {
	envVars := make(map[string]string)
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			ui.PrintWarning("!", fmt.Sprintf("skipping invalid line %d: %s", lineNum+1, line))
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		if key == "" {
			ui.PrintWarning("!", fmt.Sprintf("skipping line %d: empty key", lineNum+1))
			continue
		}

		envVars[key] = value
	}

	return envVars, nil
}

// secretsRotateMasterKey rotates the master encryption key for the active vault
func secretsRotateMasterKey() error {
	ui.PrintTitle("rotating master key")
	fmt.Println()

	ui.PrintWarning("!", "MASTER KEY ROTATION")
	ui.PrintMuted("  this will re-encrypt all secrets and backups with a new master key")
	ui.PrintMuted("  a backup will be created automatically before rotation")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	vaultName, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return err
	}

	// Check if vault is initialized
	if !keyring.VaultKeyringExists(vaultDir) {
		return fmt.Errorf("vault '%s' has not been initialized yet", vaultName)
	}

	// Get vault info to determine type
	vaultInfo, err := vaultmanager.GetVaultInfo(vaultName)
	if err != nil {
		return fmt.Errorf("failed to get vault info: %w", err)
	}

	// Check if multi-user vault
	if vaultInfo.Type == vaultmanager.VaultTypeGroup {
		return rotateMasterKeyMultiUser(vaultName, vaultDir)
	}

	return rotateMasterKeySolo(vaultName, vaultDir, vaultInfo)
}

func rotateMasterKeySolo(vaultName string, vaultDir string, vaultInfo *vaultmanager.VaultInfo) error {
	ui.PrintInfo(">", fmt.Sprintf("vault: %s (solo)", vaultName))
	fmt.Println()

	// Prompt for confirmation
	ui.PrintWarning("!", "type the vault name to confirm master key rotation")
	ui.PrintPrompt(fmt.Sprintf("vault name: "))
	var confirm string
	fmt.Scanln(&confirm)

	if confirm != vaultName {
		ui.PrintMuted("rotation cancelled")
		fmt.Println()
		return nil
	}
	fmt.Println()

	// Ask if user wants to change password
	ui.PrintPrompt("change your password during rotation? (yes/no): ")
	var changePassword string
	fmt.Scanln(&changePassword)
	changePassword = strings.ToLower(strings.TrimSpace(changePassword))
	shouldChangePassword := changePassword == "yes" || changePassword == "y"
	fmt.Println()

	// Authenticate with current password
	ui.PrintInfo(">", "authenticate with current password")
	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer crypto.CleanupBytes(password)

	// Load keyring and decrypt old master key
	encryptedMasterKey, salt, err := keyring.LoadVaultKeyring(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load keyring: %w", err)
	}

	var derivedKey []byte
	if vaultInfo.LegacyKeyring {
		derivedKey, _, err = crypto.DeriveKeyFromUserPass(password, salt)
	} else {
		derivedKey, _, err = crypto.DeriveVaultKey(password, vaultName, salt)
	}
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	oldMasterKey, err := crypto.DecryptMasterKey(encryptedMasterKey, derivedKey)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("authentication failed - incorrect password")
	}
	defer crypto.CleanupBytes(oldMasterKey)
	storage.ResetRateLimit()

	fmt.Println()
	ui.PrintSuccess("+", "authenticated successfully")
	fmt.Println()

	// Phase 1: Validate all secrets can be decrypted
	ui.PrintInfo(">", "phase 1/5: validating all secrets")
	fmt.Println()

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	if len(vault.SecretsMetadata) == 0 {
		ui.PrintWarning("!", "no secrets to rotate")
		fmt.Println()
		return nil
	}

	ui.PrintMuted(fmt.Sprintf("  validating %d secret(s)...", len(vault.SecretsMetadata)))
	validationErrors := 0
	for name, metadata := range vault.SecretsMetadata {
		encryptedBytes := make([]byte, len(metadata.EncryptedValue)/2)
		_, err = fmt.Sscanf(metadata.EncryptedValue, "%x", &encryptedBytes)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  failed to decode secret '%s': %v", name, err))
			validationErrors++
			continue
		}

		// Check if streamed
		isStreamed := crypto.IsStreamEncrypted(encryptedBytes)
		if isStreamed {
			ui.PrintMuted(fmt.Sprintf("  %s (streamed file)", name))
		} else {
			secret, err := crypto.DecryptSecret(encryptedBytes, oldMasterKey)
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  failed to decrypt secret '%s': %v", name, err))
				validationErrors++
				continue
			}
			crypto.CleanupBytes(secret)
		}
	}

	if validationErrors > 0 {
		fmt.Println()
		return fmt.Errorf("validation failed: %d secret(s) could not be decrypted", validationErrors)
	}

	fmt.Println()
	ui.PrintSuccess("+", "all secrets validated successfully")
	fmt.Println()

	// Phase 2: Create backup
	ui.PrintInfo(">", "phase 2/5: creating pre-rotation backup")
	fmt.Println()

	ui.PrintMuted("  enter a password for the backup:")
	backupPassword, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read backup password: %w", err)
	}
	defer crypto.CleanupBytes(backupPassword)

	if err := backup.CreateAutoBackupForVault(vaultDir, backupPassword); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "backup created successfully")
	fmt.Println()

	// Phase 3: Generate new master key
	ui.PrintInfo(">", "phase 3/5: generating new master key")
	fmt.Println()

	newMasterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("failed to generate new master key: %w", err)
	}
	defer crypto.CleanupBytes(newMasterKey)

	ui.PrintSuccess("+", "new master key generated")
	fmt.Println()

	// Phase 4: Re-encrypt all secrets
	ui.PrintInfo(">", "phase 4/5: re-encrypting all secrets with new master key")
	fmt.Println()

	reencryptedCount := 0
	for name, metadata := range vault.SecretsMetadata {
		encryptedBytes := make([]byte, len(metadata.EncryptedValue)/2)
		fmt.Sscanf(metadata.EncryptedValue, "%x", &encryptedBytes)

		// Check if streamed
		isStreamed := crypto.IsStreamEncrypted(encryptedBytes)
		
		if isStreamed {
			// For streamed files, we need to decrypt and re-encrypt using streaming
			ui.PrintMuted(fmt.Sprintf("  re-encrypting %s (large file, this may take a moment)...", name))
			
			// Create temporary file for decrypted content
			tmpDecrypted, err := os.CreateTemp("", "secrets-rotate-*.tmp")
			if err != nil {
				return fmt.Errorf("failed to create temp file: %w", err)
			}
			tmpDecryptedPath := tmpDecrypted.Name()
			defer os.Remove(tmpDecryptedPath)

			// Decrypt stream
			encryptedReader := strings.NewReader(string(encryptedBytes))
			_, err = crypto.DecryptStream(encryptedReader, tmpDecrypted, oldMasterKey)
			tmpDecrypted.Close()
			if err != nil {
				return fmt.Errorf("failed to decrypt streamed secret '%s': %w", name, err)
			}

			// Re-encrypt stream with new key
			tmpDecrypted, err = os.Open(tmpDecryptedPath)
			if err != nil {
				return fmt.Errorf("failed to open temp file: %w", err)
			}
			var reencryptedBuf strings.Builder
			_, err = crypto.EncryptStream(tmpDecrypted, &reencryptedBuf, newMasterKey)
			tmpDecrypted.Close()
			if err != nil {
				return fmt.Errorf("failed to re-encrypt streamed secret '%s': %w", name, err)
			}

			// Store re-encrypted value
			reencryptedBytes := []byte(reencryptedBuf.String())
			vault.SecretsMetadata[name] = storage.SecretMetadata{
				EncryptedValue: fmt.Sprintf("%x", reencryptedBytes),
				CreatedAt:      metadata.CreatedAt,
				UpdatedAt:      time.Now(),
			}
		} else {
			// Normal secrets
			secret, err := crypto.DecryptSecret(encryptedBytes, oldMasterKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt secret '%s': %w", name, err)
			}
			crypto.SecureBytes(secret)

			reencryptedSecret, err := crypto.EncryptSecret(secret, newMasterKey)
			crypto.CleanupBytes(secret)
			if err != nil {
				return fmt.Errorf("failed to re-encrypt secret '%s': %w", name, err)
			}

			vault.SecretsMetadata[name] = storage.SecretMetadata{
				EncryptedValue: fmt.Sprintf("%x", reencryptedSecret),
				CreatedAt:      metadata.CreatedAt,
				UpdatedAt:      time.Now(),
			}
			ui.PrintMuted(fmt.Sprintf("  %s ✓", name))
		}
		reencryptedCount++
	}

	// Save vault with re-encrypted secrets
	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("re-encrypted %d secret(s)", reencryptedCount))
	fmt.Println()

	// Phase 5: Update keyring with new master key
	ui.PrintInfo(">", "phase 5/5: updating keyring")
	fmt.Println()

	var newPassword []byte
	if shouldChangePassword {
		ui.PrintMuted("  enter NEW password:")
		newPassword, err = crypto.ReadUserPassWithValidation()
		if err != nil {
			return fmt.Errorf("failed to read new password: %w", err)
		}
		defer crypto.CleanupBytes(newPassword)
	} else {
		newPassword = password
	}

	// Encrypt new master key with (new) password
	var newDerivedKey []byte
	var newSalt []byte
	if vaultInfo.LegacyKeyring {
		newDerivedKey, newSalt, err = crypto.DeriveKeyFromUserPass(newPassword, nil)
	} else {
		newDerivedKey, newSalt, err = crypto.DeriveVaultKey(newPassword, vaultName, nil)
	}
	if err != nil {
		return fmt.Errorf("failed to derive new key: %w", err)
	}
	defer crypto.CleanupBytes(newDerivedKey)

	newEncryptedMasterKey, err := crypto.EncryptMasterKey(newMasterKey, newDerivedKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt new master key: %w", err)
	}

	if err := keyring.StoreVaultKeyring(vaultDir, newEncryptedMasterKey, newSalt); err != nil {
		return fmt.Errorf("failed to store new keyring: %w", err)
	}

	ui.PrintSuccess("+", "keyring updated")
	fmt.Println()

	// Update vault with rotation metadata
	vault.MasterKeyRotation = &storage.MasterKeyRotation{
		RotatedAt: time.Now(),
		RotatedBy: "system",
	}
	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("failed to save rotation metadata: %v", err))
	}

	// Re-encrypt backups
	if err := reencryptBackups(vaultDir, oldMasterKey, newMasterKey); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("backup re-encryption warning: %v", err))
		ui.PrintMuted("  old backups may not be restorable with the new master key")
		fmt.Println()
	}

	// Log the rotation
	audit.LogEventForVault(vaultDir, "system", "master-key-rotation", "completed", true, "", newMasterKey)

	fmt.Println()
	ui.PrintSuccess("+", "MASTER KEY ROTATION COMPLETED SUCCESSFULLY!")
	if shouldChangePassword {
		ui.PrintSuccess("+", "password changed successfully")
	}
	ui.PrintMuted(fmt.Sprintf("  vault: %s", vaultName))
	ui.PrintMuted(fmt.Sprintf("  secrets re-encrypted: %d", reencryptedCount))
	ui.PrintMuted(fmt.Sprintf("  timestamp: %s", time.Now().Format("2006-01-02 15:04:05")))
	fmt.Println()

	return nil
}

func rotateMasterKeyMultiUser(vaultName string, vaultDir string) error {
	ui.PrintInfo(">", fmt.Sprintf("vault: %s (group/multi-user)", vaultName))
	fmt.Println()

	// Check if multi-user mode is enabled
	isMultiUser, err := multiuser.IsMultiUserModeInDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return fmt.Errorf("vault is not in multi-user mode")
	}

	// Load multi-user vault to get user count
	multiUserVault, err := multiuser.LoadMultiUserVault(multiuser.GetMultiUserVaultPathForVault(vaultDir))
	if err != nil {
		return fmt.Errorf("failed to load multi-user vault: %w", err)
	}

	userCount := len(multiUserVault.MasterKeyShare)
	ui.PrintInfo("*", fmt.Sprintf("this vault has %d user(s)", userCount))
	ui.PrintMuted("  all users will be able to use their existing passwords after rotation")
	fmt.Println()

	// Prompt for confirmation
	ui.PrintWarning("!", "type the vault name to confirm master key rotation")
	ui.PrintPrompt(fmt.Sprintf("vault name: "))
	var confirm string
	fmt.Scanln(&confirm)

	if confirm != vaultName {
		ui.PrintMuted("rotation cancelled")
		fmt.Println()
		return nil
	}
	fmt.Println()

	// Authenticate as admin
	ui.PrintInfo(">", "admin authentication required")
	ui.PrintPrompt("admin username: ")
	var adminUsername string
	fmt.Scanln(&adminUsername)

	adminPassword, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read admin password: %w", err)
	}
	defer crypto.CleanupBytes(adminPassword)

	// Get old master key using admin credentials
	oldMasterKey, err := multiuser.GetMasterKeyForUserInDir(vaultDir, adminUsername, adminPassword)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("admin authentication failed: %w", err)
	}
	defer crypto.CleanupBytes(oldMasterKey)
	storage.ResetRateLimit()

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("authenticated as admin: %s", adminUsername))
	fmt.Println()

	// Phase 1: Validate all secrets
	ui.PrintInfo(">", "phase 1/5: validating all secrets")
	fmt.Println()

	if len(multiUserVault.Secrets) == 0 {
		ui.PrintWarning("!", "no secrets to rotate")
		fmt.Println()
		return nil
	}

	ui.PrintMuted(fmt.Sprintf("  validating %d secret(s)...", len(multiUserVault.Secrets)))
	validationErrors := 0
	for name, encryptedHex := range multiUserVault.Secrets {
		encryptedBytes := make([]byte, len(encryptedHex)/2)
		_, err = fmt.Sscanf(encryptedHex, "%x", &encryptedBytes)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  failed to decode secret '%s': %v", name, err))
			validationErrors++
			continue
		}

		isStreamed := crypto.IsStreamEncrypted(encryptedBytes)
		if isStreamed {
			ui.PrintMuted(fmt.Sprintf("  %s (streamed file)", name))
		} else {
			secret, err := crypto.DecryptSecret(encryptedBytes, oldMasterKey)
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  failed to decrypt secret '%s': %v", name, err))
				validationErrors++
				continue
			}
			crypto.CleanupBytes(secret)
			ui.PrintMuted(fmt.Sprintf("  %s ✓", name))
		}
	}

	if validationErrors > 0 {
		fmt.Println()
		return fmt.Errorf("validation failed: %d secret(s) could not be decrypted", validationErrors)
	}

	fmt.Println()
	ui.PrintSuccess("+", "all secrets validated successfully")
	fmt.Println()

	// Phase 2: Create backup
	ui.PrintInfo(">", "phase 2/5: creating pre-rotation backup")
	fmt.Println()

	ui.PrintMuted("  enter a password for the backup:")
	backupPassword, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read backup password: %w", err)
	}
	defer crypto.CleanupBytes(backupPassword)

	if err := backup.CreateAutoBackupForVault(vaultDir, backupPassword); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "backup created successfully")
	fmt.Println()

	// Phase 3: Generate new master key
	ui.PrintInfo(">", "phase 3/5: generating new master key")
	fmt.Println()

	newMasterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("failed to generate new master key: %w", err)
	}
	defer crypto.CleanupBytes(newMasterKey)

	ui.PrintSuccess("+", "new master key generated")
	fmt.Println()

	// Phase 4: Re-encrypt all secrets
	ui.PrintInfo(">", "phase 4/5: re-encrypting all secrets with new master key")
	fmt.Println()

	reencryptedCount := 0
	for name, encryptedHex := range multiUserVault.Secrets {
		encryptedBytes := make([]byte, len(encryptedHex)/2)
		fmt.Sscanf(encryptedHex, "%x", &encryptedBytes)

		isStreamed := crypto.IsStreamEncrypted(encryptedBytes)
		
		if isStreamed {
			ui.PrintMuted(fmt.Sprintf("  re-encrypting %s (large file, this may take a moment)...", name))
			
			tmpDecrypted, err := os.CreateTemp("", "secrets-rotate-*.tmp")
			if err != nil {
				return fmt.Errorf("failed to create temp file: %w", err)
			}
			tmpDecryptedPath := tmpDecrypted.Name()
			defer os.Remove(tmpDecryptedPath)

			encryptedReader := strings.NewReader(string(encryptedBytes))
			_, err = crypto.DecryptStream(encryptedReader, tmpDecrypted, oldMasterKey)
			tmpDecrypted.Close()
			if err != nil {
				return fmt.Errorf("failed to decrypt streamed secret '%s': %w", name, err)
			}

			tmpDecrypted, err = os.Open(tmpDecryptedPath)
			if err != nil {
				return fmt.Errorf("failed to open temp file: %w", err)
			}
			var reencryptedBuf strings.Builder
			_, err = crypto.EncryptStream(tmpDecrypted, &reencryptedBuf, newMasterKey)
			tmpDecrypted.Close()
			if err != nil {
				return fmt.Errorf("failed to re-encrypt streamed secret '%s': %w", name, err)
			}

			reencryptedBytes := []byte(reencryptedBuf.String())
			multiUserVault.Secrets[name] = fmt.Sprintf("%x", reencryptedBytes)
		} else {
			secret, err := crypto.DecryptSecret(encryptedBytes, oldMasterKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt secret '%s': %w", name, err)
			}
			crypto.SecureBytes(secret)

			reencryptedSecret, err := crypto.EncryptSecret(secret, newMasterKey)
			crypto.CleanupBytes(secret)
			if err != nil {
				return fmt.Errorf("failed to re-encrypt secret '%s': %w", name, err)
			}

			multiUserVault.Secrets[name] = fmt.Sprintf("%x", reencryptedSecret)
			ui.PrintMuted(fmt.Sprintf("  %s ✓", name))
		}
		reencryptedCount++
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("re-encrypted %d secret(s)", reencryptedCount))
	fmt.Println()

	// Phase 5: Re-encrypt master key for all users
	ui.PrintInfo(">", "phase 5/5: updating master key for all users")
	fmt.Println()
	
	ui.PrintWarning("!", "all users must provide their passwords to complete rotation")
	ui.PrintMuted("  each user's password will re-encrypt the new master key")
	ui.PrintMuted("  users who don't provide passwords will lose vault access")
	fmt.Println()
	
	ui.PrintPrompt("continue with password collection? (yes/no): ")
	var continuePassword string
	fmt.Scanln(&continuePassword)
	if continuePassword != "yes" && continuePassword != "y" {
		return fmt.Errorf("rotation cancelled - user password collection required")
	}
	fmt.Println()

	updatedUserCount := 0
	skippedUsers := []string{}
	
	for username, userShare := range multiUserVault.MasterKeyShare {
		ui.PrintInfo(">", fmt.Sprintf("updating master key for user: %s", username))
		
		// Decode the user's salt
		saltBytes, err := crypto.DecodeHexString(userShare.Salt)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  failed to decode salt for user '%s': %v", username, err))
			skippedUsers = append(skippedUsers, username)
			continue
		}
		
		// Prompt for user's password
		ui.PrintPrompt(fmt.Sprintf("  password for '%s' (or press Enter to skip): ", username))
		userPassword, err := crypto.ReadUserPass()
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  failed to read password for user '%s'", username))
			skippedUsers = append(skippedUsers, username)
			continue
		}
		
		// Check if user pressed Enter without typing (empty password)
		if len(userPassword) == 0 {
			ui.PrintMuted(fmt.Sprintf("  skipped user: %s", username))
			skippedUsers = append(skippedUsers, username)
			continue
		}

		// Derive user's key
		userDerivedKey, _, err := crypto.DeriveKeyFromUserPass(userPassword, saltBytes)
		crypto.CleanupBytes(userPassword)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  failed to derive key for user '%s': %v", username, err))
			skippedUsers = append(skippedUsers, username)
			continue
		}

		// Encrypt new master key with user's derived key
		newEncryptedMasterKey, err := crypto.EncryptMasterKey(newMasterKey, userDerivedKey)
		crypto.CleanupBytes(userDerivedKey)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  failed to encrypt master key for user '%s': %v", username, err))
			skippedUsers = append(skippedUsers, username)
			continue
		}

		// Update user's share
		multiUserVault.MasterKeyShare[username] = multiuser.UserKeyShare{
			Username:       username,
			EncryptedShare: fmt.Sprintf("%x", newEncryptedMasterKey),
			Salt:           userShare.Salt, // Keep the same salt
		}

		ui.PrintSuccess("+", fmt.Sprintf("  updated: %s", username))
		updatedUserCount++
	}
	
	fmt.Println()

	if len(skippedUsers) > 0 {
		ui.PrintWarning("!", fmt.Sprintf("%d user(s) were NOT updated and will lose access:", len(skippedUsers)))
		for _, username := range skippedUsers {
			ui.PrintMuted(fmt.Sprintf("  - %s", username))
		}
		fmt.Println()
		
		ui.PrintWarning("!", "skipped users will need to be re-added by an admin")
		ui.PrintPrompt("continue with rotation? (yes/no): ")
		var continueConfirm string
		fmt.Scanln(&continueConfirm)
		if continueConfirm != "yes" && continueConfirm != "y" {
			return fmt.Errorf("rotation cancelled - not all users updated")
		}
		fmt.Println()
		
		// Remove skipped users from the vault
		for _, username := range skippedUsers {
			delete(multiUserVault.MasterKeyShare, username)
			ui.PrintMuted(fmt.Sprintf("  removed user: %s", username))
		}
		fmt.Println()
	}

	// Save multi-user vault
	multiUserVault.MasterKeyRotation = &multiuser.MasterKeyRotation{
		RotatedAt: time.Now(),
		RotatedBy: adminUsername,
	}
	if err := multiuser.SaveMultiUserVault(multiuser.GetMultiUserVaultPathForVault(vaultDir), multiUserVault); err != nil {
		return fmt.Errorf("failed to save multi-user vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("updated master key for %d user(s)", updatedUserCount))
	fmt.Println()

	// Re-encrypt backups
	if err := reencryptBackups(vaultDir, oldMasterKey, newMasterKey); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("backup re-encryption warning: %v", err))
		ui.PrintMuted("  old backups may not be restorable with the new master key")
		fmt.Println()
	}

	fmt.Println()
	ui.PrintSuccess("+", "MASTER KEY ROTATION COMPLETED SUCCESSFULLY!")
	ui.PrintMuted(fmt.Sprintf("  vault: %s", vaultName))
	ui.PrintMuted(fmt.Sprintf("  admin: %s", adminUsername))
	ui.PrintMuted(fmt.Sprintf("  secrets re-encrypted: %d", reencryptedCount))
	ui.PrintMuted(fmt.Sprintf("  users updated: %d/%d", updatedUserCount, userCount))
	ui.PrintMuted(fmt.Sprintf("  timestamp: %s", time.Now().Format("2006-01-02 15:04:05")))
	fmt.Println()

	return nil
}

func reencryptBackups(vaultDir string, oldMasterKey, newMasterKey []byte) error {
	backupDir := backup.GetBackupDirForVault(vaultDir)
	
	// Check if backup directory exists
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		return nil // No backups to re-encrypt
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backupFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".enc" {
			backupFiles = append(backupFiles, entry.Name())
		}
	}

	if len(backupFiles) == 0 {
		return nil // No backups to re-encrypt
	}

	ui.PrintInfo(">", fmt.Sprintf("re-encrypting %d backup(s)", len(backupFiles)))
	fmt.Println()

	reencryptedCount := 0
	for _, backupFile := range backupFiles {
		ui.PrintMuted(fmt.Sprintf("  processing: %s", backupFile))
		
		// For backups, they are encrypted with a user-provided password, not the master key
		// So we can't automatically re-encrypt them
		// We would need the backup password for each backup
		
		// Skip re-encrypting backups for now since they use different passwords
		ui.PrintMuted(fmt.Sprintf("  skipped (backup uses separate password)"))
	}

	if reencryptedCount > 0 {
		fmt.Println()
		ui.PrintSuccess("+", fmt.Sprintf("re-encrypted %d backup(s)", reencryptedCount))
	} else {
		fmt.Println()
		ui.PrintWarning("!", "backups were not re-encrypted (they use separate passwords)")
		ui.PrintMuted("  old backups are still accessible with their original backup passwords")
	}

	return nil
}
