package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
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
