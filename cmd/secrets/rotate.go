package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/backup"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/keyring"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
)

func secretsRotate(args []string) error {
	ui.PrintTitle("rotating secrets")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer crypto.CleanupBytes(password)

	encryptedMasterKey, salt, err := keyring.LoadEncryptedMasterKey()
	if err != nil {
		return fmt.Errorf("failed to load encrypted master key: %w", err)
	}

	derivedKey, _, err := crypto.DeriveKeyFromUserPass([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	masterKey, err := crypto.DecryptMasterKey(encryptedMasterKey, derivedKey)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("failed to decrypt master key - incorrect password")
	}
	defer crypto.CleanupBytes(masterKey)

	storage.ResetRateLimit()

	if len(args) > 0 {
		secretName := args[0]
		return rotateSpecificSecret(secretName, masterKey, password)
	}

	return rotateAllSecrets(masterKey, password)
}

func rotateSpecificSecret(secretName string, masterKey []byte, password []byte) error {
	ui.PrintWarning("!", fmt.Sprintf("rotating secret: %s", secretName))
	fmt.Println()

	_, err := storage.GetSecretWithMode(secretName, useGroupVault)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
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

	if err := storage.AddSecretWithMode(secretName, encryptedSecret, useGroupVault); err != nil {
		audit.LogEvent(currentUsername, "rotate", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to update secret: %w", err)
	}

	if err := backup.CreateAutoBackup(password); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("warning: auto-backup failed: %v", err))
	}

	audit.LogEvent(currentUsername, "rotate", secretName, true, "", masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' rotated successfully!", secretName))
	fmt.Println()
	return nil
}

func rotateAllSecrets(masterKey []byte, password []byte) error {
	names, err := storage.ListSecretsWithMode(useGroupVault)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
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
		return rotateFromEnvFile(names, masterKey, password)
	}

	return rotateInteractively(names, masterKey, password)
}

func rotateFromEnvFile(existingNames []string, masterKey []byte, password []byte) error {
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

	if err := storage.ClearAllSecrets(useGroupVault); err != nil {
		return fmt.Errorf("failed to clear secrets: %w", err)
	}

	rotatedCount := 0
	for name, value := range envVars {
		secretBytes := []byte(value)
		crypto.SecureBytes(secretBytes)

		encryptedSecret, err := crypto.EncryptSecret(secretBytes, masterKey)
		crypto.CleanupBytes(secretBytes)

		if err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to encrypt %s: %v", name, err))
			continue
		}

		if err := storage.AddSecretWithMode(name, encryptedSecret, useGroupVault); err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to store %s: %v", name, err))
			continue
		}

		audit.LogEvent(currentUsername, "rotate", name, true, "", masterKey)
		ui.PrintSuccess("+", fmt.Sprintf("rotated: %s", name))
		rotatedCount++
	}

	if err := backup.CreateAutoBackup(password); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("warning: auto-backup failed: %v", err))
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

func rotateInteractively(names []string, masterKey []byte, password []byte) error {
	ui.PrintInfo(">", "enter new values for each secret")
	ui.PrintMuted("  press Enter to skip a secret (it will be deleted)")
	fmt.Println()
	if err := storage.ClearAllSecrets(useGroupVault); err != nil {
		return fmt.Errorf("failed to clear secrets: %w", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	rotatedCount := 0

	for _, name := range names {
		ui.PrintPrompt(fmt.Sprintf("%s: ", name))
		if !scanner.Scan() {
			break
		}

		newValue := strings.TrimSpace(scanner.Text())
		if newValue == "" {
			ui.PrintMuted(fmt.Sprintf("  skipped %s (will be deleted)", name))
			audit.LogEvent(currentUsername, "rotate-skip", name, true, "skipped during rotation", masterKey)
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

		if err := storage.AddSecretWithMode(name, encryptedSecret, useGroupVault); err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to store %s: %v", name, err))
			continue
		}

		audit.LogEvent(currentUsername, "rotate", name, true, "", masterKey)
		rotatedCount++
	}

	if err := backup.CreateAutoBackup(password); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("warning: auto-backup failed: %v", err))
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
