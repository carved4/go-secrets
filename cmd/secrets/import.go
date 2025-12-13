package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/importer"
	"github.com/carved4/go-secrets/internal/multiuser"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
)

func secretsRestore(args []string) error {
	ui.PrintTitle("restoring secret to file")
	fmt.Println()

	if len(args) < 1 {
		ui.PrintError("x", "usage: secrets restore <name> [--output <path>]")
		return nil
	}

	secretName := args[0]
	var outputPath string

	for i := 1; i < len(args); i++ {
		if args[i] == "--output" && i+1 < len(args) {
			outputPath = args[i+1]
			break
		}
	}

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	ui.PrintSuccess(">", fmt.Sprintf("restoring: %s", secretName))
	fmt.Println()

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	if useGroupVault {
		if err := promptForUsername(); err != nil {
			return err
		}
		canAccess, err := multiuser.UserCanAccessSecret(currentUsername, secretName)
		if err != nil {
			return fmt.Errorf("failed to check access: %w", err)
		}
		if !canAccess {
			return fmt.Errorf("access denied: user '%s' does not have permission to access secret '%s'", currentUsername, secretName)
		}
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	metadata, exists := vault.SecretsMetadata[secretName]
	if !exists {
		return fmt.Errorf("secret '%s' not found", secretName)
	}


	encryptedBytes := make([]byte, len(metadata.EncryptedValue)/2)
	_, err = fmt.Sscanf(metadata.EncryptedValue, "%x", &encryptedBytes)
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}


	isStreamed := crypto.IsStreamEncrypted(encryptedBytes)


	if outputPath == "" {
		ui.PrintPrompt("enter output path (or press Enter for current directory): ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			outputPath = strings.TrimSpace(scanner.Text())
		}


		if outputPath == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current directory: %w", err)
			}

			filename := strings.ToLower(strings.ReplaceAll(secretName, "_", "-"))
			outputPath = filepath.Join(cwd, filename)
			ui.PrintMuted(fmt.Sprintf("  using default path: %s", outputPath))
			fmt.Println()
		}
	}


	if _, err := os.Stat(outputPath); err == nil {
		ui.PrintWarning("!", fmt.Sprintf("file already exists: %s", outputPath))
		ui.PrintPrompt("overwrite? (yes/no): ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "yes" && confirm != "y" {
			ui.PrintMuted("restore cancelled")
			fmt.Println()
			return nil
		}
	}


	var bytesWritten int64
	
	if isStreamed {
		ui.PrintInfo(">", "decrypting streamed file...")
		fmt.Println()
		

		outFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			audit.LogEventForVault(vaultDir, currentUsername, "restore", secretName, false, err.Error(), masterKey)
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer outFile.Close()


		encryptedReader := strings.NewReader(string(encryptedBytes))
		

		bytesWritten, err = crypto.DecryptStream(encryptedReader, outFile, masterKey)
		if err != nil {
			audit.LogEventForVault(vaultDir, currentUsername, "restore", secretName, false, err.Error(), masterKey)
			return fmt.Errorf("failed to decrypt streamed file: %w", err)
		}
	} else {

		secret, err := crypto.DecryptSecret(encryptedBytes, masterKey)
		if err != nil {
			audit.LogEventForVault(vaultDir, currentUsername, "restore", secretName, false, err.Error(), masterKey)
			return fmt.Errorf("failed to decrypt secret: %w", err)
		}
		crypto.SecureBytes(secret)
		defer crypto.CleanupBytes(secret)


		if err := os.WriteFile(outputPath, secret, 0600); err != nil {
			audit.LogEventForVault(vaultDir, currentUsername, "restore", secretName, false, err.Error(), masterKey)
			return fmt.Errorf("failed to write file: %w", err)
		}
		bytesWritten = int64(len(secret))
	}

	audit.LogEventForVault(vaultDir, currentUsername, "restore", secretName, true, "", masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' restored to: %s", secretName, outputPath))
	if bytesWritten < 1024 {
		ui.PrintMuted(fmt.Sprintf("  size: %d bytes", bytesWritten))
	} else if bytesWritten < 1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  size: %.2f KB", float64(bytesWritten)/1024))
	} else if bytesWritten < 1024*1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  size: %.2f MB", float64(bytesWritten)/(1024*1024)))
	} else {
		ui.PrintMuted(fmt.Sprintf("  size: %.2f GB", float64(bytesWritten)/(1024*1024*1024)))
	}
	fmt.Println()
	ui.PrintWarning("!", "remember to securely delete this file when done!")
	ui.PrintTip("tip: use 'secrets wipe <path>' to securely delete the file")
	fmt.Println()
	return nil
}

func secretsWipeFile(filePath string) error {
	ui.PrintTitle("securely wiping file")
	fmt.Println()

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", filePath)
		}
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", filePath)
	}

	fileSize := fileInfo.Size()
	ui.PrintWarning("!", fmt.Sprintf("this will securely delete: %s", filePath))
	if fileSize < 1024 {
		ui.PrintMuted(fmt.Sprintf("  size: %d bytes", fileSize))
	} else if fileSize < 1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  size: %.2f KB", float64(fileSize)/1024))
	} else {
		ui.PrintMuted(fmt.Sprintf("  size: %.2f MB", float64(fileSize)/(1024*1024)))
	}
	fmt.Println()

	ui.PrintPrompt("confirm deletion? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)

	if confirm != "yes" && confirm != "y" {
		ui.PrintMuted("deletion cancelled")
		fmt.Println()
		return nil
	}

	file, err := os.OpenFile(filePath, os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file for wiping: %w", err)
	}
	defer file.Close()

	ui.PrintInfo(">", "overwriting file with random data...")
	fmt.Println()

	bufferSize := 1024 * 1024
	if fileSize < int64(bufferSize) {
		bufferSize = int(fileSize)
	}
	buffer := make([]byte, bufferSize)

	for pass := 1; pass <= 3; pass++ {
		ui.PrintMuted(fmt.Sprintf("  pass %d/3...", pass))
		
		if _, err := file.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek file: %w", err)
		}

		remaining := fileSize
		for remaining > 0 {
			writeSize := int64(bufferSize)
			if remaining < writeSize {
				writeSize = remaining
			}

			if _, err := io.ReadFull(rand.Reader, buffer[:writeSize]); err != nil {
				return fmt.Errorf("failed to generate random data: %w", err)
			}

			if _, err := file.Write(buffer[:writeSize]); err != nil {
				return fmt.Errorf("failed to overwrite file: %w", err)
			}

			remaining -= writeSize
		}

		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync file: %w", err)
		}
	}

	file.Close()

	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to remove file: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "file securely wiped and deleted!")
	ui.PrintMuted(fmt.Sprintf("  removed: %s", filePath))
	fmt.Println()
	return nil
}

func secretsImportPasswords(csvFile string) error {
	ui.PrintTitle("importing passwords from CSV")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	ui.PrintInfo(">", fmt.Sprintf("parsing CSV file: %s", csvFile))
	fmt.Println()

	entries, err := importer.ParseChromePasswordCSV(csvFile)
	if err != nil {
		return fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(entries) == 0 {
		ui.PrintWarning("!", "no password entries found in CSV file")
		fmt.Println()
		return nil
	}

	ui.PrintSuccess("+", fmt.Sprintf("found %d password(s) in CSV", len(entries)))
	

	siteCounts := importer.DetectDuplicateSites(entries)
	duplicateCount := 0
	for _, count := range siteCounts {
		if count > 1 {
			duplicateCount++
		}
	}
	
	if duplicateCount > 0 {
		ui.PrintWarning("!", fmt.Sprintf("detected %d site(s) with multiple credentials - will append username to secret name", duplicateCount))
	}
	fmt.Println()


	ui.PrintInfo("*", "preview of entries to import:")
	fmt.Println()
	previewCount := len(entries)
	if previewCount > 5 {
		previewCount = 5
	}
	for i := 0; i < previewCount; i++ {
		entry := entries[i]
		baseName := importer.FormatSecretName(entry, 0, false)
		includeUsername := siteCounts[baseName] > 1
		secretName := importer.FormatSecretName(entry, 0, includeUsername)
		ui.PrintMuted(fmt.Sprintf("  %d. %s -> %s (%s)", i+1, entry.Name, secretName, entry.Username))
	}
	if len(entries) > 5 {
		ui.PrintMuted(fmt.Sprintf("  ... and %d more", len(entries)-5))
	}
	fmt.Println()


	ui.PrintWarning("!", "this will add all passwords as individual secrets to your vault")
	ui.PrintPrompt("continue? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "yes" && confirm != "y" {
		ui.PrintMuted("import cancelled")
		fmt.Println()
		return nil
	}

	fmt.Println()


	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}


	siteCounts = importer.DetectDuplicateSites(entries)

	nameCount := make(map[string]int)


	ui.PrintInfo(">", "importing passwords...")
	fmt.Println()

	successCount := 0
	failCount := 0

	for i, entry := range entries {
		baseName := importer.FormatSecretName(entry, 0, false)
		includeUsername := siteCounts[baseName] > 1
		
		secretName := importer.FormatSecretName(entry, 0, includeUsername)
		
		if _, exists := vault.SecretsMetadata[secretName]; exists {
			count := nameCount[secretName]
			secretName = importer.FormatSecretName(entry, count, includeUsername)
			nameCount[secretName] = count + 1
		} else if nameCount[secretName] > 0 {
			secretName = importer.FormatSecretName(entry, nameCount[secretName], includeUsername)
			nameCount[secretName]++
		} else {
			nameCount[secretName] = 1
		}

		if useGroupVault {
			if err := promptForUsername(); err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d. %s - access check failed: %v", i+1, secretName, err))
				failCount++
				continue
			}
			canAccess, err := multiuser.UserCanAccessSecret(currentUsername, secretName)
			if err != nil || !canAccess {
				ui.PrintError("x", fmt.Sprintf("  %d. %s - access denied", i+1, secretName))
				failCount++
				continue
			}
		}


		secretValue := importer.FormatSecretValue(entry)
		secretBytes := []byte(secretValue)
		crypto.SecureBytes(secretBytes)


		encryptedSecret, err := crypto.EncryptSecret(secretBytes, masterKey)
		crypto.CleanupBytes(secretBytes)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d. %s - encryption failed: %v", i+1, secretName, err))
			failCount++
			continue
		}


		now := time.Now()
		existing, exists := vault.SecretsMetadata[secretName]
		if exists {
			vault.SecretsMetadata[secretName] = storage.SecretMetadata{
				EncryptedValue: fmt.Sprintf("%x", encryptedSecret),
				CreatedAt:      existing.CreatedAt,
				UpdatedAt:      now,
			}
			ui.PrintMuted(fmt.Sprintf("  %d. %s - updated (already exists)", i+1, secretName))
		} else {
			vault.SecretsMetadata[secretName] = storage.SecretMetadata{
				EncryptedValue: fmt.Sprintf("%x", encryptedSecret),
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			ui.PrintSuccess("+", fmt.Sprintf("  %d. %s - imported", i+1, secretName))
		}

		successCount++
	}


	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("import complete! %d passwords imported successfully", successCount))
	if failCount > 0 {
		ui.PrintWarning("!", fmt.Sprintf("%d passwords failed to import", failCount))
	}
	fmt.Println()

	ui.PrintTip("tip: use 'secrets list' to view all imported passwords")
	ui.PrintTip("     use 'secrets get <name> --clip' to retrieve a password")
	fmt.Println()

	return nil
}

