package main 

import (
	"fmt"
	"os"
	
	"github.com/carved4/go-secrets/internal/backup"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
	"github.com/carved4/go-secrets/internal/vaultmanager"
)
func secretsExport(outputFile string) error {
	ui.PrintTitle("exporting secrets")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	ui.PrintInfo(">", "creating encrypted backup...")
	fmt.Println()

	ui.PrintMuted("  enter a password to encrypt the export file:")
	exportPassword, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read export password: %w", err)
	}
	defer crypto.CleanupBytes(exportPassword)

	encryptedBlob, err := backup.ExportSecretsFromVault(vaultDir, exportPassword)
	if err != nil {
		return fmt.Errorf("failed to export secrets: %w", err)
	}

	if err := os.WriteFile(outputFile, encryptedBlob, 0600); err != nil {
		return fmt.Errorf("failed to write export file: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("secrets exported to: %s", outputFile))
	ui.PrintMuted("  this file is encrypted with your password")
	ui.PrintMuted("  keep it safe - it contains all your secrets!")
	fmt.Println()
	return nil
}

func secretsImport(inputFile string) error {
	ui.PrintTitle("importing secrets")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	encryptedBlob, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read import file: %w", err)
	}

	// First get the vault directory
	activeVault, err := vaultmanager.GetActiveVault()
	if err != nil {
		return err
	}
	vaultDir := vaultmanager.GetVaultDir(activeVault)

	ui.PrintMuted("  enter the password used to encrypt the backup:")
	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer crypto.CleanupBytes(password)

	ui.PrintInfo(">", "decrypting backup...")
	fmt.Println()

	blob, err := backup.ImportSecrets(encryptedBlob, password)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("failed to import secrets: %w", err)
	}

	storage.ResetRateLimit()

	ui.PrintInfo(">", fmt.Sprintf("found %d secret(s) in backup", len(blob.SecretsMetadata)))
	ui.PrintMuted(fmt.Sprintf("  exported at: %s", blob.ExportedAt.Format("2006-01-02 15:04:05")))
	fmt.Println()

	ui.PrintWarning("!", "this will merge secrets into your current vault")
	ui.PrintPrompt("continue? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)
	if confirm != "yes" && confirm != "y" {
		ui.PrintMuted("import cancelled")
		fmt.Println()
		return nil
	}

	if err := backup.RestoreFromBlobToVault(blob, vaultDir); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "secrets imported successfully!")
	fmt.Println()
	return nil
}

func secretsBackup() error {
	ui.PrintTitle("creating backup")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	ui.PrintInfo(">", "creating encrypted backup...")
	fmt.Println()

	ui.PrintMuted("  enter a password to encrypt the backup:")
	backupPassword, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read backup password: %w", err)
	}
	defer crypto.CleanupBytes(backupPassword)

	if err := backup.CreateAutoBackupForVault(vaultDir, backupPassword); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	backups, err := backup.ListBackups()
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "backup created successfully!")
	ui.PrintMuted(fmt.Sprintf("  backup location: %s", backup.GetBackupDir()))
	ui.PrintMuted(fmt.Sprintf("  total backups: %d (keeping last 10)", len(backups)))
	fmt.Println()
	return nil
}
