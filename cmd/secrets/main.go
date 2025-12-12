package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/keyring"
	"github.com/carved4/go-secrets/internal/privileges"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
)

func main() {
	if len(os.Args) < 2 {
		runInteractiveMode()
		return
	}

	err := executeCommand(os.Args[1:])
	if err != nil {
		fmt.Println()
		ui.PrintError("x", fmt.Sprintf("error: %v", err))
		os.Exit(1)
	}
}

func runInteractiveMode() {
	ui.PrintTitle("secrets manager")
	ui.PrintMuted("interactive mode - type 'help' for commands, 'exit' to quit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		ui.PrintPrompt("secrets> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		if input == "exit" || input == "quit" {
			ui.PrintMuted("goodbye!")
			fmt.Println()
			break
		}

		if input == "help" {
			printUsage()
			continue
		}

		args := parseCommand(input)
		if len(args) == 0 {
			continue
		}

		err := executeCommand(args)
		if err != nil {
			fmt.Println()
			ui.PrintError("x", fmt.Sprintf("error: %v", err))
		}
		fmt.Println()
	}
}

func parseCommand(input string) []string {
	var args []string
	var current strings.Builder
	inQuotes := false

	for _, char := range input {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ' ':
			if inQuotes {
				current.WriteRune(char)
			} else if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(char)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

func executeCommand(args []string) error {
	command := args[0]

	switch command {
	case "init":
		return secretsInit()
	case "add":
		return secretsAdd()
	case "get":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets get <name> [--clip]")
			return nil
		}
		useClipboard := len(args) > 2 && args[2] == "--clip"
		return secretsGet(args[1], useClipboard)
	case "list":
		return secretsList()
	case "delete":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets delete <name>")
			return nil
		}
		return secretsDelete(args[1])
	case "env":
		if len(args) < 3 || args[1] != "run" || args[2] != "--" {
			ui.PrintError("x", "usage: secrets env run -- <command> [args...]")
			return nil
		}
		return secretsEnvRun(args[3:])
	default:
		ui.PrintError("x", fmt.Sprintf("unknown command: %s", command))
		fmt.Println()
		printUsage()
		return nil
	}
}

func printUsage() {
	ui.PrintTitle("secrets manager")
	ui.PrintMuted("usage: secrets <command> [arguments]")
	fmt.Println()
	ui.PrintInfo("*", "available commands:")
	fmt.Println()
	ui.PrintListItem("  >", "init           initialize a new secrets vault")
	ui.PrintListItem("  >", "add            add a new secret from clipboard")
	ui.PrintListItem("  >", "get <name> [--clip]  retrieve a secret")
	ui.PrintListItem("  >", "list           list all secret names")
	ui.PrintListItem("  >", "delete <name>  delete a secret")
	ui.PrintListItem("  >", "env run -- <cmd>  run command with secrets as env vars")
	fmt.Println()
}

func secretsInit() error {
	if err := privileges.RequireElevated(); err != nil {
		return err
	}

	ui.PrintTitle("initializing vault")
	fmt.Println()
	ui.PrintMuted("setting up your secure secrets vault...")
	fmt.Println()

	vaultPath := storage.GetVaultPath()
	if _, err := os.Stat(vaultPath); err == nil {
		return fmt.Errorf("vault already initialized at %s", vaultPath)
	}

	userPass, err := crypto.ReadUserPassWithValidation()
	if err != nil {
		return fmt.Errorf("could not read user passphrase: %w", err)
	}

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("could not generate master key: %w", err)
	}

	derivedKey, salt, err := crypto.DeriveKeyFromUserPass([]byte(userPass), nil)
	if err != nil {
		return fmt.Errorf("could not derive key from user pass: %w", err)
	}

	encryptedMasterKey, err := crypto.EncryptMasterKey(masterKey, derivedKey)
	if err != nil {
		return fmt.Errorf("could not encrypt master key: %w", err)
	}

	if err := keyring.StoreEncryptedMasterKey(encryptedMasterKey, salt); err != nil {
		return fmt.Errorf("could not store in keyring: %w", err)
	}

	if err := storage.InitVault(); err != nil {
		return fmt.Errorf("could not initialize vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "vault initialized successfully!")
	ui.PrintMuted(fmt.Sprintf("  vault location: %s", vaultPath))
	fmt.Println()
	return nil
}

func secretsAdd() error {
	ui.PrintTitle("adding secret")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	secretValue, err := clipboard.ReadAll()
	if err != nil || secretValue == "" {
		ui.PrintError("x", "clipboard is empty")
		ui.PrintMuted("  copy your secret to clipboard first, then run 'secrets add'")
		fmt.Println()
		return fmt.Errorf("no secret in clipboard")
	}

	ui.PrintSuccess("+", "secret loaded from clipboard")
	fmt.Println()

	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password")
	}
	encryptedMasterKey, salt, err := keyring.LoadEncryptedMasterKey()
	if err != nil {
		return fmt.Errorf("failed to load encrypted master key from vault")
	}
	derivedKey, _, err := crypto.DeriveKeyFromUserPass([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key from user secret")
	}
	defer crypto.CleanupBytes(derivedKey)

	masterKey, err := crypto.DecryptMasterKey(encryptedMasterKey, derivedKey)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("failed to decrypt master key - incorrect password")
	}
	crypto.SecureBytes(masterKey)
	defer crypto.CleanupBytes(masterKey)

	storage.ResetRateLimit()

	secretBytes := []byte(secretValue)
	crypto.SecureBytes(secretBytes)
	defer crypto.CleanupBytes(secretBytes)

	encryptedSecret, err := crypto.EncryptSecret(secretBytes, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret")
	}
	secretName, err := crypto.ReadSecretName()
	if err != nil {
		return fmt.Errorf("failed to read secret name")
	}
	if err := storage.AddSecret(secretName, encryptedSecret); err != nil {
		return fmt.Errorf("failed to store secret in vault")
	}

	clipboard.WriteAll("")

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' added successfully!", secretName))
	ui.PrintSuccess("+", "clipboard cleared for security")
	fmt.Println()
	ui.PrintTip("tip: name secrets like env vars (e.g., DATABASE_URL, API_KEY)")
	ui.PrintTip("     then use: secrets env run -- <your-command>")
	fmt.Println()
	return nil
}

func secretsGet(secretName string, useClipboard bool) error {
	ui.PrintTitle("retrieving secret")
	fmt.Println()
	ui.PrintInfo(">", fmt.Sprintf("fetching: %s", secretName))
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Load and decrypt master key
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
	crypto.SecureBytes(masterKey)
	defer crypto.CleanupBytes(masterKey)

	storage.ResetRateLimit()

	// Get encrypted secret from vault
	encryptedSecret, err := storage.GetSecret(secretName)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// Decrypt the secret
	secret, err := crypto.DecryptSecret(encryptedSecret, masterKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt secret: %w", err)
	}
	crypto.SecureBytes(secret)
	defer crypto.CleanupBytes(secret)

	fmt.Println()

	if useClipboard {
		secretStr := string(secret)
		if err := clipboard.WriteAll(secretStr); err != nil {
			return fmt.Errorf("failed to copy to clipboard: %w", err)
		}
		ui.PrintSuccess("+", "secret copied to clipboard")
		ui.PrintMuted("  clipboard will be cleared in 30 seconds...")
		fmt.Println()

		go func() {
			time.Sleep(30 * time.Second)
			current, err := clipboard.ReadAll()
			if err == nil && current == secretStr {
				clipboard.WriteAll("")
			}
		}()
	} else {
		ui.PrintSuccess("+", "secret displayed below")
		ui.PrintMuted("  use --clip flag to copy to clipboard instead")
		fmt.Println()
		ui.PrintDivider()
		ui.PrintHighlight(strings.TrimRight(string(secret), "\n\r"))
		fmt.Println()
		ui.PrintDivider()
		fmt.Println()
	}

	return nil
}

func secretsList() error {
	ui.PrintTitle("secrets list")
	fmt.Println()

	names, err := storage.ListSecrets()
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if len(names) == 0 {
		ui.PrintMuted("no secrets stored yet")
		fmt.Println()
		return nil
	}

	ui.PrintInfo("*", fmt.Sprintf("found %d secret(s):", len(names)))
	fmt.Println()
	for _, name := range names {
		ui.PrintListItem("  -", name)
	}
	fmt.Println()
	return nil
}

func secretsDelete(secretName string) error {
	ui.PrintTitle("deleting secret")
	fmt.Println()
	ui.PrintWarning("!", fmt.Sprintf("deleting: %s", secretName))
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

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
	crypto.CleanupBytes(masterKey)

	storage.ResetRateLimit()

	if err := storage.DeleteSecret(secretName); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' deleted successfully", secretName))
	fmt.Println()
	return nil
}

func secretsEnvRun(cmdArgs []string) error {
	ui.PrintTitle("running with secrets")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

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
	crypto.SecureBytes(masterKey)
	defer crypto.CleanupBytes(masterKey)

	storage.ResetRateLimit()

	secrets, err := loadAllSecrets(masterKey)
	if err != nil {
		return fmt.Errorf("failed to load secrets: %w", err)
	}

	ui.PrintSuccess("+", fmt.Sprintf("loaded %d secret(s) into environment", len(secrets)))
	for _, env := range secrets {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			preview := parts[1]
			if len(preview) > 30 {
				preview = preview[:30] + "..."
			}
			ui.PrintMuted(fmt.Sprintf("  %s=%s", parts[0], preview))
		}
	}
	ui.PrintMuted(fmt.Sprintf("  running: %s", strings.Join(cmdArgs, " ")))
	fmt.Println()

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), secrets...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

func loadAllSecrets(masterKey []byte) ([]string, error) {
	names, err := storage.ListSecrets()
	if err != nil {
		return nil, err
	}

	var envVars []string
	for _, name := range names {
		encryptedSecret, err := storage.GetSecret(name)
		if err != nil {
			return nil, fmt.Errorf("failed to get secret %s: %w", name, err)
		}

		secret, err := crypto.DecryptSecret(encryptedSecret, masterKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", name, err)
		}
		crypto.SecureBytes(secret)
		envVars = append(envVars, fmt.Sprintf("%s=%s", name, strings.TrimSpace(string(secret))))
		crypto.CleanupBytes(secret)
	}

	return envVars, nil
}
