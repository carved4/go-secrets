package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/backup"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/keyring"
	"github.com/carved4/go-secrets/internal/multiuser"
	"github.com/carved4/go-secrets/internal/privileges"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
)

var useGroupVault bool

func main() {
	if len(os.Args) < 2 {
		runInteractiveMode()
		return
	}

	args, groupFlag := parseGlobalFlags(os.Args[1:])
	useGroupVault = groupFlag

	err := executeCommand(args)
	if err != nil {
		fmt.Println()
		ui.PrintError("x", fmt.Sprintf("error: %v", err))
		os.Exit(1)
	}
}

func parseGlobalFlags(args []string) ([]string, bool) {
	var cleanArgs []string
	useGroup := false

	for _, arg := range args {
		if arg == "--group" {
			useGroup = true
		} else {
			cleanArgs = append(cleanArgs, arg)
		}
	}

	return cleanArgs, useGroup
}

func runInteractiveMode() {
	ui.PrintTitle("secrets manager")
	ui.PrintMuted("interactive mode - type 'help' for commands, 'exit' to quit")
	ui.PrintMuted("type 'mode' to toggle between solo/group vault")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		prompt := "secrets> "
		if useGroupVault {
			prompt = "secrets[group]> "
		}
		ui.PrintPrompt(prompt)
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

		if input == "mode" || input == "toggle" {
			useGroupVault = !useGroupVault
			if useGroupVault {
				ui.PrintSuccess("+", "switched to GROUP vault mode")
			} else {
				ui.PrintSuccess("+", "switched to SOLO vault mode")
			}
			fmt.Println()
			continue
		}

		args := parseCommand(input)
		if len(args) > 0 {
			// Store current mode state
			previousMode := useGroupVault
			cleanArgs, groupFlag := parseGlobalFlags(args)
			// Only override if --group flag is explicitly present
			// Otherwise preserve the toggled state from 'mode' command
			if groupFlag {
				useGroupVault = true
			} else {
				// Restore previous mode if no flag was specified
				useGroupVault = previousMode
			}
			args = cleanArgs
		}
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
		return secretsInit(useGroupVault)
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
	case "export":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets export <output-file>")
			return nil
		}
		return secretsExport(args[1])
	case "import":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets import <input-file>")
			return nil
		}
		return secretsImport(args[1])
	case "backup":
		return secretsBackup()
	case "user":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets user <add|list>")
			return nil
		}
		return handleUserCommand(args[1:])
	case "group":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets group <create|list|add-user>")
			return nil
		}
		return handleGroupCommand(args[1:])
	case "history":
		return secretsHistory()
	default:
		ui.PrintError("x", fmt.Sprintf("unknown command: %s", command))
		fmt.Println()
		printUsage()
		return nil
	}
}

func printUsage() {
	ui.PrintTitle("secrets manager")
	ui.PrintMuted("usage: secrets [--group] <command> [arguments]")
	fmt.Println()
	ui.PrintInfo("*", "global flags:")
	fmt.Println()
	ui.PrintListItem("  >", "--group        use group vault instead of solo vault")
	fmt.Println()
	ui.PrintInfo("*", "interactive mode commands:")
	fmt.Println()
	ui.PrintListItem("  >", "mode / toggle  switch between solo and group vault")
	fmt.Println()
	ui.PrintInfo("*", "available commands:")
	fmt.Println()
	ui.PrintListItem("  >", "init           initialize a new secrets vault")
	ui.PrintListItem("  >", "add            add a new secret from clipboard")
	ui.PrintListItem("  >", "get <name> [--clip]  retrieve a secret")
	ui.PrintListItem("  >", "list           list all secret names")
	ui.PrintListItem("  >", "delete <name>  delete a secret")
	ui.PrintListItem("  >", "env run -- <cmd>  run command with secrets as env vars")
	ui.PrintListItem("  >", "export <file>  export encrypted backup to file")
	ui.PrintListItem("  >", "import <file>  import secrets from encrypted backup")
	ui.PrintListItem("  >", "backup         create automatic backup")
	ui.PrintListItem("  >", "history        view audit log history")
	fmt.Println()
	ui.PrintInfo("*", "multi-user commands (use with --group):")
	fmt.Println()
	ui.PrintListItem("  >", "user add       add a new user to vault")
	ui.PrintListItem("  >", "user list      list all users")
	ui.PrintListItem("  >", "group create   create a new group")
	ui.PrintListItem("  >", "group list     list all groups")
	fmt.Println()
	ui.PrintInfo("*", "examples:")
	fmt.Println()
	ui.PrintMuted("  secrets init                    # create solo vault")
	ui.PrintMuted("  secrets --group init            # create group vault")
	ui.PrintMuted("  secrets add                     # add to solo vault")
	ui.PrintMuted("  secrets --group add             # add to group vault")
	ui.PrintMuted("  secrets --group user add        # add user to group vault")
	fmt.Println()
}

func secretsInit(useGroups bool) error {
	if err := privileges.RequireElevated(); err != nil {
		return err
	}

	ui.PrintTitle("initializing vault")
	fmt.Println()

	if useGroups {
		ui.PrintMuted("setting up multi-user vault with groups...")
	} else {
		ui.PrintMuted("setting up your secure secrets vault...")
	}
	fmt.Println()

	vaultPath := storage.GetVaultPathForMode(useGroups)
	if _, err := os.Stat(vaultPath); err == nil {
		if useGroups {
			return fmt.Errorf("group vault already initialized at %s", vaultPath)
		}
		return fmt.Errorf("solo vault already initialized at %s", vaultPath)
	}

	if useGroups {
		return secretsInitMultiUser()
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
	if err := storage.AddSecretWithMode(secretName, encryptedSecret, useGroupVault); err != nil {
		audit.LogEvent("default", "add", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to store secret in vault")
	}

	clipboard.WriteAll("")

	if err := backup.CreateAutoBackup(password); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("warning: auto-backup failed: %v", err))
	}

	audit.LogEvent("default", "add", secretName, true, "", masterKey)

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
	ui.PrintSuccess(">", fmt.Sprintf("fetching: %s", secretName))
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
	encryptedSecret, err := storage.GetSecretWithMode(secretName, useGroupVault)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// Decrypt the secret
	secret, err := crypto.DecryptSecret(encryptedSecret, masterKey)
	if err != nil {
		audit.LogEvent("default", "get", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to decrypt secret: %w", err)
	}
	crypto.SecureBytes(secret)
	defer crypto.CleanupBytes(secret)

	audit.LogEvent("default", "get", secretName, true, "", masterKey)

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
		ui.PrintMuted("  use --clip flag to copy to clipboard instead")
		fmt.Println()
		ui.PrintDivider()
		fmt.Println(ui.SuccessStyle.Render(strings.TrimRight(string(secret), "\n\r")))
		fmt.Println()
		ui.PrintDivider()
		fmt.Println()
	}

	return nil
}

func secretsList() error {
	ui.PrintTitle("secrets list")
	fmt.Println()

	names, err := storage.ListSecretsWithMode(useGroupVault)
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
		ui.PrintSuccess("  +", name)
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

	if err := storage.DeleteSecretWithMode(secretName, useGroupVault); err != nil {
		audit.LogEvent("default", "delete", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if err := backup.CreateAutoBackup(password); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("warning: auto-backup failed: %v", err))
	}

	audit.LogEvent("default", "delete", secretName, true, "", masterKey)

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
	names, err := storage.ListSecretsWithMode(useGroupVault)
	if err != nil {
		return nil, err
	}

	var envVars []string
	for _, name := range names {
		encryptedSecret, err := storage.GetSecretWithMode(name, useGroupVault)
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

func secretsExport(outputFile string) error {
	ui.PrintTitle("exporting secrets")
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

	_, err = crypto.DecryptMasterKey(encryptedMasterKey, derivedKey)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("failed to decrypt master key - incorrect password")
	}

	storage.ResetRateLimit()

	ui.PrintInfo(">", "creating encrypted backup...")
	fmt.Println()

	encryptedBlob, err := backup.ExportSecrets(password)
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

	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	ui.PrintInfo(">", "decrypting backup...")
	fmt.Println()

	blob, err := backup.ImportSecrets(encryptedBlob, password)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("failed to import secrets: %w", err)
	}

	storage.ResetRateLimit()

	ui.PrintInfo(">", fmt.Sprintf("found %d secret(s) in backup", len(blob.Secrets)))
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

	if err := backup.RestoreFromBlob(blob); err != nil {
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

	_, err = crypto.DecryptMasterKey(encryptedMasterKey, derivedKey)
	if err != nil {
		storage.RecordFailedAttempt()
		return fmt.Errorf("failed to decrypt master key - incorrect password")
	}

	storage.ResetRateLimit()

	ui.PrintInfo(">", "creating encrypted backup...")
	fmt.Println()

	if err := backup.CreateAutoBackup(password); err != nil {
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

func secretsInitMultiUser() error {
	ui.PrintPrompt("enter username for first admin: ")
	var username string
	fmt.Scanln(&username)

	userPass, err := crypto.ReadUserPassWithValidation()
	if err != nil {
		return fmt.Errorf("could not read user passphrase: %w", err)
	}

	fmt.Println()
	ui.PrintPrompt("enter initial group name (e.g., admins, devs): ")
	var groupName string
	fmt.Scanln(&groupName)

	ui.PrintPrompt("enter secret prefixes for this group (comma-separated, e.g., DB_,API_): ")
	var prefixesInput string
	fmt.Scanln(&prefixesInput)
	prefixes := strings.Split(prefixesInput, ",")
	for i := range prefixes {
		prefixes[i] = strings.TrimSpace(prefixes[i])
	}

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("could not generate master key: %w", err)
	}
	defer crypto.CleanupBytes(masterKey)

	if err := multiuser.InitMultiUserVault(username, userPass, masterKey); err != nil {
		return fmt.Errorf("could not initialize multi-user vault: %w", err)
	}

	if err := multiuser.CreateGroup(groupName, []string{username}, prefixes); err != nil {
		return fmt.Errorf("could not create initial group: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "multi-user vault initialized successfully!")
	ui.PrintMuted(fmt.Sprintf("  admin user: %s", username))
	ui.PrintMuted(fmt.Sprintf("  initial group: %s", groupName))
	ui.PrintMuted(fmt.Sprintf("  secret prefixes: %s", strings.Join(prefixes, ", ")))
	ui.PrintMuted(fmt.Sprintf("  vault location: %s", multiuser.GetMultiUserVaultPath()))
	fmt.Println()
	ui.PrintTip("tip: use 'secrets --group user add' to add more users")
	ui.PrintTip("     use 'secrets --group group create' to create more access groups")
	fmt.Println()
	return nil
}

func handleUserCommand(args []string) error {
	if len(args) == 0 {
		ui.PrintError("x", "usage: secrets user <add|list>")
		return nil
	}

	subcommand := args[0]
	switch subcommand {
	case "add":
		return userAdd()
	case "list":
		return userList()
	default:
		ui.PrintError("x", fmt.Sprintf("unknown user command: %s", subcommand))
		return nil
	}
}

func handleGroupCommand(args []string) error {
	if len(args) == 0 {
		ui.PrintError("x", "usage: secrets group <create|list>")
		return nil
	}

	subcommand := args[0]
	switch subcommand {
	case "create":
		return groupCreate()
	case "list":
		return groupList()
	default:
		ui.PrintError("x", fmt.Sprintf("unknown group command: %s", subcommand))
		return nil
	}
}

func userAdd() error {
	ui.PrintTitle("adding user")
	fmt.Println()

	if !useGroupVault {
		return fmt.Errorf("user commands require --group flag or group mode. use 'mode' to toggle or run with --group")
	}

	isMultiUser, err := multiuser.IsMultiUserMode()
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return fmt.Errorf("group vault is not in multi-user mode. use 'secrets --group init' to create a multi-user vault")
	}

	ui.PrintPrompt("enter admin username: ")
	var adminUsername string
	fmt.Scanln(&adminUsername)

	adminPassword, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read admin password: %w", err)
	}

	masterKey, err := multiuser.GetMasterKeyForUser(adminUsername, adminPassword)
	if err != nil {
		return fmt.Errorf("failed to authenticate admin: %w", err)
	}
	defer crypto.CleanupBytes(masterKey)

	fmt.Println()
	ui.PrintPrompt("enter new username: ")
	var newUsername string
	fmt.Scanln(&newUsername)

	newPassword, err := crypto.ReadUserPassWithValidation()
	if err != nil {
		return fmt.Errorf("failed to read new user password: %w", err)
	}

	if err := multiuser.AddUserToVault(newUsername, newPassword, masterKey); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("user '%s' added successfully!", newUsername))
	fmt.Println()
	return nil
}

func userList() error {
	ui.PrintTitle("user list")
	fmt.Println()

	if !useGroupVault {
		return fmt.Errorf("user commands require --group flag or group mode. use 'mode' to toggle or run with --group")
	}

	isMultiUser, err := multiuser.IsMultiUserMode()
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return fmt.Errorf("group vault is not in multi-user mode")
	}

	vault, err := multiuser.LoadMultiUserVault(multiuser.GetMultiUserVaultPath())
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	if len(vault.MasterKeyShare) == 0 {
		ui.PrintMuted("no users found")
		fmt.Println()
		return nil
	}

	ui.PrintInfo("*", fmt.Sprintf("found %d user(s):", len(vault.MasterKeyShare)))
	fmt.Println()
	for username := range vault.MasterKeyShare {
		ui.PrintSuccess("  +", username)
	}
	fmt.Println()
	return nil
}

func groupCreate() error {
	ui.PrintTitle("creating group")
	fmt.Println()

	if !useGroupVault {
		return fmt.Errorf("group commands require --group flag or group mode. use 'mode' to toggle or run with --group")
	}

	isMultiUser, err := multiuser.IsMultiUserMode()
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return fmt.Errorf("group vault is not in multi-user mode")
	}

	ui.PrintPrompt("enter group name: ")
	var groupName string
	fmt.Scanln(&groupName)

	ui.PrintPrompt("enter usernames (comma-separated): ")
	var usersInput string
	fmt.Scanln(&usersInput)
	users := strings.Split(usersInput, ",")
	for i := range users {
		users[i] = strings.TrimSpace(users[i])
	}

	ui.PrintPrompt("enter secret prefixes (comma-separated, e.g., DB_,API_): ")
	var prefixesInput string
	fmt.Scanln(&prefixesInput)
	prefixes := strings.Split(prefixesInput, ",")
	for i := range prefixes {
		prefixes[i] = strings.TrimSpace(prefixes[i])
	}

	if err := multiuser.CreateGroup(groupName, users, prefixes); err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("group '%s' created successfully!", groupName))
	ui.PrintMuted(fmt.Sprintf("  users: %s", strings.Join(users, ", ")))
	ui.PrintMuted(fmt.Sprintf("  can access secrets with prefixes: %s", strings.Join(prefixes, ", ")))
	fmt.Println()
	return nil
}

func groupList() error {
	ui.PrintTitle("group list")
	fmt.Println()

	if !useGroupVault {
		return fmt.Errorf("group commands require --group flag or group mode. use 'mode' to toggle or run with --group")
	}

	isMultiUser, err := multiuser.IsMultiUserMode()
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return fmt.Errorf("group vault is not in multi-user mode")
	}

	vault, err := multiuser.LoadMultiUserVault(multiuser.GetMultiUserVaultPath())
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	if len(vault.Groups) == 0 {
		ui.PrintMuted("no groups found")
		fmt.Println()
		return nil
	}

	ui.PrintInfo("*", fmt.Sprintf("found %d group(s):", len(vault.Groups)))
	fmt.Println()
	for _, group := range vault.Groups {
		ui.PrintSuccess("  +", fmt.Sprintf("%s (users: %s, prefixes: %s)",
			group.Name,
			strings.Join(group.Users, ", "),
			strings.Join(group.SecretPrefix, ", ")))
	}
	fmt.Println()
	return nil
}

func secretsHistory() error {
	ui.PrintTitle("audit history")
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

	ui.PrintInfo(">", "loading audit history...")
	fmt.Println()

	events, err := audit.GetAuditHistory(masterKey, 50, "", "")
	if err != nil {
		return fmt.Errorf("failed to get audit history: %w", err)
	}

	if len(events) == 0 {
		ui.PrintMuted("no audit events found")
		fmt.Println()
		return nil
	}

	ui.PrintInfo("*", fmt.Sprintf("showing last %d event(s):", len(events)))
	fmt.Println()

	for _, event := range events {
		timestamp := event.Timestamp.Local().Format("2006-01-02 15:04:05")

		eventLine := fmt.Sprintf("[%s] %s - %s %s",
			timestamp,
			event.User,
			event.Action,
			event.Secret)

		if event.Success {
			ui.PrintSuccess("+", eventLine)
		} else {
			ui.PrintError("x", eventLine)
		}

		if event.IP != "" {
			ui.PrintMuted(fmt.Sprintf("    IP: %s", event.IP))
		}
		if event.Error != "" {
			ui.PrintMuted(fmt.Sprintf("    Error: %s", event.Error))
		}
	}

	fmt.Println()
	ui.PrintTip("tip: audit logs are encrypted and stored securely")
	ui.PrintTip("     last 10,000 events are retained")
	fmt.Println()
	return nil
}
