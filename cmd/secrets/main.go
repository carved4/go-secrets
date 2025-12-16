package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard"
	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/backup"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/envinjector"
	"github.com/carved4/go-secrets/internal/importer"
	"github.com/carved4/go-secrets/internal/keyring"
	"github.com/carved4/go-secrets/internal/multiuser"
	"github.com/carved4/go-secrets/internal/privileges"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
	"github.com/carved4/go-secrets/internal/vaultmanager"
)

var useGroupVault bool
var currentUsername string = "default"

func getActiveVaultContext() (vaultName string, vaultDir string, err error) {
	vaultName, err = vaultmanager.GetActiveVault()
	if err != nil {
		return "", "", err
	}
	vaultDir = vaultmanager.GetVaultDir(vaultName)
	return vaultName, vaultDir, nil
}

func authenticateVault() (masterKey []byte, vaultDir string, err error) {
	vaultName, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return nil, "", err
	}

	password, err := crypto.ReadUserPass()
	if err != nil {
		return nil, "", fmt.Errorf("failed to read password: %w", err)
	}
	defer crypto.CleanupBytes(password)

	encryptedMasterKey, salt, err := keyring.LoadVaultKeyring(vaultDir)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load keyring: %w", err)
	}

	// Check if this is a legacy vault (migrated from old system)
	vaultInfo, err := vaultmanager.GetVaultInfo(vaultName)
	if err != nil {
		// Auto-register vault if keyring exists but vault isn't in config (backwards compatibility)
		if keyring.VaultKeyringExists(vaultDir) {
			if regErr := vaultmanager.CreateVault(vaultName, vaultmanager.VaultTypeSolo, ""); regErr == nil {
				vaultInfo, err = vaultmanager.GetVaultInfo(vaultName)
			}
		}
		if err != nil {
			return nil, "", fmt.Errorf("failed to get vault info: %w", err)
		}
	}

	var derivedKey []byte
	if vaultInfo.LegacyKeyring {
		// Use old key derivation (without vault context)
		derivedKey, _, err = crypto.DeriveKeyFromUserPass([]byte(password), salt)
	} else {
		// Use new vault-context key derivation
		derivedKey, _, err = crypto.DeriveVaultKey([]byte(password), vaultName, salt)
	}
	
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	masterKey, err = crypto.DecryptMasterKey(encryptedMasterKey, derivedKey)
	if err != nil {
		storage.RecordFailedAttempt()
		return nil, "", fmt.Errorf("failed to decrypt master key - incorrect password")
	}

	storage.ResetRateLimit()
	
	// Check for master key rotation notification
	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err == nil && vault.MasterKeyRotation != nil {
		fmt.Println()
		ui.PrintWarning("!", "MASTER KEY WAS ROTATED")
		ui.PrintMuted(fmt.Sprintf("  rotated at: %s", vault.MasterKeyRotation.RotatedAt.Format("2006-01-02 15:04:05")))
		ui.PrintMuted(fmt.Sprintf("  rotated by: %s", vault.MasterKeyRotation.RotatedBy))
		fmt.Println()
	}
	
	return masterKey, vaultDir, nil
}

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
		activeVault, _ := vaultmanager.GetActiveVault()
		prompt := fmt.Sprintf("secrets[%s]> ", activeVault)
		if useGroupVault {
			prompt = fmt.Sprintf("secrets[%s:group]> ", activeVault)
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
			// Check if active vault is initialized and prevent mode switching
			activeVault, _ := vaultmanager.GetActiveVault()
			vaultDir := vaultmanager.GetVaultDir(activeVault)
			
			// Check if vault is initialized as solo
			if keyring.VaultKeyringExists(vaultDir) {
				vaultInfo, err := vaultmanager.GetVaultInfo(activeVault)
				if err == nil {
					if vaultInfo.Type == vaultmanager.VaultTypeSolo && useGroupVault == false {
						ui.PrintError("x", "vault is initialized as SOLO vault - cannot switch to group mode")
						ui.PrintMuted("  create a new vault with type 'group' if you need multi-user support")
						fmt.Println()
						continue
					} else if vaultInfo.Type == vaultmanager.VaultTypeGroup && useGroupVault == true {
						ui.PrintError("x", "vault is initialized as GROUP vault - cannot switch to solo mode")
						fmt.Println()
						continue
					}
				}
			}
			
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
		if len(args) > 1 && args[1] == "--file" {
			if len(args) < 3 {
				ui.PrintError("x", "usage: secrets add --file <filepath>")
				return nil
			}
			return secretsAddFromFile(args[2])
		}
		if len(args) > 1 && args[1] == "--folder" {
			if len(args) < 3 {
				ui.PrintError("x", "usage: secrets add --folder <folderpath>")
				return nil
			}
			return secretsAddFromFolder(args[2])
		}
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
			ui.PrintError("x", "usage: secrets delete <name> [--folder]")
			return nil
		}
		if len(args) > 2 && args[2] == "--folder" {
			return secretsDeleteFolder(args[1])
		}
		return secretsDelete(args[1])
	case "env":
		if len(args) < 3 || args[1] != "run" || args[2] != "--" {
			ui.PrintError("x", "usage: secrets env run [--prefix PREFIX1,PREFIX2] -- <command> [args...]")
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
	case "import-passwords":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets import-passwords <csv-file>")
			return nil
		}
		return secretsImportPasswords(args[1])
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
	case "rotate":
		if len(args) > 1 && args[1] == "--master-key" {
			return secretsRotateMasterKey()
		}
		return secretsRotate(args[1:])
	case "vault":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets vault <create|list|switch|delete|info>")
			return nil
		}
		return handleVaultCommand(args[1:])
	case "restore":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets restore <name> [--output <path>] [--folder]")
			return nil
		}
		return secretsRestore(args[1:])
	case "wipe":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets wipe <path> [--folder]")
			return nil
		}
		if len(args) > 2 && args[2] == "--folder" {
			return secretsWipeFolder(args[1])
		}
		return secretsWipeFile(args[1])
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
	ui.PrintListItem("  >", "add --file <path>  add a secret from file")
	ui.PrintListItem("  >", "add --folder <path>  add all files from a folder")
	ui.PrintListItem("  >", "get <name> [--clip]  retrieve a secret")
	ui.PrintListItem("  >", "list           list all secret names")
	ui.PrintListItem("  >", "delete <name>  delete a secret")
	ui.PrintListItem("  >", "delete <name> --folder  delete all files in a folder")
	ui.PrintListItem("  >", "env run -- <cmd>  run command with secrets as env vars")
	ui.PrintListItem("  >", "export <file>  export encrypted backup to file")
	ui.PrintListItem("  >", "import <file>  import secrets from encrypted backup")
	ui.PrintListItem("  >", "import-passwords <csv>  import passwords from Chrome CSV export")
	ui.PrintListItem("  >", "backup         create automatic backup")
	ui.PrintListItem("  >", "history        view audit log history")
	ui.PrintListItem("  >", "rotate [name]  rotate all secrets or a specific secret")
	ui.PrintListItem("  >", "rotate --master-key  rotate the master encryption key")
	ui.PrintListItem("  >", "restore <name> [--output <path>]  restore secret to file")
	ui.PrintListItem("  >", "restore <name> --folder [--output <path>]  restore folder")
	ui.PrintListItem("  >", "wipe <path>    securely delete a file")
	ui.PrintListItem("  >", "wipe <path> --folder  securely delete entire folder")
	fmt.Println()
	ui.PrintInfo("*", "vault management:")
	fmt.Println()
	ui.PrintListItem("  >", "vault create   create a new vault")
	ui.PrintListItem("  >", "vault list     list all vaults")
	ui.PrintListItem("  >", "vault switch <name>  switch to a different vault")
	ui.PrintListItem("  >", "vault delete <name>  delete a vault")
	ui.PrintListItem("  >", "vault info     show active vault information")
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
	ui.PrintMuted("  secrets add --file secret.txt   # add from file")
	ui.PrintMuted("  secrets add --folder ./configs  # add entire folder")
	ui.PrintMuted("  secrets import-passwords passwords.csv  # import Chrome passwords")
	ui.PrintMuted("  secrets rotate                  # rotate all secrets")
	ui.PrintMuted("  secrets rotate API_KEY          # rotate specific secret")
	ui.PrintMuted("  secrets rotate --master-key     # rotate master encryption key")
	ui.PrintMuted("  secrets restore DB_FILE --output ./database.db  # restore file secret")
	ui.PrintMuted("  secrets restore MY_CONFIGS --folder --output ./restored  # restore folder")
	ui.PrintMuted("  secrets delete MY_CONFIGS --folder  # delete entire folder from vault")
	ui.PrintMuted("  secrets wipe ./database.db      # securely delete file")
	ui.PrintMuted("  secrets wipe ./restored-folder --folder  # securely delete entire folder")
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

	activeVault, err := vaultmanager.GetActiveVault()
	if err != nil {
		return err
	}

	vaultDir := vaultmanager.GetVaultDir(activeVault)

	if useGroups {
		ui.PrintMuted("setting up multi-user vault with groups...")
	} else {
		ui.PrintMuted("setting up your secure secrets vault...")
	}
	fmt.Println()

	if keyring.VaultKeyringExists(vaultDir) {
		return fmt.Errorf("vault '%s' is already initialized", activeVault)
	}
	
	// Check if multiuser vault exists for group vaults
	if useGroups {
		isMultiUser, _ := multiuser.IsMultiUserModeInDir(vaultDir)
		if isMultiUser {
			return fmt.Errorf("vault '%s' is already initialized as multi-user vault", activeVault)
		}
	}

	// Ensure vault is registered in config (needed for GetVaultInfo during authentication)
	exists, err := vaultmanager.VaultExists(activeVault)
	if err != nil {
		return fmt.Errorf("failed to check vault existence: %w", err)
	}
	
	// Check vault type matches initialization mode
	if exists {
		vaultInfo, err := vaultmanager.GetVaultInfo(activeVault)
		if err == nil {
			if useGroups && vaultInfo.Type != vaultmanager.VaultTypeGroup {
				return fmt.Errorf("vault '%s' is configured as %s vault, not group vault", activeVault, vaultInfo.Type)
			}
			if !useGroups && vaultInfo.Type != vaultmanager.VaultTypeSolo {
				return fmt.Errorf("vault '%s' is configured as %s vault, not solo vault", activeVault, vaultInfo.Type)
			}
		}
	}
	
	if !exists {
		vaultType := vaultmanager.VaultTypeSolo
		if useGroups {
			vaultType = vaultmanager.VaultTypeGroup
		}
		if err := vaultmanager.CreateVault(activeVault, vaultType, ""); err != nil {
			return fmt.Errorf("failed to register vault: %w", err)
		}
	}

	if useGroups {
		return secretsInitMultiUser()
	}

	userPass, err := crypto.ReadUserPassWithValidation()
	if err != nil {
		return fmt.Errorf("could not read user passphrase: %w", err)
	}
	defer crypto.CleanupBytes(userPass)

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("could not generate master key: %w", err)
	}

	derivedKey, salt, err := crypto.DeriveVaultKey([]byte(userPass), activeVault, nil)
	if err != nil {
		return fmt.Errorf("could not derive key from user pass: %w", err)
	}
	defer crypto.CleanupBytes(derivedKey)

	encryptedMasterKey, err := crypto.EncryptMasterKey(masterKey, derivedKey)
	if err != nil {
		return fmt.Errorf("could not encrypt master key: %w", err)
	}

	if err := keyring.StoreVaultKeyring(vaultDir, encryptedMasterKey, salt); err != nil {
		return fmt.Errorf("could not store keyring: %w", err)
	}

	if err := storage.InitVaultInDir(vaultDir); err != nil {
		return fmt.Errorf("could not initialize vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("vault '%s' initialized successfully!", activeVault))
	ui.PrintMuted(fmt.Sprintf("  vault location: %s", vaultDir))
	fmt.Println()
	return nil
}

func promptForUsername() error {
	if !useGroupVault {
		return nil
	}

	// Get vault directory
	_, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return fmt.Errorf("failed to get vault context: %w", err)
	}

	isMultiUser, err := multiuser.IsMultiUserModeInDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return nil
	}

	ui.PrintPrompt("enter your username: ")
	fmt.Scanln(&currentUsername)

	password, err := crypto.ReadUserPass()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer crypto.CleanupBytes(password)

	_, err = multiuser.GetMasterKeyForUserInDir(vaultDir, currentUsername, password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Check for master key rotation notification
	multiUserVault, err := multiuser.LoadMultiUserVault(multiuser.GetMultiUserVaultPathForVault(vaultDir))
	if err == nil && multiUserVault.MasterKeyRotation != nil {
		fmt.Println()
		ui.PrintWarning("!", "MASTER KEY WAS ROTATED")
		ui.PrintMuted(fmt.Sprintf("  rotated at: %s", multiUserVault.MasterKeyRotation.RotatedAt.Format("2006-01-02 15:04:05")))
		ui.PrintMuted(fmt.Sprintf("  rotated by: %s", multiUserVault.MasterKeyRotation.RotatedBy))
		fmt.Println()
	}

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

	const maxSecretSize = 1024 * 1024
	if len(secretValue) > maxSecretSize {
		ui.PrintError("x", fmt.Sprintf("secret too large (max %d bytes, got %d bytes)", maxSecretSize, len(secretValue)))
		fmt.Println()
		return fmt.Errorf("secret exceeds maximum size")
	}

	ui.PrintSuccess("+", "secret loaded from clipboard")
	fmt.Println()

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

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

	if useGroupVault {
		if err := promptForUsername(); err != nil {
			return err
		}
		canAccess, err := multiuser.UserCanAccessSecretInDir(vaultDir, currentUsername, secretName)
		if err != nil {
			return fmt.Errorf("failed to check access: %w", err)
		}
		if !canAccess {
			return fmt.Errorf("access denied: user '%s' does not have permission to add secrets with prefix '%s'", currentUsername, secretName)
		}
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "add", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to load vault: %w", err)
	}

	now := time.Now()
	existing, exists := vault.SecretsMetadata[secretName]
	if exists {
		vault.SecretsMetadata[secretName] = storage.SecretMetadata{
			EncryptedValue: fmt.Sprintf("%x", encryptedSecret),
			CreatedAt:      existing.CreatedAt,
			UpdatedAt:      now,
		}
	} else {
		vault.SecretsMetadata[secretName] = storage.SecretMetadata{
			EncryptedValue: fmt.Sprintf("%x", encryptedSecret),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "add", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to save vault: %w", err)
	}

	clipboard.WriteAll("")

	audit.LogEventForVault(vaultDir, currentUsername, "add", secretName, true, "", masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' added successfully!", secretName))
	ui.PrintSuccess("+", "clipboard cleared for security")
	fmt.Println()
	ui.PrintTip("tip: name secrets like env vars (e.g., DATABASE_URL, API_KEY)")
	ui.PrintTip("     then use: secrets env run -- <your-command>")
	fmt.Println()
	return nil
}

func secretsAddFromFile(filePath string) error {
	ui.PrintTitle("adding secret from file")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	// Get file info first
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		ui.PrintError("x", fmt.Sprintf("failed to stat file: %v", err))
		fmt.Println()
		return fmt.Errorf("failed to stat file: %w", err)
	}

	fileSize := fileInfo.Size()
	const maxSecretSize = 100 * 1024 * 1024 * 1024 // 100GB max with streaming
	if fileSize > maxSecretSize {
		ui.PrintError("x", fmt.Sprintf("file too large (max %d GB, got %.2f GB)", maxSecretSize/(1024*1024*1024), float64(fileSize)/(1024*1024*1024)))
		fmt.Println()
		return fmt.Errorf("file exceeds maximum size")
	}

	// Determine if we should use streaming encryption (files > 100MB)
	useStreaming := fileSize > 100*1024*1024

	if fileSize < 1024 {
		ui.PrintSuccess("+", fmt.Sprintf("loading file: %s (%d bytes)", filePath, fileSize))
	} else if fileSize < 1024*1024 {
		ui.PrintSuccess("+", fmt.Sprintf("loading file: %s (%.2f KB)", filePath, float64(fileSize)/1024))
	} else if fileSize < 1024*1024*1024 {
		ui.PrintSuccess("+", fmt.Sprintf("loading file: %s (%.2f MB)", filePath, float64(fileSize)/(1024*1024)))
	} else {
		ui.PrintSuccess("+", fmt.Sprintf("loading file: %s (%.2f GB)", filePath, float64(fileSize)/(1024*1024*1024)))
	}

	if useStreaming {
		ui.PrintMuted("  using streaming encryption (64MB chunks) for large file...")
	}
	fmt.Println()

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	secretName, err := crypto.ReadSecretName()
	if err != nil {
		return fmt.Errorf("failed to read secret name")
	}

	if useGroupVault {
		if err := promptForUsername(); err != nil {
			return err
		}
		canAccess, err := multiuser.UserCanAccessSecretInDir(vaultDir, currentUsername, secretName)
		if err != nil {
			return fmt.Errorf("failed to check access: %w", err)
		}
		if !canAccess {
			return fmt.Errorf("access denied: user '%s' does not have permission to add secrets with prefix '%s'", currentUsername, secretName)
		}
	}

	var encryptedValue string

	if useStreaming {
		// Stream encryption for large files
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()

		// Create a buffer to hold encrypted stream data
		var encryptedBuf strings.Builder

		ui.PrintInfo(">", "encrypting file in chunks (this may take a moment for large files)...")
		fmt.Println()

		_, err = crypto.EncryptStream(file, &encryptedBuf, masterKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file: %w", err)
		}

		// Convert to hex
		encryptedBytes := []byte(encryptedBuf.String())
		encryptedValue = fmt.Sprintf("%x", encryptedBytes)
		
		ui.PrintSuccess("+", "file encrypted successfully")
		fmt.Println()
	} else {
		// Standard encryption for smaller files
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to read file: %v", err))
			fmt.Println()
			return fmt.Errorf("failed to read file: %w", err)
		}

		secretBytes := fileData
		// Only lock memory for small files (< 10MB) to avoid quota issues on Windows
		if len(secretBytes) < 10*1024*1024 {
			crypto.SecureBytes(secretBytes)
			defer crypto.CleanupBytes(secretBytes)
		}

		encryptedSecret, err := crypto.EncryptSecret(secretBytes, masterKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt secret")
		}
		encryptedValue = fmt.Sprintf("%x", encryptedSecret)
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "add", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to load vault: %w", err)
	}

	now := time.Now()
	existing, exists := vault.SecretsMetadata[secretName]
	if exists {
		vault.SecretsMetadata[secretName] = storage.SecretMetadata{
			EncryptedValue: encryptedValue,
			CreatedAt:      existing.CreatedAt,
			UpdatedAt:      now,
		}
	} else {
		vault.SecretsMetadata[secretName] = storage.SecretMetadata{
			EncryptedValue: encryptedValue,
			CreatedAt:      now,
			UpdatedAt:      now,
		}
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "add", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to save vault: %w", err)
	}

	audit.LogEventForVault(vaultDir, currentUsername, "add", secretName, true, "", masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' added successfully!", secretName))
	fmt.Println()

	ui.PrintWarning("!", "delete the source file for security?")
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
	ui.PrintTip("tip: use 'secrets restore' to decrypt the file back to disk when needed")
	ui.PrintTip("     use 'secrets wipe' to securely delete restored files")
	fmt.Println()
	return nil
}

func secretsAddFromFolder(folderPath string) error {
	ui.PrintTitle("adding folder to vault")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	folderInfo, err := os.Stat(folderPath)
	if err != nil {
		ui.PrintError("x", fmt.Sprintf("failed to access folder: %v", err))
		fmt.Println()
		return fmt.Errorf("failed to access folder: %w", err)
	}

	if !folderInfo.IsDir() {
		ui.PrintError("x", "path is not a directory")
		fmt.Println()
		return fmt.Errorf("path is not a directory: %s", folderPath)
	}

	var files []string
	var totalSize int64
	err = filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		ui.PrintError("x", fmt.Sprintf("failed to scan folder: %v", err))
		fmt.Println()
		return fmt.Errorf("failed to scan folder: %w", err)
	}

	if len(files) == 0 {
		ui.PrintWarning("!", "no files found in folder")
		fmt.Println()
		return nil
	}

	ui.PrintSuccess("+", fmt.Sprintf("found %d file(s) in folder", len(files)))
	if totalSize < 1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %d bytes", totalSize))
	} else if totalSize < 1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f KB", float64(totalSize)/1024))
	} else if totalSize < 1024*1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f MB", float64(totalSize)/(1024*1024)))
	} else {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f GB", float64(totalSize)/(1024*1024*1024)))
	}
	fmt.Println()

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	ui.PrintPrompt("enter a name for this folder backup: ")
	var folderName string
	fmt.Scanln(&folderName)
	
	if folderName == "" {
		return fmt.Errorf("folder name cannot be empty")
	}

	if useGroupVault {
		if err := promptForUsername(); err != nil {
			return err
		}
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	fmt.Println()
	ui.PrintInfo(">", "encrypting files...")
	fmt.Println()

	absFolderPath, err := filepath.Abs(folderPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	successCount := 0
	failCount := 0

	for i, filePath := range files {
		relPath, err := filepath.Rel(absFolderPath, filePath)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to get relative path", i+1, len(files), filepath.Base(filePath)))
			failCount++
			continue
		}

		relPathForward := filepath.ToSlash(relPath)
		secretName := fmt.Sprintf("%s__%s", folderName, relPathForward)

		if useGroupVault {
			canAccess, err := multiuser.UserCanAccessSecretInDir(vaultDir, currentUsername, secretName)
			if err != nil || !canAccess {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - access denied", i+1, len(files), relPath))
				failCount++
				continue
			}
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to stat", i+1, len(files), relPath))
			failCount++
			continue
		}

		fileSize := fileInfo.Size()
		useStreaming := fileSize > 100*1024*1024

		var encryptedValue string

		if useStreaming {
			file, err := os.Open(filePath)
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to open", i+1, len(files), relPath))
				failCount++
				continue
			}

			var encryptedBuf strings.Builder
			_, err = crypto.EncryptStream(file, &encryptedBuf, masterKey)
			file.Close()
			
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - encryption failed", i+1, len(files), relPath))
				failCount++
				continue
			}

			encryptedBytes := []byte(encryptedBuf.String())
			encryptedValue = fmt.Sprintf("%x", encryptedBytes)
		} else {
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to read", i+1, len(files), relPath))
				failCount++
				continue
			}

			encryptedSecret, err := crypto.EncryptSecret(fileData, masterKey)
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - encryption failed", i+1, len(files), relPath))
				failCount++
				continue
			}
			encryptedValue = fmt.Sprintf("%x", encryptedSecret)
		}

		now := time.Now()
		existing, exists := vault.SecretsMetadata[secretName]
		if exists {
			vault.SecretsMetadata[secretName] = storage.SecretMetadata{
				EncryptedValue: encryptedValue,
				CreatedAt:      existing.CreatedAt,
				UpdatedAt:      now,
			}
		} else {
			vault.SecretsMetadata[secretName] = storage.SecretMetadata{
				EncryptedValue: encryptedValue,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
		}

		ui.PrintSuccess("+", fmt.Sprintf("  %d/%d: %s", i+1, len(files), relPath))
		successCount++
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "add-folder", folderName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to save vault: %w", err)
	}

	audit.LogEventForVault(vaultDir, currentUsername, "add-folder", folderName, true, fmt.Sprintf("%d files", successCount), masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("folder '%s' added successfully!", folderName))
	ui.PrintMuted(fmt.Sprintf("  %d file(s) encrypted and stored", successCount))
	if failCount > 0 {
		ui.PrintWarning("!", fmt.Sprintf("  %d file(s) failed", failCount))
	}
	fmt.Println()

	ui.PrintWarning("!", "delete the source folder for security?")
	ui.PrintPrompt("remove folder? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)

	if confirm == "yes" || confirm == "y" {
		if err := os.RemoveAll(folderPath); err != nil {
			ui.PrintError("x", fmt.Sprintf("failed to remove folder: %v", err))
			ui.PrintMuted("  you may need to delete it manually")
		} else {
			ui.PrintSuccess("+", "source folder removed")
		}
	} else {
		ui.PrintWarning("!", "source folder kept - remember to delete it manually!")
	}

	fmt.Println()
	ui.PrintTip(fmt.Sprintf("tip: use 'secrets restore %s --folder' to restore all files", folderName))
	ui.PrintTip("     folder structure will be preserved during restore")
	fmt.Println()
	return nil
}

type clipboardClearToken struct {
	token string
	value string
}

var activeClipboardToken *clipboardClearToken
var clipboardMutex sync.Mutex

func secretsGet(secretName string, useClipboard bool) error {
	ui.PrintTitle("retrieving secret")
	fmt.Println()
	ui.PrintSuccess(">", fmt.Sprintf("fetching: %s", secretName))
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	// Check access control for multi-user mode
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

	// Get encrypted secret from vault
	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	metadata, exists := vault.SecretsMetadata[secretName]
	if !exists {
		return fmt.Errorf("secret '%s' not found", secretName)
	}

	// Decode the hex-encoded encrypted value
	encryptedBytes := make([]byte, len(metadata.EncryptedValue)/2)
	_, err = fmt.Sscanf(metadata.EncryptedValue, "%x", &encryptedBytes)
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	// Decrypt the secret
	secret, err := crypto.DecryptSecret(encryptedBytes, masterKey)
	if err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "get", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to decrypt secret: %w", err)
	}
	crypto.SecureBytes(secret)
	defer crypto.CleanupBytes(secret)

	audit.LogEventForVault(vaultDir, currentUsername, "get", secretName, true, "", masterKey)

	fmt.Println()

	if useClipboard {
		secretStr := string(secret)
		if err := clipboard.WriteAll(secretStr); err != nil {
			return fmt.Errorf("failed to copy to clipboard: %w", err)
		}
		ui.PrintSuccess("+", "secret copied to clipboard")
		ui.PrintMuted("  clipboard will be cleared in 30 seconds...")
		fmt.Println()

		token := fmt.Sprintf("%d", time.Now().UnixNano())
		clipboardMutex.Lock()
		activeClipboardToken = &clipboardClearToken{
			token: token,
			value: secretStr,
		}
		clipboardMutex.Unlock()

		go func(clearToken string) {
			time.Sleep(30 * time.Second)
			clipboardMutex.Lock()
			defer clipboardMutex.Unlock()
			if activeClipboardToken != nil && activeClipboardToken.token == clearToken {
				clipboard.WriteAll("")
				activeClipboardToken = nil
			}
		}(token)
	} else {
		ui.PrintWarning("!", "WARNING: Secrets printed to terminal may be logged by your shell or terminal emulator")
		ui.PrintMuted("  use --clip flag to copy to clipboard instead (recommended)")
		fmt.Println()
		secretStr := strings.TrimRight(string(secret), "\n\r")
		ui.PrintMuted("  value:")
		fmt.Println(ui.SuccessStyle.Render("  " + secretStr))
		fmt.Println()
	}

	return nil
}

func secretsList() error {
	ui.PrintTitle("secrets list")
	fmt.Println()

	vaultName, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return err
	}
	if !keyring.VaultKeyringExists(vaultDir) {
		ui.PrintWarning("!", fmt.Sprintf("vault '%s' has not been initialized yet", vaultName))
		fmt.Println()
		ui.PrintTip("run 'secrets init' to initialize this vault")
		fmt.Println()
		return nil
	}

	metadata, err := storage.LoadMetadataIndex(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if len(metadata) == 0 {
		ui.PrintMuted("no secrets stored yet")
		fmt.Println()
		return nil
	}

	ui.PrintInfo("*", fmt.Sprintf("found %d secret(s):", len(metadata)))
	fmt.Println()

	names := make([]string, 0, len(metadata))
	for name := range metadata {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		meta := metadata[name]
		age := time.Since(meta.CreatedAt)
		ageStr := formatDuration(age)

		if meta.CreatedAt.Equal(meta.UpdatedAt) {
			ui.PrintSuccess("  +", fmt.Sprintf("%s (created %s ago)", name, ageStr))
		} else {
			updateAge := time.Since(meta.UpdatedAt)
			ui.PrintSuccess("  +", fmt.Sprintf("%s (created %s ago, updated %s ago)", name, ageStr, formatDuration(updateAge)))
		}
	}
	fmt.Println()
	return nil
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	days := int(d.Hours() / 24)
	if days == 1 {
		return "1 day"
	}
	if days < 30 {
		return fmt.Sprintf("%d days", days)
	}
	months := days / 30
	if months == 1 {
		return "1 month"
	}
	if months < 12 {
		return fmt.Sprintf("%d months", months)
	}
	years := months / 12
	if years == 1 {
		return "1 year"
	}
	return fmt.Sprintf("%d years", years)
}

func secretsDelete(secretName string) error {
	ui.PrintTitle("deleting secret")
	fmt.Println()
	ui.PrintWarning("!", fmt.Sprintf("deleting: %s", secretName))
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

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
			return fmt.Errorf("access denied: user '%s' does not have permission to delete secret '%s'", currentUsername, secretName)
		}
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "delete", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to load vault: %w", err)
	}

	if _, exists := vault.SecretsMetadata[secretName]; !exists {
		return fmt.Errorf("secret '%s' not found", secretName)
	}

	delete(vault.SecretsMetadata, secretName)

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "delete", secretName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to save vault: %w", err)
	}

	audit.LogEventForVault(vaultDir, currentUsername, "delete", secretName, true, "", masterKey)

	ui.PrintSuccess("+", fmt.Sprintf("secret '%s' deleted successfully", secretName))
	fmt.Println()
	return nil
}

func secretsDeleteFolder(folderName string) error {
	ui.PrintTitle("deleting folder from vault")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	if useGroupVault {
		if err := promptForUsername(); err != nil {
			return err
		}
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	prefix := folderName + "__"
	var folderSecrets []string
	for secretName := range vault.SecretsMetadata {
		if strings.HasPrefix(secretName, prefix) {
			folderSecrets = append(folderSecrets, secretName)
		}
	}

	if len(folderSecrets) == 0 {
		return fmt.Errorf("no secrets found for folder '%s'", folderName)
	}

	ui.PrintWarning("!", fmt.Sprintf("this will delete %d file(s) from folder '%s':", len(folderSecrets), folderName))
	fmt.Println()

	previewCount := len(folderSecrets)
	if previewCount > 10 {
		previewCount = 10
	}
	sort.Strings(folderSecrets)
	for i := 0; i < previewCount; i++ {
		relPath := strings.TrimPrefix(folderSecrets[i], prefix)
		ui.PrintMuted(fmt.Sprintf("  - %s", relPath))
	}
	if len(folderSecrets) > 10 {
		ui.PrintMuted(fmt.Sprintf("  ... and %d more", len(folderSecrets)-10))
	}
	fmt.Println()

	ui.PrintPrompt("continue? (yes/no): ")
	var confirm string
	fmt.Scanln(&confirm)

	if confirm != "yes" && confirm != "y" {
		ui.PrintMuted("deletion cancelled")
		fmt.Println()
		return nil
	}

	fmt.Println()
	ui.PrintInfo(">", "deleting files...")
	fmt.Println()

	successCount := 0
	failCount := 0

	for i, secretName := range folderSecrets {
		relPath := strings.TrimPrefix(secretName, prefix)

		if useGroupVault {
			canAccess, err := multiuser.UserCanAccessSecret(currentUsername, secretName)
			if err != nil || !canAccess {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - access denied", i+1, len(folderSecrets), relPath))
				failCount++
				continue
			}
		}

		delete(vault.SecretsMetadata, secretName)
		ui.PrintSuccess("+", fmt.Sprintf("  %d/%d: %s", i+1, len(folderSecrets), relPath))
		successCount++
	}

	if err := storage.SaveVaultToDir(vaultDir, vault); err != nil {
		audit.LogEventForVault(vaultDir, currentUsername, "delete-folder", folderName, false, err.Error(), masterKey)
		return fmt.Errorf("failed to save vault: %w", err)
	}

	audit.LogEventForVault(vaultDir, currentUsername, "delete-folder", folderName, true, fmt.Sprintf("%d files", successCount), masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("folder '%s' deleted successfully!", folderName))
	ui.PrintMuted(fmt.Sprintf("  %d file(s) deleted", successCount))
	if failCount > 0 {
		ui.PrintWarning("!", fmt.Sprintf("  %d file(s) failed", failCount))
	}
	fmt.Println()
	return nil
}

func secretsEnvRun(cmdArgs []string) error {
	ui.PrintTitle("running with secrets")
	fmt.Println()

	var filterPrefixes []string
	var actualCmd []string

	for i := 0; i < len(cmdArgs); i++ {
		if cmdArgs[i] == "--prefix" && i+1 < len(cmdArgs) {
			filterPrefixes = strings.Split(cmdArgs[i+1], ",")
			for j := range filterPrefixes {
				filterPrefixes[j] = strings.TrimSpace(filterPrefixes[j])
			}
			i++
		} else if cmdArgs[i] == "--" {
			actualCmd = cmdArgs[i+1:]
			break
		} else {
			actualCmd = cmdArgs[i:]
			break
		}
	}

	if len(actualCmd) == 0 {
		return fmt.Errorf("no command specified after --")
	}

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	masterKey, _, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	injector := envinjector.NewSecureEnvInjector()
	defer injector.Cleanup()

	if err := loadSecretsIntoInjector(masterKey, injector, filterPrefixes); err != nil {
		return fmt.Errorf("failed to load secrets: %w", err)
	}

	ui.PrintSuccess("+", fmt.Sprintf("loaded %d secret(s) into environment", injector.GetSecretCount()))
	if len(filterPrefixes) > 0 {
		ui.PrintMuted(fmt.Sprintf("  filtered by prefixes: %s", strings.Join(filterPrefixes, ", ")))
	}
	for _, name := range injector.GetSecretNames() {
		ui.PrintMuted(fmt.Sprintf("  %s=[REDACTED]", name))
	}
	ui.PrintMuted(fmt.Sprintf("  running: %s", strings.Join(actualCmd, " ")))
	fmt.Println()

	if err := injector.RunCommand(actualCmd, filterPrefixes); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

func loadSecretsIntoInjector(masterKey []byte, injector *envinjector.SecureEnvInjector, filterPrefixes []string) error {
	names, err := storage.ListSecretsWithMode(useGroupVault)
	if err != nil {
		return err
	}

	filter := envinjector.NewSecretFilter()
	if len(filterPrefixes) > 0 {
		filter.AllowPrefixes(filterPrefixes)
	}

	filteredNames := filter.FilterSecrets(names)

	for _, name := range filteredNames {
		encryptedSecret, err := storage.GetSecretWithMode(name, useGroupVault)
		if err != nil {
			return fmt.Errorf("failed to get secret %s: %w", name, err)
		}

		secret, err := crypto.DecryptSecret(encryptedSecret, masterKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt secret %s: %w", name, err)
		}

		injector.AddSecret(name, secret)
		crypto.CleanupBytes(secret)
	}

	return nil
}

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

func secretsInitMultiUser() error {
	// Get active vault context first
	vaultName, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return err
	}

	ui.PrintPrompt("enter username for first admin: ")
	var username string
	fmt.Scanln(&username)

	userPass, err := crypto.ReadUserPassWithValidation()
	if err != nil {
		return fmt.Errorf("could not read user passphrase: %w", err)
	}
	defer crypto.CleanupBytes(userPass)

	fmt.Println()
	ui.PrintPrompt("enter initial group name (e.g., admins, devs): ")
	var groupName string
	fmt.Scanln(&groupName)

	var prefixes []string
	for {
		ui.PrintPrompt("enter secret prefixes for this group (comma-separated, e.g., DB_,API_): ")
		var prefixesInput string
		fmt.Scanln(&prefixesInput)

		if strings.Contains(prefixesInput, ", ") {
			ui.PrintError("x", "invalid format: spaces detected after commas")
			ui.PrintMuted("  use format: DB_,API_ (no spaces after commas)")
			fmt.Println()
			continue
		}

		prefixes = strings.Split(prefixesInput, ",")
		for i := range prefixes {
			prefixes[i] = strings.TrimSpace(prefixes[i])
		}
		break
	}

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("could not generate master key: %w", err)
	}
	defer crypto.CleanupBytes(masterKey)

	if err := multiuser.InitMultiUserVaultInDir(vaultDir, username, userPass, masterKey); err != nil {
		return fmt.Errorf("could not initialize multi-user vault: %w", err)
	}

	if err := multiuser.CreateGroupInDir(vaultDir, groupName, []string{username}, prefixes); err != nil {
		return fmt.Errorf("could not create initial group: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "multi-user vault initialized successfully!")
	ui.PrintMuted(fmt.Sprintf("  vault: %s", vaultName))
	ui.PrintMuted(fmt.Sprintf("  admin user: %s", username))
	ui.PrintMuted(fmt.Sprintf("  initial group: %s", groupName))
	ui.PrintMuted(fmt.Sprintf("  secret prefixes: %s", strings.Join(prefixes, ", ")))
	ui.PrintMuted(fmt.Sprintf("  vault location: %s", vaultDir))
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

	// Get vault directory
	_, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return err
	}

	isMultiUser, err := multiuser.IsMultiUserModeInDir(vaultDir)
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
	defer crypto.CleanupBytes(adminPassword)

	masterKey, err := multiuser.GetMasterKeyForUserInDir(vaultDir, adminUsername, adminPassword)
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
	defer crypto.CleanupBytes(newPassword)

	if err := multiuser.AddUserToVaultInDir(vaultDir, newUsername, newPassword, masterKey); err != nil {
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

	// Get vault directory
	_, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return err
	}

	isMultiUser, err := multiuser.IsMultiUserModeInDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return fmt.Errorf("group vault is not in multi-user mode")
	}

	vault, err := multiuser.LoadMultiUserVault(multiuser.GetMultiUserVaultPathForVault(vaultDir))
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

	// Get vault directory
	_, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return err
	}

	isMultiUser, err := multiuser.IsMultiUserModeInDir(vaultDir)
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

	var prefixes []string
	for {
		ui.PrintPrompt("enter secret prefixes (comma-separated, e.g., DB_,API_): ")
		var prefixesInput string
		fmt.Scanln(&prefixesInput)

		if strings.Contains(prefixesInput, ", ") {
			ui.PrintError("x", "invalid format: spaces detected after commas")
			ui.PrintMuted("  use format: DB_,API_ (no spaces after commas)")
			fmt.Println()
			continue
		}

		prefixes = strings.Split(prefixesInput, ",")
		for i := range prefixes {
			prefixes[i] = strings.TrimSpace(prefixes[i])
		}
		break
	}

	if err := multiuser.CreateGroupInDir(vaultDir, groupName, users, prefixes); err != nil {
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

	// Get vault directory
	_, vaultDir, err := getActiveVaultContext()
	if err != nil {
		return err
	}

	isMultiUser, err := multiuser.IsMultiUserModeInDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to check vault mode: %w", err)
	}
	if !isMultiUser {
		return fmt.Errorf("group vault is not in multi-user mode")
	}

	vault, err := multiuser.LoadMultiUserVault(multiuser.GetMultiUserVaultPathForVault(vaultDir))
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

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}
	defer crypto.CleanupBytes(masterKey)

	ui.PrintInfo(">", "loading audit history...")
	fmt.Println()

	events, err := audit.GetAuditHistoryForVault(vaultDir, masterKey, 50, "", "")
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

		if event.IP != "" || event.PublicIP != "" {
			ipInfo := ""
			if event.IP != "" {
				ipInfo = fmt.Sprintf("Local: %s", event.IP)
			}
			if event.PublicIP != "" {
				if ipInfo != "" {
					ipInfo += ", "
				}
				ipInfo += fmt.Sprintf("Public: %s", event.PublicIP)
			}
			ui.PrintMuted(fmt.Sprintf("    IP: %s", ipInfo))
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

func handleVaultCommand(args []string) error {
	if len(args) == 0 {
		ui.PrintError("x", "usage: secrets vault <create|list|switch|delete|info>")
		return nil
	}

	subcommand := args[0]
	switch subcommand {
	case "create":
		return vaultCreate()
	case "list":
		return vaultList()
	case "switch":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets vault switch <name>")
			return nil
		}
		return vaultSwitch(args[1])
	case "delete":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets vault delete <name>")
			return nil
		}
		return vaultDelete(args[1])
	case "info":
		return vaultInfo()
	default:
		ui.PrintError("x", fmt.Sprintf("unknown vault command: %s", subcommand))
		return nil
	}
}

func vaultCreate() error {
	ui.PrintTitle("creating new vault")
	fmt.Println()

	ui.PrintPrompt("enter vault name: ")
	var vaultName string
	fmt.Scanln(&vaultName)

	if vaultName == "" {
		return fmt.Errorf("vault name cannot be empty")
	}

	exists, err := vaultmanager.VaultExists(vaultName)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("vault '%s' already exists", vaultName)
	}

	ui.PrintPrompt("enter description (optional): ")
	scanner := bufio.NewScanner(os.Stdin)
	var description string
	if scanner.Scan() {
		description = scanner.Text()
	}

	ui.PrintPrompt("vault type (solo/group): ")
	var vaultTypeStr string
	fmt.Scanln(&vaultTypeStr)

	var vaultType vaultmanager.VaultType
	if vaultTypeStr == "group" {
		vaultType = vaultmanager.VaultTypeGroup
	} else {
		vaultType = vaultmanager.VaultTypeSolo
	}

	if err := vaultmanager.CreateVault(vaultName, vaultType, description); err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("vault '%s' created successfully!", vaultName))
	ui.PrintMuted(fmt.Sprintf("  type: %s", vaultType))
	if description != "" {
		ui.PrintMuted(fmt.Sprintf("  description: %s", description))
	}
	fmt.Println()
	ui.PrintTip(fmt.Sprintf("tip: use 'secrets vault switch %s' to activate this vault", vaultName))
	ui.PrintTip("     then use 'secrets init' to initialize it")
	fmt.Println()
	return nil
}

func vaultList() error {
	ui.PrintTitle("vaults")
	fmt.Println()

	vaults, err := vaultmanager.ListVaults()
	if err != nil {
		return fmt.Errorf("failed to list vaults: %w", err)
	}

	if len(vaults) == 0 {
		ui.PrintMuted("no vaults created yet")
		fmt.Println()
		ui.PrintTip("tip: use 'secrets vault create' to create a vault")
		fmt.Println()
		return nil
	}

	activeVault, err := vaultmanager.GetActiveVault()
	if err != nil {
		return err
	}

	ui.PrintInfo("*", fmt.Sprintf("found %d vault(s):", len(vaults)))
	fmt.Println()

	for _, vault := range vaults {
		indicator := " "
		if vault.Name == activeVault {
			indicator = "*"
			ui.PrintSuccess(fmt.Sprintf("  %s", indicator), fmt.Sprintf("%s (%s) - %s [ACTIVE]",
				vault.Name, vault.Type, vault.Description))
		} else {
			ui.PrintListItem(fmt.Sprintf("  %s", indicator), fmt.Sprintf("%s (%s) - %s",
				vault.Name, vault.Type, vault.Description))
		}
	}
	fmt.Println()
	return nil
}

func vaultSwitch(vaultName string) error {
	ui.PrintTitle("switching vault")
	fmt.Println()

	exists, err := vaultmanager.VaultExists(vaultName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("vault '%s' does not exist", vaultName)
	}

	if err := vaultmanager.SetActiveVault(vaultName); err != nil {
		return fmt.Errorf("failed to switch vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("switched to vault '%s'", vaultName))
	fmt.Println()
	return nil
}

func vaultDelete(vaultName string) error {
	ui.PrintTitle("deleting vault")
	fmt.Println()

	exists, err := vaultmanager.VaultExists(vaultName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("vault '%s' does not exist", vaultName)
	}

	ui.PrintWarning("!", fmt.Sprintf("this will permanently delete vault '%s' and all its secrets!", vaultName))
	ui.PrintPrompt("type the vault name to confirm: ")
	var confirm string
	fmt.Scanln(&confirm)

	if confirm != vaultName {
		ui.PrintMuted("deletion cancelled")
		fmt.Println()
		return nil
	}

	if err := vaultmanager.DeleteVault(vaultName); err != nil {
		return fmt.Errorf("failed to delete vault: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("vault '%s' deleted successfully", vaultName))
	fmt.Println()
	return nil
}

func vaultInfo() error {
	ui.PrintTitle("vault information")
	fmt.Println()

	activeVault, err := vaultmanager.GetActiveVault()
	if err != nil {
		return err
	}

	info, err := vaultmanager.GetVaultInfo(activeVault)
	if err != nil {
		return err
	}

	ui.PrintSuccess("+", fmt.Sprintf("active vault: %s", info.Name))
	ui.PrintMuted(fmt.Sprintf("  type: %s", info.Type))
	ui.PrintMuted(fmt.Sprintf("  description: %s", info.Description))
	ui.PrintMuted(fmt.Sprintf("  created: %s", info.CreatedAt.Format("2006-01-02 15:04:05")))
	
	vaultDir := vaultmanager.GetVaultDir(activeVault)
	ui.PrintMuted(fmt.Sprintf("  location: %s", vaultDir))
	
	initialized := keyring.VaultKeyringExists(vaultDir)
	if initialized {
		ui.PrintMuted("  status: initialized")
	} else {
		ui.PrintMuted("  status: not initialized")
		fmt.Println()
		ui.PrintTip("tip: use 'secrets init' to initialize this vault")
	}
	
	fmt.Println()
	return nil
}

func secretsRestore(args []string) error {
	if len(args) < 1 {
		ui.PrintError("x", "usage: secrets restore <name> [--output <path>] [--folder]")
		return nil
	}

	secretName := args[0]
	var outputPath string
	isFolder := false

	for i := 1; i < len(args); i++ {
		if args[i] == "--output" && i+1 < len(args) {
			outputPath = args[i+1]
			i++
		} else if args[i] == "--folder" {
			isFolder = true
		}
	}

	if isFolder {
		return secretsRestoreFolder(secretName, outputPath)
	}

	ui.PrintTitle("restoring secret to file")
	fmt.Println()

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

func secretsRestoreFolder(folderName string, outputPath string) error {
	ui.PrintTitle("restoring folder from vault")
	fmt.Println()

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	ui.PrintSuccess(">", fmt.Sprintf("restoring folder: %s", folderName))
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
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to load vault: %w", err)
	}

	prefix := folderName + "__"
	var folderSecrets []string
	for secretName := range vault.SecretsMetadata {
		if strings.HasPrefix(secretName, prefix) {
			folderSecrets = append(folderSecrets, secretName)
		}
	}

	if len(folderSecrets) == 0 {
		return fmt.Errorf("no secrets found for folder '%s' - use 'secrets list' to see available secrets", folderName)
	}

	ui.PrintInfo("*", fmt.Sprintf("found %d file(s) in folder backup", len(folderSecrets)))
	fmt.Println()

	if outputPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		outputPath = filepath.Join(cwd, folderName)
		ui.PrintMuted(fmt.Sprintf("  using default path: %s", outputPath))
		fmt.Println()
	}

	if _, err := os.Stat(outputPath); err == nil {
		ui.PrintWarning("!", fmt.Sprintf("directory already exists: %s", outputPath))
		ui.PrintPrompt("overwrite contents? (yes/no): ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "yes" && confirm != "y" {
			ui.PrintMuted("restore cancelled")
			fmt.Println()
			return nil
		}
	}

	if err := os.MkdirAll(outputPath, 0700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	ui.PrintInfo(">", "restoring files...")
	fmt.Println()

	successCount := 0
	failCount := 0
	var totalBytesWritten int64

	sort.Strings(folderSecrets)

	for i, secretName := range folderSecrets {
		relPath := strings.TrimPrefix(secretName, prefix)
		relPath = filepath.FromSlash(relPath)
		
		fullOutputPath := filepath.Join(outputPath, relPath)

		if useGroupVault {
			canAccess, err := multiuser.UserCanAccessSecret(currentUsername, secretName)
			if err != nil || !canAccess {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - access denied", i+1, len(folderSecrets), relPath))
				failCount++
				continue
			}
		}

		metadata, exists := vault.SecretsMetadata[secretName]
		if !exists {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - not found", i+1, len(folderSecrets), relPath))
			failCount++
			continue
		}

		encryptedBytes := make([]byte, len(metadata.EncryptedValue)/2)
		_, err = fmt.Sscanf(metadata.EncryptedValue, "%x", &encryptedBytes)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to decode", i+1, len(folderSecrets), relPath))
			failCount++
			continue
		}

		parentDir := filepath.Dir(fullOutputPath)
		if err := os.MkdirAll(parentDir, 0700); err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to create directory", i+1, len(folderSecrets), relPath))
			failCount++
			continue
		}

		isStreamed := crypto.IsStreamEncrypted(encryptedBytes)
		var bytesWritten int64

		if isStreamed {
			outFile, err := os.OpenFile(fullOutputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to create file", i+1, len(folderSecrets), relPath))
				failCount++
				continue
			}

			encryptedReader := strings.NewReader(string(encryptedBytes))
			bytesWritten, err = crypto.DecryptStream(encryptedReader, outFile, masterKey)
			outFile.Close()

			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - decryption failed", i+1, len(folderSecrets), relPath))
				failCount++
				continue
			}
		} else {
			secret, err := crypto.DecryptSecret(encryptedBytes, masterKey)
			if err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - decryption failed", i+1, len(folderSecrets), relPath))
				failCount++
				continue
			}

			if err := os.WriteFile(fullOutputPath, secret, 0600); err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to write", i+1, len(folderSecrets), relPath))
				failCount++
				continue
			}

			bytesWritten = int64(len(secret))
		}

		totalBytesWritten += bytesWritten
		ui.PrintSuccess("+", fmt.Sprintf("  %d/%d: %s", i+1, len(folderSecrets), relPath))
		successCount++
	}

	audit.LogEventForVault(vaultDir, currentUsername, "restore-folder", folderName, true, fmt.Sprintf("%d files", successCount), masterKey)

	fmt.Println()
	ui.PrintSuccess("+", fmt.Sprintf("folder '%s' restored to: %s", folderName, outputPath))
	ui.PrintMuted(fmt.Sprintf("  %d file(s) restored successfully", successCount))
	if failCount > 0 {
		ui.PrintWarning("!", fmt.Sprintf("  %d file(s) failed", failCount))
	}
	if totalBytesWritten < 1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %d bytes", totalBytesWritten))
	} else if totalBytesWritten < 1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f KB", float64(totalBytesWritten)/1024))
	} else if totalBytesWritten < 1024*1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f MB", float64(totalBytesWritten)/(1024*1024)))
	} else {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f GB", float64(totalBytesWritten)/(1024*1024*1024)))
	}
	fmt.Println()
	ui.PrintWarning("!", "remember to securely delete restored files when done!")
	ui.PrintTip(fmt.Sprintf("tip: use 'secrets wipe %s --folder' to securely delete when done", outputPath))
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

func secretsWipeFolder(folderPath string) error {
	ui.PrintTitle("securely wiping folder")
	fmt.Println()

	folderInfo, err := os.Stat(folderPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("folder does not exist: %s", folderPath)
		}
		return fmt.Errorf("failed to stat folder: %w", err)
	}

	if !folderInfo.IsDir() {
		return fmt.Errorf("path is not a directory: %s", folderPath)
	}

	var files []string
	var totalSize int64
	err = filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to scan folder: %w", err)
	}

	if len(files) == 0 {
		ui.PrintWarning("!", "no files found in folder")
		fmt.Println()
		return nil
	}

	ui.PrintWarning("!", fmt.Sprintf("this will securely delete folder: %s", folderPath))
	ui.PrintMuted(fmt.Sprintf("  contains %d file(s)", len(files)))
	if totalSize < 1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %d bytes", totalSize))
	} else if totalSize < 1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f KB", float64(totalSize)/1024))
	} else if totalSize < 1024*1024*1024 {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f MB", float64(totalSize)/(1024*1024)))
	} else {
		ui.PrintMuted(fmt.Sprintf("  total size: %.2f GB", float64(totalSize)/(1024*1024*1024)))
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

	fmt.Println()
	ui.PrintInfo(">", "securely wiping files...")
	fmt.Println()

	successCount := 0
	failCount := 0

	for i, filePath := range files {
		relPath, _ := filepath.Rel(folderPath, filePath)

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to stat", i+1, len(files), relPath))
			failCount++
			continue
		}

		fileSize := fileInfo.Size()

		file, err := os.OpenFile(filePath, os.O_WRONLY, 0600)
		if err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to open", i+1, len(files), relPath))
			failCount++
			continue
		}

		bufferSize := 1024 * 1024
		if fileSize < int64(bufferSize) {
			bufferSize = int(fileSize)
		}
		buffer := make([]byte, bufferSize)

		wiped := true
		for pass := 1; pass <= 3; pass++ {
			if _, err := file.Seek(0, 0); err != nil {
				ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - wipe failed at pass %d", i+1, len(files), relPath, pass))
				wiped = false
				break
			}

			remaining := fileSize
			for remaining > 0 {
				writeSize := int64(bufferSize)
				if remaining < writeSize {
					writeSize = remaining
				}

				if _, err := io.ReadFull(rand.Reader, buffer[:writeSize]); err != nil {
					wiped = false
					break
				}

				if _, err := file.Write(buffer[:writeSize]); err != nil {
					wiped = false
					break
				}

				remaining -= writeSize
			}

			if !wiped {
				break
			}

			file.Sync()
		}

		file.Close()

		if !wiped {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - wipe failed", i+1, len(files), relPath))
			failCount++
			continue
		}

		if err := os.Remove(filePath); err != nil {
			ui.PrintError("x", fmt.Sprintf("  %d/%d: %s - failed to remove", i+1, len(files), relPath))
			failCount++
			continue
		}

		ui.PrintSuccess("+", fmt.Sprintf("  %d/%d: %s", i+1, len(files), relPath))
		successCount++
	}

	if successCount > 0 {
		if err := os.RemoveAll(folderPath); err != nil {
			ui.PrintWarning("!", fmt.Sprintf("failed to remove folder structure: %v", err))
		}
	}

	fmt.Println()
	ui.PrintSuccess("+", "folder securely wiped and deleted!")
	ui.PrintMuted(fmt.Sprintf("  %d file(s) wiped successfully", successCount))
	if failCount > 0 {
		ui.PrintWarning("!", fmt.Sprintf("  %d file(s) failed", failCount))
	}
	ui.PrintMuted(fmt.Sprintf("  removed: %s", folderPath))
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


