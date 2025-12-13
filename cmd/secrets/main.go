package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/keyring"
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
		return secretsRotate(args[1:])
	case "vault":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets vault <create|list|switch|delete|info>")
			return nil
		}
		return handleVaultCommand(args[1:])
	case "restore":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets restore <name> [--output <path>]")
			return nil
		}
		return secretsRestore(args[1:])
	case "wipe":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets wipe <filepath>")
			return nil
		}
		return secretsWipeFile(args[1])
	case "daemon":
		if len(args) < 2 {
			ui.PrintError("x", "usage: secrets daemon <start|stop|status>")
			return nil
		}
		return handleDaemonCommand(args[1:])
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
	ui.PrintListItem("  >", "get <name> [--clip]  retrieve a secret")
	ui.PrintListItem("  >", "list           list all secret names")
	ui.PrintListItem("  >", "delete <name>  delete a secret")
	ui.PrintListItem("  >", "env run -- <cmd>  run command with secrets as env vars")
	ui.PrintListItem("  >", "export <file>  export encrypted backup to file")
	ui.PrintListItem("  >", "import <file>  import secrets from encrypted backup")
	ui.PrintListItem("  >", "import-passwords <csv>  import passwords from Chrome CSV export")
	ui.PrintListItem("  >", "backup         create automatic backup")
	ui.PrintListItem("  >", "history        view audit log history")
	ui.PrintListItem("  >", "rotate [name]  rotate all secrets or a specific secret")
	ui.PrintListItem("  >", "restore <name> [--output <path>]  restore secret to file")
	ui.PrintListItem("  >", "wipe <path>    securely delete a file")
	fmt.Println()
	ui.PrintInfo("*", "daemon management:")
	fmt.Println()
	ui.PrintListItem("  >", "daemon start   start the secrets daemon (for transparent env var injection)")
	ui.PrintListItem("  >", "daemon stop    stop the running daemon")
	ui.PrintListItem("  >", "daemon status  check daemon status")
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
	ui.PrintMuted("  # Basic secrets management")
	ui.PrintMuted("  secrets init                    # create solo vault")
	ui.PrintMuted("  secrets add                     # add to solo vault")
	ui.PrintMuted("  secrets add --file secret.txt   # add from file")
	ui.PrintMuted("  secrets get API_KEY --clip      # get secret to clipboard")
	fmt.Println()
	ui.PrintMuted("  # Daemon-based transparent injection (recommended)")
	ui.PrintMuted("  secrets daemon start            # start daemon (authenticate once)")
	ui.PrintMuted("  secrets env run -- node app.js  # run node app with secrets")
	ui.PrintMuted("  secrets env run -- python main.py  # run python app with secrets")
	ui.PrintMuted("  secrets daemon stop             # stop daemon when done")
	fmt.Println()
	ui.PrintMuted("  # Other commands")
	ui.PrintMuted("  secrets import-passwords passwords.csv  # import Chrome passwords")
	ui.PrintMuted("  secrets rotate                  # rotate all secrets")
	ui.PrintMuted("  secrets rotate API_KEY          # rotate specific secret")
	ui.PrintMuted("  secrets restore DB_FILE --output ./database.db  # restore file secret")
	ui.PrintMuted("  secrets wipe ./database.db      # securely delete file")
	fmt.Println()
	ui.PrintMuted("  # Multi-user vaults")
	ui.PrintMuted("  secrets --group init            # create group vault")
	ui.PrintMuted("  secrets --group add             # add to group vault")
	ui.PrintMuted("  secrets --group user add        # add user to group vault")
	fmt.Println()
	ui.PrintInfo("*", "daemon workflow:")
	fmt.Println()
	ui.PrintMuted("  The daemon holds your vault credentials in memory, so you")
	ui.PrintMuted("  authenticate once and run multiple commands without re-entering")
	ui.PrintMuted("  passwords. Secrets are never in the process environment - they're")
	ui.PrintMuted("  fetched on-demand via IPC from the daemon. Perfect for CI/CD!")
	fmt.Println()
}
