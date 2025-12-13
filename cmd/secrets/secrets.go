package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"github.com/atotto/clipboard"
	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/daemon"
	"github.com/carved4/go-secrets/internal/keyring"
	"github.com/carved4/go-secrets/internal/multiuser"
	"github.com/carved4/go-secrets/internal/privileges"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
	"github.com/carved4/go-secrets/internal/vaultmanager"
	"github.com/carved4/go-secrets/shims"
) 



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

	// Ensure vault is registered in config (needed for GetVaultInfo during authentication)
	exists, err := vaultmanager.VaultExists(activeVault)
	if err != nil {
		return fmt.Errorf("failed to check vault existence: %w", err)
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

	isMultiUser, err := multiuser.IsMultiUserMode()
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

	_, err = multiuser.GetMasterKeyForUser(currentUsername, password)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
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
		canAccess, err := multiuser.UserCanAccessSecret(currentUsername, secretName)
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
		canAccess, err := multiuser.UserCanAccessSecret(currentUsername, secretName)
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

	// Check if vault is initialized
	if !keyring.VaultKeyringExists(vaultDir) {
		ui.PrintWarning("!", fmt.Sprintf("vault '%s' has not been initialized yet", vaultName))
		fmt.Println()
		ui.PrintTip("run 'secrets init' to initialize this vault")
		fmt.Println()
		return nil
	}

	vault, err := storage.LoadVaultFromDir(vaultDir)
	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if len(vault.SecretsMetadata) == 0 {
		ui.PrintMuted("no secrets stored yet")
		fmt.Println()
		return nil
	}

	ui.PrintInfo("*", fmt.Sprintf("found %d secret(s):", len(vault.SecretsMetadata)))
	fmt.Println()

	names := make([]string, 0, len(vault.SecretsMetadata))
	for name := range vault.SecretsMetadata {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		metadata := vault.SecretsMetadata[name]
		age := time.Since(metadata.CreatedAt)
		ageStr := formatDuration(age)

		if metadata.CreatedAt.Equal(metadata.UpdatedAt) {
			ui.PrintSuccess("  +", fmt.Sprintf("%s (created %s ago)", name, ageStr))
		} else {
			updateAge := time.Since(metadata.UpdatedAt)
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

func secretsEnvRun(cmdArgs []string) error {
	ui.PrintTitle("running with secrets (daemon mode)")
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

	// Check if daemon is running
	if !daemon.IsDaemonRunning() {
		ui.PrintError("x", "secrets daemon is not running")
		fmt.Println()
		ui.PrintTip("tip: start the daemon first:")
		ui.PrintMuted("     secrets daemon start")
		fmt.Println()
		ui.PrintMuted("the daemon holds your vault credentials in memory so you don't")
		ui.PrintMuted("need to enter passwords for every command - perfect for CI/CD!")
		fmt.Println()
		return fmt.Errorf("daemon not running")
	}

	ui.PrintSuccess("+", "daemon is running")

	// Detect runtime and get shim path
	runtime, shimPath, err := detectRuntimeAndShim(actualCmd)
	if err != nil {
		ui.PrintWarning("!", fmt.Sprintf("could not detect runtime: %v", err))
		ui.PrintMuted("  supported: node, python")
		fmt.Println()
		return err
	}

	ui.PrintSuccess("+", fmt.Sprintf("detected runtime: %s", runtime))
	ui.PrintMuted(fmt.Sprintf("  shim: %s", shimPath))

	// Generate auth token for this process
	authToken, err := daemon.GenerateAuthTokenForDaemon()
	if err != nil {
		return fmt.Errorf("failed to generate auth token: %w", err)
	}
	ui.PrintSuccess("+", "generated auth token for secure IPC")

	// Build command with shim injection
	var modifiedCmd []string
	switch runtime {
	case "node":
		modifiedCmd = []string{"node", "-r", shimPath}
		modifiedCmd = append(modifiedCmd, actualCmd[1:]...) // skip "node" from actualCmd
	case "python":
		// For Python, use -c to import preload module then exec the script
		pythonShimDir := filepath.Dir(shimPath)
		importCmd := fmt.Sprintf("import sys; sys.path.insert(0, r'%s'); import go_secrets_preload; exec(open(r'%s').read())", 
			pythonShimDir, 
			actualCmd[1]) // The script path
		modifiedCmd = []string{"python", "-c", importCmd}
	default:
		return fmt.Errorf("unsupported runtime: %s", runtime)
	}

	if len(filterPrefixes) > 0 {
		ui.PrintMuted(fmt.Sprintf("  filtered by prefixes: %s", strings.Join(filterPrefixes, ", ")))
	}
	ui.PrintMuted(fmt.Sprintf("  running: %s", strings.Join(modifiedCmd, " ")))
	fmt.Println()

	// Set up environment with auth token
	cmd := exec.Command(modifiedCmd[0], modifiedCmd[1:]...)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("__SECRETS_AUTH_TOKEN=%s", authToken))

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	fmt.Println()
	ui.PrintSuccess("+", "command completed successfully")
	return nil
}

func detectRuntimeAndShim(cmdArgs []string) (string, string, error) {
	if len(cmdArgs) == 0 {
		return "", "", fmt.Errorf("no command specified")
	}

	command := filepath.Base(cmdArgs[0])
	
	var runtime string
	var shimContent string
	var shimFilename string
	
	switch {
	case strings.Contains(command, "node"):
		runtime = "node"
		shimContent = shims.NodeShimContent
		shimFilename = "go-secrets-preload.js"
	case strings.Contains(command, "python"):
		runtime = "python"
		shimContent = shims.PythonShimContent
		shimFilename = "go_secrets_preload.py"
	default:
		return "", "", fmt.Errorf("unsupported command: %s (only node and python are supported)", command)
	}
	
	// Write shim to temp directory
	shimDir := filepath.Join(os.TempDir(), "go-secrets-shims")
	if err := os.MkdirAll(shimDir, 0700); err != nil {
		return "", "", fmt.Errorf("failed to create shim directory: %w", err)
	}
	
	shimPath := filepath.Join(shimDir, shimFilename)
	
	// Write the embedded shim content to the temp file
	if err := os.WriteFile(shimPath, []byte(shimContent), 0600); err != nil {
		return "", "", fmt.Errorf("failed to write shim file: %w", err)
	}
	
	return runtime, shimPath, nil
}

