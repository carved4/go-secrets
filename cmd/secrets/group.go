package main

import (
	"fmt"
	"strings"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/audit"
	"github.com/carved4/go-secrets/internal/multiuser"
	"github.com/carved4/go-secrets/internal/ui"
)
func secretsInitMultiUser() error {
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
	defer crypto.CleanupBytes(adminPassword)

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
	defer crypto.CleanupBytes(newPassword)

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
