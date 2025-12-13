package main

import (
	"bufio"
	"fmt"
	"os"
	
	"github.com/carved4/go-secrets/internal/keyring"
	"github.com/carved4/go-secrets/internal/ui"
	"github.com/carved4/go-secrets/internal/vaultmanager"
)
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
