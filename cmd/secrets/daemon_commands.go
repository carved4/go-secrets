package main

import (
	"fmt"
	"os"

	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/daemon"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/carved4/go-secrets/internal/ui"
)

func handleDaemonCommand(args []string) error {
	if len(args) == 0 {
		ui.PrintError("x", "usage: secrets daemon <start|stop|status>")
		return nil
	}

	subcommand := args[0]
	switch subcommand {
	case "start":
		return daemonStart()
	case "stop":
		return daemonStop()
	case "status":
		return daemonStatus()
	default:
		ui.PrintError("x", fmt.Sprintf("unknown daemon command: %s", subcommand))
		return nil
	}
}

func daemonStart() error {
	ui.PrintTitle("starting secrets daemon")
	fmt.Println()

	if daemon.IsDaemonRunning() {
		ui.PrintWarning("!", "daemon is already running")
		fmt.Println()
		return nil
	}

	if err := storage.CheckRateLimit(); err != nil {
		return err
	}

	masterKey, vaultDir, err := authenticateVault()
	if err != nil {
		return err
	}

	ui.PrintInfo(">", "initializing daemon...")
	fmt.Println()

	d := daemon.New(masterKey, vaultDir)

	if err := d.Start(); err != nil {
		crypto.CleanupBytes(masterKey)
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	if err := daemon.WritePidFile(os.Getpid()); err != nil {
		ui.PrintWarning("!", fmt.Sprintf("failed to write PID file: %v", err))
	}

	ui.PrintSuccess("+", "daemon started successfully!")
	ui.PrintMuted("  listening on: " + daemon.WindowsPipeName)
	ui.PrintMuted("  cache TTL: 30 seconds")
	fmt.Println()
	ui.PrintTip("tip: use 'secrets env run -- <command>' to run apps with transparent secret injection")
	ui.PrintTip("     use 'secrets daemon stop' to stop the daemon")
	fmt.Println()

	// Keep daemon running
	sigChan := make(chan os.Signal, 1)
	<-sigChan

	ui.PrintInfo(">", "shutting down daemon...")
	d.Stop()
	daemon.RemovePidFile()

	return nil
}

func daemonStop() error {
	ui.PrintTitle("stopping secrets daemon")
	fmt.Println()

	if !daemon.IsDaemonRunning() {
		ui.PrintWarning("!", "daemon is not running")
		fmt.Println()
		return nil
	}

	pid, err := daemon.ReadPidFile()
	if err != nil {
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	ui.PrintInfo(">", fmt.Sprintf("sending shutdown signal to PID %d...", pid))
	fmt.Println()

	if err := process.Kill(); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	daemon.RemovePidFile()

	ui.PrintSuccess("+", "daemon stopped successfully!")
	fmt.Println()
	return nil
}

func daemonStatus() error {
	ui.PrintTitle("daemon status")
	fmt.Println()

	if daemon.IsDaemonRunning() {
		pid, err := daemon.ReadPidFile()
		if err != nil {
			ui.PrintSuccess("+", "daemon is running (PID unknown)")
		} else {
			ui.PrintSuccess("+", fmt.Sprintf("daemon is running (PID: %d)", pid))
		}
		ui.PrintMuted("  pipe: " + daemon.WindowsPipeName)

		// Try to ping the daemon
		client := daemon.NewDaemonClient("status-check")
		if client.Ping() == nil {
			ui.PrintSuccess("+", "daemon is responsive")
		} else {
			ui.PrintWarning("!", "daemon is not responding to ping")
		}
	} else {
		ui.PrintWarning("!", "daemon is not running")
		fmt.Println()
		ui.PrintTip("tip: use 'secrets daemon start' to start the daemon")
	}

	fmt.Println()
	return nil
}

