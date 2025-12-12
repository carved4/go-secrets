package audit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/storage"
)

type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Secret    string    `json:"secret,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
}

type AuditLog struct {
	Events   []string `json:"events"`
	Checksum string   `json:"checksum"`
}

func GetAuditLogPath() string {
	vaultDir := storage.GetVaultDir()
	return filepath.Join(vaultDir, "audit.json")
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

func LogEvent(user string, action string, secret string, success bool, errorMsg string, masterKey []byte) error {
	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		User:      user,
		Action:    action,
		Secret:    secret,
		IP:        getLocalIP(),
		Success:   success,
		Error:     errorMsg,
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	encryptedEvent, err := crypto.EncryptSecret(eventJSON, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt audit event: %w", err)
	}

	auditLogPath := GetAuditLogPath()
	auditLog, err := loadAuditLog(auditLogPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load audit log: %w", err)
	}

	if auditLog == nil {
		auditLog = &AuditLog{
			Events: []string{},
		}
	}

	auditLog.Events = append(auditLog.Events, hex.EncodeToString(encryptedEvent))

	if len(auditLog.Events) > 10000 {
		auditLog.Events = auditLog.Events[len(auditLog.Events)-10000:]
	}

	auditLog.Checksum = computeAuditLogChecksum(auditLog.Events, masterKey)

	if err := saveAuditLog(auditLogPath, auditLog); err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}

	return nil
}

func loadAuditLog(path string) (*AuditLog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var auditLog AuditLog
	if err := json.Unmarshal(data, &auditLog); err != nil {
		return nil, err
	}

	return &auditLog, nil
}

func VerifyAuditLogIntegrity(masterKey []byte) error {
	auditLogPath := GetAuditLogPath()
	auditLog, err := loadAuditLog(auditLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to load audit log: %w", err)
	}

	if auditLog.Checksum == "" {
		return nil
	}

	expectedChecksum := computeAuditLogChecksum(auditLog.Events, masterKey)
	if auditLog.Checksum != expectedChecksum {
		return fmt.Errorf("audit log integrity check failed - possible tampering detected")
	}

	return nil
}

func computeAuditLogChecksum(events []string, masterKey []byte) string {
	h := crypto.NewHMAC(masterKey)
	for _, event := range events {
		h.Write([]byte(event))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func saveAuditLog(path string, auditLog *AuditLog) error {
	data, err := json.MarshalIndent(auditLog, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal audit log: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write audit log: %w", err)
	}

	return nil
}

func GetAuditHistory(masterKey []byte, limit int, filterUser string, filterAction string) ([]AuditEvent, error) {
	if err := VerifyAuditLogIntegrity(masterKey); err != nil {
		return nil, err
	}

	auditLogPath := GetAuditLogPath()
	auditLog, err := loadAuditLog(auditLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEvent{}, nil
		}
		return nil, fmt.Errorf("failed to load audit log: %w", err)
	}

	var events []AuditEvent
	for _, encryptedEventHex := range auditLog.Events {
		encryptedEvent, err := hex.DecodeString(encryptedEventHex)
		if err != nil {
			continue
		}

		decryptedEvent, err := crypto.DecryptSecret(encryptedEvent, masterKey)
		if err != nil {
			continue
		}

		var event AuditEvent
		if err := json.Unmarshal(decryptedEvent, &event); err != nil {
			crypto.CleanupBytes(decryptedEvent)
			continue
		}
		crypto.CleanupBytes(decryptedEvent)

		if filterUser != "" && event.User != filterUser {
			continue
		}

		if filterAction != "" && event.Action != filterAction {
			continue
		}

		events = append(events, event)
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}

	return events, nil
}

func ClearAuditLog() error {
	auditLogPath := GetAuditLogPath()
	if err := os.Remove(auditLogPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear audit log: %w", err)
	}
	return nil
}
