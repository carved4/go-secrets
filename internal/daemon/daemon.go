package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
	"runtime"
	"github.com/carved4/go-secrets/internal/crypto"
	"github.com/carved4/go-secrets/internal/storage"
	"github.com/Microsoft/go-winio"
)

const (
	WindowsPipeName = `\\.\pipe\go-secrets-daemon`
	MaxCacheTTL     = 30 * time.Second
)

type SecretsDaemon struct {
	masterKey      []byte
	vaultDir       string
	secretCache    map[string]*CachedSecret
	cacheMutex     sync.RWMutex
	authTokens     map[string]*AuthToken
	authMutex      sync.RWMutex
	listener       net.Listener
	stopChan       chan struct{}
	activeConns    sync.WaitGroup
}

type CachedSecret struct {
	Value     []byte
	ExpiresAt time.Time
}

type AuthToken struct {
	Token     string
	ProcessID int
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Request struct {
	Type      string `json:"type"`
	AuthToken string `json:"auth_token"`
	SecretKey string `json:"secret_key,omitempty"`
	ProcessID int    `json:"process_id,omitempty"` // For token registration
}

type Response struct {
	Success bool              `json:"success"`
	Value   string            `json:"value,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"` // For bulk get_all
	Error   string            `json:"error,omitempty"`
}

func New(masterKey []byte, vaultDir string) *SecretsDaemon {
	secureKey := make([]byte, len(masterKey))
	copy(secureKey, masterKey)
	crypto.SecureBytes(secureKey)

	return &SecretsDaemon{
		masterKey:   secureKey,
		vaultDir:    vaultDir,
		secretCache: make(map[string]*CachedSecret),
		authTokens:  make(map[string]*AuthToken),
		stopChan:    make(chan struct{}),
	}
}

func (d *SecretsDaemon) Start() error {
	// Use Windows Named Pipes
	listener, err := winio.ListenPipe(WindowsPipeName, nil)
	if err != nil {
		return fmt.Errorf("failed to create named pipe: %w", err)
	}
	d.listener = listener

	// Start cache cleanup goroutine
	go d.cleanupExpiredCache()

	// Accept connections
	go d.acceptConnections()

	return nil
}

func (d *SecretsDaemon) Stop() {
	close(d.stopChan)
	if d.listener != nil {
		d.listener.Close()
	}
	d.activeConns.Wait()
	d.cleanup()
}

func (d *SecretsDaemon) cleanup() {
	d.cacheMutex.Lock()
	defer d.cacheMutex.Unlock()

	for key, secret := range d.secretCache {
		if secret.Value != nil {
			crypto.CleanupBytes(secret.Value)
		}
		delete(d.secretCache, key)
	}

	if d.masterKey != nil {
		crypto.CleanupBytes(d.masterKey)
		d.masterKey = nil
	}

	runtime.GC()
}

func (d *SecretsDaemon) GenerateAuthToken(processID int) string {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	d.authMutex.Lock()
	defer d.authMutex.Unlock()

	d.authTokens[token] = &AuthToken{
		Token:     token,
		ProcessID: processID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	return token
}

func (d *SecretsDaemon) validateAuthToken(token string) bool {
	d.authMutex.RLock()
	defer d.authMutex.RUnlock()

	auth, exists := d.authTokens[token]
	if !exists {
		return false
	}

	if time.Now().After(auth.ExpiresAt) {
		return false
	}

	return true
}

func (d *SecretsDaemon) acceptConnections() {
	for {
		select {
		case <-d.stopChan:
			return
		default:
			conn, err := d.listener.Accept()
			if err != nil {
				select {
				case <-d.stopChan:
					return
				default:
					continue
				}
			}

			d.activeConns.Add(1)
			go d.handleConnection(conn)
		}
	}
}

func (d *SecretsDaemon) handleConnection(conn net.Conn) {
	defer d.activeConns.Done()
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	var req Request
	if err := decoder.Decode(&req); err != nil {
		if err != io.EOF {
			encoder.Encode(Response{
				Success: false,
				Error:   "invalid request format",
			})
		}
		return
	}

	switch req.Type {
	case "register_token":
		d.handleRegisterToken(req, encoder)
		return
	case "ping":
		encoder.Encode(Response{Success: true})
		return
	case "get_secret":
		if !d.validateAuthToken(req.AuthToken) {
			encoder.Encode(Response{
				Success: false,
				Error:   "authentication failed",
			})
			return
		}
		d.handleGetSecret(req, encoder)
	case "get_all_secrets":
		if !d.validateAuthToken(req.AuthToken) {
			encoder.Encode(Response{
				Success: false,
				Error:   "authentication failed",
			})
			return
		}
		d.handleGetAllSecrets(req, encoder)
	default:
		encoder.Encode(Response{
			Success: false,
			Error:   "unknown request type",
		})
	}
}

func (d *SecretsDaemon) handleGetSecret(req Request, encoder *json.Encoder) {
	if req.SecretKey == "" {
		encoder.Encode(Response{
			Success: false,
			Error:   "secret_key is required",
		})
		return
	}

	// Check cache first
	d.cacheMutex.RLock()
	cached, exists := d.secretCache[req.SecretKey]
	d.cacheMutex.RUnlock()

	if exists && time.Now().Before(cached.ExpiresAt) {
		encoder.Encode(Response{
			Success: true,
			Value:   string(cached.Value),
		})
		return
	}

	// Load from vault
	secret, err := d.loadSecretFromVault(req.SecretKey)
	if err != nil {
		encoder.Encode(Response{
			Success: false,
			Error:   fmt.Sprintf("secret not found: %v", err),
		})
		return
	}

	// Cache the secret
	d.cacheMutex.Lock()
	if old, exists := d.secretCache[req.SecretKey]; exists {
		if old.Value != nil {
			crypto.CleanupBytes(old.Value)
		}
	}
	d.secretCache[req.SecretKey] = &CachedSecret{
		Value:     secret,
		ExpiresAt: time.Now().Add(MaxCacheTTL),
	}
	d.cacheMutex.Unlock()

	encoder.Encode(Response{
		Success: true,
		Value:   string(secret),
	})
}

func (d *SecretsDaemon) handleRegisterToken(req Request, encoder *json.Encoder) {
	if req.AuthToken == "" {
		encoder.Encode(Response{
			Success: false,
			Error:   "auth_token is required",
		})
		return
	}

	d.authMutex.Lock()
	d.authTokens[req.AuthToken] = &AuthToken{
		Token:     req.AuthToken,
		ProcessID: req.ProcessID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	d.authMutex.Unlock()

	encoder.Encode(Response{
		Success: true,
	})
}

func (d *SecretsDaemon) handleGetAllSecrets(req Request, encoder *json.Encoder) {
	vault, err := storage.LoadVaultFromDir(d.vaultDir)
	if err != nil {
		encoder.Encode(Response{
			Success: false,
			Error:   fmt.Sprintf("failed to load vault: %v", err),
		})
		return
	}

	secrets := make(map[string]string)
	
	for secretKey, metadata := range vault.SecretsMetadata {
		encryptedBytes := make([]byte, len(metadata.EncryptedValue)/2)
		_, err = fmt.Sscanf(metadata.EncryptedValue, "%x", &encryptedBytes)
		if err != nil {
			continue
		}

		secret, err := crypto.DecryptSecret(encryptedBytes, d.masterKey)
		if err != nil {
			continue
		}

		secrets[secretKey] = string(secret)
		crypto.CleanupBytes(secret)
	}

	encoder.Encode(Response{
		Success: true,
		Secrets: secrets,
	})
}

func (d *SecretsDaemon) loadSecretFromVault(secretKey string) ([]byte, error) {
	vault, err := storage.LoadVaultFromDir(d.vaultDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load vault: %w", err)
	}

	metadata, exists := vault.SecretsMetadata[secretKey]
	if !exists {
		return nil, fmt.Errorf("secret '%s' not found", secretKey)
	}

	encryptedBytes := make([]byte, len(metadata.EncryptedValue)/2)
	_, err = fmt.Sscanf(metadata.EncryptedValue, "%x", &encryptedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret: %w", err)
	}

	secret, err := crypto.DecryptSecret(encryptedBytes, d.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Make a secured copy
	secureCopy := make([]byte, len(secret))
	copy(secureCopy, secret)
	crypto.SecureBytes(secureCopy)
	crypto.CleanupBytes(secret)

	return secureCopy, nil
}

func (d *SecretsDaemon) cleanupExpiredCache() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopChan:
			return
		case <-ticker.C:
			d.cacheMutex.Lock()
			now := time.Now()
			for key, secret := range d.secretCache {
				if now.After(secret.ExpiresAt) {
					if secret.Value != nil {
						crypto.CleanupBytes(secret.Value)
					}
					delete(d.secretCache, key)
				}
			}
			d.cacheMutex.Unlock()

			// Cleanup expired auth tokens
			d.authMutex.Lock()
			for token, auth := range d.authTokens {
				if now.After(auth.ExpiresAt) {
					delete(d.authTokens, token)
				}
			}
			d.authMutex.Unlock()
		}
	}
}

// Client functions for connecting to daemon

type DaemonClient struct {
	authToken string
}

func NewDaemonClient(authToken string) *DaemonClient {
	return &DaemonClient{
		authToken: authToken,
	}
}

func (c *DaemonClient) GetSecret(key string) (string, error) {
	conn, err := winio.DialPipe(WindowsPipeName, nil)
	if err != nil {
		return "", fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := Request{
		Type:      "get_secret",
		AuthToken: c.authToken,
		SecretKey: key,
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if !resp.Success {
		return "", fmt.Errorf("daemon error: %s", resp.Error)
	}

	return resp.Value, nil
}

func (c *DaemonClient) Ping() error {
	conn, err := winio.DialPipe(WindowsPipeName, nil)
	if err != nil {
		return fmt.Errorf("daemon not running: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	req := Request{
		Type:      "ping",
		AuthToken: c.authToken,
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("ping failed: %s", resp.Error)
	}

	return nil
}

// PID file management for daemon lifecycle (Windows)

func GetPidFilePath() string {
	return filepath.Join(os.TempDir(), "go-secrets-daemon.pid")
}

func WritePidFile(pid int) error {
	return os.WriteFile(GetPidFilePath(), []byte(fmt.Sprintf("%d", pid)), 0600)
}

func ReadPidFile() (int, error) {
	data, err := os.ReadFile(GetPidFilePath())
	if err != nil {
		return 0, err
	}
	var pid int
	_, err = fmt.Sscanf(string(data), "%d", &pid)
	return pid, err
}

func RemovePidFile() error {
	return os.Remove(GetPidFilePath())
}

func IsDaemonRunning() bool {
	// On Windows, the best way is to try to connect to the named pipe
	client := NewDaemonClient("ping-check")
	return client.Ping() == nil
}

// GenerateAuthTokenForDaemon generates a token and registers it with the running daemon
// Returns the token string that should be passed to child processes
func GenerateAuthTokenForDaemon() (string, error) {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	
	// Connect to daemon and register the token
	conn, err := winio.DialPipe(WindowsPipeName, nil)
	if err != nil {
		return "", fmt.Errorf("failed to connect to daemon: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send registration request
	req := Request{
		Type:      "register_token",
		AuthToken: token,
		ProcessID: os.Getpid(), // Current process PID (the secrets CLI)
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return "", fmt.Errorf("failed to send registration request: %w", err)
	}

	decoder := json.NewDecoder(conn)
	var resp Response
	if err := decoder.Decode(&resp); err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if !resp.Success {
		return "", fmt.Errorf("token registration failed: %s", resp.Error)
	}

	return token, nil
}

