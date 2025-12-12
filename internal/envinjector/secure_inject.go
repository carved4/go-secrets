package envinjector

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/carved4/go-secrets/internal/crypto"
)

type SecureEnvInjector struct {
	secrets     map[string][]byte
	secretNames []string
	mu          sync.Mutex
}

func NewSecureEnvInjector() *SecureEnvInjector {
	return &SecureEnvInjector{
		secrets: make(map[string][]byte),
	}
}

func (s *SecureEnvInjector) AddSecret(name string, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	secureValue := make([]byte, len(value))
	copy(secureValue, value)
	crypto.SecureBytes(secureValue)

	s.secrets[name] = secureValue
	s.secretNames = append(s.secretNames, name)
}

func (s *SecureEnvInjector) BuildEnv(baseEnv []string, filterPrefixes []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	filteredBase := s.filterExistingSecrets(baseEnv)

	env := make([]string, 0, len(filteredBase)+len(s.secrets))
	env = append(env, filteredBase...)

	for name, value := range s.secrets {
		if len(filterPrefixes) > 0 && !s.matchesPrefix(name, filterPrefixes) {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", name, strings.TrimSpace(string(value))))
	}

	return env
}

func (s *SecureEnvInjector) filterExistingSecrets(baseEnv []string) []string {
	filtered := make([]string, 0, len(baseEnv))
	for _, env := range baseEnv {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		if _, exists := s.secrets[parts[0]]; !exists {
			filtered = append(filtered, env)
		}
	}
	return filtered
}

func (s *SecureEnvInjector) matchesPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func (s *SecureEnvInjector) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for name, value := range s.secrets {
		crypto.CleanupBytes(value)
		delete(s.secrets, name)
	}
	s.secretNames = nil

	runtime.GC()
}

func (s *SecureEnvInjector) RunCommand(cmdArgs []string, filterPrefixes []string) error {
	if len(cmdArgs) == 0 {
		return fmt.Errorf("no command specified")
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)

	cmd.Env = s.BuildEnv(os.Environ(), filterPrefixes)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	return nil
}

func (s *SecureEnvInjector) GetSecretCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.secrets)
}

func (s *SecureEnvInjector) GetSecretNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, len(s.secretNames))
	copy(names, s.secretNames)
	return names
}
