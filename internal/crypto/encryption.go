package crypto

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"runtime/secret"
	"strings"
	"sync"
	"syscall"

	"github.com/carved4/go-secrets/internal/ui"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatalf("could not generate master key: %v", err)
		return nil, err
	}
	return key, nil

}
func ValidatePasswordStrength(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must be at least 12 characters long")
	}
	return nil
}

func ReadUserPass() ([]byte, error) {
	ui.PrintPrompt("enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Println("passphrase could not be read")
		return nil, err
	}
	return password, nil
}

func ReadUserPassWithValidation() ([]byte, error) {
	for {
		ui.PrintPrompt("enter password (min 12 chars): ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			log.Println("passphrase could not be read")
			return nil, err
		}
		if err := ValidatePasswordStrength(string(password)); err != nil {
			ui.PrintError("x", err.Error())
			fmt.Println()
			CleanupBytes(password)
			continue
		}
		return password, nil
	}
}

func ValidateSecretName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("secret name cannot be empty")
	}
	if len(name) > 100 {
		return fmt.Errorf("secret name too long (max 100 chars)")
	}
	for i, c := range name {
		if i == 0 {
			if !((c >= 'A' && c <= 'Z') || c == '_') {
				return fmt.Errorf("secret name must start with A-Z or underscore")
			}
		} else {
			if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return fmt.Errorf("secret name can only contain A-Z, 0-9, and underscore")
			}
		}
	}
	return nil
}

func ReadSecretName() (string, error) {
	for {
		ui.PrintPrompt("enter a name for this secret (A-Z, 0-9, _): ")
		var name string
		_, err := fmt.Scanln(&name)
		if err != nil {
			return "", err
		}
		if err := ValidateSecretName(name); err != nil {
			ui.PrintError("x", err.Error())
			fmt.Println()
			continue
		}
		return name, nil
	}
}
func ReadUserSecret() (string, error) {
	ui.PrintInfo(">", "paste your secret below")
	ui.PrintMuted("  (type 'END' on a new line when done)")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	var lines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		if strings.TrimSpace(line) == "END" {
			break
		}
		lines = append(lines, line)
		if err == io.EOF {
			break
		}
	}

	return strings.Join(lines, ""), nil
}
func DeriveKeyFromUserPass(password []byte, salt []byte) (derivedKey []byte, usedSalt []byte, err error) {
	secret.Do(func() {
		// Only generate salt if none provided
		if len(salt) == 0 {
			salt = make([]byte, 16)
			if _, err = io.ReadFull(rand.Reader, salt); err != nil {
				log.Println("could not generate salt")
				return
			}
		}
		iterations := 600000
		keyLength := 32
		derivedKey = pbkdf2.Key(password, salt, iterations, keyLength, sha256.New)
		usedSalt = salt
	})
	return derivedKey, usedSalt, err
}

func DeriveVaultKey(password []byte, vaultName string, salt []byte) (derivedKey []byte, usedSalt []byte, err error) {
	secret.Do(func() {
		// Only generate salt if none provided
		if len(salt) == 0 {
			salt = make([]byte, 16)
			if _, err = io.ReadFull(rand.Reader, salt); err != nil {
				log.Println("could not generate salt")
				return
			}
		}

		// Mix vault context into password for vault-specific key derivation
		// This ensures each vault has a cryptographically independent master key
		// even when using the same passphrase
		h := sha256.New()
		h.Write(password)
		h.Write([]byte("::vault-context::"))
		h.Write([]byte(vaultName))
		contextualPassword := h.Sum(nil)
		defer ZeroMemory(contextualPassword)

		iterations := 600000
		keyLength := 32
		derivedKey = pbkdf2.Key(contextualPassword, salt, iterations, keyLength, sha256.New)
		usedSalt = salt
	})
	return derivedKey, usedSalt, err
}

func EncryptMasterKey(masterKey []byte, derivedKey []byte) (encryptedMasterKey []byte, err error) {
	secret.Do(func() {
		var c cipher.Block
		c, err = aes.NewCipher(derivedKey)
		if err != nil {
			log.Println("could not make cipher")
			return
		}
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(c)
		if err != nil {
			log.Println("could not make gcm")
			return
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			log.Println("could not generate nonce")
			return
		}
		encryptedMasterKey = gcm.Seal(nonce, nonce, masterKey, nil)
	})
	return encryptedMasterKey, err
}

func DecryptMasterKey(encryptedMasterKey []byte, derivedKey []byte) (masterKey []byte, err error) {
	secret.Do(func() {
		var c cipher.Block
		c, err = aes.NewCipher(derivedKey)
		if err != nil {
			log.Println("could not make cipher")
			return
		}
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(c)
		if err != nil {
			log.Println("could not make gcm")
			return
		}
		nonceSize := gcm.NonceSize()
		if len(encryptedMasterKey) < nonceSize {
			log.Println("ciphertext too short")
			err = fmt.Errorf("ciphertext too short")
			return
		}
		nonce, ciphertext := encryptedMasterKey[:nonceSize], encryptedMasterKey[nonceSize:]
		masterKey, err = gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Println("could not decrypt master key")
			return
		}
	})
	return masterKey, err
}

func EncryptSecret(secretData []byte, masterKey []byte) (encryptedSecret []byte, err error) {
	secret.Do(func() {
		var c cipher.Block
		c, err = aes.NewCipher(masterKey)
		if err != nil {
			log.Println("could not make cipher")
			return
		}
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(c)
		if err != nil {
			log.Println("could not make gcm")
			return
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			log.Println("could not generate nonce")
			return
		}
		encryptedSecret = gcm.Seal(nonce, nonce, secretData, nil)
	})
	return encryptedSecret, err
}

func DecryptSecret(secretData []byte, masterKey []byte) (decryptedSecret []byte, err error) {
	secret.Do(func() {
		var c cipher.Block
		c, err = aes.NewCipher(masterKey)
		if err != nil {
			log.Println("could not make cipher")
			return
		}
		var gcm cipher.AEAD
		gcm, err = cipher.NewGCM(c)
		if err != nil {
			log.Println("could not make gcm")
			return
		}
		nonceSize := gcm.NonceSize()
		if len(secretData) < nonceSize {
			log.Println("ciphertext too short")
			err = fmt.Errorf("ciphertext too short")
			return
		}
		nonce, ciphertext := secretData[:nonceSize], secretData[nonceSize:]
		decryptedSecret, err = gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Println("could not decrypt secret")
			return
		}
	})
	return decryptedSecret, err
}

var lockedMemory = make(map[*byte]bool)
var lockMutex sync.Mutex

func SecureBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	lockMutex.Lock()
	defer lockMutex.Unlock()

	if lockedMemory[&data[0]] {
		return
	}

	if err := LockMemory(data); err != nil {
		log.Printf("warning: could not lock memory: %v", err)
		return
	}
	lockedMemory[&data[0]] = true
}

func CleanupBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	ZeroMemory(data)

	lockMutex.Lock()
	wasLocked := lockedMemory[&data[0]]
	if wasLocked {
		delete(lockedMemory, &data[0])
	}
	lockMutex.Unlock()

	if wasLocked {
		if err := UnlockMemory(data); err != nil {
			log.Printf("warning: could not unlock memory: %v", err)
		}
	}
}

func NewHMAC(key []byte) hash.Hash {
	return hmac.New(sha256.New, key)
}

func DecodeHexString(hexStr string) ([]byte, error) {
	decoded := make([]byte, len(hexStr)/2)
	_, err := fmt.Sscanf(hexStr, "%x", &decoded)
	return decoded, err
}
