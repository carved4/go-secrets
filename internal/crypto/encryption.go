package crypto

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
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

func ReadUserPass() (password string, err error) {
	ui.PrintPrompt("enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Println("passphrase could not be read")
		return
	}
	password = string(bytePassword)
	return password, nil
}

func ReadUserPassWithValidation() (password string, err error) {
	for {
		ui.PrintPrompt("enter password (min 12 chars): ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			log.Println("passphrase could not be read")
			return "", err
		}
		password = string(bytePassword)
		if err := ValidatePasswordStrength(password); err != nil {
			ui.PrintError("x", err.Error())
			fmt.Println()
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
	// Only generate salt if none provided
	if len(salt) == 0 {
		salt = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			log.Println("could not generate salt")
			return nil, nil, err
		}
	}
	iterations := 600000
	keyLength := 32
	derivedKey = pbkdf2.Key(password, salt, iterations, keyLength, sha256.New)
	return derivedKey, salt, nil
}

func EncryptMasterKey(masterKey []byte, derivedKey []byte) ([]byte, error) {
	c, err := aes.NewCipher(derivedKey)
	if err != nil {
		log.Println("could not make cipher")
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("could not make gcm")
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println("could not generate nonce")
		return nil, err
	}
	encryptedMasterKey := gcm.Seal(nonce, nonce, masterKey, nil)
	return encryptedMasterKey, nil
}

func DecryptMasterKey(encryptedMasterKey []byte, derivedKey []byte) ([]byte, error) {
	c, err := aes.NewCipher(derivedKey)
	if err != nil {
		log.Println("could not make cipher")
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("could not make gcm")
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(encryptedMasterKey) < nonceSize {
		log.Println("ciphertext too short")
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := encryptedMasterKey[:nonceSize], encryptedMasterKey[nonceSize:]
	masterKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println("could not decrypt master key")
		return nil, err
	}
	return masterKey, nil
}

func EncryptSecret(secret []byte, masterKey []byte) ([]byte, error) {
	c, err := aes.NewCipher(masterKey)
	if err != nil {
		log.Println("could not make cipher")
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("could not make gcm")
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Println("could not generate nonce")
		return nil, err
	}
	encryptedSecret := gcm.Seal(nonce, nonce, secret, nil)
	return encryptedSecret, nil
}

func DecryptSecret(secret []byte, masterKey []byte) ([]byte, error) {
	c, err := aes.NewCipher(masterKey)
	if err != nil {
		log.Println("could not make cipher")
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("could not make gcm")
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(secret) < nonceSize {
		log.Println("ciphertext too short")
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := secret[:nonceSize], secret[nonceSize:]
	decryptedSecret, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println("could not decrypt secret")
		return nil, err
	}
	return decryptedSecret, nil
}

var lockedMemory = make(map[*byte]bool)
var lockMutex sync.Mutex

func SecureBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	if err := LockMemory(data); err != nil {
		log.Printf("warning: could not lock memory: %v", err)
		return
	}
	lockMutex.Lock()
	lockedMemory[&data[0]] = true
	lockMutex.Unlock()
}

func CleanupBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	ZeroMemory(data)

	lockMutex.Lock()
	wasLocked := lockedMemory[&data[0]]
	delete(lockedMemory, &data[0])
	lockMutex.Unlock()

	if wasLocked {
		if err := UnlockMemory(data); err != nil {
			log.Printf("warning: could not unlock memory: %v", err)
		}
	}
}
