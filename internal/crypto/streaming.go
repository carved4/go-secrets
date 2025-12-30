package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"runtime/secret"
)

const (
	ChunkSize = 64 * 1024 * 1024
)

type StreamHeader struct {
	Version   uint8
	ChunkSize uint32
}

func EncryptStream(reader io.Reader, writer io.Writer, masterKey []byte) (totalBytes int64, err error) {
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

		header := StreamHeader{
			Version:   1,
			ChunkSize: ChunkSize,
		}
		if err = binary.Write(writer, binary.LittleEndian, header.Version); err != nil {
			err = fmt.Errorf("failed to write version: %w", err)
			return
		}
		if err = binary.Write(writer, binary.LittleEndian, header.ChunkSize); err != nil {
			err = fmt.Errorf("failed to write chunk size: %w", err)
			return
		}

		buffer := make([]byte, ChunkSize)
		chunkNum := uint64(0)

		for {
			n, readErr := io.ReadFull(reader, buffer)
			if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				err = fmt.Errorf("failed to read chunk: %w", readErr)
				return
			}

			if n == 0 {
				break
			}

			nonce := make([]byte, gcm.NonceSize())
			if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
				err = fmt.Errorf("failed to generate nonce: %w", err)
				return
			}

			encryptedChunk := gcm.Seal(nonce, nonce, buffer[:n], nil)

			if err = binary.Write(writer, binary.LittleEndian, chunkNum); err != nil {
				err = fmt.Errorf("failed to write chunk number: %w", err)
				return
			}

			chunkLen := uint32(len(encryptedChunk))
			if err = binary.Write(writer, binary.LittleEndian, chunkLen); err != nil {
				err = fmt.Errorf("failed to write chunk length: %w", err)
				return
			}

			if _, err = writer.Write(encryptedChunk); err != nil {
				err = fmt.Errorf("failed to write encrypted chunk: %w", err)
				return
			}

			totalBytes += int64(n)
			chunkNum++

			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				break
			}
		}
	})
	return totalBytes, err
}

func DecryptStream(reader io.Reader, writer io.Writer, masterKey []byte) (totalBytes int64, err error) {
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

		var version uint8
		if err = binary.Read(reader, binary.LittleEndian, &version); err != nil {
			err = fmt.Errorf("failed to read version: %w", err)
			return
		}
		if version != 1 {
			err = fmt.Errorf("unsupported stream version: %d", version)
			return
		}

		var chunkSize uint32
		if err = binary.Read(reader, binary.LittleEndian, &chunkSize); err != nil {
			err = fmt.Errorf("failed to read chunk size: %w", err)
			return
		}

		nonceSize := gcm.NonceSize()

		for {
			var chunkNum uint64
			if err = binary.Read(reader, binary.LittleEndian, &chunkNum); err != nil {
				if err == io.EOF {
					err = nil
					break
				}
				err = fmt.Errorf("failed to read chunk number: %w", err)
				return
			}

			var encryptedLen uint32
			if err = binary.Read(reader, binary.LittleEndian, &encryptedLen); err != nil {
				err = fmt.Errorf("failed to read chunk length: %w", err)
				return
			}

			encryptedChunk := make([]byte, encryptedLen)
			if _, err = io.ReadFull(reader, encryptedChunk); err != nil {
				err = fmt.Errorf("failed to read encrypted chunk: %w", err)
				return
			}

			if len(encryptedChunk) < nonceSize {
				err = fmt.Errorf("encrypted chunk too short")
				return
			}
			nonce, ciphertext := encryptedChunk[:nonceSize], encryptedChunk[nonceSize:]

			var plaintext []byte
			plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				err = fmt.Errorf("failed to decrypt chunk %d: %w", chunkNum, err)
				return
			}

			if _, err = writer.Write(plaintext); err != nil {
				err = fmt.Errorf("failed to write plaintext: %w", err)
				return
			}

			totalBytes += int64(len(plaintext))
		}
	})
	return totalBytes, err
}

func IsStreamEncrypted(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	version := data[0]
	if version != 1 {
		return false
	}
	chunkSize := binary.LittleEndian.Uint32(data[1:5])
	return chunkSize >= 1024*1024 && chunkSize <= 256*1024*1024
}
