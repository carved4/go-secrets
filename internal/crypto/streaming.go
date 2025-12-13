package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
)

const (
	ChunkSize = 64 * 1024 * 1024 
)

type StreamHeader struct {
	Version   uint8
	ChunkSize uint32
}


func EncryptStream(reader io.Reader, writer io.Writer, masterKey []byte) (int64, error) {
	c, err := aes.NewCipher(masterKey)
	if err != nil {
		log.Println("could not make cipher")
		return 0, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("could not make gcm")
		return 0, err
	}

	header := StreamHeader{
		Version:   1,
		ChunkSize: ChunkSize,
	}
	if err := binary.Write(writer, binary.LittleEndian, header.Version); err != nil {
		return 0, fmt.Errorf("failed to write version: %w", err)
	}
	if err := binary.Write(writer, binary.LittleEndian, header.ChunkSize); err != nil {
		return 0, fmt.Errorf("failed to write chunk size: %w", err)
	}

	var totalBytes int64
	buffer := make([]byte, ChunkSize)
	chunkNum := uint64(0)

	for {
		n, err := io.ReadFull(reader, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return totalBytes, fmt.Errorf("failed to read chunk: %w", err)
		}

		if n == 0 {
			break
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return totalBytes, fmt.Errorf("failed to generate nonce: %w", err)
		}

		encryptedChunk := gcm.Seal(nonce, nonce, buffer[:n], nil)

		if err := binary.Write(writer, binary.LittleEndian, chunkNum); err != nil {
			return totalBytes, fmt.Errorf("failed to write chunk number: %w", err)
		}

		chunkLen := uint32(len(encryptedChunk))
		if err := binary.Write(writer, binary.LittleEndian, chunkLen); err != nil {
			return totalBytes, fmt.Errorf("failed to write chunk length: %w", err)
		}

		if _, err := writer.Write(encryptedChunk); err != nil {
			return totalBytes, fmt.Errorf("failed to write encrypted chunk: %w", err)
		}

		totalBytes += int64(n)
		chunkNum++

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	return totalBytes, nil
}

func DecryptStream(reader io.Reader, writer io.Writer, masterKey []byte) (int64, error) {
	c, err := aes.NewCipher(masterKey)
	if err != nil {
		log.Println("could not make cipher")
		return 0, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println("could not make gcm")
		return 0, err
	}

	var version uint8
	if err := binary.Read(reader, binary.LittleEndian, &version); err != nil {
		return 0, fmt.Errorf("failed to read version: %w", err)
	}
	if version != 1 {
		return 0, fmt.Errorf("unsupported stream version: %d", version)
	}

	var chunkSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &chunkSize); err != nil {
		return 0, fmt.Errorf("failed to read chunk size: %w", err)
	}

	var totalBytes int64
	nonceSize := gcm.NonceSize()

	for {
		var chunkNum uint64
		if err := binary.Read(reader, binary.LittleEndian, &chunkNum); err != nil {
			if err == io.EOF {
				break
			}
			return totalBytes, fmt.Errorf("failed to read chunk number: %w", err)
		}

		var encryptedLen uint32
		if err := binary.Read(reader, binary.LittleEndian, &encryptedLen); err != nil {
			return totalBytes, fmt.Errorf("failed to read chunk length: %w", err)
		}

		encryptedChunk := make([]byte, encryptedLen)
		if _, err := io.ReadFull(reader, encryptedChunk); err != nil {
			return totalBytes, fmt.Errorf("failed to read encrypted chunk: %w", err)
		}

		if len(encryptedChunk) < nonceSize {
			return totalBytes, fmt.Errorf("encrypted chunk too short")
		}
		nonce, ciphertext := encryptedChunk[:nonceSize], encryptedChunk[nonceSize:]

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return totalBytes, fmt.Errorf("failed to decrypt chunk %d: %w", chunkNum, err)
		}

		if _, err := writer.Write(plaintext); err != nil {
			return totalBytes, fmt.Errorf("failed to write plaintext: %w", err)
		}

		totalBytes += int64(len(plaintext))
	}

	return totalBytes, nil
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

