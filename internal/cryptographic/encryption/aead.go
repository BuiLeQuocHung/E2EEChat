package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AES-GCM helper. key must be 16/24/32 bytes. We produce keys of 32 bytes from KDF.
func AEADEncrypt(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("rand.Read nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	// return nonce || ciphertext
	return append(nonce, ciphertext...), nil
}

func AEADDecrypt(key, nonceAndCiphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	ns := aead.NonceSize()
	if len(nonceAndCiphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := nonceAndCiphertext[:ns]
	ct := nonceAndCiphertext[ns:]
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("aead.Open: %w", err)
	}
	return plain, nil
}
