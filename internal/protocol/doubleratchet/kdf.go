package doubleratchet

import (
	"crypto/sha256"
	"e2e_chat/internal/cryptographic/kdf"
)

// InitialRootKey: a simple helper that derives an initial root key from a shared secret.
func InitialRootKey(sharedSecret []byte) []byte {
	sum := sha256.Sum256(sharedSecret)
	return sum[:]
}

// KDFRootKey derives a new RootKey and ChainKey from the old root key + DH output.
// Uses HKDF with SHA-256, info = "RootKDF".
func KDFRootKey(rootKey, dhOut []byte) (newRootKey, newChainKey []byte, err error) {
	salt := rootKey           // old root key acts as salt
	ikm := dhOut              // input key material = DH output
	info := []byte("RootKDF") // domain separation

	buffer := make([]byte, 64)
	_, err = kdf.HKDF(ikm, salt, info, buffer)
	if err != nil {
		return nil, nil, err
	}

	newRootKey = buffer[:32]
	newChainKey = buffer[32:]

	return newRootKey, newChainKey, nil
}

// KDFChainKey derives the next ChainKey and a MessageKey.
// Uses HKDF with SHA-256, info = "ChainKDF".
func KDFChainKey(chainKey []byte) (nextChainKey, msgKey []byte, err error) {
	salt := chainKey
	ikm := []byte("ChainInput") // filler, doesn’t matter much as long as unique
	info := []byte("ChainKDF")

	buffer := make([]byte, 64)
	_, err = kdf.HKDF(ikm, salt, info, buffer)
	if err != nil {
		return nil, nil, err
	}

	nextChainKey = buffer[:32]
	msgKey = buffer[32:]

	return nextChainKey, msgKey, err
}
