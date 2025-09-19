package kdf

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KDFRootKey derives a new RootKey and ChainKey from the old root key + DH output.
// Uses HKDF with SHA-256, info = "RootKDF".
func HKDF(secret, salt, info, buffer []byte) (int, error) {
	h := hkdf.New(sha256.New, secret, salt, info)
	return io.ReadFull(h, buffer)
}
