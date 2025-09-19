package dh

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Generate a new X25519 key pair
func NewX25519KeyPair() (priv, pub [32]byte, err error) {
	_, err = rand.Read(priv[:])
	if err != nil {
		return priv, pub, fmt.Errorf("failed to generate private key: %w", err)
	}
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub, nil
}

// Perform X25519 scalar multiplication: priv * pub
func X25519SharedSecret(priv, pub [32]byte) ([]byte, error) {
	return curve25519.X25519(priv[:], pub[:])
}

func ConvertToECDHFormat(privKey []byte) (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	return curve.NewPrivateKey(privKey)

}
