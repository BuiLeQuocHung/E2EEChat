package signature

import (
	"crypto/ed25519"
	"crypto/rand"
)

func NewEd25519Keypair() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func ED25519Sign(privKeyBytes []byte, message []byte) []byte {
	privKey := ed25519.PrivateKey(privKeyBytes)
	return ed25519.Sign(privKey, message)
}

func ED25519Verify(pubKeyBytes []byte, message []byte, signature []byte) bool {
	pubKey := ed25519.PublicKey(pubKeyBytes)
	return ed25519.Verify(pubKey, message, signature)
}
