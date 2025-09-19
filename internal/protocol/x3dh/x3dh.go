package x3dh

import (
	"e2e_chat/internal/cryptographic/dh"
	"e2e_chat/internal/cryptographic/kdf"
	"e2e_chat/internal/model"
)

type (
	X3DHBase struct {
	}

	X3DHSender struct {
		*X3DHBase
	}

	X3DHReceiver struct {
		*X3DHBase
	}
)

func (s *X3DHBase) GenerateShareKey(dh1, dh2, dh3, dh4 []byte) ([]byte, error) {
	var concat []byte = make([]byte, 0)
	concat = append(concat, dh1...)
	concat = append(concat, dh2...)
	concat = append(concat, dh3...)
	if dh4 != nil {
		concat = append(concat, dh4...)
	}

	var sk = make([]byte, 32)
	var secret []byte = nil
	var salt []byte = concat
	var info []byte = []byte("SharedKey")

	_, err := kdf.HKDF(secret, salt, info, sk)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

func (s *X3DHSender) GenerateShareKey(skb *model.SenderKeyBundle) ([]byte, error) {
	dh1, err := dh.X25519SharedSecret([32]byte(skb.IKPrivA), [32]byte(skb.SPKPubB))
	if err != nil {
		return nil, err
	}

	dh2, err := dh.X25519SharedSecret([32]byte(skb.EKPrivA), [32]byte(skb.IKPubB))
	if err != nil {
		return nil, err
	}

	dh3, err := dh.X25519SharedSecret([32]byte(skb.EKPrivA), [32]byte(skb.SPKPubB))
	if err != nil {
		return nil, err
	}

	var dh4 []byte = nil
	if skb.OTKPubB != nil {
		dh4, err = dh.X25519SharedSecret([32]byte(skb.EKPrivA), [32]byte(skb.OTKPubB))
		if err != nil {
			return nil, err
		}
	}

	// f, err := os.Create("sender.txt")
	// f.WriteString(hex.EncodeToString(dh1))
	// f.WriteString("\n")
	// f.WriteString(hex.EncodeToString(dh2))
	// f.WriteString("\n")
	// f.WriteString(hex.EncodeToString(dh3))

	sk, err := s.X3DHBase.GenerateShareKey(dh1, dh2, dh3, dh4)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func (s *X3DHReceiver) GenerateShareKey(rkb *model.ReceiverKeyBundle) ([]byte, error) {
	dh1, err := dh.X25519SharedSecret([32]byte(rkb.SPKPrivB), [32]byte(rkb.IKPubA))
	if err != nil {
		return nil, err
	}

	dh2, err := dh.X25519SharedSecret([32]byte(rkb.IKPrivB), [32]byte(rkb.EKPubA))
	if err != nil {
		return nil, err
	}

	dh3, err := dh.X25519SharedSecret([32]byte(rkb.SPKPrivB), [32]byte(rkb.EKPubA))
	if err != nil {
		return nil, err
	}

	var dh4 []byte = nil
	if rkb.OTKPrivB != nil {
		dh4, err = dh.X25519SharedSecret([32]byte(rkb.OTKPrivB), [32]byte(rkb.EKPubA))
		if err != nil {
			return nil, err
		}
	}

	// f, err := os.Create("receiver.txt")
	// f.WriteString(hex.EncodeToString(dh1))
	// f.WriteString("\n")
	// f.WriteString(hex.EncodeToString(dh2))
	// f.WriteString("\n")
	// f.WriteString(hex.EncodeToString(dh3))

	sk, err := s.X3DHBase.GenerateShareKey(dh1, dh2, dh3, dh4)
	if err != nil {
		return nil, err
	}
	return sk, nil
}
