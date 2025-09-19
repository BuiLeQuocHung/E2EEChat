package model

type (
	SharedKey struct {
		IKPub     []byte `json:"ik_pub"`
		SPKPub    []byte `json:"spk_pub"`
		Signature []byte `json:"signature"`
	}
)
