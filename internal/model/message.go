package model

type (
	// Header is the message header carried along with each ciphertext.
	Header struct {
		Pub    [32]byte // sender's current ratchet public key
		MsgNum uint32   // message number in the sending chain
		Prev   uint32   // previous sending chain length (PN)
	}

	Message struct {
		From          string         `json:"from" validate:"required"`
		To            string         `json:"to" validate:"required"`
		Header        *Header        `json:"header" validate:"required"`
		Ciphertext    []byte         `json:"ciphertext" validate:"required"`
		X3DHHandShake *X3DHHandshake `json:"x3dh_handshake,omitempty"`
	}
)
