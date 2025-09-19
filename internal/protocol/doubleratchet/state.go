package doubleratchet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"e2e_chat/internal/cryptographic/dh"
	"e2e_chat/internal/cryptographic/encryption"
	"e2e_chat/internal/model"

	"golang.org/x/crypto/curve25519"
)

const MaxSkip = 1000

func headerToAAD(h model.Header) []byte {
	b := make([]byte, 32+4+4)
	copy(b[:32], h.Pub[:])
	binary.BigEndian.PutUint32(b[32:36], h.MsgNum)
	binary.BigEndian.PutUint32(b[36:40], h.Prev)
	return b
}

func skippedKey(pub [32]byte, msgNum uint32) string {
	return hex.EncodeToString(pub[:]) + ":" + fmt.Sprint(msgNum)
}

type RatchetState struct {
	RootKey []byte

	// Our current DH (private/public) used for sending ratchets
	DHsPriv [32]byte
	DHsPub  [32]byte

	// Remote party's current DH public key
	DHr [32]byte

	// Chain keys and counters
	SendingChainKey   []byte // CKs
	ReceivingChainKey []byte // CKr
	Ns                uint32 // messages sent in current sending chain
	Nr                uint32 // messages received in current receiving chain
	PN                uint32 // previous sending chain length

	// Skipped message keys: key => messageKey
	Skipped map[string][]byte
}

func NewState(rootKey []byte, ourPriv, ourPub, theirPub [32]byte) *RatchetState {
	st := &RatchetState{
		RootKey: rootKey,
		DHsPriv: ourPriv,
		DHsPub:  ourPub,
		DHr:     theirPub,
		Skipped: make(map[string][]byte),
	}
	return st
}

func (s *RatchetState) SetDHr(dhr [32]byte) {
	s.DHr = dhr
}

// InitiateSendingRatchet generates a new DH key for this party and derives a
// sending chain key (CKs). Call this before sending the first message of a
// new sending chain.
func (s *RatchetState) InitiateSendingRatchet() error {
	// new ephemeral DH key pair
	newPriv, newPub, err := dh.NewX25519KeyPair()
	if err != nil {
		return err
	}

	// DH with the *current* remote public key
	if bytes.Equal(s.DHr[:], make([]byte, 32)) {
		return errors.New("remote public key (DHr) not set; cannot ratchet")
	}
	shared, err := curve25519.X25519(newPriv[:], s.DHr[:])
	if err != nil {
		return fmt.Errorf("X25519 during InitiateSendingRatchet: %w", err)
	}

	// Update RK and derive the sending chain key
	s.RootKey, s.SendingChainKey, err = KDFRootKey(s.RootKey, shared)
	if err != nil {
		return fmt.Errorf("InitiateSendingRatchet: %v", err)
	}

	// commit the new DH key pair as our current sending key
	s.DHsPriv = newPriv
	s.DHsPub = newPub
	s.Ns = 0
	return nil
}

// saveSkippedMessages fills the skipped map for messages that were not received.
// oldTheirPub: the previous remote public key for which ReceivingChainKey applies.
// until: generate keys for message indices [Nr, until)
func (s *RatchetState) saveSkippedMessages(oldTheirPub [32]byte, until uint32) error {
	// nothing to do if receiving chain key is absent
	if s.ReceivingChainKey == nil {
		return errors.New("no receiving chain key when saving skipped messages")
	}

	// if until <= Nr, there are no new skipped messages to generate
	if until <= s.Nr {
		return nil
	}

	// how many keys we will generate
	toGenerate := int(until - s.Nr)

	// fail early if that would exceed our per-call limit
	if toGenerate > MaxSkip {
		return fmt.Errorf("skip limit exceeded: attempting to generate %d keys (max %d)", toGenerate, MaxSkip)
	}

	// optionally enforce a global cap on stored skipped keys
	if len(s.Skipped)+toGenerate > MaxSkip {
		return fmt.Errorf("skip map would exceed limit: have=%d need=%d max=%d", len(s.Skipped), toGenerate, MaxSkip)
	}

	// produce the keys
	for toGenerate > 0 {
		var msgKey []byte
		var err error
		s.ReceivingChainKey, msgKey, err = KDFChainKey(s.ReceivingChainKey)
		if err != nil {
			return err
		}

		k := skippedKey(oldTheirPub, s.Nr)
		cpy := make([]byte, len(msgKey))
		copy(cpy, msgKey)
		s.Skipped[k] = cpy

		s.Nr++
		toGenerate--
	}
	return nil
}

// Send produces a header and ciphertext for the plaintext message.
// It will produce a new sending chain (ratchet) if SendingChainKey is nil.
func (s *RatchetState) Send(plaintext []byte) (*model.Header, []byte, error) {
	var hdr model.Header
	// ensure we have a sending chain key; if not, start a ratchet
	if s.SendingChainKey == nil {
		if err := s.InitiateSendingRatchet(); err != nil {
			return &hdr, nil, err
		}
	}

	msgNum := s.Ns
	// derive next sender chain key and message key
	var msgKey []byte
	var err error
	s.SendingChainKey, msgKey, err = KDFChainKey(s.SendingChainKey)
	if err != nil {
		return nil, nil, err
	}
	s.Ns++

	hdr.Pub = s.DHsPub
	hdr.MsgNum = msgNum
	hdr.Prev = s.PN

	aad := headerToAAD(hdr)
	ct, err := encryption.AEADEncrypt(msgKey, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return &hdr, ct, nil
}

// Receive consumes a header and ciphertext, returns plaintext or error.
// It handles skipped messages and incoming ratchets.
func (s *RatchetState) Receive(h model.Header, ciphertext []byte) ([]byte, error) {
	// First — if this exact message was previously stored in skipped, use it
	key := skippedKey(h.Pub, h.MsgNum)
	if mk, ok := s.Skipped[key]; ok {
		// use it and delete from skipped list
		delete(s.Skipped, key)
		plain, err := encryption.AEADDecrypt(mk, ciphertext, headerToAAD(h))
		if err != nil {
			return nil, err
		}
		return plain, nil
	}

	// If header's pub != current DHr, a DH ratchet happened (sender generated a new DH)
	if !bytes.Equal(h.Pub[:], s.DHr[:]) {
		// Save skipped keys for the *old* receiving chain up to h.Prev (PN)
		oldTheirPub := s.DHr
		if s.ReceivingChainKey != nil && h.Prev > s.Nr {
			if err := s.saveSkippedMessages(oldTheirPub, h.Prev); err != nil {
				return nil, err
			}
		}

		// move to the new sending/receiving chain
		s.PN = s.Ns
		s.Ns = 0
		s.Nr = 0

		// compute DH using our current DHsPriv and the header's pub
		shared, err := curve25519.X25519(s.DHsPriv[:], h.Pub[:])
		if err != nil {
			return nil, fmt.Errorf("X25519 during receive ratchet: %w", err)
		}

		s.RootKey, s.ReceivingChainKey, err = KDFRootKey(s.RootKey, shared)
		if err != nil {
			return nil, err
		}
		// adopt new remote public key
		s.DHr = h.Pub
	}

	// Now generate skipped message keys within the (possibly new) receiving chain up to h.MsgNum
	if h.MsgNum > s.Nr {
		// create skipped keys for indices [Nr, h.MsgNum)
		if s.ReceivingChainKey == nil {
			return nil, errors.New("no receiving chain key available")
		}
		if err := s.saveSkippedMessages(s.DHr, h.MsgNum); err != nil {
			return nil, err
		}
	}

	// derive message key for the current message
	if s.ReceivingChainKey == nil {
		return nil, errors.New("no receiving chain key to derive message key")
	}
	var msgKey []byte
	var err error
	s.ReceivingChainKey, msgKey, err = KDFChainKey(s.ReceivingChainKey)
	if err != nil {
		return nil, err
	}
	s.Nr++

	plain, err := encryption.AEADDecrypt(msgKey, ciphertext, headerToAAD(h))
	if err != nil {
		return nil, err
	}
	return plain, nil
}
