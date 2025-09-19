package app

import (
	"e2e_chat/internal/cryptographic/dh"
	"e2e_chat/internal/model"
	"e2e_chat/internal/protocol/doubleratchet"
	"e2e_chat/internal/protocol/x3dh"
)

func (c *App) initReceiverState(message *model.Message) error {
	if c.state != nil {
		return nil
	}

	recv := &x3dh.X3DHReceiver{}
	sk, err := recv.GenerateShareKey(&model.ReceiverKeyBundle{
		IKPubA:   c.toSharedKeys.IKPub,
		EKPubA:   message.X3DHHandShake.EKPub,
		IKPrivB:  c.user.IKPriv,
		SPKPrivB: c.user.SPKPriv,
		OTKPrivB: nil,
	})
	if err != nil {
		return err
	}

	spkPrivB, err := dh.ConvertToECDHFormat(c.user.SPKPriv)
	if err != nil {
		return err
	}
	spkPubB := spkPrivB.PublicKey().Bytes()

	c.state = doubleratchet.NewState(sk, [32]byte(c.user.SPKPriv), [32]byte(spkPubB), [32]byte{})
	return nil
}

func (c *App) initSendingState() error {
	if c.state != nil {
		return nil
	}

	send := &x3dh.X3DHSender{}
	sk, err := send.GenerateShareKey(&model.SenderKeyBundle{
		IKPrivA: c.user.IKPriv,
		EKPrivA: c.ekPriv,
		IKPubB:  c.toSharedKeys.IKPub,
		SPKPubB: c.toSharedKeys.SPKPub,
		OTKPubB: nil,
	})
	if err != nil {
		return err
	}

	c.state = doubleratchet.NewState(sk, [32]byte{}, [32]byte{}, [32]byte(c.toSharedKeys.SPKPub))
	return nil
}
