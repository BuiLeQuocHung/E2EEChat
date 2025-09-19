package model

type (
	X3DHHandshake struct {
		EKPub []byte
	}

	SenderKeyBundle struct {
		IKPrivA []byte
		EKPrivA []byte

		IKPubB  []byte
		SPKPubB []byte
		OTKPubB []byte
	}

	ReceiverKeyBundle struct {
		IKPubA []byte
		EKPubA []byte

		IKPrivB  []byte
		SPKPrivB []byte
		OTKPrivB []byte
	}
)
