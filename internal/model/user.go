package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type (
	User struct {
		ID      primitive.ObjectID `bson:"_id,omitempty"`
		Name    string             `bson:"name"`
		IKPriv  []byte             `bson:"ikPriv"`
		SPKPriv []byte             `bson:"spkPriv"`
	}
)
