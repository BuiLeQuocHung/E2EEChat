package user

import (
	"context"
	"e2e_chat/internal/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type (
	UserRepo struct {
		collection *mongo.Collection
	}
)

func NewUserRepo(db *mongo.Database) *UserRepo {
	return &UserRepo{
		collection: db.Collection("users"),
	}
}

func (r *UserRepo) GetByName(ctx context.Context, name string) (*model.User, error) {
	filter := bson.M{
		"name": name,
	}

	var user model.User
	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepo) Create(ctx context.Context, user *model.User) (primitive.ObjectID, error) {
	res, err := r.collection.InsertOne(ctx, user)
	if err != nil {
		return primitive.NilObjectID, err
	}

	id := res.InsertedID.(primitive.ObjectID)
	user.ID = id
	return id, nil
}
