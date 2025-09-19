package app

import (
	"context"
	"e2e_chat/internal/cryptographic/dh"
	"e2e_chat/internal/model"
)

func (c *App) getUserAndCreateIfNotExist(ctx context.Context, username string) (*model.User, error) {
	user, err := c.userRepo.GetByName(ctx, username)
	if err != nil {
		return nil, err
	}

	if user != nil {
		return user, nil
	}

	ikPriv, _, err := dh.NewX25519KeyPair()
	if err != nil {
		return nil, err
	}

	spkPriv, _, err := dh.NewX25519KeyPair()
	if err != nil {
		return nil, err
	}

	user = &model.User{
		Name:    username,
		IKPriv:  ikPriv[:],
		SPKPriv: spkPriv[:],
	}

	_, err = c.userRepo.Create(ctx, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}
