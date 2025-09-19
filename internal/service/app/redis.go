package app

import (
	"context"
	"e2e_chat/internal/protocol/doubleratchet"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

func (c *App) SaveState(ctx context.Context, from string, to string, state *doubleratchet.RatchetState) error {
	key := fmt.Sprintf("from: %s, to: %s", from, to)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return c.redisService.Set(ctx, key, data, 2*time.Hour)
}

func (c *App) GetState(ctx context.Context, from string, to string) (*doubleratchet.RatchetState, error) {
	key := fmt.Sprintf("from: %s, to: %s", from, to)
	v, err := c.redisService.Get(ctx, key)
	if err == redis.Nil {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var state doubleratchet.RatchetState
	err = json.Unmarshal([]byte(v), &state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}
