package server

import (
	"context"
	"e2e_chat/internal/model"
	"encoding/json"
	"fmt"
)

func (c *HttpServer) GetMessagesFromCache(ctx context.Context, to string) ([]*model.Message, error) {
	key := fmt.Sprintf("to: %s", to)
	vals, err := c.redisService.LRange(ctx, key)
	if err != nil {
		return nil, err
	}
	c.redisService.Del(ctx, key)

	var res []*model.Message
	for _, v := range vals {
		var m model.Message
		err := json.Unmarshal([]byte(v), &m)
		if err != nil {
			return nil, err
		}

		res = append(res, &m)
	}

	return res, nil
}

func (c *HttpServer) PutMessagesToCache(ctx context.Context, to string, messages []*model.Message) error {
	key := fmt.Sprintf("to: %s", to)
	var vals []interface{}
	for _, m := range messages {
		data, _ := json.Marshal(m)
		vals = append(vals, data)
	}

	return c.redisService.RPush(ctx, key, vals)
}
