package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type (
	RedisService struct {
		rdb *redis.Client
	}
)

func NewRedis(rdb *redis.Client) *RedisService {
	return &RedisService{
		rdb: rdb,
	}
}

func (r *RedisService) RPush(ctx context.Context, key string, value ...any) error {
	return r.rdb.RPush(ctx, key, value...).Err()
}

func (r *RedisService) LRange(ctx context.Context, key string) ([]string, error) {
	return r.rdb.LRange(ctx, key, 0, -1).Result()
}

func (r *RedisService) Del(ctx context.Context, key string) error {
	return r.rdb.Del(ctx, key).Err()
}

func (r *RedisService) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	return r.rdb.Set(ctx, key, value, ttl).Err()
}

func (r *RedisService) Get(ctx context.Context, key string) (string, error) {
	return r.rdb.Get(ctx, key).Result()
}
