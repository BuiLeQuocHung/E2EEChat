package main

import (
	"context"
	"e2e_chat/internal/repository/user"
	redisSvc "e2e_chat/internal/service/redis"
	"e2e_chat/internal/service/server"

	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	mongoDBClient, err := initMongo()
	if err != nil {
		panic(err)
	}

	db := mongoDBClient.Database("mydb")

	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Redis server
		Password: "",               // no password by default
		DB:       0,                // use default DB
	})

	redis := redisSvc.NewRedis(rdb)

	userRepo := user.NewUserRepo(db)
	c := server.NewHttpServer(userRepo, redis)
	c.Run()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done
}

func initMongo() (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		return nil, err
	}
	return client, client.Ping(ctx, nil)
}
