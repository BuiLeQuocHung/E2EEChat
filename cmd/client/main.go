package main

import (
	"context"
	"e2e_chat/internal/repository/user"
	"e2e_chat/internal/service/app"
	redisSvc "e2e_chat/internal/service/redis"

	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	// os.Args[0] is the program name, os.Args[1:] are arguments
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <username>")
	}

	username := os.Args[1]

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

	ctx := context.Background()

	userRepo := user.NewUserRepo(db)
	app := app.NewApp(userRepo, redis)
	app.Run(ctx, username)

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	<-done

	app.Stop()
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
