package server

import (
	"context"
	"e2e_chat/internal/cryptographic/dh"
	"e2e_chat/internal/model"
	userRepo "e2e_chat/internal/repository/user"
	"e2e_chat/internal/service/redis"
	"e2e_chat/internal/utils/log"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type (
	HttpServer struct {
		mapper       map[string]*websocket.Conn
		userRepo     *userRepo.UserRepo
		redisService *redis.RedisService
	}
)

func NewHttpServer(userRepo *userRepo.UserRepo, redisSvc *redis.RedisService) *HttpServer {
	return &HttpServer{
		mapper:       make(map[string]*websocket.Conn),
		userRepo:     userRepo,
		redisService: redisSvc,
	}
}

func (s *HttpServer) Run() {
	r := mux.NewRouter()

	r.HandleFunc("/init", s.HandleInitWS()).Methods(http.MethodGet)
	r.HandleFunc("/keys/{name}", s.GetSharedKeysOfUser()).Methods(http.MethodGet)
	http.ListenAndServe("localhost:9090", r)
}

func (s *HttpServer) HandleInitWS() http.HandlerFunc {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("userID")
		if userID == "" {
			http.Error(w, "userID cannot be empty", http.StatusBadRequest)
			return
		}

		if _, ok := s.mapper[userID]; ok {
			http.Error(w, "duplicated userID", http.StatusBadRequest)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, "Failed to upgrade", http.StatusInternalServerError)
			return
		}

		s.mapper[userID] = conn
		go s.processWSMessage(userID, conn)
		err = s.ForwardUnsentMessages(userID)
		if err != nil {
			log.Error("forward msg failed", zap.Error(err))
		}
	}
}

func (s *HttpServer) processWSMessage(userID string, conn *websocket.Conn) {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			log.Debug("worker web socket closed", zap.Error(err))
			delete(s.mapper, userID)
			conn.Close()
			break
		}

		var message model.Message
		err = json.Unmarshal(data, &message)
		if err != nil {
			log.Error("Unmarshal message failed", zap.Error(err))
		}

		if conn, ok := s.mapper[message.To]; ok {
			conn.WriteMessage(websocket.TextMessage, data)
		} else {
			if err := s.PutMessagesToCache(context.TODO(), message.To, []*model.Message{&message}); err != nil {
				log.Error("PutMessagesToCache failed", zap.Error(err))
			}
		}
	}
}

func (s *HttpServer) GetSharedKeysOfUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		vars := mux.Vars(r)
		name := vars["name"]
		log.Info("GetSharedKeysOfUser: ", zap.String("name", name))

		user, err := s.userRepo.GetByName(ctx, name)
		if err != nil {
			log.Error("Get shared keys failed", zap.Error(err))
			http.Error(w, "Get shared keys failed", http.StatusInternalServerError)
			return
		}

		if user == nil {
			log.Error("Get shared keys failed", zap.Error(fmt.Errorf("user not found")))
			http.Error(w, "user does not exist", http.StatusBadRequest)
			return
		}

		ikPriv, err := dh.ConvertToECDHFormat(user.IKPriv)
		if err != nil {
			log.Error("Get shared keys failed", zap.Error(err))
			http.Error(w, "Get shared keys failed", http.StatusInternalServerError)
			return
		}

		spkPriv, err := dh.ConvertToECDHFormat(user.SPKPriv)
		if err != nil {
			log.Error("Get shared keys failed", zap.Error(err))
			http.Error(w, "Get shared keys failed", http.StatusInternalServerError)
			return
		}
		// spkPubBytes := spkPriv.PublicKey().Bytes()

		// signature := signature.ED25519Sign(user.IKPriv, spkPubBytes)

		sharedKeys := &model.SharedKey{
			IKPub:  ikPriv.PublicKey().Bytes(),
			SPKPub: spkPriv.PublicKey().Bytes(),
			// Signature: signature,
		}

		data, err := json.Marshal(sharedKeys)
		if err != nil {
			log.Error("Get shared keys failed", zap.Error(err))
			http.Error(w, "Get shared keys failed", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

func (s *HttpServer) ForwardUnsentMessages(userId string) error {
	messages, err := s.GetMessagesFromCache(context.TODO(), userId)
	if err != nil {
		log.Error("ForwardUnsentMessages failed: ", zap.Error(err))
		return err
	}

	for _, message := range messages {
		s.mapper[userId].WriteJSON(&message)
	}
	return nil
}
