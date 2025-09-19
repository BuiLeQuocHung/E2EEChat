package app

import (
	"context"
	"e2e_chat/internal/cryptographic/dh"
	"e2e_chat/internal/model"
	"e2e_chat/internal/protocol/doubleratchet"
	userRepo "e2e_chat/internal/repository/user"
	"e2e_chat/internal/service/redis"
	"e2e_chat/internal/utils/log"
	"encoding/json"
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/gorilla/websocket"
	"github.com/rivo/tview"
	"go.uber.org/zap"
)

type (
	App struct {
		app     *tview.Application
		chatbox *tview.TextView
		input   *tview.InputField

		redisService *redis.RedisService

		userRepo *userRepo.UserRepo
		user     *model.User

		state *doubleratchet.RatchetState

		toName       string
		toSharedKeys *model.SharedKey

		// Only needed before ratchet state is initialized
		ekPriv []byte

		conn *websocket.Conn
	}
)

func NewApp(userRepo *userRepo.UserRepo, redis *redis.RedisService) *App {
	return &App{
		app:          tview.NewApplication(),
		userRepo:     userRepo,
		redisService: redis,
	}
}

func (c *App) Run(ctx context.Context, name string) {
	user, err := c.getUserAndCreateIfNotExist(ctx, name)
	if err != nil {
		log.Fatal("get user info failed", zap.Error(err))
	}
	c.user = user

	var toName string
	fmt.Print("Enter recipient's name: ")
	_, err = fmt.Scan(&toName) // reads until whitespace
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	c.toName = toName

	toSharedKeys, err := c.getSharedKeysOfUser(c.toName)
	if err != nil {
		log.Fatal("cannot init share_secret", zap.Error(err))
	}

	// if !signature.ED25519Verify(toSharedKeys.IKPub, toSharedKeys.SPKPub, toSharedKeys.Signature) {
	// 	log.Fatal("verify spkPub failed")
	// }
	c.toSharedKeys = toSharedKeys

	c.conn, err = c.initWebhook(c.user.Name)
	if err != nil {
		log.Fatal("init webhook to server failed", zap.Error(err))
	}

	go c.listenOnWebhook()
	c.renderUI()
}

func (c *App) Stop() {
	c.SaveState(context.TODO(), c.user.Name, c.toName, c.state)
}

// blocking function
func (c *App) renderUI() {
	c.chatbox = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)
	c.chatbox.SetBorder(true).SetTitle(fmt.Sprintf(" Chat with %s ", c.toName))

	c.input = tview.NewInputField().
		SetLabel("Message: ").
		SetFieldWidth(0)
	c.input.SetBorder(true).SetTitle(" New Message ")

	// This is the key change: We set the input capture on the input field itself.
	c.input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			text := c.input.GetText()
			if text == "" {
				return
			}

			go func(msg string) {
				err := c.SendMessage(msg)
				if err != nil {
					c.app.Suspend(func() {
						log.Error("Send message failed", zap.Error(err))
					})
				}
			}(text)
		}
	})

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(c.chatbox, 0, 1, false).
		AddItem(c.input, 3, 0, true)

	if err := c.app.SetRoot(layout, true).SetFocus(c.input).Run(); err != nil {
		log.Fatal("cannot init app", zap.Error(err))
	}
}

func (c *App) listenOnWebhook() {
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			log.Debug("worker web socket closed", zap.Error(err))
			c.conn.Close()
			break
		}

		var message model.Message
		err = json.Unmarshal(data, &message)
		if err != nil {
			log.Error("Unmarshal message failed", zap.Error(err))
			continue
		}

		if err := c.ReceiveMessage(&message); err != nil {
			c.app.Suspend(func() {
				log.Info("root key receiver: ", zap.String("RK", fmt.Sprintf("%x\n", c.state.RootKey)))
				log.Error("receive message failed: ", zap.Error(err))
			})
		}
	}
}

func (c *App) SendMessage(msg string) error {
	var x3dhHandshake *model.X3DHHandshake = nil

	// try to retrieve state from cache first
	if c.state == nil {
		state, err := c.GetState(context.TODO(), c.user.Name, c.toName)
		if err != nil {
			return err
		}
		c.state = state
	}

	if c.state == nil {
		ekPriv, ekPub, err := dh.NewX25519KeyPair()
		if err != nil {
			return err
		}

		c.ekPriv = ekPriv[:]

		err = c.initSendingState()
		if err != nil {
			return err
		}

		x3dhHandshake = &model.X3DHHandshake{
			EKPub: ekPub[:],
		}
	}

	hdr, ciphertext, err := c.state.Send([]byte(msg))
	if err != nil {
		return err
	}

	c.conn.WriteJSON(&model.Message{
		From:          c.user.Name,
		To:            c.toName,
		Header:        hdr,
		Ciphertext:    ciphertext,
		X3DHHandShake: x3dhHandshake,
	})

	c.app.QueueUpdateDraw(func() {
		fmt.Fprintf(c.chatbox, "[yellow]You:[-] %s\n", msg)
		c.input.SetText("")
		c.chatbox.ScrollToEnd()
	})
	return nil
}

func (c *App) ReceiveMessage(message *model.Message) error {
	if c.state == nil {
		state, err := c.GetState(context.TODO(), c.user.Name, c.toName)
		if err != nil {
			return err
		}
		c.state = state
	}

	if c.state == nil || (message.X3DHHandShake != nil && message.X3DHHandShake.EKPub != nil) {
		err := c.initReceiverState(message)
		if err != nil {
			return err
		}
	}

	msgBytes, err := c.state.Receive(*message.Header, message.Ciphertext)
	if err != nil {
		return err
	}

	c.app.QueueUpdateDraw(func() {
		fmt.Fprintf(c.chatbox, ("[green]%s:[-] %s\n"), message.From, string(msgBytes))
		c.chatbox.ScrollToEnd()
	})
	return nil
}
