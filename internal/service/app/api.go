package app

import (
	"e2e_chat/internal/model"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"
)

var (
	host string = "localhost:9090"
)

func (c *App) getSharedKeysOfUser(name string) (*model.SharedKey, error) {
	u := url.URL{
		Scheme: "http",
		Host:   host,
		Path:   fmt.Sprintf("/keys/%s", name),
	}

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)

	var sk model.SharedKey
	err = json.NewDecoder(resp.Body).Decode(&sk)
	if err != nil {
		return nil, err
	}

	return &sk, nil
}

func (c *App) initWebhook(name string) (*websocket.Conn, error) {
	params := url.Values{
		"userID": []string{name},
	}

	u := url.URL{
		Scheme:   "ws",
		Host:     host,
		Path:     "/init",
		RawQuery: params.Encode(),
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	return conn, nil
}
