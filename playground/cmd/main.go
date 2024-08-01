package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/tkhq/go-sdk/pkg/apikey"
)

const (
	pub = "8ba00e7ee515fc82b53d525802d3769d66a0e1cc8b9927b6ca854d1a1e7d3211"
	// priv = "4a75145aaa0a0ebdd6f8dea28410b8749cabe7355b5ff8e924ecf4197b6f4d872b19840560a4af14976d1ae70f5c04199d2c99385eac7be462d33b64610140d5"
	priv = "3514c6f83c8fb2facfd1947d6332d8f38512dd945f3cb87b9b6ea3b877b564388ba00e7ee515fc82b53d525802d3769d66a0e1cc8b9927b6ca854d1a1e7d3211"
)

func main() {
	key, err := existingKey()
	if err != nil {
		panic(err)
	}

	fmt.Printf("[pub]: %s\n[priv]: %s\n", key.TkPublicKey, key.TkPrivateKey)

	msg := "MESSAGE"

	sig, err := apikey.Stamp([]byte(msg), key)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[msg]: %s\n[stamp]: %s\n", msg, sig)
}

func newKey() (*apikey.Key, error) {
	return apikey.New(uuid.NewString(), apikey.SchemeED25519)
}

func existingKey() (*apikey.Key, error) {
	raw, err := hex.DecodeString(priv)
	if err != nil {
		return nil, err
	}

	priv := ed25519.PrivateKey(raw)
	return apikey.FromED25519PrivateKey(priv)
}
