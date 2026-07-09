package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/tkhq/go-sdk/crypto"
)

var keyName string

func init() {
	flag.StringVar(&keyName, "name", "default", "name of API key")
}

func main() {
	flag.Parse()

	key, err := crypto.NewAPIKey()
	if err != nil {
		log.Fatalln("failed to generate API key:", err)
	}

	if err = crypto.NewLocal[*crypto.APIKey]().Store(keyName, key); err != nil {
		log.Fatalln("failed to store new API key:", err)
	}

	if key, err = crypto.NewLocal[*crypto.APIKey]().Load(keyName); err != nil {
		log.Fatalln("failed to load new API key:", err)
	}

	fmt.Println("API Key successfully generated!")
	fmt.Println("Now log into your Turnkey account and register this API key:")
	fmt.Printf("\t%s\n", key.PublicKey)
}
