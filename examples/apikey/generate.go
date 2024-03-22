package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/store/local"
)

var (
	keyName        string
	organizationID string
)

func init() {
	flag.StringVar(&keyName, "name", "default", "name of API key")
	flag.StringVar(&organizationID, "org", "", "organization ID of API key")
}

func main() {
	flag.Parse()

	if organizationID == "" {
		log.Fatalln("organization ID must be set")
	}

	key, err := apikey.New(organizationID)
	if err != nil {
		log.Fatalln("failed to generate API key:", err)
	}

	if err = local.New[apikey.Key]().Store(keyName, key); err != nil {
		log.Fatalln("failed to store new API key:", err)
	}

	if key, err = local.New[apikey.Key]().Load(keyName); err != nil {
		log.Fatalln("failed to load new API key:", err)
	}

	fmt.Println("API Key successfully generated!")
	fmt.Println("Now log into your Turnkey account and register this API key:")
	fmt.Printf("\t%s\n", key.PublicKey)
}
