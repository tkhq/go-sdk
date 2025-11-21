package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/joho/godotenv"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/signing"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
)

func main() {

	// Load env variables
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	rpcURL := os.Getenv("RPC_URL")
	signWith := os.Getenv("SIGN_WITH")
	organizationId := os.Getenv("TURNKEY_ORGANIZATION_ID")

	if rpcURL == "" || signWith == "" {
		log.Fatal("RPC_URL and SIGN_WITH must be set")
	}

	// Organization API key used to stamp the requests to Turnkey
	apiKey, err := apikey.FromTurnkeyPrivateKey(os.Getenv("TURNKEY_API_PRIVATE_KEY"), apikey.SchemeP256)

	if err != nil {
		log.Fatal("creating API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal("creating SDK client: %w", err)
	}

	fromAddress := common.HexToAddress(signWith)

	rpc, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatal("RPC connection error:", err)
	}

	chainID, err := rpc.NetworkID(context.Background())
	if err != nil {
		log.Fatal("failed to get chain ID:", err)
	}

	nonce, err := rpc.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal("failed to get account nonce:", err)
	}

	// Build DynamicFee (EIP-1559) transaction
	to := common.HexToAddress(signWith)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(2_000_000_000),  // 2 gwei
		GasFeeCap: big.NewInt(40_000_000_000), // 40 gwei
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1_000_000_000_000_000), // 0.001 ETH
		Data:      []byte{},
	})

	// Build Turnkey-compatible unsigned payload
	unsignedPayload := []any{
		tx.ChainId(),
		tx.Nonce(),
		tx.GasTipCap(),
		tx.GasFeeCap(),
		tx.Gas(),
		tx.To(),
		tx.Value(),
		tx.Data(),
		tx.AccessList(),
	}

	rlpBytes, err := rlp.EncodeToBytes(unsignedPayload)
	if err != nil {
		log.Fatal("failed to RLP-encode unsigned tx:", err)
	}

	// Prepend type byte for EIP-1559
	unsigned := append([]byte{types.DynamicFeeTxType}, rlpBytes...)
	unsignedHex := hex.EncodeToString(unsigned)

	// Turnkey SignTransaction
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

	params := signing.NewSignTransactionParams().WithBody(&models.SignTransactionRequest{
		OrganizationID: &organizationId,
		TimestampMs:    &ts,
		Parameters: &models.SignTransactionIntentV2{
			SignWith:            &signWith,
			Type:                models.TransactionTypeEthereum.Pointer(),
			UnsignedTransaction: &unsignedHex,
		},
		Type: (*string)(models.ActivityTypeSignTransactionV2.Pointer()),
	})

	resp, err := client.V0().Signing.SignTransaction(params, client.Authenticator)
	if err != nil {
		log.Fatal("Turnkey signing error:", err)
	}

	signedHex := *resp.Payload.Activity.Result.SignTransactionResult.SignedTransaction
	rawSigned, err := hex.DecodeString(strings.TrimPrefix(signedHex, "0x"))
	if err != nil {
		log.Fatal("failed to decode signed tx:", err)
	}

	finalTx := new(types.Transaction)
	if err := finalTx.UnmarshalBinary(rawSigned); err != nil {
		log.Fatal("failed to unmarshal signed tx:", err)
	}

	fmt.Println("Signed tx hash:", finalTx.Hash().Hex())

	// Broadcast transaction
	if err := rpc.SendTransaction(context.Background(), finalTx); err != nil {
		log.Fatal("broadcast error:", err)
	}

	fmt.Println("Broadcast OK:", finalTx.Hash().Hex())
}
