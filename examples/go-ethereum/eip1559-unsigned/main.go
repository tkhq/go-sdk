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
	////////////////////////////////////////////////////////////////////////////
	// 1) Load configuration from environment
	////////////////////////////////////////////////////////////////////////////

	if err := godotenv.Load(); err != nil {
		log.Fatalf("error loading .env file: %v", err)
	}

	rpcURL := os.Getenv("RPC_URL")
	signWith := os.Getenv("SIGN_WITH")
	organizationID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	privateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")

	if rpcURL == "" || signWith == "" || organizationID == "" || privateKey == "" {
		log.Fatal("RPC_URL, SIGN_WITH, TURNKEY_ORGANIZATION_ID, and TURNKEY_API_PRIVATE_KEY must be set")
	}

	fromAddress := common.HexToAddress(signWith)

	////////////////////////////////////////////////////////////////////////////
	// 2) Build Turnkey API key + SDK client
	////////////////////////////////////////////////////////////////////////////

	apiKey, err := apikey.FromTurnkeyPrivateKey(privateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatalf("creating API key: %v", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatalf("creating SDK client: %v", err)
	}

	////////////////////////////////////////////////////////////////////////////
	// 3) Ethereum RPC client + chain ID + nonce
	////////////////////////////////////////////////////////////////////////////

	rpc, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("rpc connection error: %v", err)
	}

	chainID, err := rpc.NetworkID(context.Background())
	if err != nil {
		log.Fatalf("failed to get chain ID: %v", err)
	}

	nonce, err := rpc.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("failed to get account nonce: %v", err)
	}

	////////////////////////////////////////////////////////////////////////////
	// 4) Build a DynamicFee (EIP-1559) transaction
	////////////////////////////////////////////////////////////////////////////

	to := common.HexToAddress(signWith) // send to self for demo

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(2_000_000_000),  // 2 gwei
		GasFeeCap: big.NewInt(40_000_000_000), // 40 gwei
		Gas:       21_000,
		To:        &to,
		Value:     big.NewInt(1_000_000_000_000_000), // 0.001 ETH
		Data:      []byte{},                          // no calldata
	})

	////////////////////////////////////////////////////////////////////////////
	// 5) Build Turnkey-compatible unsigned payload
	//
	// Turnkey expects the EIP-1559 unsigned payload as:
	// [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList]
	// RLP-encoded, with the 0x02 type byte prepended.
	////////////////////////////////////////////////////////////////////////////

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
		log.Fatalf("failed to RLP-encode unsigned tx: %v", err)
	}

	// Prepend type byte for EIP-1559 (0x02)
	unsigned := append([]byte{types.DynamicFeeTxType}, rlpBytes...)
	unsignedHex := hex.EncodeToString(unsigned) // Turnkey expects hex without 0x

	////////////////////////////////////////////////////////////////////////////
	// 6) Sign the transaction via Turnkey SignTransactionV2
	////////////////////////////////////////////////////////////////////////////

	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

	params := signing.NewSignTransactionParams().WithBody(&models.SignTransactionRequest{
		OrganizationID: &organizationID,
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
		log.Fatalf("turnkey signing error: %v", err)
	}

	signedHex := resp.Payload.Activity.
		Result.
		SignTransactionResult.
		SignedTransaction
	if signedHex == nil {
		log.Fatal("turnkey returned nil signed transaction")
	}

	rawSigned, err := hex.DecodeString(strings.TrimPrefix(*signedHex, "0x"))
	if err != nil {
		log.Fatalf("failed to decode signed tx: %v", err)
	}

	finalTx := new(types.Transaction)
	if err := finalTx.UnmarshalBinary(rawSigned); err != nil {
		log.Fatalf("failed to unmarshal signed tx: %v", err)
	}

	fmt.Println("Signed tx hash:", finalTx.Hash().Hex())

	////////////////////////////////////////////////////////////////////////////
	// 7) Broadcast the signed transaction
	////////////////////////////////////////////////////////////////////////////

	if err := rpc.SendTransaction(context.Background(), finalTx); err != nil {
		log.Fatalf("broadcast error: %v", err)
	}

	fmt.Println("Broadcast OK:", finalTx.Hash().Hex())
}
