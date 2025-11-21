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

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
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
	// -------------------------------------------------------------------------
	// 1) Load config from .env
	// -------------------------------------------------------------------------
	if err := godotenv.Load(); err != nil {
		log.Fatalf("error loading .env file: %v", err)
	}

	rpcURL := os.Getenv("RPC_URL")
	signWith := os.Getenv("SIGN_WITH")
	orgID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	privateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")

	if rpcURL == "" || signWith == "" || orgID == "" || privateKey == "" {
		log.Fatal("missing RPC_URL, SIGN_WITH, TURNKEY_ORGANIZATION_ID, TURNKEY_API_PRIVATE_KEY")
	}

	fromAddress := common.HexToAddress(signWith)

	// ---------------------------------------------------------------------
	// Turnkey API Key and SDK client
	// ---------------------------------------------------------------------
	apiKey, err := apikey.FromTurnkeyPrivateKey(privateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatalf("creating API key: %v", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatalf("creating SDK client: %v", err)
	}

	// ---------------------------------------------------------------------
	// RPC client & chainID
	// ---------------------------------------------------------------------
	rpc, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("rpc connection error: %v", err)
	}

	chainID, err := rpc.NetworkID(context.Background())
	if err != nil {
		log.Fatalf("failed to get chain ID: %v", err)
	}

	// ---------------------------------------------------------------------
	// Turnkey-backed bind/v2 SignerFn
	// ---------------------------------------------------------------------
	signerFn := MakeTurnkeySignerFn(client, signWith, chainID, orgID)

	// ---------------------------------------------------------------------
	// Build a simple EIP-1559 transfer transaction
	// ---------------------------------------------------------------------
	nonce, err := rpc.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("failed to get nonce: %v", err)
	}

	to := common.HexToAddress(signWith) // self-transfer
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(2_000_000_000),  // 2 gwei
		GasFeeCap: big.NewInt(40_000_000_000), // 40 gwei
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1_000_000_000_000_000), // 0.001 ETH
	})

	// ---------------------------------------------------------------------
	// Sign transaction via bind/v2 SignerFn
	// ---------------------------------------------------------------------
	signedTx, err := signerFn(fromAddress, tx)
	if err != nil {
		log.Fatalf("signerFn error: %v", err)
	}

	fmt.Println("Signed tx hash:", signedTx.Hash().Hex())

	// ---------------------------------------------------------------------
	// Broadcast
	// ---------------------------------------------------------------------
	if err := rpc.SendTransaction(context.Background(), signedTx); err != nil {
		log.Fatalf("broadcast error: %v", err)
	}

	fmt.Println("Broadcast OK:", signedTx.Hash().Hex())
}

///////////////////////////////////////////////////////////////////////////////
// Signer Function (bind/v2)
///////////////////////////////////////////////////////////////////////////////

func cloneTxWithChainID(tx *types.Transaction, chainID *big.Int) *types.Transaction {
	if tx.Type() != types.DynamicFeeTxType {
		return tx
	}
	to := tx.To()
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:    chainID,
		Nonce:      tx.Nonce(),
		GasTipCap:  tx.GasTipCap(),
		GasFeeCap:  tx.GasFeeCap(),
		Gas:        tx.Gas(),
		To:         to,
		Value:      tx.Value(),
		Data:       tx.Data(),
		AccessList: tx.AccessList(),
	})
}

func MakeTurnkeySignerFn(
	client *sdk.Client,
	signWith string,
	chainID *big.Int,
	orgID string,
) bind.SignerFn {
	return func(from common.Address, tx *types.Transaction) (*types.Transaction, error) {

		if !strings.EqualFold(from.Hex(), signWith) {
			return nil, fmt.Errorf("signer mismatch: from=%s signWith=%s", from.Hex(), signWith)
		}

		if tx.Type() != types.DynamicFeeTxType {
			return nil, fmt.Errorf("only EIP-1559 supported")
		}

		// Inject real chain ID if empty
		if tx.ChainId() == nil || tx.ChainId().Cmp(big.NewInt(0)) == 0 {
			tx = cloneTxWithChainID(tx, chainID)
		}

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
			return nil, fmt.Errorf("rlp encode error: %w", err)
		}

		unsigned := append([]byte{types.DynamicFeeTxType}, rlpBytes...)
		unsignedHex := hex.EncodeToString(unsigned)

		ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

		params := signing.NewSignTransactionParams().WithBody(&models.SignTransactionRequest{
			OrganizationID: &orgID,
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
			return nil, fmt.Errorf("turnkey signing error: %w", err)
		}

		signedHex := resp.Payload.Activity.Result.SignTransactionResult.SignedTransaction
		if signedHex == nil {
			return nil, fmt.Errorf("nil signed transaction from turnkey")
		}

		rawSigned, err := hex.DecodeString(strings.TrimPrefix(*signedHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("decode signed tx: %w", err)
		}

		finalTx := new(types.Transaction)
		if err := finalTx.UnmarshalBinary(rawSigned); err != nil {
			return nil, fmt.Errorf("unmarshal signed tx: %w", err)
		}

		return finalTx, nil
	}
}
