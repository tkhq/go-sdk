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

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
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

	//Ethereum RPC client and chainID
	rpc, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatal("rpc connection error:", err)
	}

	chainID, err := rpc.NetworkID(context.Background())
	if err != nil {
		log.Fatal("failed to get chain ID:", err)
	}

	// Create a Turnkey-backed bind.SignerFn
	signerFn := MakeTurnkeySignerFn(client, signWith, chainID)

	// Build a simple EIP-1559 transfer tx
	nonce, err := rpc.PendingNonceAt(context.Background(), fromAddress)

	if err != nil {
		log.Fatal("failed to get account nonce:", err)
	}

	// Send to self for demo
	to := common.HexToAddress(signWith)

	unsignedTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(2_000_000_000),  // 2 gwei
		GasFeeCap: big.NewInt(40_000_000_000), // 40 gwei
		Gas:       21_000,
		To:        &to,
		Value:     big.NewInt(1_000_000_000_000_000), // 0.001 ETH
		Data:      []byte{},
	})

	// Let bind.SignerFn + Turnkey sign the tx
	signedTx, err := signerFn(fromAddress, unsignedTx)

	if err != nil {
		log.Fatal("turnkey signerFn error:", err)
	}

	fmt.Println("Signed tx hash:", signedTx.Hash().Hex())

	// Broadcast the signed transaction
	if err := rpc.SendTransaction(context.Background(), signedTx); err != nil {
		log.Fatal("broadcast error:", err)
	}

	fmt.Println("Broadcast OK:", signedTx.Hash().Hex())
}

// Turnkey-backed bind.SignerFn
// cloneTxWithChainID rebuilds a DynamicFeeTx with the given chainID (needed when bind / upstream code left ChainId empty and expects the signer to enforce it)
func cloneTxWithChainID(tx *types.Transaction, chainID *big.Int) *types.Transaction {
	if tx.Type() != types.DynamicFeeTxType {
		return tx
	}

	to := tx.To()

	newTx := &types.DynamicFeeTx{
		ChainID:    chainID,
		Nonce:      tx.Nonce(),
		GasTipCap:  tx.GasTipCap(),
		GasFeeCap:  tx.GasFeeCap(),
		Gas:        tx.Gas(),
		To:         to,
		Value:      tx.Value(),
		Data:       tx.Data(),
		AccessList: tx.AccessList(),
	}

	return types.NewTx(newTx)
}

// MakeTurnkeySignerFn returns a bind.SignerFn that:
//   - normalizes the transaction (ensures chainID is set)
//   - builds the EIP-1559 unsigned payload Turnkey expects
//   - calls SignTransactionV2
//   - returns a fully signed *types.Transaction
func MakeTurnkeySignerFn(client *sdk.Client, signWith string, chainID *big.Int) bind.SignerFn {
	return func(from common.Address, tx *types.Transaction) (*types.Transaction, error) {
		// Optional sanity check: ensure signer address matches the Turnkey address
		if !strings.EqualFold(from.Hex(), signWith) {
			return nil, fmt.Errorf("signer mismatch: from=%s, signWith=%s", from.Hex(), signWith)
		}

		// This example only supports EIP-1559 (DynamicFee) txs.
		if tx.Type() != types.DynamicFeeTxType {
			return nil, fmt.Errorf("only DynamicFeeTxType (EIP-1559) supported in this example")
		}

		// Some bind flows set ChainId only via the signer. If it's empty/zero,
		// rebuild the DynamicFeeTx with the real chainID.
		if tx.ChainId() == nil || tx.ChainId().Cmp(big.NewInt(0)) == 0 {
			tx = cloneTxWithChainID(tx, chainID)
		}

		// Build the unsigned EIP-1559 payload:
		// [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList]
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
			return nil, fmt.Errorf("failed to rlp-encode unsigned tx: %w", err)
		}

		// Prepend EIP-1559 type byte 0x02
		unsigned := append([]byte{types.DynamicFeeTxType}, rlpBytes...)
		unsignedHex := hex.EncodeToString(unsigned) // Turnkey expects hex without 0x

		// Prepare Turnkey SignTransactionV2 request
		ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

		// Get the Turnkey organization id from .env
		organizationId := os.Getenv("TURNKEY_ORGANIZATION_ID")

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
			return nil, fmt.Errorf("turnkey signTransactionV2 error: %w", err)
		}

		signedHex := resp.Payload.Activity.
			Result.
			SignTransactionResult.
			SignedTransaction
		if signedHex == nil {
			return nil, fmt.Errorf("turnkey returned nil signed transaction")
		}

		rawSigned, err := hex.DecodeString(strings.TrimPrefix(*signedHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("failed to hex-decode signed tx: %w", err)
		}

		finalTx := new(types.Transaction)
		if err := finalTx.UnmarshalBinary(rawSigned); err != nil {
			return nil, fmt.Errorf("failed to unmarshal signed tx: %w", err)
		}

		return finalTx, nil
	}
}
