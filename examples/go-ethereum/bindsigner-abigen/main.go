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

	"github.com/tkhq/go-sdk/examples/go-ethereum/bindsigner-abigen/erc20"
)

func main() {
	// -------------------------------------------------------------------------
	// 1) Load config from .env
	// -------------------------------------------------------------------------
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	rpcURL := os.Getenv("RPC_URL")
	signWith := os.Getenv("SIGN_WITH")
	orgID := os.Getenv("TURNKEY_ORGANIZATION_ID")
	privateKey := os.Getenv("TURNKEY_API_PRIVATE_KEY")
	contractAddress := os.Getenv("CONTRACT_ADDRESS")

	if rpcURL == "" || signWith == "" || orgID == "" || privateKey == "" || contractAddress == "" {
		log.Fatal("RPC_URL, SIGN_WITH, TURNKEY_ORGANIZATION_ID, TURNKEY_API_PRIVATE_KEY, and CONTRACT_ADDRESS must be set")
	}

	fromAddress := common.HexToAddress(signWith)

	// -------------------------------------------------------------------------
	// 2) Turnkey API key + SDK client
	// -------------------------------------------------------------------------
	apiKey, err := apikey.FromTurnkeyPrivateKey(privateKey, apikey.SchemeP256)
	if err != nil {
		log.Fatalf("creating API key: %v", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(apiKey))
	if err != nil {
		log.Fatalf("creating SDK client: %v", err)
	}

	// -------------------------------------------------------------------------
	// 3) Ethereum RPC client + chain ID
	// -------------------------------------------------------------------------
	ctx := context.Background()

	rpc, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("rpc connection error: %v", err)
	}

	chainID, err := rpc.NetworkID(ctx)
	if err != nil {
		log.Fatalf("failed to get chain ID: %v", err)
	}

	// -------------------------------------------------------------------------
	// 4) Turnkey-backed bind/v2 TransactOpts (SignerFn)
	// -------------------------------------------------------------------------
	signerFn := MakeTurnkeySignerFn(client, signWith, chainID, orgID)

	auth := &bind.TransactOpts{
		From:   fromAddress,
		Signer: signerFn,
	}

	// -------------------------------------------------------------------------
	// 5) ERC20 abigen v2 binding: pack calldata for transfer(to, amount)
	// -------------------------------------------------------------------------
	tokenAddr := common.HexToAddress(contractAddress)
	erc := erc20.NewErc20()

	to := fromAddress                               // send to self for demo
	amount := big.NewInt(1_000_000_000_000_000_000) // 1 token (18 decimals)

	// This uses the generated ABI helpers to build the calldata.
	calldata := erc.PackTransfer(to, amount)

	// -------------------------------------------------------------------------
	// 6) Build an EIP-1559 tx that calls the ERC20 contract
	// -------------------------------------------------------------------------
	nonce, err := rpc.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		log.Fatalf("failed to get account nonce: %v", err)
	}

	// For a real app you might want to query suggested fees or use 1559 estimators.
	gasTipCap := big.NewInt(2_000_000_000)  // 2 gwei
	gasFeeCap := big.NewInt(40_000_000_000) // 40 gwei
	gasLimit := uint64(100_000)             // enough for ERC20 transfer on most networks

	unsignedTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gasLimit,
		To:        &tokenAddr,
		Value:     big.NewInt(0), // ERC20 transfer has value=0, uses calldata instead
		Data:      calldata,
	})

	fmt.Println("→ Calling ERC20.transfer via abigen v2 + Turnkey...")

	// -------------------------------------------------------------------------
	// 7) Let the Turnkey-backed SignerFn sign the tx
	// -------------------------------------------------------------------------
	signedTx, err := auth.Signer(fromAddress, unsignedTx)
	if err != nil {
		log.Fatalf("Turnkey signer error: %v", err)
	}

	// -------------------------------------------------------------------------
	// 8) Broadcast the signed transaction
	// -------------------------------------------------------------------------
	if err := rpc.SendTransaction(ctx, signedTx); err != nil {
		log.Fatalf("broadcast error: %v", err)
	}

	fmt.Println("Broadcast OK, tx hash:", signedTx.Hash().Hex())
}

///////////////////////////////////////////////////////////////////////////////
// Turnkey-backed bind/v2 SignerFn
///////////////////////////////////////////////////////////////////////////////

// cloneTxWithChainID rebuilds a DynamicFeeTx with the given chainID (needed when
// upstream code left ChainId empty and expects the signer to enforce it).
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

// MakeTurnkeySignerFn returns a bind/v2.SignerFn that:
//
//   - normalizes the transaction (ensures chainID is set),
//   - builds the EIP-1559 unsigned payload Turnkey expects,
//   - calls SignTransactionV2,
//   - returns a fully signed *types.Transaction.
func MakeTurnkeySignerFn(
	client *sdk.Client,
	signWith string,
	chainID *big.Int,
	orgID string,
) bind.SignerFn {
	return func(from common.Address, tx *types.Transaction) (*types.Transaction, error) {
		// Ensure signer address matches the Turnkey address
		if !strings.EqualFold(from.Hex(), signWith) {
			return nil, fmt.Errorf("signer mismatch: from=%s, signWith=%s", from.Hex(), signWith)
		}

		// This example only supports EIP-1559 (DynamicFee) txs.
		if tx.Type() != types.DynamicFeeTxType {
			return nil, fmt.Errorf("only DynamicFeeTxType (eip-1559) supported in this example")
		}

		// Some flows set ChainId only via the signer. If it's empty/zero,
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
			return nil, fmt.Errorf("turnkey SignTransactionV2 error: %w", err)
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
