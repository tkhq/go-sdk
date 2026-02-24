// Package main demonstrates Solana transaction management with Turnkey.
//
// It supports two actions:
//   - send: SOL transfer (defaults to self-transfer if no destination)
//   - send-token: SPL token transfer, e.g. USDC (defaults to self-transfer if no destination)
//
// Both actions use Turnkey Gas Station for gas sponsorship by default.
// Pass -sponsor=false to use non-sponsored mode (requires -rpc-url).
//
// Usage:
//
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -action send
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -action send-token -token-mint "..." -destination "..."
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -sponsor=false -rpc-url "https://api.devnet.solana.com" -action send

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/broadcasting"
	"github.com/tkhq/go-sdk/pkg/api/client/send_transactions"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/util"
)

const actionSendToken = "send-token"

var (
	apiPrivateKey  string
	organizationID string
	signWith       string
	caip2          string
	action         string
	sponsor        bool
	rpcURL         string

	// Token / destination flags
	tokenMint   string
	destination string
	amount      uint64
	decimals    uint
)

func init() {
	flag.StringVar(&apiPrivateKey, "api-private-key", "", "Turnkey API private key")
	flag.StringVar(&organizationID, "organization-id", "", "Turnkey organization ID")
	flag.StringVar(&signWith, "sign-with", "", "Solana wallet address (base58)")
	flag.StringVar(&caip2, "caip2", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "CAIP-2 chain ID (default: Solana devnet)")
	flag.StringVar(&action, "action", "send", "action to perform: 'send' or 'send-token'")
	flag.BoolVar(&sponsor, "sponsor", true, "use gas station sponsorship (default: true)")
	flag.StringVar(&rpcURL, "rpc-url", "", "Solana RPC URL (required for non-sponsored mode)")

	// Token / destination flags
	flag.StringVar(&tokenMint, "token-mint", "", "SPL token mint address (required for send-token)")
	flag.StringVar(&destination, "destination", "", "destination wallet address (defaults to self-transfer)")
	flag.Uint64Var(&amount, "amount", 1_000_000, "token amount in smallest units (default: 1000000 = 1 USDC)")
	flag.UintVar(&decimals, "decimals", 6, "token decimals (default: 6 for USDC)")
}

func main() {
	flag.Parse()

	if err := validateFlags(); err != nil {
		log.Println(err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func validateFlags() error {
	if apiPrivateKey == "" || organizationID == "" || signWith == "" {
		return fmt.Errorf("missing required flags: -api-private-key, -organization-id, and -sign-with are required")
	}

	if action != "send" && action != actionSendToken {
		return fmt.Errorf("invalid action %q: must be 'send' or 'send-token'", action)
	}

	if action == actionSendToken && tokenMint == "" {
		return fmt.Errorf("send-token requires -token-mint flag")
	}

	if !sponsor && rpcURL == "" {
		return fmt.Errorf("non-sponsored mode requires -rpc-url to fetch a recent blockhash")
	}

	return nil
}

func run() error {
	client, err := initClient()
	if err != nil {
		return err
	}

	switch action {
	case "send":
		err = sendSOL(client)
	case actionSendToken:
		err = sendToken(client)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return err
}

func initClient() (*sdk.Client, error) {
	key, err := apikey.FromTurnkeyPrivateKey(apiPrivateKey, apikey.SchemeP256)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	client, err := sdk.New(sdk.WithAPIKey(key))
	if err != nil {
		return nil, fmt.Errorf("failed to create SDK client: %w", err)
	}

	return client, nil
}

// sendSOL sends 890,880 lamports (~0.00089 SOL) to the destination address.
// If no destination is specified, defaults to a self-transfer.
func sendSOL(client *sdk.Client) error {
	from := solana.MustPublicKeyFromBase58(signWith)

	to := from // default: self-transfer
	if destination != "" {
		to = solana.MustPublicKeyFromBase58(destination)
	}

	transferIx := system.NewTransferInstruction(
		890_880, // ~0.00089 SOL — minimum rent-exempt balance for a new account
		from,
		to,
	).Build()

	// For sponsored mode, use a placeholder blockhash — Turnkey fetches a fresh one.
	// For non-sponsored mode, fetch a real blockhash from the Solana RPC.
	var blockhash solana.Hash
	if sponsor {
		fmt.Printf("Action: send 890,880 lamports (~0.00089 SOL) to %s (sponsored)\n", to)
	} else {
		fmt.Printf("Action: send 890,880 lamports (~0.00089 SOL) to %s (non-sponsored)\n", to)

		solClient := rpc.New(rpcURL)
		result, err := solClient.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
		if err != nil {
			return fmt.Errorf("failed to get latest blockhash: %w", err)
		}
		blockhash = result.Value.Blockhash
		fmt.Printf("Recent blockhash: %s\n", blockhash)
	}

	tx, err := solana.NewTransactionBuilder().
		SetRecentBlockHash(blockhash).
		SetFeePayer(from).
		AddInstruction(transferIx).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build transaction: %w", err)
	}

	tx.Message.SetVersion(solana.MessageVersionV0)

	unsignedTxHex, err := serializeTxHex(tx)
	if err != nil {
		return err
	}

	intent := &models.SolSendTransactionIntent{
		SignWith:            &signWith,
		UnsignedTransaction: &unsignedTxHex,
		Caip2:               &caip2,
		Sponsor:             &sponsor,
	}

	txSig, err := submitAndWait(client, intent)
	if err != nil {
		return err
	}

	fmt.Printf("SOL transfer complete! Tx signature: %s\n", txSig)
	return nil
}

// sendToken sends an SPL token transfer (e.g. USDC).
// If no destination is specified, defaults to a self-transfer.
func sendToken(client *sdk.Client) error {
	from := solana.MustPublicKeyFromBase58(signWith)
	dest := from // default: self-transfer
	if destination != "" {
		dest = solana.MustPublicKeyFromBase58(destination)
	}
	mint := solana.MustPublicKeyFromBase58(tokenMint)

	// Derive Associated Token Accounts for source and destination.
	sourceATA, _, err := solana.FindAssociatedTokenAddress(from, mint)
	if err != nil {
		return fmt.Errorf("failed to derive source ATA: %w", err)
	}
	destATA, _, err := solana.FindAssociatedTokenAddress(dest, mint)
	if err != nil {
		return fmt.Errorf("failed to derive destination ATA: %w", err)
	}

	fmt.Printf("Source ATA:      %s\n", sourceATA)
	fmt.Printf("Destination ATA: %s\n", destATA)

	// Always include idempotent ATA creation — safe if the ATA already exists.
	// In sponsored mode, Turnkey covers the rent-exemption fee.
	// The library only has the non-idempotent Create (instruction 0), so we build
	// CreateIdempotent (instruction 1) manually with the same account layout.
	createATAIx := createIdempotentATAInstruction(from, dest, mint, destATA)

	// Build the SPL token transfer instruction.
	transferIx := token.NewTransferCheckedInstructionBuilder().
		SetSourceAccount(sourceATA).
		SetDestinationAccount(destATA).
		SetOwnerAccount(from).
		SetMintAccount(mint).
		SetAmount(amount).
		SetDecimals(uint8(decimals)).
		Build()

	// For sponsored mode, use a placeholder blockhash — Turnkey fetches a fresh one.
	// For non-sponsored mode, fetch a real blockhash from the Solana RPC.
	var blockhash solana.Hash
	if sponsor {
		fmt.Printf("Action: send %d tokens (sponsored)\n", amount)
	} else {
		fmt.Printf("Action: send %d tokens (non-sponsored)\n", amount)

		solClient := rpc.New(rpcURL)
		result, err := solClient.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
		if err != nil {
			return fmt.Errorf("failed to get latest blockhash: %w", err)
		}
		blockhash = result.Value.Blockhash
		fmt.Printf("Recent blockhash: %s\n", blockhash)
	}

	tx, err := solana.NewTransactionBuilder().
		SetRecentBlockHash(blockhash).
		SetFeePayer(from).
		AddInstruction(createATAIx).
		AddInstruction(transferIx).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build transaction: %w", err)
	}

	tx.Message.SetVersion(solana.MessageVersionV0)

	unsignedTxHex, err := serializeTxHex(tx)
	if err != nil {
		return err
	}

	intent := &models.SolSendTransactionIntent{
		SignWith:            &signWith,
		UnsignedTransaction: &unsignedTxHex,
		Caip2:               &caip2,
		Sponsor:             &sponsor,
	}

	txSig, err := submitAndWait(client, intent)
	if err != nil {
		return err
	}

	fmt.Printf("Token transfer complete! Tx signature: %s\n", txSig)
	return nil
}

// createIdempotentATAInstruction builds a CreateIdempotent instruction for the
// Associated Token Account program. Unlike Create, this succeeds even if the
// ATA already exists. The library (v1.12.0) only provides the non-idempotent
// variant, so we build instruction index 1 manually with the same account layout.
func createIdempotentATAInstruction(payer, owner, mint, ataAddr solana.PublicKey) *solana.GenericInstruction {
	return solana.NewInstruction(
		solana.SPLAssociatedTokenAccountProgramID,
		solana.AccountMetaSlice{
			{PublicKey: payer, IsSigner: true, IsWritable: true},
			{PublicKey: ataAddr, IsSigner: false, IsWritable: true},
			{PublicKey: owner, IsSigner: false, IsWritable: false},
			{PublicKey: mint, IsSigner: false, IsWritable: false},
			{PublicKey: solana.SystemProgramID, IsSigner: false, IsWritable: false},
			{PublicKey: solana.TokenProgramID, IsSigner: false, IsWritable: false},
		},
		[]byte{1}, // instruction index 1 = CreateIdempotent
	)
}

// serializeTxHex serializes a Solana transaction to a hex string.
func serializeTxHex(tx *solana.Transaction) (string, error) {
	b64, err := tx.ToBase64()
	if err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %w", err)
	}

	txBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	return hex.EncodeToString(txBytes), nil
}

func submitAndWait(client *sdk.Client, intent *models.SolSendTransactionIntent) (string, error) {
	activityType := string(models.ActivityTypeSolSendTransaction)

	params := broadcasting.NewSolSendTransactionParams().WithBody(&models.SolSendTransactionRequest{
		OrganizationID: &organizationID,
		TimestampMs:    util.RequestTimestamp(),
		Type:           &activityType,
		Parameters:     intent,
	})

	resp, err := client.V0().Broadcasting.SolSendTransaction(params, client.Authenticator)
	if err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}

	statusID := resp.Payload.Activity.Result.SolSendTransactionResult.SendTransactionStatusID
	if statusID == nil {
		return "", fmt.Errorf("no sendTransactionStatusId in response")
	}

	fmt.Printf("Transaction submitted, status ID: %s\n", *statusID)
	fmt.Println("Polling for confirmation...")

	return pollTransactionStatus(client, *statusID)
}

func pollTransactionStatus(client *sdk.Client, statusID string) (string, error) {
	const (
		pollInterval = 2 * time.Second
		timeout      = 60 * time.Second
	)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		params := send_transactions.NewGetSendTransactionStatusParams().WithBody(&models.GetSendTransactionStatusRequest{
			OrganizationID:          &organizationID,
			SendTransactionStatusID: &statusID,
		})

		resp, err := client.V0().SendTransactions.GetSendTransactionStatus(params, client.Authenticator)
		if err != nil {
			return "", fmt.Errorf("failed to get transaction status: %w", err)
		}

		status := resp.Payload

		if status.TxError != nil && *status.TxError != "" {
			return "", fmt.Errorf("transaction failed: %s", *status.TxError)
		}

		// The API reuses the Eth field for Solana tx signatures.
		if status.Eth != nil && status.Eth.TxHash != nil && *status.Eth.TxHash != "" {
			return *status.Eth.TxHash, nil
		}

		if status.TxStatus != nil {
			fmt.Printf("  Status: %s\n", *status.TxStatus)
		}

		time.Sleep(pollInterval)
	}

	return "", fmt.Errorf("timed out waiting for transaction confirmation after %s", timeout)
}
