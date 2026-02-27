// Package main demonstrates Solana transaction management with Turnkey.
//
// It supports four actions:
//   - send: SOL transfer (defaults to self-transfer if no destination)
//   - send-token: SPL token transfer, e.g. USDC (defaults to self-transfer if no destination)
//   - swap: SOL → USDC swap via Jupiter (mainnet only)
//   - assets: list supported assets for the chain
//
// All actions use Turnkey Gas Station for gas sponsorship by default.
// Pass -sponsor=false to use non-sponsored mode (requires -rpc-url).
//
// Usage:
//
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -action send
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -action send-token -token-mint "..." -destination "..."
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -action swap -jupiter-api-key "..." -caip2 "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -sponsor=false -rpc-url "https://api.devnet.solana.com" -action send
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "..." -action assets

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/broadcasting"
	"github.com/tkhq/go-sdk/pkg/api/client/send_transactions"
	"github.com/tkhq/go-sdk/pkg/api/client/wallets"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/util"
)

const (
	actionSendToken = "send-token"
	actionSwap      = "swap"

	// Jupiter swap constants (mainnet only).
	jupiterBaseURL = "https://api.jup.ag"
	solMint        = "So11111111111111111111111111111111111111112"
	mainnetUSDC    = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
)

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

	// Swap flags
	jupiterAPIKey string
	swapAmount    string
)

func init() {
	flag.StringVar(&apiPrivateKey, "api-private-key", "", "Turnkey API private key")
	flag.StringVar(&organizationID, "organization-id", "", "Turnkey organization ID")
	flag.StringVar(&signWith, "sign-with", "", "Solana wallet address (base58)")
	flag.StringVar(&caip2, "caip2", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "CAIP-2 chain ID (default: Solana devnet)")
	flag.StringVar(&action, "action", "send", "action to perform: 'send', 'send-token', 'swap', or 'assets'")
	flag.BoolVar(&sponsor, "sponsor", true, "use gas station sponsorship (default: true)")
	flag.StringVar(&rpcURL, "rpc-url", "", "Solana RPC URL (required for non-sponsored mode)")

	// Token / destination flags
	flag.StringVar(&tokenMint, "token-mint", "", "SPL token mint address (required for send-token)")
	flag.StringVar(&destination, "destination", "", "destination wallet address (defaults to self-transfer)")
	flag.Uint64Var(&amount, "amount", 1_000_000, "token amount in smallest units (default: 1000000 = 1 USDC)")
	flag.UintVar(&decimals, "decimals", 6, "token decimals (default: 6 for USDC)")

	// Swap flags
	flag.StringVar(&jupiterAPIKey, "jupiter-api-key", "", "Jupiter API key (required for swap)")
	flag.StringVar(&swapAmount, "swap-amount", "0.0001", "amount of SOL to swap (default: 0.0001)")
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

	if err := validateAction(); err != nil {
		return err
	}

	if action != "assets" && !sponsor && rpcURL == "" {
		return fmt.Errorf("non-sponsored mode requires -rpc-url to fetch a recent blockhash")
	}

	return nil
}

func validateAction() error {
	switch action {
	case "send":
		return nil
	case actionSendToken:
		if tokenMint == "" {
			return fmt.Errorf("send-token requires -token-mint flag")
		}
		return nil
	case actionSwap:
		if jupiterAPIKey == "" {
			return fmt.Errorf("swap requires -jupiter-api-key flag")
		}
		return nil
	case "assets":
		return nil
	default:
		return fmt.Errorf("invalid action %q: must be 'send', 'send-token', 'swap', or 'assets'", action)
	}
}

func run() error {
	client, err := initClient()
	if err != nil {
		return err
	}

	if err := printBalances(client, signWith); err != nil {
		return err
	}

	// If a different destination was specified, show its balances before the tx too.
	if destination != "" && destination != signWith {
		if err := printBalances(client, destination); err != nil {
			return err
		}
	}

	switch action {
	case "send":
		err = sendSOL(client)
	case actionSendToken:
		err = sendToken(client)
	case actionSwap:
		err = swapSOL(client)
	case "assets":
		return listSupportedAssets(client)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
	if err != nil {
		return err
	}

	if err := printBalances(client, signWith); err != nil {
		return err
	}

	// If a different destination was specified, also show its updated balances.
	if destination != "" && destination != signWith {
		if err := printBalances(client, destination); err != nil {
			return err
		}
	}

	return nil
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

// listSupportedAssets lists all supported assets for the configured chain.
func listSupportedAssets(client *sdk.Client) error {
	params := wallets.NewListSupportedAssetsParams().WithBody(&models.ListSupportedAssetsRequest{
		OrganizationID: &organizationID,
		Caip2:          &caip2,
	})

	resp, err := client.V0().Wallets.ListSupportedAssets(params, client.Authenticator)
	if err != nil {
		return fmt.Errorf("failed to list supported assets: %w", err)
	}

	fmt.Printf("Supported assets for %s:\n", caip2)
	if len(resp.Payload.Assets) == 0 {
		fmt.Println("  (none)")
	}
	for _, a := range resp.Payload.Assets {
		fmt.Printf("  %s (decimals: %d, caip19: %s)\n", a.Symbol, a.Decimals, a.Caip19)
	}

	return nil
}

// printBalances fetches and displays the wallet's asset balances for the given address.
func printBalances(client *sdk.Client, address string) error {
	params := wallets.NewGetWalletAddressBalancesParams().WithBody(&models.GetWalletAddressBalancesRequest{
		OrganizationID: &organizationID,
		Address:        &address,
		Caip2:          &caip2,
	})

	resp, err := client.V0().Wallets.GetWalletAddressBalances(params, client.Authenticator)
	if err != nil {
		return fmt.Errorf("failed to get balances: %w", err)
	}

	fmt.Printf("Balances for %s:\n", address)
	if len(resp.Payload.Balances) == 0 {
		fmt.Println("  (no balances)")
	}
	for _, b := range resp.Payload.Balances {
		if b.Display != nil && b.Display.Crypto != "" {
			fmt.Printf("  %s %s", b.Display.Crypto, b.Symbol)
			if b.Display.Usd != "" {
				fmt.Printf(" ($%s)", b.Display.Usd)
			}
			fmt.Println()
		} else {
			fmt.Printf("  %s %s (raw: %s, decimals: %d)\n", b.Balance, b.Symbol, b.Balance, b.Decimals)
		}
	}
	fmt.Println()

	return nil
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
		fmt.Printf("Action: send 890,880 lamports (~0.00089 SOL) to %s (sponsored, %s)\n", to, caip2)
	} else {
		fmt.Printf("Action: send 890,880 lamports (~0.00089 SOL) to %s (non-sponsored, %s)\n", to, caip2)

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
		fmt.Printf("Action: send %d tokens (sponsored, %s)\n", amount, caip2)
	} else {
		fmt.Printf("Action: send %d tokens (non-sponsored, %s)\n", amount, caip2)

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

// swapSOL swaps SOL for USDC via Jupiter (mainnet only).
// Jupiter builds the transaction; we just convert it to hex and submit to Turnkey.
func swapSOL(client *sdk.Client) error {
	lamports, err := solToLamports(swapAmount)
	if err != nil {
		return fmt.Errorf("invalid swap amount %q: %w", swapAmount, err)
	}

	mode := "sponsored"
	if !sponsor {
		mode = "non-sponsored"
	}

	fmt.Printf("Action: swap %s SOL → USDC via Jupiter (%s, %s)\n", swapAmount, mode, caip2)

	// 1. Get a quote from Jupiter.
	quoteBody, err := jupiterQuote(lamports)
	if err != nil {
		return err
	}

	fmt.Println("Quote received from Jupiter")

	// 2. Request the swap transaction from Jupiter.
	swapTxB64, err := jupiterSwapTx(quoteBody)
	if err != nil {
		return err
	}

	// 3. Convert the base64 transaction to hex and submit via Turnkey.
	txBytes, err := base64.StdEncoding.DecodeString(swapTxB64)
	if err != nil {
		return fmt.Errorf("failed to decode swap transaction: %w", err)
	}

	unsignedTxHex := hex.EncodeToString(txBytes)

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

	fmt.Printf("Swap complete! Tx signature: %s\n", txSig)
	return nil
}

// jupiterQuote fetches a swap quote from Jupiter's API.
func jupiterQuote(lamports uint64) ([]byte, error) {
	quoteURL := fmt.Sprintf(
		"%s/swap/v1/quote?inputMint=%s&outputMint=%s&amount=%d&slippageBps=50",
		jupiterBaseURL, solMint, mainnetUSDC, lamports,
	)

	quoteReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, quoteURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create quote request: %w", err)
	}

	quoteReq.Header.Set("x-api-key", jupiterAPIKey)

	quoteResp, err := http.DefaultClient.Do(quoteReq)
	if err != nil {
		return nil, fmt.Errorf("jupiter quote request failed: %w", err)
	}
	defer quoteResp.Body.Close() //nolint:errcheck // best-effort close

	body, err := io.ReadAll(quoteResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read quote response: %w", err)
	}

	if quoteResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jupiter quote failed (status %d): %s", quoteResp.StatusCode, body)
	}

	return body, nil
}

// jupiterSwapTx requests a swap transaction from Jupiter and returns the base64-encoded transaction.
func jupiterSwapTx(quoteBody []byte) (string, error) {
	reqBody, err := json.Marshal(map[string]any{
		"quoteResponse":             json.RawMessage(quoteBody),
		"userPublicKey":             signWith,
		"wrapAndUnwrapSol":          true,
		"dynamicComputeUnitLimit":   true,
		"prioritizationFeeLamports": "auto",
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal swap request: %w", err)
	}

	swapReq, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost,
		jupiterBaseURL+"/swap/v1/swap",
		strings.NewReader(string(reqBody)),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create swap request: %w", err)
	}

	swapReq.Header.Set("Content-Type", "application/json")
	swapReq.Header.Set("x-api-key", jupiterAPIKey)

	swapResp, err := http.DefaultClient.Do(swapReq)
	if err != nil {
		return "", fmt.Errorf("jupiter swap request failed: %w", err)
	}
	defer swapResp.Body.Close() //nolint:errcheck // best-effort close

	body, err := io.ReadAll(swapResp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read swap response: %w", err)
	}

	if swapResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("jupiter swap failed (status %d): %s", swapResp.StatusCode, body)
	}

	var result struct {
		SwapTransaction string `json:"swapTransaction"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse swap response: %w", err)
	}

	if result.SwapTransaction == "" {
		return "", fmt.Errorf("jupiter did not return a swap transaction")
	}

	return result.SwapTransaction, nil
}

// solToLamports converts a decimal SOL string (e.g. "0.0001") to lamports.
func solToLamports(sol string) (uint64, error) {
	f, err := strconv.ParseFloat(sol, 64)
	if err != nil {
		return 0, err
	}

	if f <= 0 {
		return 0, fmt.Errorf("amount must be greater than zero")
	}

	lamports := uint64(math.Round(f * 1e9))

	return lamports, nil
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
