// Package main demonstrates Ethereum transaction management with Turnkey.
//
// It supports three actions, selected via the ACTION environment variable:
//   - send: ETH self-transfer (default)
//   - swap: Uniswap V3 swap (ETH → USDC)
//   - assets: list supported assets for the chain
//
// The send and swap actions use Turnkey Gas Station for gas sponsorship by
// default. Set SPONSOR=false to use non-sponsored mode (the EOA pays gas).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	turnkey "github.com/tkhq/go-sdk/v2"
)

// Uniswap V3 SwapRouter02 and token addresses on Ethereum Sepolia.
// SwapRouter02 docs: https://docs.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments
const (
	sepoliaSwapRouter02 = "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E"
	sepoliaWETH         = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"
	sepoliaUSDC         = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"

	// selfTransferValue is 0.0001 ETH in wei, used for both send and swap.
	selfTransferValue = "100000000000000"
)

// config holds the example's runtime settings, read from the environment.
type config struct {
	apiPrivateKey  string
	organizationID string
	signWith       string
	caip2          string
	action         string
	sponsor        bool
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	stamper, err := turnkey.NewAPIKeyStamper(cfg.apiPrivateKey)
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, cfg.organizationID)
	if err != nil {
		log.Fatal("failed to create Turnkey client:", err)
	}

	if err := run(context.Background(), client, cfg); err != nil {
		log.Fatal(err)
	}
}

// loadConfig reads settings from the environment and validates them.
func loadConfig() (config, error) {
	// Parse SPONSOR rather than comparing against "false", so that values like
	// "False", "0" or "f" are honoured instead of silently sponsoring.
	sponsorEnv := envOr("SPONSOR", "true")
	sponsor, err := strconv.ParseBool(sponsorEnv)
	if err != nil {
		return config{}, fmt.Errorf("invalid SPONSOR %q: must be a boolean, e.g. true, false, 1 or 0", sponsorEnv)
	}

	cfg := config{
		apiPrivateKey:  os.Getenv("TURNKEY_API_PRIVATE_KEY"),
		organizationID: os.Getenv("TURNKEY_ORGANIZATION_ID"),
		signWith:       os.Getenv("TURNKEY_SIGN_WITH"),
		caip2:          envOr("TURNKEY_CAIP2", "eip155:11155111"), // Ethereum Sepolia testnet
		action:         envOr("ACTION", "send"),
		sponsor:        sponsor,
	}

	if cfg.apiPrivateKey == "" || cfg.organizationID == "" || cfg.signWith == "" {
		return config{}, errors.New("TURNKEY_API_PRIVATE_KEY, TURNKEY_ORGANIZATION_ID, and TURNKEY_SIGN_WITH are required")
	}
	if cfg.action != "send" && cfg.action != "swap" && cfg.action != "assets" {
		return config{}, fmt.Errorf("invalid ACTION %q: must be 'send', 'swap', or 'assets'", cfg.action)
	}

	return cfg, nil
}

// run dispatches to the selected action, printing balances before and after
// send/swap transactions.
func run(ctx context.Context, client *turnkey.Client, cfg config) error {
	if cfg.action == "assets" {
		return listSupportedAssets(ctx, client, cfg)
	}

	if err := printBalances(ctx, client, cfg); err != nil {
		return err
	}

	var err error
	switch cfg.action {
	case "send":
		err = sendETH(ctx, client, cfg)
	case "swap":
		err = swapETH(ctx, client, cfg)
	default:
		return fmt.Errorf("unknown action: %q", cfg.action)
	}
	if err != nil {
		return err
	}

	return printBalances(ctx, client, cfg)
}

// listSupportedAssets lists all supported assets for the configured chain.
func listSupportedAssets(ctx context.Context, client *turnkey.Client, cfg config) error {
	resp, err := client.ListSupportedAssets(ctx, turnkey.ListSupportedAssetsRequest{
		OrganizationID: cfg.organizationID,
		Caip2:          cfg.caip2,
	})
	if err != nil {
		return apiError("failed to list supported assets", err)
	}

	fmt.Printf("Supported assets for %s:\n", cfg.caip2)
	if len(resp.Assets) == 0 {
		fmt.Println("  (none)")
	}
	for _, a := range resp.Assets {
		fmt.Printf("  %s (decimals: %d, caip19: %s)\n", str(a.Symbol), intVal(a.Decimals), str(a.Caip19))
	}

	return nil
}

// printBalances fetches and displays the wallet's asset balances.
func printBalances(ctx context.Context, client *turnkey.Client, cfg config) error {
	resp, err := client.GetWalletAddressBalances(ctx, turnkey.GetWalletAddressBalancesRequest{
		OrganizationID: cfg.organizationID,
		Address:        cfg.signWith,
		Caip2:          cfg.caip2,
	})
	if err != nil {
		return apiError("failed to get balances", err)
	}

	fmt.Printf("Balances for %s:\n", cfg.signWith)
	if len(resp.Balances) == 0 {
		fmt.Println("  (no balances)")
	}
	for _, b := range resp.Balances {
		fmt.Printf("  %s\n", formatBalance(b))
	}
	fmt.Println()

	return nil
}

// formatBalance renders a single asset balance, preferring the display values
// when present and falling back to raw atomic units.
func formatBalance(b turnkey.AssetBalance) string {
	symbol := str(b.Symbol)
	if b.Display != nil && b.Display.Crypto != nil && *b.Display.Crypto != "" {
		line := fmt.Sprintf("%s %s", *b.Display.Crypto, symbol)
		if b.Display.Usd != nil && *b.Display.Usd != "" {
			line += fmt.Sprintf(" ($%s)", *b.Display.Usd)
		}
		return line
	}
	return fmt.Sprintf("%s %s (decimals: %d)", str(b.Balance), symbol, intVal(b.Decimals))
}

// sendETH sends a self-transfer of 0.0001 ETH.
func sendETH(ctx context.Context, client *turnkey.Client, cfg config) error {
	fmt.Printf("Action: send %s ETH self-transfer\n", sponsorLabel(cfg.sponsor))

	calls := []turnkey.ETHCallParams{{
		To:    cfg.signWith,
		Value: ptr(selfTransferValue),
	}}

	txHash, err := submitAndWait(ctx, client, cfg, calls)
	if err != nil {
		return err
	}

	fmt.Printf("Send complete! Tx hash: %s\n", txHash)
	return nil
}

// swapETH performs a Uniswap V3 swap of 0.0001 ETH → USDC.
func swapETH(ctx context.Context, client *turnkey.Client, cfg config) error {
	fmt.Printf("Action: swap ETH → USDC via Uniswap V3 (%s)\n", sponsorLabel(cfg.sponsor))

	calldata, err := encodeExactInputSingle(
		sepoliaWETH,
		sepoliaUSDC,
		3000, // 0.3% fee tier
		cfg.signWith,
		big.NewInt(100_000_000_000_000), // 0.0001 ETH
		big.NewInt(0),                   // amountOutMinimum (0 for demo)
		big.NewInt(0),                   // sqrtPriceLimitX96
	)
	if err != nil {
		return fmt.Errorf("failed to encode swap calldata: %w", err)
	}

	calls := []turnkey.ETHCallParams{{
		To:    sepoliaSwapRouter02,
		Value: ptr(selfTransferValue), // msg.value for ETH→token swap
		Data:  ptr("0x" + hex.EncodeToString(calldata)),
	}}

	txHash, err := submitAndWait(ctx, client, cfg, calls)
	if err != nil {
		return err
	}

	fmt.Printf("Swap complete! Tx hash: %s\n", txHash)
	return nil
}

// submitAndWait submits an ETH transaction and polls until it confirms.
func submitAndWait(ctx context.Context, client *turnkey.Client, cfg config, calls []turnkey.ETHCallParams) (string, error) {
	req := turnkey.ETHSendTransactionRequest{
		OrganizationID: cfg.organizationID,
		From:           cfg.signWith,
		Caip2:          cfg.caip2,
		Calls:          calls,
		Sponsor:        ptr(cfg.sponsor),
	}

	// For sponsored transactions, pass the gas station nonce explicitly for
	// maximal replay protection. Turnkey resolves the on-chain nonce
	// automatically in both modes.
	if cfg.sponsor {
		nonce, err := getGasStationNonce(ctx, client, cfg)
		if err != nil {
			return "", err
		}
		req.GasStationNonce = nonce
	}

	resp, err := client.ETHSendTransaction(ctx, req)
	if err != nil {
		return "", apiError("failed to submit transaction", err)
	}

	fmt.Printf("Transaction submitted, status ID: %s\n", resp.SendTransactionStatusID)
	fmt.Println("Polling for confirmation...")

	return pollTransactionStatus(ctx, client, cfg, resp.SendTransactionStatusID)
}

// getGasStationNonce fetches the gas station delegate contract nonce, used to
// order and replay-protect sponsored transactions.
//
// This is optional when sponsor=true (Turnkey handles it internally if
// omitted), but including it explicitly provides maximal security against
// replay attacks: a signed request can then only produce a single transaction,
// even if infrastructure outside the enclave is compromised.
// See: https://docs.turnkey.com/features/transaction-management#security
//
// Note: if you run multiple transactions back-to-back, wait for the previous
// one to confirm before sending the next — otherwise the gas station nonce may
// not have incremented yet, causing an InvalidNonce error.
func getGasStationNonce(ctx context.Context, client *turnkey.Client, cfg config) (*string, error) {
	resp, err := client.GetNonces(ctx, turnkey.GetNoncesRequest{
		OrganizationID:  cfg.organizationID,
		Address:         cfg.signWith,
		Caip2:           cfg.caip2,
		GasStationNonce: ptr(true),
	})
	if err != nil {
		return nil, apiError("failed to get nonces", err)
	}
	if resp.GasStationNonce == nil {
		return nil, errors.New("gas station nonce not returned (is gas station enabled for this org?)")
	}

	fmt.Printf("Gas station nonce: %s\n", *resp.GasStationNonce)
	return resp.GasStationNonce, nil
}

// pollTransactionStatus polls the send transaction status until a tx hash is
// returned, an error occurs, or the timeout elapses.
func pollTransactionStatus(ctx context.Context, client *turnkey.Client, cfg config, statusID string) (string, error) {
	const (
		pollInterval = 2 * time.Second
		timeout      = 60 * time.Second
	)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.GetSendTransactionStatus(ctx, turnkey.GetSendTransactionStatusRequest{
			OrganizationID:          cfg.organizationID,
			SendTransactionStatusID: statusID,
		})
		if err != nil {
			return "", apiError("failed to get transaction status", err)
		}

		if hash, done, err := txResult(resp); done {
			return hash, err
		}

		if resp.TxStatus != "" {
			fmt.Printf("  Status: %s\n", resp.TxStatus)
		}
		time.Sleep(pollInterval)
	}

	return "", fmt.Errorf("timed out waiting for transaction confirmation after %s", timeout)
}

// txResult reports whether a poll response is terminal, returning the tx hash on
// success or an error on failure.
func txResult(resp *turnkey.GetSendTransactionStatusResponse) (hash string, done bool, err error) {
	if msg := formatTxError(resp); msg != "" {
		return "", true, fmt.Errorf("transaction failed: %s", msg)
	}
	if resp.ETH != nil && resp.ETH.TxHash != nil && *resp.ETH.TxHash != "" {
		return *resp.ETH.TxHash, true, nil
	}
	return "", false, nil
}

// formatTxError renders a transaction failure, preferring the structured error
// (which carries the contract revert chain) over the flat txError string. It
// returns "" when the response reports no failure.
//
// The revert chain is the useful signal for the swap action, where a revert from
// slippage or thin pool liquidity is the likely failure mode.
func formatTxError(resp *turnkey.GetSendTransactionStatusResponse) string {
	flat := str(resp.TxError)
	if resp.Error == nil {
		return flat
	}

	// The chain is reported either at the top level or under the chain-specific
	// failure details, depending on where the failure was detected.
	chain := resp.Error.RevertChain
	if len(chain) == 0 && resp.Error.ETH != nil {
		chain = resp.Error.ETH.RevertChain
	}

	msg := str(resp.Error.Message)
	if msg == "" {
		msg = flat
	}
	if msg == "" {
		if len(chain) == 0 {
			return ""
		}
		msg = "transaction reverted"
	}

	var b strings.Builder
	b.WriteString(msg)
	for i, entry := range chain {
		fmt.Fprintf(&b, "\n  [%d] %s", i, revertEntry(entry))
	}

	return b.String()
}

// revertEntry renders a single frame of the revert chain, falling back through
// the decoded error variants when no display message is provided.
func revertEntry(e turnkey.RevertChainEntry) string {
	desc := str(e.DisplayMessage)
	if desc == "" {
		switch {
		case e.Native != nil && e.Native.Message != nil:
			desc = *e.Native.Message
		case e.Native != nil && e.Native.PanicCode != nil:
			desc = fmt.Sprintf("panic(%s)", *e.Native.PanicCode)
		case e.Custom != nil && e.Custom.ErrorName != nil:
			desc = fmt.Sprintf("%s(%s)", *e.Custom.ErrorName, str(e.Custom.ParamsJSON))
		case e.Unknown != nil && e.Unknown.Selector != nil:
			desc = fmt.Sprintf("unrecognized revert, selector %s", *e.Unknown.Selector)
		default:
			desc = "unrecognized revert"
		}
	}
	if addr := str(e.Address); addr != "" {
		desc += fmt.Sprintf(" (at %s)", addr)
	}

	return desc
}

// encodeExactInputSingle ABI-encodes a call to SwapRouter02.exactInputSingle.
//
// Function signature (SwapRouter02 — no deadline field):
//
//	exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96))
//
// Selector: 0x04e45aaf
func encodeExactInputSingle(
	tokenIn, tokenOut string,
	fee uint32,
	recipient string,
	amountIn, amountOutMinimum, sqrtPriceLimitX96 *big.Int,
) ([]byte, error) {
	selector, err := hex.DecodeString("04e45aaf")
	if err != nil {
		return nil, fmt.Errorf("failed to decode selector: %w", err)
	}

	data := make([]byte, 4+7*32) // selector + 7 ABI-encoded words
	copy(data[0:4], selector)

	// Word 0: tokenIn (address, left-padded to 32 bytes)
	tokenInBytes, err := addressToBytes(tokenIn)
	if err != nil {
		return nil, err
	}
	copy(data[4+12:4+32], tokenInBytes)
	// Word 1: tokenOut
	tokenOutBytes, err := addressToBytes(tokenOut)
	if err != nil {
		return nil, err
	}
	copy(data[4+32+12:4+64], tokenOutBytes)
	// Word 2: fee (uint24)
	padBigInt(data[4+64:4+96], new(big.Int).SetUint64(uint64(fee)))
	// Word 3: recipient
	recipientBytes, err := addressToBytes(recipient)
	if err != nil {
		return nil, err
	}
	copy(data[4+96+12:4+128], recipientBytes)
	// Word 4: amountIn
	padBigInt(data[4+128:4+160], amountIn)
	// Word 5: amountOutMinimum
	padBigInt(data[4+160:4+192], amountOutMinimum)
	// Word 6: sqrtPriceLimitX96
	padBigInt(data[4+192:4+224], sqrtPriceLimitX96)

	return data, nil
}

// addressToBytes converts a 0x-prefixed hex address to a 20-byte slice.
//
// The length check matters: a short address would be copied into the low-order
// end of its ABI word and silently encode as a different, valid-looking address.
func addressToBytes(addr string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if len(b) != 20 {
		return nil, fmt.Errorf("invalid address %q: got %d bytes, want 20", addr, len(b))
	}

	return b, nil
}

// padBigInt writes a big.Int right-aligned into a 32-byte slot.
//
// Values are assumed to be non-negative and to fit in 32 bytes, which holds for
// every field this example encodes. big.Int.Bytes returns the magnitude without
// a sign, so a negative value would encode as its absolute value.
func padBigInt(dst []byte, v *big.Int) {
	b := v.Bytes()
	if offset := 32 - len(b); offset > 0 {
		copy(dst[offset:], b)
	} else {
		copy(dst, b[len(b)-32:])
	}
}

// sponsorLabel returns a human-readable label for the sponsorship mode.
func sponsorLabel(sponsor bool) string {
	if sponsor {
		return "sponsored"
	}
	return "non-sponsored"
}

// apiError annotates a failed SDK call with the HTTP status and response body
// when the failure came from the Turnkey API. The body carries the actionable
// detail — for example, that the organization is not entitled to use
// transaction management, or that Gas Station is not enabled for it.
func apiError(op string, err error) error {
	var reqErr *turnkey.RequestError
	if errors.As(err, &reqErr) {
		return fmt.Errorf("%s (status=%d): %s", op, reqErr.StatusCode, reqErr.Body)
	}

	return fmt.Errorf("%s: %w", op, err)
}

// envOr returns the environment variable value, or fallback if unset/empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ptr returns a pointer to v, for populating optional request fields.
func ptr[T any](v T) *T { return &v }

// str safely dereferences an optional string.
func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// intVal safely dereferences an optional int.
func intVal(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
