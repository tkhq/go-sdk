// Package main demonstrates transaction management with Turnkey.
//
// It supports two actions:
//   - send: ETH self-transfer
//   - swap: Uniswap V3 swap (ETH → USDC)
//
// Both actions use Turnkey Gas Station for gas sponsorship by default.
// Optionally, pass -rpc-url to use your own nonce from an external RPC (non-sponsored).
//
// Usage:
//
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "0x..." -action send
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "0x..." -action swap
//	go run main.go -api-private-key "..." -organization-id "..." -sign-with "0x..." -rpc-url "https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY" -action send
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/broadcasting"
	"github.com/tkhq/go-sdk/pkg/api/client/send_transactions"
	"github.com/tkhq/go-sdk/pkg/api/models"
	"github.com/tkhq/go-sdk/pkg/apikey"
	"github.com/tkhq/go-sdk/pkg/util"
)

// Uniswap V3 SwapRouter02 and token addresses on Sepolia.
// SwapRouter02 docs: https://docs.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments
const (
	sepoliaSwapRouter02 = "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E"
	sepoliaWETH         = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"
	sepoliaUSDC         = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
)

var (
	apiPrivateKey  string
	organizationID string
	signWith       string
	caip2          string
	action         string
	rpcURL         string
)

func init() {
	flag.StringVar(&apiPrivateKey, "api-private-key", "", "Turnkey API private key")
	flag.StringVar(&organizationID, "organization-id", "", "Turnkey organization ID")
	flag.StringVar(&signWith, "sign-with", "", "wallet address to sign with (0x-prefixed)")
	flag.StringVar(&caip2, "caip2", "eip155:11155111", "CAIP-2 chain ID (default: Sepolia)")
	flag.StringVar(&action, "action", "send", "action to perform: 'send' or 'swap'")
	flag.StringVar(&rpcURL, "rpc-url", "", "Alchemy RPC URL (e.g. https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY)")
}

func main() {
	flag.Parse()

	if apiPrivateKey == "" || organizationID == "" || signWith == "" {
		log.Println("Missing required flags: -api-private-key, -organization-id, and -sign-with are required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if action != "send" && action != "swap" {
		log.Fatalf("Invalid action %q: must be 'send' or 'swap'", action)
	}

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	client, err := initClient()
	if err != nil {
		return err
	}

	switch action {
	case "send":
		return sendETH(client)
	case "swap":
		return swapETH(client)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
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

// sendETH sends a sponsored self-transfer of 0.0001 ETH.
// When -rpc-url is provided, uses the on-chain nonce directly (non-sponsored).
// Otherwise, uses gas station sponsorship.
func sendETH(client *sdk.Client) error {
	fmt.Println("Action: send sponsored ETH self-transfer")

	value := "100000000000000" // 0.0001 ETH in wei
	intent := &models.EthSendTransactionIntent{
		From:  &signWith,
		To:    &signWith,
		Value: &value,
		Caip2: &caip2,
	}

	// When -rpc-url is provided, fetch the nonce from an external RPC (e.g. Alchemy)
	// and use non-sponsored mode. The nonce is not strictly needed — Turnkey resolves it
	// automatically — but is shown here for completeness. Note: custom nonces are not
	// compatible with sponsored transactions.
	if rpcURL != "" {
		n, err := getTxNonce(signWith)
		if err != nil {
			return err
		}
		fmt.Printf("Tx nonce from RPC provider: %s\n", n)
		sponsor := false
		intent.Nonce = &n
		intent.Sponsor = &sponsor
	} else {
		nonce, err := getGasStationNonce(client)
		if err != nil {
			return err
		}
		sponsor := true
		intent.Sponsor = &sponsor
		intent.GasStationNonce = nonce
	}

	txHash, err := submitAndWait(client, intent)
	if err != nil {
		return err
	}

	fmt.Printf("Send complete! Tx hash: %s\n", txHash)
	return nil
}

// swapETH performs a sponsored Uniswap V3 swap of 0.0001 ETH → USDC.
// When -rpc-url is provided, uses the on-chain nonce directly (non-sponsored).
// Otherwise, uses gas station sponsorship.
func swapETH(client *sdk.Client) error {
	fmt.Println("Action: swap ETH → USDC via Uniswap V3 (sponsored)")

	calldata, err := encodeExactInputSingle(
		sepoliaWETH,
		sepoliaUSDC,
		3000, // 0.3% fee tier
		signWith,
		big.NewInt(100_000_000_000_000), // 0.0001 ETH
		big.NewInt(0),                   // amountOutMinimum (0 for demo)
		big.NewInt(0),                   // sqrtPriceLimitX96
	)
	if err != nil {
		return fmt.Errorf("failed to encode swap calldata: %w", err)
	}

	calldataHex := "0x" + hex.EncodeToString(calldata)
	value := "100000000000000" // msg.value for ETH→token swap
	router := sepoliaSwapRouter02

	intent := &models.EthSendTransactionIntent{
		From:  &signWith,
		To:    &router,
		Value: &value,
		Data:  &calldataHex,
		Caip2: &caip2,
	}

	// When -rpc-url is provided, fetch the nonce from an external RPC (e.g. Alchemy)
	// and use non-sponsored mode. The nonce is not strictly needed — Turnkey resolves it
	// automatically — but is shown here for completeness. Note: custom nonces are not
	// compatible with sponsored transactions.
	if rpcURL != "" {
		n, err := getTxNonce(signWith)
		if err != nil {
			return err
		}
		fmt.Printf("Tx nonce from RPC provider: %s\n", n)
		sponsor := false
		intent.Nonce = &n
		intent.Sponsor = &sponsor
	} else {
		nonce, err := getGasStationNonce(client)
		if err != nil {
			return err
		}
		sponsor := true
		intent.Sponsor = &sponsor
		intent.GasStationNonce = nonce
	}

	txHash, err := submitAndWait(client, intent)
	if err != nil {
		return err
	}

	fmt.Printf("Swap complete! Tx hash: %s\n", txHash)
	return nil
}

// getGasStationNonce fetches the gas station delegate contract nonce.
// This is optional when sponsor=true (Turnkey handles it internally if omitted),
// but including it explicitly provides maximal security posture against replay attacks.
func getGasStationNonce(client *sdk.Client) (*string, error) {
	params := broadcasting.NewGetNoncesParams().WithBody(&models.GetNoncesRequest{
		OrganizationID:  &organizationID,
		Address:         &signWith,
		Caip2:           &caip2,
		GasStationNonce: true,
	})

	resp, err := client.V0().Broadcasting.GetNonces(params, client.Authenticator)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonces: %w", err)
	}

	nonce := resp.Payload.GasStationNonce
	if nonce == nil {
		return nil, fmt.Errorf("gas station nonce not returned (is gas station enabled for this org?)")
	}

	fmt.Printf("Gas station nonce: %s\n", *nonce)
	return nonce, nil
}

// getTxNonce fetches the on-chain transaction nonce via an Alchemy JSON-RPC call (eth_getTransactionCount).
// This is not strictly needed — Turnkey resolves the nonce automatically when it's omitted.
// It is included here for the sake of completeness, to show how you can provide your own nonce.
// Note: providing a nonce is not compatible with sponsored transactions (sponsor=true).
func getTxNonce(address string) (string, error) {
	if rpcURL == "" {
		return "", fmt.Errorf("rpc-url flag is required to fetch tx nonce")
	}

	reqBody, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "eth_getTransactionCount",
		"params":  []string{address, "latest"},
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("RPC request failed: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("failed to read RPC response: %w", err)
	}
	if closeErr != nil {
		return "", fmt.Errorf("failed to close RPC response body: %w", closeErr)
	}

	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return "", fmt.Errorf("failed to parse RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	// Convert hex nonce to decimal
	nonce := new(big.Int)
	nonce.SetString(strings.TrimPrefix(rpcResp.Result, "0x"), 16)
	return nonce.String(), nil
}

func submitAndWait(client *sdk.Client, intent *models.EthSendTransactionIntent) (string, error) {
	activityType := string(models.ActivityTypeEthSendTransaction)

	params := broadcasting.NewEthSendTransactionParams().WithBody(&models.EthSendTransactionRequest{
		OrganizationID: &organizationID,
		TimestampMs:    util.RequestTimestamp(),
		Type:           &activityType,
		Parameters:     intent,
	})

	resp, err := client.V0().Broadcasting.EthSendTransaction(params, client.Authenticator)
	if err != nil {
		return "", fmt.Errorf("failed to submit transaction: %w", err)
	}

	statusID := resp.Payload.Activity.Result.EthSendTransactionResult.SendTransactionStatusID
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
	feeBig := new(big.Int).SetUint64(uint64(fee))
	padBigInt(data[4+64:4+96], feeBig)
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
func addressToBytes(addr string) ([]byte, error) {
	addr = strings.TrimPrefix(addr, "0x")
	b, err := hex.DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	return b, nil
}

// padBigInt writes a big.Int right-aligned into a 32-byte slot.
func padBigInt(dst []byte, v *big.Int) {
	b := v.Bytes()
	offset := 32 - len(b)
	if offset > 0 {
		copy(dst[offset:], b)
	} else {
		copy(dst, b[len(b)-32:])
	}
}
