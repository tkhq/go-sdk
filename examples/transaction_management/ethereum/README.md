# Transaction Management Example

Demonstrates the Turnkey's sponsored [transaction management](https://docs.turnkey.com/concepts/transaction-management) feature.

## Actions

- **send** — Sponsored self-transfer of 0.0001 ETH
- **swap** — Sponsored Uniswap V3 swap (ETH → USDC) via SwapRouter02

Both actions use Turnkey Gas Station for gas sponsorship.

## Prerequisites

- A Turnkey organization with Gas Station enabled on Sepolia
- A wallet with Sepolia ETH
- A Turnkey API key (P-256)

## Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-api-private-key` | Yes | | Turnkey API private key |
| `-organization-id` | Yes | | Turnkey organization ID |
| `-sign-with` | Yes | | Wallet address to sign with (0x-prefixed) |
| `-action` | No | `send` | Action to perform: `send` or `swap` |
| `-caip2` | No | `eip155:11155111` | CAIP-2 chain ID |

## Usage

```bash
# From go-sdk/examples/transaction_management/ethereum/

# Send 0.0001 ETH to self (sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "0x..." \
  -action send

# Swap 0.0001 ETH → USDC via Uniswap V3 (sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "0x..." \
  -action swap
```

## Example output

```
$ go run main.go -api-private-key ... -organization-id "7ff189fb-..." -sign-with "0xB2E8..." -action send
Action: send sponsored ETH self-transfer
Gas station nonce: 5
Transaction submitted, status ID: sha256:0e061f4b3fc0437e8c21dd7059ac05f6966af5d574456744cd48a6e22e2c40dd
Polling for confirmation...
  Status: INITIALIZED
Send complete! Tx hash: 0xda2a8c705f19d9f4e17ea354d213e50b7d38f76ccdce23f7c3492f87260e456d
```

```
$ go run main.go -api-private-key ... -organization-id "7ff189fb-..." -sign-with "0xB2E8..." -action swap
Action: swap ETH → USDC via Uniswap V3 (sponsored)
Gas station nonce: 6
Transaction submitted, status ID: sha256:bafb08367618c0e727c5b99f6ddc2f0cb05d5a81d723062af0cb8fc3c5018d08
Polling for confirmation...
  Status: INITIALIZED
Swap complete! Tx hash: 0xde41d1f35986f7f9a661afba568674d51a5913ba9f1c6d2391f99d6dd7a98e74
```

## How it works

1. Creates a Turnkey SDK client using the provided API key
2. Fetches a gas station nonce via `GetNonces` for transaction ordering
3. Submits the transaction via `EthSendTransaction` with `sponsor: true`
4. Polls `GetSendTransactionStatus` until a tx hash is returned or an error occurs

For the **swap** action, the calldata is ABI-encoded for Uniswap V3 [SwapRouter02](https://docs.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments)'s `exactInputSingle` (selector `0x04e45aaf`), targeting the WETH/USDC pool with a 0.3% fee tier on Sepolia.
