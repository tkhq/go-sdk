# Transaction Management Example

Demonstrates Turnkey's [transaction management](https://docs.turnkey.com/concepts/transaction-management) feature with both sponsored and non-sponsored modes.

## Actions

- **send** — Self-transfer of 0.0001 ETH
- **swap** — Uniswap V3 swap (ETH → USDC) via SwapRouter02

Both actions use Turnkey Gas Station for gas sponsorship by default. Pass `-sponsor=false` to use non-sponsored mode.

## Prerequisites

- A Turnkey organization entitles to use the Transaction Management feature
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
| `-sponsor` | No | `true` | Use gas station sponsorship |

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

# Send 0.0001 ETH to self (non-sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "0x..." \
  -sponsor=false \
  -action send

# Swap 0.0001 ETH → USDC via Uniswap V3 (non-sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "0x..." \
  -sponsor=false \
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
2. **Sponsored mode** (`-sponsor=true`, default): fetches a gas station nonce via `GetNonces` for transaction ordering and replay protection
3. **Non-sponsored mode** (`-sponsor=false`): Turnkey resolves the on-chain nonce automatically
4. Submits the transaction via `EthSendTransaction`
5. Polls `GetSendTransactionStatus` until a tx hash is returned or an error occurs

For the **swap** action, the calldata is ABI-encoded for Uniswap V3 [SwapRouter02](https://docs.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments)'s `exactInputSingle` (selector `0x04e45aaf`), targeting the WETH/USDC pool with a 0.3% fee tier on Sepolia.

## Nonce handling

There are two distinct nonces involved in transaction management:

- **On-chain nonce** — the standard Ethereum transaction nonce. Turnkey resolves this automatically in both sponsored and non-sponsored modes; you never need to provide it. If you want to manage it yourself, you can fetch it via `GetNonces` with `Nonce: true` and set `intent.Nonce` (see example below). Custom on-chain nonces are not compatible with sponsored transactions.

- **Gas station nonce** — a nonce specific to the gas station delegate contract, only relevant for sponsored transactions (`sponsor: true`). Turnkey handles this internally if omitted, but passing it explicitly provides maximal security against replay attacks: it ensures a signed request can only produce a single transaction. See the [Gas Station security docs](https://docs.turnkey.com/signing-automation/gas-station#security). This example passes it explicitly.

### Providing a custom on-chain nonce

```go
params := broadcasting.NewGetNoncesParams().WithBody(&models.GetNoncesRequest{
    OrganizationID: &organizationID,
    Address:        &signWith,
    Caip2:          &caip2,
    Nonce:          true,
})

resp, err := client.V0().Broadcasting.GetNonces(params, client.Authenticator)
if err != nil {
    return err
}

intent.Nonce = resp.Payload.Nonce
```

**Note:** if you run multiple sponsored transactions back-to-back, wait for the previous one to confirm before sending the next — otherwise the gas station nonce may not have incremented yet, causing an `InvalidNonce` error.
