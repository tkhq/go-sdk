# Transaction Management: Ethereum

Demonstrates Turnkey's [transaction management](https://docs.turnkey.com/features/transaction-management) feature on Ethereum, in both sponsored and non-sponsored modes.

## Actions

Select the action with the `ACTION` environment variable:

- **send** (default) — self-transfer of 0.0001 ETH
- **swap** — Uniswap V3 swap (ETH → USDC) via SwapRouter02
- **assets** — list supported assets for Ethereum Sepolia

The `send` and `swap` actions use Turnkey Gas Station for gas sponsorship by default. Set `SPONSOR=false` to use non-sponsored mode (the EOA pays gas).

## Prerequisites

- A Turnkey organization entitled to use the Transaction Management feature
- A wallet with Ethereum Sepolia testnet ETH
- A Turnkey API key (P-256)

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TURNKEY_API_PRIVATE_KEY` | Yes | | Turnkey API private key |
| `TURNKEY_ORGANIZATION_ID` | Yes | | Turnkey organization ID |
| `TURNKEY_SIGN_WITH` | Yes | | Wallet address to sign with (0x-prefixed) |
| `ACTION` | No | `send` | Action to perform: `send`, `swap`, or `assets` |
| `SPONSOR` | No | `true` | Set to `false` for non-sponsored mode |

## Setup

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/transaction_management/ethereum/.env.example examples/transaction_management/ethereum/.env
```

## Running

```bash
# Send 0.0001 ETH to self (sponsored, the default)
set -a && source examples/transaction_management/ethereum/.env && set +a && \
  go run ./examples/transaction_management/ethereum

# Swap 0.0001 ETH → USDC via Uniswap V3 (sponsored)
set -a && source examples/transaction_management/ethereum/.env && set +a && \
  ACTION=swap go run ./examples/transaction_management/ethereum

# Send 0.0001 ETH to self (non-sponsored)
set -a && source examples/transaction_management/ethereum/.env && set +a && \
  SPONSOR=false go run ./examples/transaction_management/ethereum

# List supported assets
set -a && source examples/transaction_management/ethereum/.env && set +a && \
  ACTION=assets go run ./examples/transaction_management/ethereum
```

Inline variables (`ACTION=swap`, `SPONSOR=false`) override the values sourced from `.env` for that run.

## Example output

Sample output; balances are abridged for readability and will differ for your wallet.

```
$ set -a && source examples/transaction_management/ethereum/.env && set +a && \
  go run ./examples/transaction_management/ethereum
Balances for 0x73e8…A666:
  0.1999 ETH ($0.00)

Action: send sponsored ETH self-transfer
Gas station nonce: 1
Transaction submitted, status ID: sha256:5873669520255f06c6617aba4c57cc3ccb4db8a9aba85dfd042fd1f5af108dfb
Polling for confirmation...
  Status: INITIALIZED
  Status: BROADCASTING
Send complete! Tx hash: 0xb36294c0e0924064f0c527ad651aeef854edc35adae3c43ead0b12d6dae17586
Balances for 0x73e8…A666:
  0.1999 ETH ($0.00)
```

The ETH balance is unchanged: the self-transfer returns the value to the same address, and Gas Station paid the fee. Run the same command with `SPONSOR=false` and the balance drops by the gas cost.

```
$ set -a && source examples/transaction_management/ethereum/.env && set +a && \
  ACTION=swap go run ./examples/transaction_management/ethereum
Balances for 0x73e8…A666:
  0.1999 ETH ($0.00)

Action: swap ETH → USDC via Uniswap V3 (sponsored)
Gas station nonce: 2
Transaction submitted, status ID: sha256:821511500618ed363444adf86b56bc5abf9389b5a94ed473c480d978d4ec424c
Polling for confirmation...
  Status: INITIALIZED
  Status: BROADCASTING
Swap complete! Tx hash: 0xc35364a6a000d8ba516c986d0f4fbd29cb0dcd3802417e8436bbdcd6d47574a1
Balances for 0x73e8…A666:
  0.1998 ETH ($0.00)
  2.6379 USDC ($0.00)
```

If a transaction reverts, the failure is reported with the contract revert chain, outermost call first:

```
transaction failed: Pre-flight simulation failed: Too little received -> ExecutionFailed() -> ExecutionFailed()
  [0] Too little received (at 0x3bfa4769fb09eefc5a80d6e87c3b9c650f7ae48e)
  [1] ExecutionFailed() (at 0x73e8aebbad9ac514bca7169f9866e1aa08d5a666)
  [2] ExecutionFailed() (at 0x5af5194b4b0909eb978e3cf1e25333852277f07d)
```

## How it works

1. Creates a Turnkey client from the API key stamper.
2. Fetches and displays wallet balances via `GetWalletAddressBalances`.
3. **Sponsored mode** (`SPONSOR=true`, default): fetches a gas station nonce via `GetNonces` for ordering and replay protection.
4. **Non-sponsored mode** (`SPONSOR=false`): Turnkey resolves the on-chain nonce automatically.
5. Submits the transaction via `ETHSendTransaction`.
6. Polls `GetSendTransactionStatus` until a tx hash is returned, an error occurs, or the example's 60-second timeout elapses. On failure, the structured error is rendered with the contract revert chain when one is available.
7. Fetches and displays updated balances. In sponsored mode a self-transfer leaves the balance unchanged — that is the point: the value returns to the sender and Gas Station covers the fee.

For the **swap** action, the calldata is ABI-encoded for Uniswap V3 [SwapRouter02](https://docs.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments)'s `exactInputSingle` (selector `0x04e45aaf`), targeting the WETH/USDC pool with a 0.3% fee tier. Those contracts are Sepolia-only, so the chain (`eip155:11155111`) is hardcoded alongside them.

**Warning:** the swap sets `amountOutMinimum` to `0`, so it accepts any output amount, however unfavourable. That keeps the example simple on a testnet with thin liquidity, but it must not be copied to mainnet, where it invites sandwich attacks. Derive a real minimum from a quote before adapting this code.

## Nonce handling

There are two distinct nonces involved in transaction management:

- **On-chain nonce** — the standard Ethereum transaction nonce. Turnkey resolves this automatically in both sponsored and non-sponsored modes; you never need to provide it. To manage it yourself, fetch it via `GetNonces` with `Nonce: ptr(true)` and set `req.Nonce` (see example below). Custom on-chain nonces are not compatible with sponsored transactions.

- **Gas station nonce** — a nonce specific to the gas station delegate contract, only relevant for sponsored transactions (`SPONSOR=true`). Turnkey handles this internally if omitted, but passing it explicitly provides maximal security against replay attacks: it ensures a signed request can only produce a single transaction. See the [Gas Station security docs](https://docs.turnkey.com/features/transaction-management#security). This example passes it explicitly.

### Providing a custom on-chain nonce

```go
resp, err := client.GetNonces(ctx, turnkey.GetNoncesRequest{
    OrganizationID: cfg.organizationID,
    Address:        cfg.signWith,
    Caip2:          sepoliaCaip2,
    Nonce:          ptr(true),
})
if err != nil {
    return err
}

req.Nonce = resp.Nonce
```

**Note:** if you run multiple sponsored transactions back-to-back, wait for the previous one to confirm before sending the next — otherwise the gas station nonce may not have incremented yet, causing an `InvalidNonce` error.
