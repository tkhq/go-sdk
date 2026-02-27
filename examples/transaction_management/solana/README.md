# Solana Transaction Management Example

Demonstrates Turnkey's [transaction management](https://docs.turnkey.com/concepts/transaction-management) feature for Solana with both sponsored and non-sponsored modes.

## Actions

- **send** — Transfer 890,880 lamports (~0.00089 SOL, the minimum rent-exempt balance). Defaults to self-transfer if no `-destination` is provided.
- **send-token** — SPL token transfer (e.g. USDC). Defaults to self-transfer if no `-destination` is provided.
- **swap** — Swap SOL for USDC via [Jupiter](https://jup.ag) (mainnet only). Requires a Jupiter API key.
- **assets** — List all supported assets for the configured chain (no transaction submitted).

All actions except `assets` use Turnkey Gas Station for gas sponsorship by default. Pass `-sponsor=false` to use non-sponsored mode.

## What sponsorship handles

Beyond simple fee-payer substitution, Turnkey's Solana sponsorship handles:

- **Rent sponsorship** for new data accounts (ATAs, etc.)
- **Blockhash management** — fetches and refreshes blockhashes automatically (Solana blockhashes expire ~60s)
- **Paymaster balance management** — keeps paymaster wallets funded
- **USD price tracking** for gas cost attribution

The user can submit a transaction with no signatures — Turnkey signs with both the user's key and the paymaster.

## Prerequisites

- A Turnkey organization entitled to use the Transaction Management feature
- A Solana wallet with devnet SOL (or mainnet SOL for `swap`)
- A Turnkey API key (P-256)
- A Solana RPC URL (only for non-sponsored mode, e.g. `https://api.devnet.solana.com`)
- A [Jupiter API key](https://station.jup.ag/docs/apis/swap-api) (only for `swap`)

## CAIP-2 Chain IDs

The `-caip2` flag identifies the Solana network. Per the [CAIP-2 spec](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md), the chain reference is the genesis hash truncated to 32 characters. The backend also accepts the full genesis hash.

| Network | CAIP-2 |
|---------|--------|
| Mainnet | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` |
| Devnet | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` |

## Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-api-private-key` | Yes | | Turnkey API private key |
| `-organization-id` | Yes | | Turnkey organization ID |
| `-sign-with` | Yes | | Solana wallet address (base58) |
| `-action` | No | `send` | Action to perform: `send`, `send-token`, `swap`, or `assets` |
| `-caip2` | No | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` | CAIP-2 chain ID (default: devnet) |
| `-sponsor` | No | `true` | Use gas station sponsorship |
| `-rpc-url` | When `-sponsor=false` | | Solana RPC URL for fetching blockhash |
| `-token-mint` | When `send-token` | | SPL token mint address (base58). Must match the chain — devnet USDC: `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, mainnet USDC: `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| `-destination` | No | self | Destination wallet address (base58). Defaults to self-transfer. |
| `-amount` | No | `890880` | Amount in smallest units: lamports for `send` (default: 890,880 ~0.00089 SOL), token units for `send-token` (e.g. 1000000 = 1 USDC) |
| `-decimals` | No | `6` | Token decimals (6 for USDC) |
| `-jupiter-api-key` | When `swap` | | Jupiter API key |
| `-swap-amount` | No | `0.0001` | Amount of SOL to swap (decimal) |

## Usage

```bash
# From go-sdk/examples/transaction_management/solana/

# Send SOL to self (sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -action send

# Send SOL to self (non-sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -sponsor=false \
  -rpc-url "https://api.devnet.solana.com" \
  -action send

# Send 1 devnet USDC to a destination (sponsored, devnet)
# Devnet USDC mint: 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -action send-token \
  -token-mint "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" \
  -destination "..."

# Send 1 devnet USDC to a destination (non-sponsored, devnet)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -sponsor=false \
  -rpc-url "https://api.devnet.solana.com" \
  -action send-token \
  -token-mint "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" \
  -destination "..."

# Send 1 mainnet USDC to a destination (sponsored, mainnet)
# Mainnet USDC mint: EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -caip2 "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" \
  -action send-token \
  -token-mint "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" \
  -destination "..."

# Swap 0.0001 SOL → USDC via Jupiter (mainnet, sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -caip2 "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" \
  -action swap \
  -jupiter-api-key "..."

# Swap 0.0001 SOL → USDC via Jupiter (mainnet, non-sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -caip2 "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" \
  -sponsor=false \
  -rpc-url "https://api.mainnet-beta.solana.com" \
  -action swap \
  -jupiter-api-key "..." \
  -swap-amount "0.0001"

# List supported assets for devnet
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -action assets
```

## Example output

```
$ go run main.go -api-private-key ... -organization-id "7ff189fb-..." -sign-with "8vXr..." -action send
Balances for 8vXr...:
  0.5 SOL ($75.00)
  10.0 USDC ($10.00)

Action: send 890,880 lamports (~0.00089 SOL) to 8vXr... (sponsored, solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1)
Transaction submitted, status ID: sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
Polling for confirmation...
  Status: INITIALIZED
SOL transfer complete! Tx signature: 5UfgJ9...
Balances for 8vXr...:
  0.5 SOL ($75.00)
  10.0 USDC ($10.00)
```

```
$ go run main.go -api-private-key ... -organization-id "7ff189fb-..." -sign-with "8vXr..." -action send-token -token-mint "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" -destination "9qHm..."
Balances for 8vXr...:
  0.4991 SOL ($74.87)
  10.0 USDC ($10.00)

Balances for 9qHm...:
  0.1 SOL ($15.00)
  0.0 USDC ($0.00)

Source ATA:      DkVn...
Destination ATA: HmZr...
Action: send 1000000 tokens (sponsored, solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1)
Transaction submitted, status ID: sha256:2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c
Polling for confirmation...
  Status: INITIALIZED
Token transfer complete! Tx signature: 3TpQK8...
Balances for 8vXr...:
  0.4991 SOL ($74.87)
  9.0 USDC ($9.00)

Balances for 9qHm...:
  0.1 SOL ($15.00)
  1.0 USDC ($1.00)
```

```
$ go run main.go -api-private-key ... -organization-id "7ff189fb-..." -sign-with "8vXr..." -action assets
Balances for 8vXr...:
  0.4991 SOL ($74.87)
  9.0 USDC ($9.00)

Supported assets for solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:
  SOL (decimals: 9, caip19: solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1/slip44:501)
  USDC (decimals: 6, caip19: solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1/spl:4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU)
```

## How it works

1. Creates a Turnkey SDK client using the provided API key
2. Fetches and prints current balances via `GetWalletAddressBalances` — for the sender, and also for the destination if it differs from the sender
3. Builds an unsigned transaction (for `send`, `send-token`, `swap`) or queries the asset list (for `assets`):
   - **send**: builds a SOL transfer locally using `gagliardetto/solana-go` (system program)
   - **send-token**: derives ATAs, builds an idempotent ATA creation instruction and a `TransferChecked` SPL token instruction locally
   - **swap**: fetches a pre-built swap transaction from Jupiter's API (quote → swap), then converts the base64 result to hex — no local transaction construction needed
   - **assets**: calls `ListSupportedAssets` and prints the result — no transaction submitted
4. **Sponsored mode** (`-sponsor=true`, default): uses a placeholder blockhash — Turnkey reconstructs the transaction with a fresh blockhash, substitutes the fee payer with a paymaster, and handles rent for any new accounts (e.g. ATA creation)
5. **Non-sponsored mode** (`-sponsor=false`): fetches a real blockhash from the Solana RPC and includes it in the unsigned transaction — the wallet pays its own fees
6. Serializes the transaction to hex and submits via `SolSendTransaction`
7. Polls `GetSendTransactionStatus` until a tx signature is returned or an error occurs
8. Fetches and prints updated balances after the transaction confirms — for the sender, and also for the destination if it differs from the sender
