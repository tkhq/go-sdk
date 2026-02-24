# Solana Transaction Management Example

Demonstrates Turnkey's [transaction management](https://docs.turnkey.com/concepts/transaction-management) feature for Solana with both sponsored and non-sponsored modes.

## Actions

- **send** — Transfer 890,880 lamports (~0.00089 SOL, the minimum rent-exempt balance). Defaults to self-transfer if no `-destination` is provided.
- **send-token** — SPL token transfer (e.g. USDC). Defaults to self-transfer if no `-destination` is provided.

Both actions use Turnkey Gas Station for gas sponsorship by default. Pass `-sponsor=false` to use non-sponsored mode.

## What sponsorship handles

Beyond simple fee-payer substitution, Turnkey's Solana sponsorship handles:

- **Rent sponsorship** for new data accounts (ATAs, etc.)
- **Blockhash management** — fetches and refreshes blockhashes automatically (Solana blockhashes expire ~60s)
- **Paymaster balance management** — keeps paymaster wallets funded
- **USD price tracking** for gas cost attribution

The user can submit a transaction with no signatures — Turnkey signs with both the user's key and the paymaster.

## Prerequisites

- A Turnkey organization entitled to use the Transaction Management feature
- A Solana wallet with devnet SOL
- A Turnkey API key (P-256)
- A Solana RPC URL (only for non-sponsored mode, e.g. `https://api.devnet.solana.com`)

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
| `-action` | No | `send` | Action to perform: `send` or `send-token` |
| `-caip2` | No | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` | CAIP-2 chain ID (default: devnet) |
| `-sponsor` | No | `true` | Use gas station sponsorship |
| `-rpc-url` | When `-sponsor=false` | | Solana RPC URL for fetching blockhash |
| `-token-mint` | When `send-token` | | SPL token mint address (base58) |
| `-destination` | No | self | Destination wallet address (base58). Defaults to self-transfer. |
| `-amount` | No | `1000000` | Token amount in smallest units (1000000 = 1 USDC) |
| `-decimals` | No | `6` | Token decimals (6 for USDC) |

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

# Send 1 USDC to a destination (sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -action send-token \
  -token-mint "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" \
  -destination "..."

# Send 1 USDC to a destination (non-sponsored)
go run main.go \
  -api-private-key "..." \
  -organization-id "..." \
  -sign-with "..." \
  -sponsor=false \
  -rpc-url "https://api.devnet.solana.com" \
  -action send-token \
  -token-mint "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU" \
  -destination "..."
```

## How it works

1. Creates a Turnkey SDK client using the provided API key
2. Builds an unsigned transaction using `gagliardetto/solana-go`:
   - **send**: a SOL self-transfer (system program)
   - **send-token**: derives ATAs for source and destination, includes an idempotent ATA creation instruction, and a `TransferChecked` SPL token instruction
3. **Sponsored mode** (`-sponsor=true`, default): uses a placeholder blockhash — Turnkey reconstructs the transaction with a fresh blockhash, substitutes the fee payer with a paymaster, and handles rent for any new accounts (e.g. ATA creation)
4. **Non-sponsored mode** (`-sponsor=false`): fetches a real blockhash from the Solana RPC and includes it in the unsigned transaction — the wallet pays its own fees
5. Serializes the transaction to hex and submits via `SolSendTransaction`
6. Polls `GetSendTransactionStatus` until a tx signature is returned or an error occurs
