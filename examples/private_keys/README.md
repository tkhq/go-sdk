# Examples: Private Keys

A Turnkey private key is a single, standalone key pair, as opposed to a [wallet](../wallets/), which is a hierarchical deterministic (HD) tree of accounts derived from one seed. Use a private key when you want to bring an existing raw key into Turnkey rather than deriving addresses from a mnemonic.

**Private Key** → one key pair, defined by a curve. Supported curves:
- `CURVE_SECP256K1` (Ethereum and other EVM chains)
- `CURVE_ED25519` (Solana)

> [!CAUTION]
>
> **SECURITY: Your private keys grant full, irrevocable access to your funds.**
> Treat them with the same care as a root password, store them offline and never log them, and never share them.
> If you have any reason to believe they were exposed, **rotate them immediately**.

---

## `import_private_key`

Imports an existing raw private key into Turnkey. The key is encrypted client-side before being sent — Turnkey's enclave decrypts it and stores it. The plaintext private key is never transmitted.

Supports either a hex-encoded Secp256k1 (Ethereum) key or a base58-encoded Ed25519 (Solana) key. Set exactly one.

### 1/ Setup

Follow the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) to get your API key and organization ID.

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/private_keys/import_private_key/.env.example examples/private_keys/import_private_key/.env
```

Set exactly one of `TURNKEY_ETHEREUM_PRIVATE_KEY` (hex-encoded) or `TURNKEY_SOLANA_PRIVATE_KEY` (base58-encoded).

### 2/ Running

```bash
set -a && source examples/private_keys/import_private_key/.env && set +a && go run ./examples/private_keys/import_private_key
```

Prints the new private key ID and derived addresses on success.
