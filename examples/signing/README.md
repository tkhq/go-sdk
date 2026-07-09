# Example: `signing`

Two sample scripts demonstrating transaction and payload signing via the Turnkey API.

## `sign_raw_payload`

Signs an arbitrary hex-encoded payload using Keccak256 hashing.

### 1/ Setup

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/signing/sign_raw_payload/.env.example examples/signing/sign_raw_payload/.env
```

### 2/ Running

```bash
set -a && source examples/signing/sign_raw_payload/.env && set +a && go run ./examples/signing/sign_raw_payload
```

Prints the signature `r`, `s`, and `v` values on success.

---

## `sign_transaction`

Signs an Ethereum transaction (EIP-1559) using a Turnkey wallet address or private key ID.

### 1/ Setup

Follow the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) to get your API key and organization ID, then create a wallet to sign with.

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/signing/sign_transaction/.env.example examples/signing/sign_transaction/.env
```

`TURNKEY_UNSIGNED_TRANSACTION` defaults to an EIP-1559 transaction sending 0 ETH to the zero address on mainnet if not set.

### 2/ Running

```bash
set -a && source examples/signing/sign_transaction/.env && set +a && go run ./examples/signing/sign_transaction
```

Prints the signed transaction hex on success.

