# Examples: Wallets

A Turnkey wallet is a hierarchical deterministic (HD) wallet. A collection of key pairs that share a common BIP-39 seed (mnemonic). From one seed you can derive addresses for any supported blockchain using standard derivation paths.

**Wallet** → holds the seed (mnemonic). Never directly exposed and only accessible via export.  
**Account** → a specific derived address. Defined by a curve, address format, and derivation path.

Common derivation paths supported by Turnkey:
- Ethereum: `m/44'/60'/0'/0/0`
- Solana: `m/44'/501'/0'/0'`
- Cosmos: `m/44'/118'/0'/0/0`

> [!CAUTION]
>
> **SECURITY: Your mnemonic and private keys grant full, irrevocable access to your funds.**
> Treat them with the same care as a root password, store them offline and never log them, and never share them.
> If you have any reason to believe they were exposed, **rotate them immediately**.

---

## `create_wallet`

Creates a new HD wallet with an initial Ethereum account.

### 1/ Setup

Follow the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) to get your API key and organization ID.

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/wallets/create_wallet/.env.example examples/wallets/create_wallet/.env
```

### 2/ Running

```bash
set -a && source examples/wallets/create_wallet/.env && set +a && go run ./examples/wallets/create_wallet
```

Prints the wallet ID and derived Ethereum address on success.

---

## `create_wallet_accounts`

Derives additional accounts (addresses) from an existing wallet.


### 1/ Setup

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/wallets/create_wallet_accounts/.env.example examples/wallets/create_wallet_accounts/.env
```

### 2/ Running

```bash
set -a && source examples/wallets/create_wallet_accounts/.env && set +a && go run ./examples/wallets/create_wallet_accounts
```

Prints the wallet ID and new addresses on success.

If you get an error, you need to change the derivation path in `main.go` to a new unused path. For example, if the wallet already has an account at `m/44'/60'/0'/0/0`, change it to `m/44'/60'/0'/0/1` and try again.

---

## `export_wallet`

Exports the BIP-39 mnemonic for a wallet. The mnemonic is decrypted locally, it never leaves your machine in plaintext. Useful for backup or migrating to another wallet provider.

The export uses an enclave flow: a local encryption key pair is generated, the enclave encrypts the mnemonic to it, and this example decrypts it client-side.

### 1/ Setup

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/wallets/export_wallet/.env.example examples/wallets/export_wallet/.env
```

### 2/ Running

```bash
set -a && source examples/wallets/export_wallet/.env && set +a && go run ./examples/wallets/export_wallet
```

Prints the wallet ID and mnemonic on success.

---

## `export_wallet_account`

Exports the raw private key for a single wallet account address. Like `export_wallet`, decryption happens locally via the enclave flow.

### 1/ Setup

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/wallets/export_wallet_account/.env.example examples/wallets/export_wallet_account/.env
```

### 2/ Running

```bash
set -a && source examples/wallets/export_wallet_account/.env && set +a && go run ./examples/wallets/export_wallet_account
```

Prints the address and private key (hex) on success.

---

## `import_wallet`

Imports an existing BIP-39 mnemonic into Turnkey. The mnemonic is encrypted client-side before being sent — Turnkey's enclave decrypts it and stores the seed. The plaintext mnemonic is never transmitted.

### 1/ Setup

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/wallets/import_wallet/.env.example examples/wallets/import_wallet/.env
```

### 2/ Running

```bash
set -a && source examples/wallets/import_wallet/.env && set +a && go run ./examples/wallets/import_wallet
```

Prints the new wallet ID and derived Ethereum address on success.
