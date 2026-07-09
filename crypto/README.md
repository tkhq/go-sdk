# Turnkey Go SDK Crypto Module

[![GoDocs](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/tkhq/go-sdk/crypto)

The `crypto` module provides utilities for API key generation, signing, encryption, and attestation. It is used transitively by the root `github.com/tkhq/go-sdk/v2` module, so most SDK users do not need to install it separately. It can also be imported directly if you only need the crypto functionality.

## Installation

```bash
go get github.com/tkhq/go-sdk/crypto

import "github.com/tkhq/go-sdk/crypto"
```

## Key Types and Functions

### `NewAPIKey`

Generates a new Turnkey API key. It defaults to `SchemeP256`; pass
`WithScheme(SchemeSECP256K1)` or `WithScheme(SchemeED25519)` to generate a
different key type. Returns an `*APIKey`; use `GetPublicKey()` and
`GetPrivateKey()` to access the Turnkey-encoded key material.

### `APIKey`

The `APIKey` type represents a Turnkey API key, including its public key,
private key, and signing scheme. It has methods for signing data and exposing
key metadata used by local storage.

### `FromTurnkeyPrivateKey`

Creates an `APIKey` object from a raw private key and signing scheme. This is useful for loading existing API keys from storage, and is the preferred method for doing so.

### `NewLocal`

Creates a filesystem-backed local key store used by the examples to save and
load API keys during local development.

### Enclave Functions

Standalone functions for encrypting to and decrypting from Turnkey enclave bundles, used in wallet import/export, email auth, and OTP flows.

## Usage Examples

See the examples directory in the root SDK for runnable code:

- [API key generation](../examples/apikey/generate.go)
- [OTP flow](../examples/otp/main.go)
- [Import wallet](../examples/wallets/import_wallet/main.go)
- [Export wallet](../examples/wallets/export_wallet/main.go)

# Contributing + License

Contributions are welcome! Please open an issue or submit a pull request with any improvements or bug fixes.

This project is licensed under the Apache License 2.0. See the [LICENSE](../LICENSE) file for details.
