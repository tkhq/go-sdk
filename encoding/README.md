# Turnkey Go SDK Encoding Module
[![GoDocs](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/tkhq/go-sdk/encoding)

The `encoding` module provides utilities for hexadecimal, Base58, and JSON encoding. It is primarily used as a shared dependency of the `crypto` module, but can also be imported independently in applications that need Turnkey-compatible encoding helpers.

## Installation

```bash
go get github.com/tkhq/go-sdk/encoding

import "github.com/tkhq/go-sdk/encoding"
```

## Key Types and Functions

### `HexBytes`
`HexBytes` is a `[]byte` type that marshals to/from a hex-encoded JSON string. Use it for fields that need to serialize as hex in JSON.

### `BytesToHex` / `HexToBytes`
`BytesToHex` converts a byte slice to a lowercase hex string. `HexToBytes` converts a hex string back to a byte slice, with optional left-padding to a target length.

### `Bs58Encode` / `Bs58Decode`
`Bs58Encode` encodes a byte slice into a Base58 string, and `Bs58Decode` decodes a Base58 string back into a byte slice.

### `HexToBase64URL`
`HexToBase64URL` converts a hex string to a base64url-encoded string (no padding). Accepts an optional target byte length for left-padding.

# Contributing + License

Contributions are welcome! Please open an issue or submit a pull request with any improvements or bug fixes.

This project is licensed under the Apache License 2.0. See the [LICENSE](../LICENSE) file for details.
