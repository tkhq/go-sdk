# CHANGELOG

## 0.2.0 — 2026-10-15
### Patch Changes
- golang was updated to v1.27 with lots of deprecations and crypto changes.  Functionally a no-op.
### Minor Changes
- Adds `EncryptSecretToBundle`, which verifies and HPKE-encrypts a secret plaintext to an `InitImportSecrets` target bundle.

### [crypto/v0.1.1 ... crypto/v0.2.0](https://github.com/tkhq/go-sdk/compare/crypto/v0.1.1...crypto/v0.2.0)

## 0.1.1 — 2026-08-25
### Patch Changes
- bumping x/crypto for https://nvd.nist.gov/vuln/detail/cve-2026-46595
- `DecryptCredentialBundle` now returns an error instead of panicking on a malformed compressed P-256 public key, and attestation parsing rejects a COSE Sign1 structure that does not have exactly 4 elements. Also documents the verification checks `VerifyProofs` and `VerifyAppProofSignature` do not perform.

### [crypto/v0.1.0 ... crypto/v0.1.1](https://github.com/tkhq/go-sdk/compare/crypto/v0.1.0...crypto/v0.1.1)

## 0.1.0 — 2026-07-09
### Minor Changes
- Initial public release of the crypto package: key management, signing, verification, and enclave encryption helpers.

### [crypto/v0.0.0 ... crypto/v0.1.0](https://github.com/tkhq/go-sdk/compare/crypto/v0.0.0...crypto/v0.1.0)
