# CHANGELOG

## 0.4.0 — 2026-11-19
### Patch Changes
- `EncryptSecretToBundle` now rejects a signed target whose `userId` is non-empty, so a substituted private key or wallet import target cannot receive a Secret.
### Minor Changes
- Adds `EncryptOAuth2ToBundle` and `OAuth2AuthenticationBundle`, which verify an `InitOAuth2Authenticate` TLS Fetcher target and HPKE-encrypt the OAuth 2.0 authentication inputs for `OAuth2AuthenticateV2`.
- Adds `EncryptBoundSecretToBundle`, `ImportSecretsPurposeBinding`, `StaticProperty`, `HPKEEncryptWithPurposeBinding`, and `HPKEDecryptWithPurposeBinding`. `EncryptBoundSecretToBundle` binds an ImportSecrets ciphertext to the secret's `name` and `static_properties` (`TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`), so the enclave rejects a ciphertext submitted with a different name or properties.
- Breaking: `EncryptSecretToBundle` now takes `name` and `staticProperties` and binds the ciphertext to them (`TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`). Callers that build the `ImportSecrets` activity themselves must send `TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`; a caller that sends V1 still compiles, but the enclave cannot decrypt the secret. Removes `EncryptBoundSecretToBundle`; use `EncryptSecretToBundle` instead.
- Adds `OAuth2AuthenticatePurposeBinding`. `EncryptOAuth2ToBundle` binds the ciphertext to `bundle.OAuth2CredentialID`, so it cannot be submitted with another credential ID. `InitOAuth2Authenticate` must request `TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`; V1 is no longer accepted.

### [crypto/v0.3.0 ... crypto/v0.4.0](https://github.com/tkhq/go-sdk/compare/crypto/v0.3.0...crypto/v0.4.0)

## 0.3.0 — 2026-10-30
### Patch Changes
- Run the `modernize` linter to replace legacy constructs with modern Go stylings
### Minor Changes
- Raises the minimum Go version in `go.mod` to 1.27.1.

### [crypto/v0.2.0 ... crypto/v0.3.0](https://github.com/tkhq/go-sdk/compare/crypto/v0.2.0...crypto/v0.3.0)

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
