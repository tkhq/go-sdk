---
module: "crypto"
bump: "major"
title: "EncryptSecretToBundle binds the ciphertext to the secret name and static properties"
date: "2026-11-12"
---

Breaking: `EncryptSecretToBundle` now takes `name` and `staticProperties` and binds the ciphertext to them (`TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`). Callers that build the `ImportSecrets` activity themselves must send `TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`; a caller that sends V1 still compiles, but the enclave cannot decrypt the secret. Removes `EncryptBoundSecretToBundle`; use `EncryptSecretToBundle` instead.
