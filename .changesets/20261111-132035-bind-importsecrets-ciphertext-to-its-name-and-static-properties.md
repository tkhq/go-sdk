---
module: "crypto"
bump: "minor"
title: "Bind ImportSecrets ciphertext to its name and static properties"
date: "2026-11-11"
---

Adds `EncryptBoundSecretToBundle`, `ImportSecretsPurposeBinding`, `StaticProperty`, `HPKEEncryptWithPurposeBinding`, and `HPKEDecryptWithPurposeBinding`. `EncryptBoundSecretToBundle` binds an ImportSecrets ciphertext to the secret's `name` and `static_properties` (`TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`), so the enclave rejects a ciphertext submitted with a different name or properties.
