---
module: "root"
bump: "minor"
title: "ImportSecret sends enclave_encrypt_v2"
date: "2026-11-11"
---

`Client.ImportSecret` now uses `TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2` and binds the ciphertext to the secret's name and static properties. Adds `TransportEncryptionSuiteEnclaveEncryptV2`.
