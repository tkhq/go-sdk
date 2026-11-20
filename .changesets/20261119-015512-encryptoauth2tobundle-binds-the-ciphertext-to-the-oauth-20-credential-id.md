---
module: "crypto"
bump: "minor"
title: "EncryptOAuth2ToBundle binds the ciphertext to the OAuth 2.0 credential ID"
date: "2026-11-19"
---

Adds `OAuth2AuthenticatePurposeBinding`. `EncryptOAuth2ToBundle` binds the ciphertext to `bundle.OAuth2CredentialID`, so it cannot be submitted with another credential ID. `InitOAuth2Authenticate` must request `TRANSPORT_ENCRYPTION_SUITE_ENCLAVE_ENCRYPT_V2`; V1 is no longer accepted.
