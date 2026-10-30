---
module: "root"
bump: "minor"
title: "Add fiat ramp credential activities"
date: "2026-10-21"
---

Add `CreateFiatRampCredential` and `UpdateFiatRampCredential` on `/public/v1/submit/create_fiat_ramp_credential` and `/public/v1/submit/update_fiat_ramp_credential`. Parameters are `provider`, `apiKey`, and `encryptedSecret`. Create also takes `sandboxMode`. Update also takes `credentialId` and leaves sandbox mode unchanged. `apiKey` is the MoonPay publishable key or the Coinbase CDP API key ID. `encryptedSecret` is the MoonPay secret key or the Coinbase Ed25519 private key, encrypted to the on-ramp public key.

`ListFiatOnRampCredentials` returns `credentialId`, `provider`, `apiKey`, and `encryptedSecret`.
