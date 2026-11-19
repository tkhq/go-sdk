---
module: "crypto"
bump: "patch"
title: "EncryptOAuth2ToBundle encrypts without a purpose binding"
date: "2026-11-18"
---

`EncryptOAuth2ToBundle` no longer calls `EncryptSecretToBundle`, whose signature changed. It verifies the TLS Fetcher target and encrypts the bundle without a purpose binding, as before. No API change.
