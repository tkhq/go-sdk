---
module: "crypto"
bump: "minor"
title: "Add EncryptOAuth2ToBundle"
date: "2026-10-14"
---

Adds `EncryptOAuth2ToBundle` and `OAuth2AuthenticationBundle`, which verify an `InitOAuth2Authenticate` TLS Fetcher target and HPKE-encrypt the OAuth 2.0 authentication inputs for `OAuth2AuthenticateV2`.
