---
module: "root"
bump: "minor"
title: "Add VerifyWalletAuthenticator"
date: "2026-09-22"
---

Adds `VerifyWalletAuthenticator` (`POST /public/v1/submit/verify_wallet_authenticator`). The parent API key stamps it. The wallet signs the SIWE/SIWS message, not the activity. The result is an enclave-signed JWT.

```json
{
  "type": "ACTIVITY_TYPE_VERIFY_WALLET_AUTHENTICATOR",
  "organizationId": "<caller org>",
  "parameters": {
    "message": "<exact SIWE or SIWS login template>",
    "signature": "<hex>",
    "expirationSeconds": "3600"
  }
}
```

> `expirationSeconds` is optional. Default 3600, maximum 86400, and the token cannot outlive the message Expiration Time.
> Ethereum signatures are 65-byte `personal_sign` hex. Solana signatures are 64-byte ed25519 hex over the raw message.
> The ephemeral public key comes from `urn:turnkey:ephemeral-key` inside the message. It must be compressed P-256, lowercase hex. The nonce is the lowercase hex SHA-256 of that string.
