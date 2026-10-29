---
module: "root"
bump: "minor"
title: "Add Auth Proxy VerifyWalletAuthenticator"
date: "2026-09-22"
---

Adds `AuthProxyVerifyWalletAuthenticator` (`POST /v1/verify_wallet_authenticator`). The auth proxy stamps `VERIFY_WALLET_AUTHENTICATOR` with the parent API key and returns the enclave-signed verification token. The wallet signs the SIWE/SIWS message, not the activity.

```json
{
  "message": "<exact SIWE or SIWS login template>",
  "signature": "<hex>"
}
```

> Token lifetime comes from the SIWE/SIWS message with a max TTL of 24 hours.
> Ethereum signatures are 65-byte `personal_sign` hex. Solana signatures are 64-byte ed25519 hex over the raw message.
