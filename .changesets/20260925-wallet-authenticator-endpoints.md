---
module: "root"
bump: "minor"
title: "Add wallet authenticator create, delete, and get"
date: "2026-09-25"
---

Adds `CreateWalletAuthenticators`, `DeleteWalletAuthenticators`, and `GetWalletAuthenticators`.

`CreateWalletAuthenticators` (`POST /public/v1/submit/create_wallet_authenticators`) adds authenticators to an existing user. Each entry is a type, address, and domain. `verificationToken` is optional. Include a wallet verification JWT to record the claim as verified. Omit it to attach the authenticator unverified.

```json
{
  "type": "ACTIVITY_TYPE_CREATE_WALLET_AUTHENTICATORS",
  "organizationId": "<sub-organization>",
  "parameters": {
    "userId": "<user>",
    "walletAuthenticators": [
      {
        "type": "WALLET_AUTHENTICATOR_TYPE_ETHEREUM",
        "address": "0x71c7656ec7ab88b098defb751b7401b5f6d8976f",
        "domain": "app.example.com",
        "verificationToken": "<wallet verification JWT>"
      }
    ]
  }
}
```

> The result is `walletAuthenticatorIds`. Ids are assigned by the enclave.
> Ethereum addresses are stored lowercase with a `0x` prefix. Solana addresses are canonical base58. Domain is a host only, lowercased.
> The same `(type, address, domain)` cannot be added twice in one sub-organization.

`DeleteWalletAuthenticators` (`POST /public/v1/submit/delete_wallet_authenticators`) removes authenticators by id. The result is the deleted ids.

```json
{
  "type": "ACTIVITY_TYPE_DELETE_WALLET_AUTHENTICATORS",
  "organizationId": "<sub-organization>",
  "parameters": {
    "userId": "<user>",
    "walletAuthenticatorIds": ["<wallet authenticator id>"]
  }
}
```

`GetWalletAuthenticators` (`POST /public/v1/query/get_wallet_authenticators`) returns the stored authenticators for a user. The response does not include verification status.

```json
{
  "organizationId": "<sub-organization>",
  "userId": "<user>"
}
```
