---
module: "root"
bump: "minor"
title: "Add tokenProgram to wallet address balances"
date: "2026-09-18"
---

Add an optional `tokenProgram` field on `AssetBalance` returned by `GetWalletAddressBalances`. For Solana token balances it is the SPL Token or Token-2022 program address that owns the mint, so clients can construct transfers without a separate chain lookup. It is omitted for native SOL and non-Solana assets.
