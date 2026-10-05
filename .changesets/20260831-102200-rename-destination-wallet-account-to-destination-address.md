---
module: "root"
bump: "patch"
title: "Rename destination_wallet_account to destination_address"
date: "2026-08-31"
---

Rename CreateSwapQuoteV2 and ExecuteSwapV3 `destinationWalletAccount` to `destinationAddress`. The value is still a raw public address for the output token protocol.
