---
module: "root"
bump: "patch"
title: "require a fee receiver wallet on UpsertSwapConfig"
date: "2026-10-13"
---

`UpsertSwapConfig` no longer creates a fee receiver wallet when `feeBps` is set and `feeReceiverWalletAddress` is omitted. The address is required whenever a fee is set, and it must be an organization wallet account. Omit both fields to clear swap fees.
