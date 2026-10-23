---
module: "root"
bump: "patch"
title: "Swap quote refusals return specific Turnkey error codes"
date: "2026-10-19"
---

Fee-sponsored and fixed-rate swap quotes now return a distinct Turnkey error code for each refusal reason: `SWAP_SPENDING_LIMIT_EXCEEDED`, `SWAP_FIXED_RATE_PRICE_OUT_OF_BAND`, and `SWAP_SPONSORSHIP_BALANCE_INSUFFICIENT`. An organization that Turnkey has not enabled the feature for, and a disabled or unconfigured spending window, now return `SWAP_FEATURE_NOT_ENABLED`. The `CreateSwapQuote` description notes that V3 returns its quotes in `createSwapQuoteResultV2`.
