---
module: "root"
bump: "minor"
title: "Clarify swap status refunds and add providerReason"
date: "2026-08-05"
---

`SwapError` now includes optional `providerReason` with provider detail when a fill does not complete.

`SwapQuote.slippageBps` is the effective total slippage tolerance from the provider response (providers may compute it when the request omits `slippage_bps`).

`GetSwapStatusResponse.refund` / `SwapRefund` describe provider-returned funds after a successful origin transfer and failed cross-chain fill; they are omitted for origin transaction failures and same-chain swaps.
