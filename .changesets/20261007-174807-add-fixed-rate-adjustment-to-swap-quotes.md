---
module: "root"
bump: "minor"
title: "Add the fixed-rate adjustment estimate to swap quotes"
date: "2026-10-07"
---

Adds `EstimatedFixedRateAdjustmentUsd` to `SwapQuoteV2`, returned by `ACTIVITY_TYPE_CREATE_SWAP_QUOTE_V3` on fixed-rate quotes: the estimated USD adjustment for the fixed rate, where positive is a cost and negative an earning. Removes `TurnkeyFeeCollection`, `SponsoredFeeComponents`, and `RemainingFeeComponents` from `SwapQuoteV2`, which restated `FeeSponsorship` and `ClientFeeBps`. The activity is not yet released.
