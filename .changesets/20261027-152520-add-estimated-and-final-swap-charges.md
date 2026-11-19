---
module: "root"
bump: "minor"
title: "Add estimated and final swap charges"
date: "2026-10-27"
---

Adds `SwapCharges`, with `ExecutionUsd`, `TurnkeyFeeUsd`, and `FixedRateAdjustmentUsd`, one field per swap invoice line. `SwapQuoteV2`, returned by `ACTIVITY_TYPE_CREATE_SWAP_QUOTE_V3`, gains `EstimatedCharges` on fee-sponsored and fixed-rate quotes, `ExecuteSwapResult` gains `EstimatedCharges` from the executed quote for `ACTIVITY_TYPE_EXECUTE_SWAP_V4`, and `GetSwapStatusResponse` gains `Charges`, the final billed amounts once the swap settles. Deprecates `SwapQuoteV2.EstimatedFixedRateAdjustmentUsd` in favor of `EstimatedCharges.FixedRateAdjustmentUsd`.
