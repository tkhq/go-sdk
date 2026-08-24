---
module: "root"
bump: "patch"
title: "Revert CreateSwapQuote fee impact fields"
date: "2026-08-10"
---

Remove unreleased `SwapQuote` fee-impact fields (`totalImpactUsd`, `totalImpactPercent`, `executionFeeUsd`, `swapImpactUsd`, `relayFeeUsd`, `appFeeUsd`, `sponsoredFeeUsd`).
