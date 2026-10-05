---
module: "root"
bump: "patch"
title: "Earn: expose forceDeallocatableLiquidity alongside liquidity"
date: "2026-08-31"
---

Add `forceDeallocatableLiquidity` and `forceDeallocatableLiquidityDisplay` to EarnVault and EarnEnabledVault: the additional assets withdrawable from a Morpho vault by force-deallocating its non-liquidity adapters at zero penalty, additive to `liquidity`. Empty when the provider does not report it (Aave).
