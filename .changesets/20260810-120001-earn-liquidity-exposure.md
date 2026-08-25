---
module: "root"
bump: "minor"
title: "Earn: vault liquidity and exposure breakdown"
date: "2026-08-10"
---

Add `liquidity`/`liquidityDisplay` to EarnVault and EarnEnabledVault, and an `exposures` breakdown (new EarnVaultExposure type) on EarnEnabledVault behind the new `includeExposure` flag on ListEarnEnabledVaults.
