---
module: "root"
bump: "patch"
title: "Earn: hide shares, add enabled-vault fees, required caip19"
date: "2026-07-08"
---

Hide vault shares across the Earn surface: removed `shares` from EarnPosition and `sharesMinted`/`sharesBurned` from the deposit/withdraw results. Add `netApyPct`, `turnkeyFeeBps`, and `clientFeeBps` to EarnEnabledVault. EarnWithdraw is now assets-only (`amountType` removed; `amountValue` accepts "MAX"). `caip19` is now required on EarnVaults.
