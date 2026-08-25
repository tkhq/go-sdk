---
module: "root"
bump: "patch"
title: "Earn: slim EarnWithdrawResult to withdrawRequestId"
date: "2026-07-14"
---

`EarnWithdrawResult` now carries only `withdrawRequestId` (`withdrawTxHash` and `assetsReceived` removed). Poll `EarnWithdrawStatus` for status + tx hash; it now reports on-chain status (COMPLETED = included) and a public-safe `error` when the transaction fails.
