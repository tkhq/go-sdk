---
module: "root"
bump: "patch"
title: "Earn: slim EarnDepositResult to depositRequestId"
date: "2026-07-09"
---

`EarnDepositResult` now carries only `depositRequestId` (`depositTxHash` and `wrapperAddress` removed). Poll `EarnDepositStatus` for status + tx hash; it now reports on-chain status (COMPLETED = included) and a public-safe `error` when the transaction fails.
