---
module: "root"
bump: "patch"
title: "Earn: expose the wrapper deploy status on enabled vaults"
date: "2026-09-02"
---

Add `deployStatus`, `deployRequestId` and `deployError` to EarnEnabledVault. A wrapper's entry is written before its deploy transaction lands, so `deployStatus` reports whether that deploy is PENDING, COMPLETED or FAILED; only a COMPLETED wrapper is usable. `deployRequestId` polls `GetEarnDeployStatus` and `deployError` carries the failure detail. All three are empty for wrappers deployed before deploy statuses were recorded.
