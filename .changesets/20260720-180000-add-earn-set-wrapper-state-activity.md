---
module: "root"
bump: "minor"
title: "Add EarnSetWrapperState activity"
date: "2026-07-20"
---

- Added `EARN_SET_WRAPPER_STATE` activity to enable or disable deposits to a deployed Earn wrapper (withdrawals are always allowed)
- Added `DepositsDisabled` to `EarnEnabledVault` and `EarnPosition` responses
