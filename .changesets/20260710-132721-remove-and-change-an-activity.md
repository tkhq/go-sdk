---
module: "root"
bump: "minor"
title: "Remove and change an activity"
date: "2026-07-10"
---

- Removed `UPSERT_EARN_CLIENT_FEE_CONFIG` activity
- Added `ClientFeeBps` and `ClientFeeWallet` to `EarnDeployWrapperIntent`
- Replaced `DeployTxHash` with `DeployRequestID` in `EarnDeployWrapperResult`
