---
module: "root"
bump: "minor"
title: "Expose Earn V1 endpoints in the SDK"
date: "2026-07-23"
---

- Removed the `INTERNAL` visibility restriction from the 10 Earn V1 RPCs, adding them to the SDK client: `EarnDeployWrapper`, `EarnDeposit`, `EarnWithdraw`, `EarnSetWrapperState` (plus `Stamp*` variants), `EarnVaults`, `EarnEnabledVaults`, `EarnPositions`, `EarnDepositStatus`, `EarnWithdrawStatus`, `EarnDeployStatus`
