---
module: "root"
bump: "minor"
title: "Rename Earn read endpoints to follow get_/list_ query convention"
date: "2026-07-28"
---

Renamed the Earn read RPCs to match the `get_`/`list_` prefix convention used by every other query endpoint. Since all Turnkey requests are POST, downstream SDK codegen relies on that prefix to distinguish queries from activities; the unprefixed names were being misclassified as activities.

- `EarnVaults` -> `ListEarnVaults` (`/public/v1/query/list_earn_vaults`)
- `EarnEnabledVaults` -> `ListEarnEnabledVaults` (`/public/v1/query/list_earn_enabled_vaults`)
- `EarnPositions` -> `ListEarnPositions` (`/public/v1/query/list_earn_positions`)
- `EarnWithdrawStatus` -> `GetEarnWithdrawStatus` (`/public/v1/query/get_earn_withdraw_status`)
- `EarnDepositStatus` -> `GetEarnDepositStatus` (`/public/v1/query/get_earn_deposit_status`)
- `EarnDeployStatus` -> `GetEarnDeployStatus` (`/public/v1/query/get_earn_deploy_status`)
- `ClaimEarnFeesStatus` -> `GetClaimEarnFeesStatus` (`/public/v1/query/get_claim_earn_fees_status`)
