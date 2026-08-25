# CHANGELOG

## 2.1.0 — 2026-08-25
### Patch Changes
- Added captcha enabled flag to the auth proxy config and a new GetWalletKitParams endpoint to the Auth Proxy
- Expose wallet account name update activity types and dashboard API bindings.
- Hide vault shares across the Earn surface: removed `shares` from EarnPosition and `sharesMinted`/`sharesBurned` from the deposit/withdraw results. Add `netApyPct`, `turnkeyFeeBps`, and `clientFeeBps` to EarnEnabledVault. EarnWithdraw is now assets-only (`amountType` removed; `amountValue` accepts "MAX"). `caip19` is now required on EarnVaults.
- `EarnDepositResult` now carries only `depositRequestId` (`depositTxHash` and `wrapperAddress` removed). Poll `EarnDepositStatus` for status + tx hash; it now reports on-chain status (COMPLETED = included) and a public-safe `error` when the transaction fails.
- Bumping x/crypto to patch vulnerable dependency
- Expose the optional replica count for CreateTvcDeploymentIntent in the generated Go SDK.
- Update generated SDK types for the ClaimSwapFees activity.
- EarnDepositIntent and EarnWithdrawIntent now carry `wrapperAddress` (the deployed Earn wrapper to act on) and no longer carry `vaultAddress`; the wrapper identifies its own vault.
- `EarnWithdrawResult` now carries only `withdrawRequestId` (`withdrawTxHash` and `assetsReceived` removed). Poll `EarnWithdrawStatus` for status + tx hash; it now reports on-chain status (COMPLETED = included) and a public-safe `error` when the transaction fails.
- UpsertSwapConfigIntent and UpsertSwapConfigResult now include optional stableFeeBps. When set, that rate is used for stablecoin pairs; otherwise feeBps applies.
- Update generated SDK types for the ClaimEarnFees activity.
- Clarify that `appName` on `get_latest_boot_proof` expects the enclave app's UUID, not its human-readable name (doc-only).
- `SolSendTransactionV2` now submits to `/public/v1/submit/sol_send_transaction` (same path as V1) with `ACTIVITY_TYPE_SOL_SEND_TRANSACTION_V2`, matching the EthSendTransaction versioning pattern. The separate `/sol_send_transaction_v2` endpoint is removed.
- Removed `turnkey_fee_bps` from `EarnEnabledVault` from `EarnEnabledVaultsResponse`. This endpoint was never exposed publicly so no breaking changes.
- Added ComplaintFeedbackType to EmailEventsDetails to surface metadata on complaints
- With the addition of time based policies, we are introducing a new policy outcome called OUTCOME_TIME_INACTIVE to denote when a policy is not being applied because the current timestamp is outside the bounds denoted in the time field
- Added share set to CreateTvcAppResult, in parity with manifets set
- Doc-comment wording only: updated Earn field descriptions and documented the client fee maximum (4000 bps / 40%). No functional changes.
- Remove unreleased `SwapQuote` fee-impact fields (`totalImpactUsd`, `totalImpactPercent`, `executionFeeUsd`, `swapImpactUsd`, `relayFeeUsd`, `appFeeUsd`, `sponsoredFeeUsd`).
- Add provisioning_state to TVC DeploymentStatus
### Minor Changes
- Adds `SolSendTransactionV2` for multi-signer Solana send transactions. The request flattens `unsignedTransaction`, `signWiths` (1–16 Solana addresses), `caip2`, optional `sponsor`, and optional `recentBlockhash`, and submits to `/public/v1/submit/sol_send_transaction` with `ACTIVITY_TYPE_SOL_SEND_TRANSACTION_V2`.
- - Removed `UPSERT_EARN_CLIENT_FEE_CONFIG` activity
- Added `ClientFeeBps` and `ClientFeeWallet` to `EarnDeployWrapperIntent`
- Replaced `DeployTxHash` with `DeployRequestID` in `EarnDeployWrapperResult`
- Add `ListEthTransactionHistory` and `ListSolTransactionHistory` to the Go SDK client, along with request/response and chain-specific transaction history payload types generated from the new public API endpoints.
- Expose the init import secrets intent and result types in the generated Go SDK.
- - Added `EARN_SET_WRAPPER_STATE` activity to enable or disable deposits to a deployed Earn wrapper (withdrawals are always allowed)
- Added `DepositsDisabled` to `EarnEnabledVault` and `EarnPosition` responses
- ExecuteSwapIntent now requires `minOutputAmount` (base units of the output asset). Execution fails if the provider quote's guaranteed minimum falls below that floor at execution time. Clients should typically haircut a prior quote's `minOutputAmount` when setting this value to tolerate normal quote drift.
- - Removed the `INTERNAL` visibility restriction from the 10 Earn V1 RPCs, adding them to the SDK client: `EarnDeployWrapper`, `EarnDeposit`, `EarnWithdraw`, `EarnSetWrapperState` (plus `Stamp*` variants), `EarnVaults`, `EarnEnabledVaults`, `EarnPositions`, `EarnDepositStatus`, `EarnWithdrawStatus`, `EarnDeployStatus`
- - Added `ETH_UNDELEGATE_7702` activity to submit an EIP-7702 undelegation transaction for an EVM account
- Adds Go SDK client methods and types for public swap endpoints: `GetSwapQuote`, `GetSwapStatus`, `ExecuteSwap`, `UpsertSwapConfig`, and `ClaimSwapFees`.
- Expose the ImportEncryptedSecrets activity intent and result types in the generated Go SDK.
- Expose the ExportSecrets activity intent and result types and the ListSecrets query in the generated Go SDK.
- Renamed the Earn read RPCs to match the `get_`/`list_` prefix convention used by every other query endpoint. Since all Turnkey requests are POST, downstream SDK codegen relies on that prefix to distinguish queries from activities; the unprefixed names were being misclassified as activities.

- `EarnVaults` -> `ListEarnVaults` (`/public/v1/query/list_earn_vaults`)
- `EarnEnabledVaults` -> `ListEarnEnabledVaults` (`/public/v1/query/list_earn_enabled_vaults`)
- `EarnPositions` -> `ListEarnPositions` (`/public/v1/query/list_earn_positions`)
- `EarnWithdrawStatus` -> `GetEarnWithdrawStatus` (`/public/v1/query/get_earn_withdraw_status`)
- `EarnDepositStatus` -> `GetEarnDepositStatus` (`/public/v1/query/get_earn_deposit_status`)
- `EarnDeployStatus` -> `GetEarnDeployStatus` (`/public/v1/query/get_earn_deploy_status`)
- `ClaimEarnFeesStatus` -> `GetClaimEarnFeesStatus` (`/public/v1/query/get_claim_earn_fees_status`)
- `ExecuteSwap` now requires `ACTIVITY_TYPE_EXECUTE_SWAP_V2` with the exact quote ID, displayed economics, sponsor choice, and optional chain replay-protection value returned by `CreateSwapQuote`. The signing wallet is derived from the signed quote rather than repeated in the execute request. The unreleased V1 swap execution shape is no longer accepted by the API.

`CreateSwapQuote` accepts optional `slippageBps` and returns `quotes[]` with per-provider economics for UI (`slippageBps`, `clientFeeBps`, optional `estimatedTimeSeconds`) plus a `quoteId` that execute must bind to.
- Adds `stable` to `AssetMetadata` returned by `ListSupportedAssets`, indicating whether the asset is on Turnkey's stablecoin list.
- list_earn_vaults now returns a page_info block (has_next_page/has_previous_page plus opaque start/end cursors) and accepts opaque keyset cursors.
- Update `ListEthTransactionHistory` and `ListSolTransactionHistory` SDK types to use shared `Pagination` request options and `PageInfo` response metadata instead of transaction-history-specific pagination cursor types.
- - Removed the `INTERNAL` visibility restriction from `GetClaimEarnFeesStatus`, adding it to the SDK client
- Add `client_fee_wallet` to `EarnEnabledVault` return object.
- Add the GetTVCQosVersions query to the generated Go SDK: returns the QOS versions supported for new TVC deployments and the latest recommended version.
- `SwapError` now includes optional `providerReason` with provider detail when a fill does not complete.

`SwapQuote.slippageBps` is the effective total slippage tolerance from the provider response (providers may compute it when the request omits `slippage_bps`).

`GetSwapStatusResponse.refund` / `SwapRefund` describe provider-returned funds after a successful origin transfer and failed cross-chain fill; they are omitted for origin transaction failures and same-chain swaps.
- - Removed the `INTERNAL` visibility restriction from `CreateSwapQuote` and `ExecuteSwap`, adding them to the SDK client
- Expose the CAIP-2 namespace supported by each wallet account in SDK responses.
- Add `earnProviders` to AssetMetadata: the Earn yield providers with vaults denominated in the asset, sourced from the server token list. Empty when the asset is not supported by Earn.
- Add `liquidity`/`liquidityDisplay` to EarnVault and EarnEnabledVault, and an `exposures` breakdown (new EarnVaultExposure type) on EarnEnabledVault behind the new `includeExposure` flag on ListEarnEnabledVaults.
- This change introduces the support of WhatsApp OTP
- Expose `InitImportSecrets` in the public API: adds `Client.InitImportSecrets` and `Client.StampInitImportSecrets` for `/public/v1/submit/init_import_secrets`.
- Add Go SDK client methods and types for creating, deleting, getting, and listing velocity controls.

### [v2.0.0 ... v2.1.0](https://github.com/tkhq/go-sdk/compare/v2.0.0...v2.1.0)

## 2.0.0 — 2026-07-09
### Major Changes
- Initial public release of the Turnkey Go SDK: the core client, stamper, and generated types.

### [v1.0.0 ... v2.0.0](https://github.com/tkhq/go-sdk/compare/v1.0.0...v2.0.0)
