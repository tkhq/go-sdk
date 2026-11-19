---
module: "root"
bump: "minor"
title: "Use shared fiat ramp types"
date: "2026-10-28"
---

Quote and fiat ramp credential types now use `FiatRampProvider`, `FiatRampCurrency`, `FiatRampPaymentMethod`, and `FiatRampAmount`.

`GetFiatOnRampQuotes`, `GetFiatOffRampQuotes`, `CreateFiatRampCredential`, and `UpdateFiatRampCredential` take those types. `FiatRampPaymentMethod` is limited to the methods those queries return: card, Apple Pay, Google Pay, PayPal, MoonPay balance, fiat wallet, and ACH.

`ListFiatOnRampCredentials` returns `provider` as `FiatRampProvider`.

`InitFiatOnRamp`, `CreateFiatOnRampCredential`, and `UpdateFiatOnRampCredential` stay on the `FiatOnRamp*` types and are deprecated. Use the quote and session activities, and `CreateFiatRampCredential` / `UpdateFiatRampCredential`, instead.
