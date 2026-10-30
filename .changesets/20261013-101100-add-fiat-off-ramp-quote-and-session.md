---
module: "root"
bump: "minor"
title: "Add fiat off-ramp quote and session"
date: "2026-10-13"
---

Add the `GetFiatOffRampQuote` query and the `CreateFiatOffRampSession` activity to the Go SDK. The query returns Coinbase and MoonPay sell quotes for a crypto amount, asset, and country. Each quote's `provider` field names the provider that produced it. The activity takes a saved quote id and wallet address and returns the provider session URL and off-ramp transaction id.
