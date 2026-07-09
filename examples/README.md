# Examples

This directory contains example code for using the Turnkey Go SDK.
Each subdirectory contains a self-contained example with its own README and `.env` file for configuration. The examples demonstrate various authentication flows and features of the Turnkey platform.

## Policies

Some examples require specific Turnkey policies to be configured on your organization before they will work. Refer to the [Turnkey policy overview](https://docs.turnkey.com/concepts/policies/overview) for details on how to create and manage policies.

## Set up

> [!NOTE]
> Please refer to the [main README](../README.md) for getting started with setting up your Turnkey environment.

All examples are run from the **repo root**. For each example:
1. Copy `.env.example` to `.env` in the example's directory and fill in the values.
2. Run using `set -a && source examples/<example>/.env && set +a && go run ./examples/<example>`

Refer to each example's README for the exact commands.

## Available Examples

- [apikey](./apikey/): Demonstrates how to authenticate using an API key.

- [delegated_access](./delegated_access/): Shows how to set up delegated access for a sub-organization. 

- [otp](./otp/): Example of using one-time password (OTP) flows for authentication.

- [signing](./signing/): Demonstrates how to sign messages and transactions using the SDK.
    - [sign_raw_payload](./signing/sign_raw_payload/): Example of signing a raw payload.
    - [sign_transaction](./signing/sign_transaction/): Example of signing a blockchain transaction.

- [wallets](./wallets/): Shows how to manage wallets and sign transactions with them.
    - [create_wallet](./wallets/create_wallet/): Example of creating a new wallet.
    - [create_wallet_accounts](./wallets/create_wallet_accounts/): Example of creating accounts within a wallet.
    - [export_wallet](./wallets/export_wallet/): Example of exporting a wallet's mnemonic phrase.
    - [export_wallet_account](./wallets/export_wallet_account/): Example of exporting a wallet account.
    - [import_wallet](./wallets/import_wallet/): Example of importing a wallet using a mnemonic phrase.

- [whoami](./whoami/): Example of using the `WhoAmI` endpoint to retrieve the current user's ID.

