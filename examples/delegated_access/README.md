# Example: `delegated-access`

A sample script that quickly configures a Delegated Access setup (see https://docs.turnkey.com/concepts/policies/delegated-access):

- Creates a Sub-Organization with a Delegated user account (having an API key) and an End User account
- Creates a new Policy for the Delegated account that allows signing transactions only to a specific destination address
- Removes the Delegated account from the Root Quorum

**Note:** The end user is created without any authenticators, it will need to be updated during the sign-up flow

### 1/ Setting up Turnkey

The first step is to set up your Turnkey organization and account. By following the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) guide, you should have:

- A public/private API key pair for Turnkey parent organization
- An organization ID

Once you've gathered these values, update them in the main.go script, you'll see placeholders like this `<parent_org_id>`.

### 2/ Running the script

```bash
go run main.go
```

### 3/ Testing the Delegated account permissions

We want to make sure that the Delegated account API keys are highly scoped to sending ETH transactions only to the specified `recipientAddress` and transactions to other addresses (and all other actions) are not possible.
You could run various ad-hoc tests by using the [Turnkey CLI](https://github.com/tkhq/tkcli), for example:

- Send a tx from the Delegated account sub-organization wallet address to the allowed Ethereum recipientAddress
- Send a tx from the Delegated account sub-organization wallet address to a different Ethereum address
- Sign a raw payload message using the the Delegated account sub-organization wallet address or any other action that is supposed to be denied by the policy engine