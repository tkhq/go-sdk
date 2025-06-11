# Example: `email OTP` backend auth flow

This example shows the backend email OTP verification flow that uses the new [init_otp](https://docs.turnkey.com/api-reference/activities/init-generic-otp) and [verify_otp](https://docs.turnkey.com/api-reference/activities/verify-generic-otp) endpoints.
It should be used in conjuction with the `indexedDbClient` on the frontend side as shown in this example:  https://github.com/tkhq/sdk/tree/main/examples/otp-auth

### 1/ Setting up Turnkey

The first step is to set up your Turnkey organization and account. By following the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) guide, you should have:

- A public/private API key pair for Turnkey parent organization
- An organization ID

Once you've gathered these values, update them in the main.go scripts, you'll see placeholders like this `<parent_org_id>`.

### 2/ Running the scripts


```bash
cd go-sdk/examples/otp

# Send the OTP code
go run init_otp/main.go

# Copy the returned OTP ID (replace <otp_id> below) and the OTP code (replace <otp_code> below) received via email and run:
go run verify_otp/main.go --id <otp_id> --code <otp_code>
```