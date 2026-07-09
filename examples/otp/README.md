# Example: `otp`

A sample script demonstrating the OTP (one-time password) email authentication flow:

- Sends an OTP to the specified email address
- Generates an ephemeral client keypair locally
- Prompts for the OTP code and verifies it with Turnkey
- Logs in with the verification token and the ephemeral key, obtaining a session JWT
- Verifies the session JWT signature locally

### 1/ Setting up Turnkey

Follow the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) to get:

- A public/private API key pair for your Turnkey parent organization
- A parent organization ID
- A sub-organization ID whose user will log in via OTP

### 2/ Running the script

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/otp/.env.example examples/otp/.env
```

Then run from the repo root:

```bash
set -a && source examples/otp/.env && set +a && go run ./examples/otp
```

The script will send an OTP to the email address, prompt you to enter the code, and print the session JWT on success.
