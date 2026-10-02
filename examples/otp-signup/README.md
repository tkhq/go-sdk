# Example: `otp-signup`

A sample script demonstrating strict OTP (one-time password) email signup:

- Sends an OTP to the specified email address
- Generates a P-256 API key for the new root user
- Prompts for the OTP code and verifies it with Turnkey
- Signs the exact signup request fields with the generated P-256 key and attaches the signature as `clientSignature`
- Creates a sub-organization with the verified email and API key

### 1/ Setting up Turnkey

Follow the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) to get a public/private API key pair and organization ID for the parent organization. The API key used by this example must be in the parent root quorum or policy-authorized for `INIT_OTP_V3`, `VERIFY_OTP_V2`, and `CREATE_SUB_ORGANIZATION_V8`.

The example keeps the new root user's P-256 API private key only in memory and discards it when the process exits. The sub-organization retains its public credential, but that API key cannot be used after the example exits.

### 2/ Running the script

Copy `.env.example` to `.env` and fill in the values:

```bash
cp examples/otp-signup/.env.example examples/otp-signup/.env
```

Then run from the repository root:

```bash
set -a && source examples/otp-signup/.env && set +a && go run ./examples/otp-signup
```

The script sends an OTP, prompts for the code, and prints the new sub-organization ID on success.
