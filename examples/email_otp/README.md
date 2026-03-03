# Example: Email OTP backend auth flow

This example demonstrates the full backend email OTP authentication flow using the
[INIT_OTP](https://docs.turnkey.com/api-reference/activities/init-generic-otp),
[VERIFY_OTP](https://docs.turnkey.com/api-reference/activities/verify-generic-otp), and
[OTP_LOGIN](https://docs.turnkey.com/api-reference/activities/login-with-otp) activities.

## Security model

The OTP code and client public key are HPKE-encrypted together to Turnkey's TLS Fetcher
enclave before being sent to the server. This means even a compromised backend or proxy
cannot substitute its own public key — only a party who knows the OTP code can bind a
public key to the resulting verification token.

The flow:
1. Client generates a P256 keypair. This is the persistent session credential — in a real
   client it would be stored in IndexedDB (or equivalent secure storage).
2. Backend calls `INIT_OTP` → receives an `otpID` and an **encryption target bundle**.
3. User receives the OTP code out-of-band (email).
4. Client extracts `targetPublic` from the bundle (verifying the enclave's signature), then
   HPKE-encrypts `{otp_code, client_public_key}` to it. Only the resulting ciphertext is
   sent to the server — the OTP code and client public key never cross the network in plaintext.
5. Backend calls `VERIFY_OTP` with the encrypted bundle → enclave issues a `verificationToken`
   bound to the client public key.
6. Client signs a `TokenUsage{LOGIN}` message with its private key, proving ownership of
   the key bound during verification.
7. Backend calls `OTP_LOGIN` with the `verificationToken`, client public key, and client
   signature → receives a session JWT embedding that public key.
8. Session JWT signature is verified against the production notarizer public key.

> **Note:** In a real deployment, steps 1, 4, and 6 would be performed on the user's device
> (browser or mobile app). This example runs all steps in a single process for demonstration
> purposes — the client keypair is a freshly generated random key, not a hardcoded mock.

### Encryption target bundle

The encryption target bundle returned by `INIT_OTP` is a signed JSON envelope from the TLS
Fetcher enclave:

```json
{
  "version": "v1.0.0",
  "data": "<JSON: { targetPublic, organizationId }>",
  "dataSignature": "<ECDSA signature over data>",
  "enclaveQuorumPublic": "<TLS Fetcher quorum public key>"
}
```

The enclave generates a **fresh HPKE keypair per `INIT_OTP` call** and puts the public half
(`targetPublic`) in the bundle. The private half never leaves the enclave. The client
encrypts the OTP attempt to `targetPublic` so only the enclave can decrypt it during
`VERIFY_OTP`.

The `dataSignature` (verified against the pinned `ProductionTLSFetcherSigningPublicKey`)
proves this ephemeral key genuinely came from the real enclave — not a compromised proxy
substituting its own key.

## Setup

Follow the [Quickstart](https://docs.turnkey.com/getting-started/quickstart) to obtain:

- A parent organization API key pair (private key + organization ID)
- A sub-organization ID containing the user to authenticate
- The user's email address

## Running

```bash
cd go-sdk/examples/email_otp

go run main.go \
  -api-private-key "your_api_private_key" \
  -parent-org-id  "parent_org_id" \
  -sub-org-id     "sub_org_id" \
  -email          "user@example.com"
```

The script will:
1. Send an OTP code to the specified email address
2. Prompt you to enter the OTP code
3. HPKE-encrypt the OTP attempt to the enclave and call `VERIFY_OTP`
4. Sign a `TokenUsage{LOGIN}` payload and call `OTP_LOGIN`
5. Print the session JWT and verify its signature against the production notarizer key
