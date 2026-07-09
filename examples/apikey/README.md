# Example: `apikey`

Generates a new P-256 API key pair, stores it locally, and prints the public key to register with Turnkey.

Run this once before using any other examples, it produces the API key that all other examples authenticate with.

> [!IMPORTANT] This should only be used for local development and testing. For production, we recommend generating API keys with the [Turnkey CLI](https://github.com/tkhq/tkcli).

### 1/ Generate

```bash
cd examples/apikey && go run .
```

Optional flag: `-name` sets the key name (default: `"default"`).

```bash
go run . -name my-key
```

Prints the public key on success:

```
API Key successfully generated!
Now log into your Turnkey account and register this API key:
    <public key hex>
```

### 2/ Register

Copy the printed public key and register it in the [Turnkey dashboard](https://app.turnkey.com) under Team -> New User -> Service User
Keys are stored locally via `crypto.NewLocal` and can be reloaded by name in your own code.
