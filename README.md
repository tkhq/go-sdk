# Turnkey Go SDK
[![GoDocs](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/tkhq/go-sdk/v2)

The Turnkey Go SDK is the official Go client for interacting with the Turnkey API.

> [!WARNING]
>
>  **Migrating from v1?** Update `github.com/tkhq/go-sdk` to the new module path:
>
> - `github.com/tkhq/go-sdk/v2` — API client and types
> 
> The v2 module will automatically pull in the required crypto and encoding dependencies 
> - `github.com/tkhq/go-sdk/crypto` 
> -  `github.com/tkhq/go-sdk/encoding`
> 

## Module Structure

The SDK has three importable Go modules:
(one for the core API client and one for each major feature area)

| Module | Import Path | Purpose |
|--------|-------------|---------|
| Root | `github.com/tkhq/go-sdk/v2` | API client, generated request/response types |
| Crypto | `github.com/tkhq/go-sdk/crypto` | API key generation, signing, encryption, attestation |
| Encoding | `github.com/tkhq/go-sdk/encoding` | Hex, Base58, and JSON encoding utilities |

```
go-sdk/
├── client.go               # HTTP client 
├── client_gen.go           # generated API methods
├── client_extensions.go    # hand-written client helpers
├── types_gen.go            # generated request/response types
├── types_extensions.go     # hand-written type helpers
├── stamper.go              # request signing (stamp) implementation
├── crypto/                 # key generation, signing, encryption, attestation
│   ├── apikey.go
│   ├── apikey_ecdsa.go
│   ├── apikey_ed25519.go
│   ├── constants.go
│   ├── enclave.go
│   ├── encryptionkey.go
│   ├── hpke.go
│   ├── store.go
│   └── verify.go
├── encoding/               # hex, base58, JSON utilities
│   ├── base58.go
│   ├── hex.go
│   └── json.go
├── codegen/                # code generation tooling
│   ├── main.go
│   ├── generators/         # per-file code generators
│   └── inputs/             # activities.json + swagger specs
└── examples/
    ├── apikey/
    ├── delegated_access/
    ├── otp/
    ├── signing/
    ├── wallets/
    └── whoami/
```

## Documentation

- [Crypto README](./crypto/README.md)
- [Encoding README](./encoding/README.md)

## Installation

```bash
go get github.com/tkhq/go-sdk/v2
```

The root v2 module pulls in the crypto and encoding modules it needs. If you
want to use those modules directly, install them explicitly:

```bash
go get github.com/tkhq/go-sdk/crypto
go get github.com/tkhq/go-sdk/encoding
```

## Example

In order to use the SDK, you first need to create and register an API key. When creating API keys, the private key never leaves the local system, but the public key must be registered to your Turnkey account.

The easiest way to manage your API keys is with the [Turnkey CLI](https://github.com/tkhq/tkcli), but you can also create one using this SDK. See [this example](./examples/apikey/generate.go).

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	turnkey "github.com/tkhq/go-sdk/v2"
)

func main() {
	// NB: make sure to create and register an API key first.
	stamper, err := turnkey.NewAPIKeyStamper(os.Getenv("TURNKEY_API_PRIVATE_KEY"))
	if err != nil {
		log.Fatal("failed to create stamper:", err)
	}

	client, err := turnkey.NewClient(stamper, os.Getenv("TURNKEY_ORGANIZATION_ID"))
	if err != nil {
		log.Fatal("failed to create SDK client:", err)
	}

	resp, err := client.GetWhoami(context.Background(), turnkey.GetWhoamiRequest{})
	if err != nil {
		log.Fatal("failed to get whoami:", err)
	}

	fmt.Printf("UserID: %s\n", resp.UserID)
}
```

## Custom Stampers

`NewAPIKeyStamper` is the built-in stamper and covers most use cases. If you need signing to happen elsewhere — a hardware security module, AWS KMS, or a remote signing service — implement the `Stamper` interface and pass it to `NewClient` identically:

```go
type Stamper interface {
    Stamp(ctx context.Context, body []byte) (*Stamp, error)
}
```

Any type that satisfies this interface works as a drop-in replacement without changing any other code.

## Error Handling

API errors are returned as `*turnkey.RequestError`, which exposes the HTTP status code, parsed status message, and raw response body.

```go
result, err := client.CreateWallet(ctx, input)
if err != nil {
    log.Printf("failed to create wallet: %v", err)

    if reqErr, ok := err.(*turnkey.RequestError); ok {
        log.Printf("Turnkey API error (HTTP %d): %s", reqErr.StatusCode, reqErr.Body)
    }

    return nil, err
}
```

For activity-specific flows, the SDK also returns `*turnkey.ActivityFailedError` (activity rejected or failed) and `*turnkey.ActivityRequiresApprovalError` (consensus required), type-assert these if you need to handle them explicitly.

## Custom Logging

By default, the SDK prints failed API responses to stdout via `fmt.Printf`. To route logs to Zap, Logrus, Datadog, or any other logger, implement the `turnkey.Logger` interface and pass it via `WithLogger`:

```go
type myLogger struct{}

func (l *myLogger) Printf(format string, v ...interface{}) {
    log.Printf("[turnkey] "+format, v...)
}

stamper, err := turnkey.NewAPIKeyStamper(os.Getenv("TURNKEY_API_PRIVATE_KEY"))
if err != nil {
    log.Fatal("failed to create stamper:", err)
}

client, err := turnkey.NewClient(
    stamper,
    os.Getenv("TURNKEY_ORGANIZATION_ID"),
    turnkey.WithLogger(&myLogger{}),
)
```

## More Examples

See this README in [examples](./examples/README.md) for more complete code samples, including:
- [API key generation](./examples/apikey/generate.go)
- [Wallets](./examples/wallets/)
- [Delegated Access](./examples/delegated_access/)
- [OTP Flows](examples/otp-login/)
- [Signing](./examples/signing/)

## Development

The SDK uses custom changeset tooling for changelog management. Each module (`root`, `crypto`, `encoding`) is versioned independently — a single release can bump any subset of them depending on which modules have pending changesets.

### Releasing

**Step 1 — Create a changeset**

Add one markdown file under `.changesets/` for each releasable module change.
Each file uses frontmatter to identify the module, bump type (`patch` / `minor`
/ `major`), title, and date:

```markdown
---
module: "root"
bump: "patch"
title: "Short release note"
date: "2026-07-09"
---

Longer release note text.
```

Use `module: "root"` for `github.com/tkhq/go-sdk/v2`, `module: "crypto"` for
`github.com/tkhq/go-sdk/crypto`, and `module: "encoding"` for
`github.com/tkhq/go-sdk/encoding`. Repeat once per logical change. Changesets
accumulate in `.changesets/` and can land across multiple PRs before a release
is cut.

**Step 2 — Cut a release branch and open the PR**

```bash
make release-branch
```

Must be run from a clean `main`. For each module with pending changesets, this:

- Bumps the module's `VERSION` file (patch/minor/major from the highest bump across its changesets).
- Prepends a release section to the module's `CHANGELOG.md`.
- Deletes the consumed changeset files from `.changesets/`.
- Rewrites inter-module `go.mod` requirements from local placeholder versions
  to the release versions.
- Rewrites matching `go.work` replaces so the release branch can build before
  the new module tags exist.
- Creates a `release/vYYYY-MM-N` branch (where `N` auto-increments per month), commits the changes, and optionally pushes + opens the PR via `gh`.

Review the diff, then merge the PR into `main`.

**Step 3 — Tag and publish (automatic)**

Merging a `release/v*` PR triggers [.github/workflows/tag.yml](.github/workflows/tag.yml), which (after manual approval on the `Production` environment):

- Lints, builds, and tests.
- Reads each module's `VERSION` and creates GitHub releases tagged `vX.Y.Z`, `crypto/vX.Y.Z`, `encoding/vX.Y.Z`.
- Pings `sum.golang.org` so pkg.go.dev indexes the new versions.

The workflow can also be triggered manually via `workflow_dispatch` with a `vYYYY-MM-N` release id.

# Contributing + License

Contributions are welcome! Please open an issue or submit a pull request with any improvements or bug fixes.

This project is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.



