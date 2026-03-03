# Turnkey GO SDK
[![GoDocs](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square)](https://pkg.go.dev/github.com/tkhq/go-sdk) 

The Turnkey Go SDK is an early tool for interacting with the Turnkey API.

There is much work to be done, but it is completly usable in its current form.  The main thing to keep in mind is that each requests needs to be manually provided the client.Authenticator.

## Usage

### API key

In order to use the SDK, you will need an API key. When creating API keys, the private key never leaves the local system, but the public key must be registered to your Turnkey account.

The easiest way to manage your API keys is with the [Turnkey CLI](https://github.com/tkhq/tkcli), but you can also create one using this SDK. See [this example](./examples/apikey/).

### Example

```go
package main

import (
	"fmt"
	"log"

	"github.com/tkhq/go-sdk"
	"github.com/tkhq/go-sdk/pkg/api/client/sessions"
	"github.com/tkhq/go-sdk/pkg/api/models"
)

func main() {
	// NB: make sure to create and register an API key, first.
	client, err := sdk.New("") // your local API key name
	if err != nil {
		log.Fatal("failed to create new SDK client:", err)
	}

	p := sessions.NewGetWhoamiParams().WithBody(&models.GetWhoamiRequest{
		OrganizationID: client.DefaultOrganization(),
	})

	resp, err := client.V0().Sessions.GetWhoami(p, client.Authenticator)
	if err != nil {
		log.Fatal("failed to make WhoAmI request:", err)
	}

	fmt.Println("UserID: ", *resp.Payload.UserID)
}
```

### Error Handling

By default, the SDK will wrap Turnkey API error responses inside the returned error.
You can inspect the raw API body by type-asserting the error to `*runtime.APIError` and reading the response body:
```go
if err != nil {
  // log the high-level error using your preferred logger
  log.Printf("failed to make request: %v", err)

  // extract and inspect the raw API response
  if apiErr, ok := err.(*runtime.APIError); ok && apiErr.Response != nil {
    b, _ := io.ReadAll(apiErr.Response.Body())
    log.Printf("Turnkey API raw response: %s", string(b))
  }

  return nil, err
}
```

### Custom Logging

By default, the SDK prints Turnkey API responses to stdout when requests fail.
If you'd like to control this output (for example, to send logs to Zap, Logrus, or Datadog), you can provide your own logger:
```go
type myLogger struct{}
func (l *myLogger) Printf(format string, v ...interface{}) {
    log.Printf("[SDK] "+format, v...)
}

client, err := sdk.New(
    sdk.WithAPIKeyName("default"),
    sdk.WithLogger(&myLogger{}), // plug in your logger
)
```
If no logger is provided, the SDK falls back to `fmt.Printf("Turnkey API response: ...")` to preserve current behavior.

## Development

### Changelog and Releases

The SDK uses a custom changeset tooling for changelog management and publishes versions to [pkg.go.dev](https://pkg.go.dev/github.com/tkhq/go-sdk).

> **Note:** Go modules on pkg.go.dev derive their versions from semver tags in the module's source repository (e.g., `v1.2.3`), which is why this release process only needs to push tags.

#### Step 1 — Sync proto / generate client (if applicable)

> **Note:** This step can be skipped if the client & types have already been generated, but it doesn't hurt to run it again just in case!

Checkout the latest mono tag and run:
```bash
make -C proto sync/go-sdk
```
This ports the swagger files over to the `api/` directory. Then regenerate the client:
```bash
make generate
```

> **Note:** Make sure you are using **go-swagger v0.30.5**. Install it by following the [instructions below](#without-nix).
> You can verify your version by running `swagger version`.

#### Step 2 — Create a changeset

> **Note:** If you are just releasing and changesets have already been made, you can skip this step!

Run `make changeset` in the repo root and follow the prompts:

```bash
$ make changeset
go run ./cmd/changeset
=== Create Go Changeset ===
Select bump type:
  1) patch
  2) minor
  3) major
Choice (1-3): 1
Short title for this change: This is my changeset title!
Enter a longer description (markdown allowed).
End input with a single '.' on its own line.

This is my changeset description!
.
```

> **Note:** The Go SDK is all one package, so you don't need to select package-specific bumps.
> **Bump level guidance:** We minor-bump whenever we sync with Mono. If you patch-bumped by mistake, update the generated changeset in `.changesets/` and change the bump level from `patch` → `minor`.

#### Step 3 — Prepare the release

Run `make prepare-release` in the repo root:
```bash
make prepare-release
```

This versions the package using the assigned bump level (`patch` → `x.x.Y`, `minor` → `x.Y.0`, `major` → `Y.0.0`) and generates a changelog from the notes in the changeset(s). Review the generated `CHANGELOG.md` and `VERSION` and manually modify as needed.

#### Step 4 — Create a release branch

Create a release branch following this naming scheme:

```
release/vX.X.X
```

where the version matches the package version you are releasing (e.g., `release/v0.15.0`).

> **Note on naming:** Because the Go SDK is a single package (not a mono repo with multiple packages), we name the release branch based on the SDK version being published — the same convention used for Ruby and Swift.

#### Step 5 — Open a PR and merge

Open a PR against `main`. Once it has gone through review and been merged, the [release workflow](https://github.com/tkhq/go-sdk/actions) will kick off automatically. Kick back, relax, and wait for it to go green!

Once CI has passed, head over to the [releases](https://github.com/tkhq/go-sdk/releases) page and verify the release was published correctly.

---

### Manual Release

If you need to publish outside the CI workflow, commit and push changes to `main`, then run:
```bash
make publish-release
```

This will:
1. Create a git tag
2. Push changes to GitHub
3. Trigger pkg.go.dev indexing

**Notes:**
- Use semantic versioning (e.g., `v1.0.0`, `v0.1.0-beta`)
- New versions appear on pkg.go.dev within a few minutes
- If needed, manually trigger pkg.go.dev indexing:
  ```bash
  GOPROXY=proxy.golang.org go list -m github.com/tkhq/go-sdk@v1.0.0
  ```

---

### Troubleshooting

If the **Validate and Tag** workflow fails, check the error logs in CI, apply the fix, push the changes to `main`, and manually re-run the workflow:

1. Head to the [Actions page](https://github.com/tkhq/go-sdk/actions)
2. Select **Validate and Tag**
3. Click **Run Workflow**

> **Note:** This reruns the workflow against your selected branch. The tag that will be published is pulled from the `VERSION` file.

---

### Updating the SDK

#### With Nix
1. Install Nix: https://nixos.org/download.html
2. Run `nix develop` to get a new nix shell
3. Update the swagger file in `api/` with a new one
4. Run `make generate`

#### Without Nix
The following assumes you have Go 1.20 installed locally:
1. Install [go-swagger](https://goswagger.io/install.html) **v0.30.5**:
```bash
go install github.com/go-swagger/go-swagger/cmd/swagger@v0.30.5
```
2. Update the swagger file in `api/` with a new one
3. Run `make generate`

> **Note:** Depending on how you installed it, `go-swagger` may be located at `/Users/<username>/go/bin/swagger` or `/opt/homebrew/bin/swagger`. If both are present, we recommend using the former for better version granularity. Verify with `swagger version`.

### Custom Templates
While custom templates should be avoided where possible, sometimes it's worth the extra maintenance burden to provide a more streamlined UX. To use a custom template, copy the original template from the [go-swagger repo](https://github.com/go-swagger/go-swagger) to the `templates` directory.

#### Current Modifications

```
// file: schemavalidator.gotmpl

// mod: less verbose enum variants
// note: seems strange, but there's an edgecase with the current logic where '_' is not supported leading to names like AllCapsALLCAPSALLTHETIME
-      {{- $variant := print $gotype (pascalize (cleanupEnumVariant .)) }}
+      {{- $variant := print ( pascalize ( camelcase (printf "%q" . ))) }}

// mod: typed and iterable enum variants
-var {{ camelize .Name }}Enum []interface{}
+var {{ pascalize .Name }}Enum []{{ template "dereffedSchemaType" . }}
-    {{ camelize .Name }}Enum = append({{ camelize .Name }}Enum, v)
+    {{ pascalize .Name }}Enum = append({{ pascalize .Name }}Enum, v)
-  if err := validate.EnumCase(path, location, value, {{ camelize .Name }}Enum, {{ if .IsEnumCI }}false{{ else }}true{{ end }}); err != nil {
+  if err := validate.EnumCase(path, location, value, {{ pascalize .Name }}Enum, {{ if .IsEnumCI }}false{{ else }}true{{ end }}); err != nil {
```
