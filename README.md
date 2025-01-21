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

## Development

### Changelog and Releases

The SDK uses [git-chglog](https://github.com/git-chglog/git-chglog) for changelog management and publishes versions to [pkg.go.dev](https://pkg.go.dev/github.com/tkhq/go-sdk).

#### Commit Conventions

Note: these are not strictly enforced yet, but rather offers general guidelines.

To ensure your changes appear correctly in the changelog, use these commit prefixes:
- `feat:` for new features
- `fix:` for bug fixes
- `perf:` for performance improvements
- `refactor:` for code refactoring
- `docs:`, `test:`, `ci:` (these are excluded from changelog)

Example: `feat(api): add new wallet creation endpoint`

#### Managing Changes

1. Install git-chglog:
   ```bash
   go install github.com/git-chglog/git-chglog/cmd/git-chglog@latest
   ```

2. Preview changelog for next version:
   ```bash
   make changelog-next v=1.0.0
   ```

3. Update changelog without releasing:
   ```bash
   make changelog
   ```

#### Creating Releases

To prepare a new release:
```bash
make prepare-release v=1.0.0
```

This will generate and update CHANGELOG.md. Please review the changes and manually modify as needed.

Commit and push the changes, get the PR approved, merge, and move to the next step.

To publish a new release (off of main):
```bash
make publish-release v=1.0.0
```

This will:
1. Create a git tag
2. Push changes to GitHub
3. Trigger pkg.go.dev indexing

Note: 
- Use semantic versioning (e.g., v1.0.0, v0.1.0-beta)
- New versions appear on pkg.go.dev within a few minutes
- If needed, manually trigger pkg.go.dev indexing:
  ```bash
  GOPROXY=proxy.golang.org go list -m github.com/tkhq/go-sdk@v1.0.0
  ```

### Updating the SDK

#### With Nix
1. Install Nix: https://nixos.org/download.html
2. Run `nix develop` to get a new nix shell
3. Update the swagger file in `api/` with a new one
4. Run `make generate`

#### Without Nix
The following assumes you have Go 1.20 installed locally:
1. Install [go-swagger](https://goswagger.io/install.html):
```
go install github.com/go-swagger/go-swagger/cmd/swagger@v0.30.5
```
2. Update the swagger file in `api/` with a new one
3. Run `make generate`

Note: depending on how you downloaded, your `go-swagger` may be located in a few locations such as `/Users/<your username>/go/bin/swagger` or `/opt/homebrew/bin/swagger`. If both are present, we would recommend using the former, for better version granularity

### Custom Templates
While custom templates should be avoided where possible, sometimes it's worth the extra maintenance burden to provide a more streamlined UX. To use a custom template, copy the original template from the [go-swagger repo](https://github.com/go-swagger/go-swagger) to the `templates` directory

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
