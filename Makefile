.PHONY: fmt
fmt:
	go tool gofumpt -w .
	go tool gci write --skip-generated -s standard -s default -s "Prefix(github.com/tkhq)" .

.PHONY: build
build:
	go build -v ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: lint
lint:
	go tool golangci-lint run --fix ./... -v

.PHONY: check
check: fmt lint build test

.PHONY: generate
generate: generate-proto
	cd codegen && go run . --out ..
	go tool golangci-lint run --fix ./... -v .
	go tool gofumpt -w .
	go tool gci write --skip-generated -s standard -s default -s "Prefix(github.com/tkhq)" .

# Regenerate the wire-format proto packages from the schema synced out of the
# mono repo (proto/schema/, refreshed by mono's `make sync/go-sdk`). Requires
# the buf CLI; protoc-gen-go is pinned as a go tool in proto/go.mod.
.PHONY: generate-proto
generate-proto:
	cd proto && buf generate

# Reconcile go.mod/go.sum across all modules after a dependency change.
# tidy ignores go.work, so it would try to fetch the unpublished v0.0.0
# inter-module versions from the proxy — temp go.mod replaces point them at
# the local dirs during tidy, then get dropped so the published go.mod stays clean.
.PHONY: tidy
tidy:
	go mod edit -replace github.com/tkhq/go-sdk/crypto=./crypto
	go mod edit -replace github.com/tkhq/go-sdk/encoding=./encoding
	cd crypto && go mod edit -replace github.com/tkhq/go-sdk/encoding=../encoding
	GOWORK=off go mod tidy
	cd crypto && GOWORK=off go mod tidy
	cd encoding && GOWORK=off go mod tidy
	cd proto && GOWORK=off go mod tidy
	go mod edit -dropreplace github.com/tkhq/go-sdk/crypto
	go mod edit -dropreplace github.com/tkhq/go-sdk/encoding
	cd crypto && go mod edit -dropreplace github.com/tkhq/go-sdk/encoding
	go work sync
	go mod edit -go=1.27.1
	cd crypto && go mod edit -go=1.27.1
	cd encoding && go mod edit -go=1.27.1
	cd proto && go mod edit -go=1.27.1
	go work edit -go=1.27.1

.PHONY: release-branch
release-branch:
	go run ./cmd/release-branch
