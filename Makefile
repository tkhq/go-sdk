SWAGGER_VERSION := $(shell swagger version 2>/dev/null)
VERSION_FILE := VERSION

v ?= $(shell cat $(VERSION_FILE) 2>/dev/null)

all: generate

.PHONY: build
build:
	go build -v ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: lint
lint:
	golangci-lint run --out-format=github-actions ./...

# Note: if you have multiple versions of swagger installed locally, point to the one located in your go path, 
# e.g. /Users/<username>/go/bin/swagger
.PHONY: generate
generate: you-need-to-install-go-swagger-check-readme clean
	mkdir -p pkg/api
	swagger generate client -f api/public_api.swagger.json -t pkg/api -A TurnkeyAPI -T templates --allow-template-override
	go mod tidy

.PHONY: clean
clean:
	rm -rf pkg/api

.PHONY: changeset
changeset:
	go run ./cmd/changeset

.PHONY: version
version:
	go run ./cmd/changeset-version

.PHONY: changelog
changelog:
	go run ./cmd/changeset-changelog

.PHONY: prepare-release
prepare-release:
	@echo "Versioning package..."
	go run ./cmd/changeset-version

	@echo "Generating changelog..."
	go run ./cmd/changeset-changelog

	@echo "Generated CHANGELOG.md"
	@echo "Review the changes and commit if satisfied:"
	@echo "  git add CHANGELOG.md"
	@echo "  git commit -m 'add changelog for v$(v)'"

.PHONY: publish-release
publish-release:
	@if [ ! -f "$(VERSION_FILE)" ]; then \
		echo "Error: VERSION file not found. Create a VERSION file first."; \
		exit 1; \
	fi

	@if [ -z "$(v)" ]; then \
		echo "Error: version number is empty. Ensure $(VERSION_FILE) contains something like '0.2.0'."; \
		exit 1; \
	fi

	@echo "\nCreating and signing tag v$(v)..."
	git config tag.forceSignAnnotated true
	git tag -a v$(v) -m "Release v$(v)" -s

	@echo "\nPushing changes..."
	git push origin main
	git push origin v$(v)
	
	@echo "\nTriggering pkg.go.dev update..."
	@curl -s "https://sum.golang.org/lookup/github.com/tkhq/go-sdk@v$(v)" || true
	@echo "\nRelease v$(v) complete. The package will be available on pkg.go.dev shortly."

you-need-to-install-go-swagger-check-readme: ; @which swagger > /dev/null
