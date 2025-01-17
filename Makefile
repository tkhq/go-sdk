SWAGGER_VERSION := $(shell swagger version 2>/dev/null)

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

.PHONY: changelog
changelog:
	@if [ -f "CHANGELOG.md" ]; then \
		mv CHANGELOG.md CHANGELOG.md.backup; \
	fi
	@git-chglog -o CHANGELOG.md
	@echo "Generated CHANGELOG.md"
	@echo "Review the changes and commit if satisfied:"
	@echo "  git add CHANGELOG.md"
	@echo "  git commit -m 'docs: update changelog'"

.PHONY: changelog-next
changelog-next:
	@if [ "$(v)" = "" ]; then \
		echo "Error: version number required. Use: make changelog-next v=1.0.0"; \
		exit 1; \
	fi
	@echo "Previewing changes for v$(v)..."
	@git-chglog --next-tag v$(v)

.PHONY: release
release:
	@if [ "$(v)" = "" ]; then \
		echo "Error: version number required. Use: make release v=1.0.0"; \
		exit 1; \
	fi

	@echo "Generating and committing changelog for v$(v)..."
	@git-chglog --next-tag v$(v) -o CHANGELOG.md
	git add CHANGELOG.md
	git commit -m "add changelog for v$(v)"

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
