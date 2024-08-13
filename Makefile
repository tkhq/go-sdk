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

.PHONY: generate
generate: you-need-to-install-go-swagger-check-readme clean
	mkdir -p pkg/api
	swagger generate client -f api/public_api.swagger.json -t pkg/api -A TurnkeyAPI -T templates --allow-template-override
	go mod tidy

.PHONY: clean
clean:
	rm -rf pkg/api

you-need-to-install-go-swagger-check-readme: ; @which swagger > /dev/null
