all: generate

.PHONY: generate
generate:
	swagger generate client -f inputs/public_api.swagger.json -t pkg/api
	go mod tidy

