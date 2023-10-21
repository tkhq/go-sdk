all: generate

.PHONY: generate
generate:
	swagger generate client -f api/public_api.swagger.json -t pkg/api -A TurnkeyPublicAPI
	go mod tidy

