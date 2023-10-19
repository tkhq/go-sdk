all: generate

.PHONY: generate
generate:
	cp ../docs/static/specs/services/coordinator/public/v1/public_api.swagger.json inputs/public_api.swagger.json
	swagger generate client -f inputs/public_api.swagger.json -t pkg/api -A TurnkeyPublicAPI
	go mod tidy

