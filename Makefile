all: generate

.PHONY: build
build:
	go build -v ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: generate
generate: clean
	mkdir -p pkg/api
	swagger generate client -f api/public_api.swagger.json -t pkg/api -A TurnkeyAPI -T templates --allow-template-override
	go mod tidy

.PHONY: clean
clean:
	rm -rf pkg/api
