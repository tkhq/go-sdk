PROTO_PATH ?= './'
COSMOS_GEN_PATH ?= '../../pkg/signer/cosmos'

.PHONY: gen
gen: clean lint
	@echo Regenerating code from protos...

	@echo Formatting proto files
	buf format -w

	@echo Generating code for cosmos signer...
	buf generate \
		--template ./buf.cosmos.gen.yaml \
		--path $(PROTO_PATH)/signer/cosmos

	@echo Formatting cosmos signer code
	gofmt -l -s -w $(COSMOS_GEN_PATH)

	@echo ...done!

.PHONY: install
install:
	# @echo Updating tooling...
	# make -C ../src/go/gen-tools install

.PHONY: clean
clean:
	@echo Cleaning...
	rm -rf \
		$(COSMOS_GEN_PATH)/*/*.pb.go

.PHONY: lint
lint: install
	@echo Linting protos...
	buf lint