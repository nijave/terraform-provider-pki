default: test

.PHONY: build
build:
	go build -o dist/ ./...

.PHONY: test
test:
	go test ./... -timeout 10m

.PHONY: testacc
testacc:
	TF_ACC=1 TF_ACC_TERRAFORM_PATH="$$(command -v tofu)" go test ./... -v $(TESTARGS) -timeout 120m

.PHONY: fmt
fmt:
	gofmt -w -l .

.PHONY: vet
vet:
	go vet ./...

.PHONY: release
release:
	@test $${RELEASE_VERSION?Please set environment variable RELEASE_VERSION}
	@git tag $$RELEASE_VERSION
	@git push origin $$RELEASE_VERSION
