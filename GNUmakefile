default: test

.PHONY: build
build:
	go build -o dist/ ./...

.PHONY: test
test:
	go test ./... -timeout 10m

# TF_ACC_PROVIDER_HOST pins the reattach/required_providers synthesis in
# terraform-plugin-testing to registry.opentofu.org. Without it, the
# library defaults to registry.terraform.io while still registering the
# legacy "-" namespace as a reattach candidate, and OpenTofu's provider
# address parser rejects that pairing outright ("The legacy provider
# namespace \"-\" can be used only with hostname registry.opentofu.org"),
# failing every acceptance test before it reaches the provider.
.PHONY: testacc
testacc:
	@command -v tofu >/dev/null || (echo "tofu not found in PATH; OpenTofu >= 1.11 is required" && exit 1)
	TF_ACC=1 TF_ACC_TERRAFORM_PATH="$$(command -v tofu)" TF_ACC_PROVIDER_HOST=registry.opentofu.org go test ./... -v $(TESTARGS) -timeout 120m

.PHONY: fmt
fmt:
	gofmt -w -l .

.PHONY: vet
vet:
	go vet ./...

.PHONY: docs
docs:
	cd tools && go generate ./...

.PHONY: release
release:
	@test $${RELEASE_VERSION?Please set environment variable RELEASE_VERSION}
	@git tag $$RELEASE_VERSION
	@git push origin $$RELEASE_VERSION
