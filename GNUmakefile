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

# test-import-fidelity is the gate on the migration follow-up (spec section
# 10): it imports an engine.py-produced device certificate and asserts the
# subsequent plan is empty, which is the precondition for adopting the
# homelab's existing 20-year device certificates without reissuing them. It is
# broken out so it can be run in isolation during the migration without
# remembering the -run pattern.
.PHONY: test-import-fidelity
test-import-fidelity:
	TF_ACC=1 TF_ACC_TERRAFORM_PATH="$$(command -v tofu)" TF_ACC_PROVIDER_HOST=registry.opentofu.org \
		go test ./internal/provider/ -run TestAccImportFidelity -v -timeout 20m

.PHONY: fmt
fmt:
	gofmt -w -l .

.PHONY: vet
vet:
	go vet ./...

.PHONY: docs
docs:
	./tools/gen-schema.sh
	cd tools && go generate ./...

.PHONY: release
release:
	@test $${RELEASE_VERSION?Please set environment variable RELEASE_VERSION}
	@git tag $$RELEASE_VERSION
	@git push origin $$RELEASE_VERSION
