# PKI Provider Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `terraform-plugin-framework` layer on top of `internal/pki` — six resources, three data sources, two provider functions, import support, drift detection, generated docs, and the OpenTofu-first CI and release pipeline.

**Architecture:** `internal/provider` is a thin, mechanical translation between Terraform values and `internal/pki` types. It contains no cryptography and no ASN.1: every decision of that kind was made and tested in Plan 1. Schema block translation lives in one shared file so the `subject`, `san`, and extension blocks are defined once and reused across every resource that accepts them.

**Tech Stack:** Go 1.25, `terraform-plugin-framework` v1.19.0 (protocol 6), `terraform-plugin-framework-validators` v0.19.0, `terraform-plugin-go` v0.31.0, `terraform-plugin-testing` v1.16.0, `terraform-plugin-docs` v0.25.0 (in a separate `tools/` module), goreleaser v2, GitHub Actions.

**Source spec:** `docs/superpowers/specs/2026-07-25-terraform-provider-pki-design.md` (approved 2026-07-25). This plan covers §4, §6, §8, §11, §12, and §13's CI gate. §5, §7, §9, and §10's unit half are Plan 1.

**Prerequisite:** `docs/superpowers/plans/2026-07-25-pki-core-library.md` must be complete. Every task here consumes `internal/pki`.

## Global Constraints

Every task's requirements implicitly include this section.

- **`terraform-plugin-framework`, not SDKv2.** Write-only attributes and provider-defined functions are framework-only. The provider speaks **plugin protocol 6**; `terraform-registry-manifest.json` must declare `"protocol_versions": ["6.0"]`. Declaring `["5.0"]` — which the cortextool template this is modeled on does, because it is SDKv2 — makes the published provider fail to load.
- **OpenTofu is the primary target.** OpenTofu ≥ 1.11 is required and is what CI tests. Acceptance tests run against `tofu` via `TF_ACC_TERRAFORM_PATH`; Terraform is never downloaded. Terraform ≥ 1.11 works but is not tested and is not the reference implementation.
- **OpenTofu ≥ 1.11 is a hard floor** because `password_wo` is a write-only attribute. Every acceptance test declares `tfversion.SkipBelow(tfversion.Version1_11_0)`.
- **License: GPLv3.** Every `.go` file starts with `// SPDX-License-Identifier: GPL-3.0-or-later`. Dependencies must be GPLv3-compatible; the audited set is MPL-2.0, BSD-3-Clause, MIT, and Apache-2.0 (spec §13). **Nothing under BUSL-1.1 may be linked in** — that is Terraform CLI since 1.6, which is not a problem because a provider is a separate process speaking gRPC, and targeting OpenTofu removes the question at test time too.
- **`internal/pki` stays Terraform-free.** Never add a `terraform-plugin-*` import under `internal/pki`; Plan 1 Task 16's boundary test fails the build if you do. Translation goes in `internal/provider`.
- **Errors become diagnostics at the boundary.** `internal/pki` returns plain errors; `internal/provider` wraps each one with `resp.Diagnostics.AddError` or `AddAttributeError`, naming the attribute whenever the error is attributable to one.
- **Sensitive attributes must be marked `Sensitive: true`.** That is every `*private_key_pem`, every password, and `pki_bundle`'s `content`/`content_base64` when a key is present. A diagnostic message must never echo key material.
- **Serial numbers, once generated, are never recomputed.** A changed serial means a replaced certificate, which for the 20-year certificates on the devices in question means a manual re-enrollment per device. Use `UseStateForUnknown` plan modifiers on every computed attribute derived from issuance.
- **Provider address:** `registry.opentofu.org/nijave/pki`. Short name in configuration and in test factories: `pki`.
- **`docs/` is generated, never hand-edited.** `make docs` must leave the tree clean; CI fails on a `git diff`. `docs/superpowers/` is unrelated hand-written content and must not be clobbered — Task 14 Step 3 verifies that explicitly.
- **Formatter/linter/test runner:** `gofmt -l` empty, `go vet ./...` clean, `go test ./...` green, `make testacc` green against `tofu`.
- **Commit style:** Conventional Commits. **Stage explicit paths;** never `git add -A`.

## Naming conventions fixed by this plan

Later tasks depend on these being stable, so they are stated once here rather than re-derived per task:

- Resource type names: `pki_private_key`, `pki_cert_request`, `pki_certificate_authority`, `pki_certificate`, `pki_crl`, `pki_bundle`.
- Data source type names: `pki_oids`, `pki_certificate`, `pki_cert_request`. Note `pki_certificate` and `pki_cert_request` exist as both a resource and a data source; the framework keys them in separate namespaces, so this is legal and intentional.
- Function names: `oid`, `oid_name`. The `MetadataResponse.Name` is the bare name with no provider prefix; OpenTofu renders the call as `provider::pki::oid(...)`.
- Go file naming inside `internal/provider`: `resource_<type>.go` and `data_source_<type>.go` with the `pki_` prefix dropped, matching spec §3.
- Go type naming: `<Type>Resource` / `<Type>DataSource` for the implementation, `<type>ResourceModel` / `<type>DataSourceModel` for the state struct — for example `CertificateResource` and `certificateResourceModel`.

## File Structure

| File | Responsibility |
| --- | --- |
| `main.go` | `providerserver.Serve`, version/commit ldflags, `-debug` flag, `//go:generate` |
| `internal/provider/provider.go` | Provider metadata, empty schema, resource/data source/function registration |
| `internal/provider/schema_common.go` | The `subject`, `san`, and extension block schemas plus their translation to `internal/pki` types |
| `internal/provider/model_common.go` | The Go structs those blocks decode into |
| `internal/provider/functions.go` | `oid` and `oid_name` |
| `internal/provider/data_source_oids.go` | `pki_oids` |
| `internal/provider/data_source_certificate.go` | `pki_certificate` (decode) |
| `internal/provider/data_source_cert_request.go` | `pki_cert_request` (decode) |
| `internal/provider/resource_private_key.go` | `pki_private_key` |
| `internal/provider/resource_cert_request.go` | `pki_cert_request` |
| `internal/provider/resource_certificate_authority.go` | `pki_certificate_authority` |
| `internal/provider/resource_certificate.go` | `pki_certificate` |
| `internal/provider/resource_crl.go` | `pki_crl` |
| `internal/provider/resource_bundle.go` | `pki_bundle` |
| `internal/provider/importer.go` | The `file://`, `pem://`, `base64://` import ID schemes |
| `internal/provider/certdrift.go` | The `ModifyPlan` shared by both certificate resources |
| `internal/provider/provider_test.go` | Acceptance test harness: factories, version checks, shared config fragments |
| `tools/go.mod`, `tools/tools.go` | `tfplugindocs`, isolated from the provider module's dependency graph |
| `examples/**` | Example configuration consumed by `tfplugindocs` |
| `templates/**` | Doc templates where the generated default is not enough |
| `docs/**` | Generated documentation, committed |
| `.goreleaser.yml`, `terraform-registry-manifest.json` | Release build |
| `.github/workflows/release.yml`, `.github/dependabot.yml` | Release automation and dependency updates |
| `.github/workflows/test.yml` | Extended with the `generate`, `acceptance`, and `license` jobs |

---

### Task 1: Provider skeleton and acceptance-test harness

An empty but servable provider, plus the test scaffolding every later task's acceptance tests plug into. Nothing user-visible ships here; the deliverable is `tofu init` and `tofu plan` succeeding against a locally built provider.

**Files:**
- Create: `main.go`
- Create: `internal/provider/provider.go`
- Test: `internal/provider/provider_test.go`
- Create: `tools/go.mod`, `tools/tools.go`
- Modify: `GNUmakefile`
- Modify: `go.mod`

**Interfaces:**
- Consumes: nothing from `internal/pki` yet.
- Produces:
  - `func New(version string) func() provider.Provider`
  - `type pkiProvider struct { version string }` implementing `provider.Provider` and `provider.ProviderWithFunctions`
  - `testAccProtoV6ProviderFactories map[string]func() (tfprotov6.ProviderServer, error)` (test-only)
  - `func testAccPreCheck(t *testing.T)` (test-only)
  - `var testAccVersionChecks []tfversion.TerraformVersionCheck` (test-only)

- [ ] **Step 1: Add the framework dependencies**

```bash
go get github.com/hashicorp/terraform-plugin-framework@v1.19.0
go get github.com/hashicorp/terraform-plugin-framework-validators@v0.19.0
go get github.com/hashicorp/terraform-plugin-go@v0.31.0
go get github.com/hashicorp/terraform-plugin-testing@v1.16.0
```

All four are MPL-2.0. Spec §13 records why that is GPLv3-compatible, and records the trap: grepping their `LICENSE` files for "Incompatible With Secondary Licenses" produces a **false positive**, because the phrase appears four times in MPL-2.0's own boilerplate in every copy of the license whether applied or not. The real test is whether source files carry the Exhibit B notice, and they do not — they carry a bare `SPDX-License-Identifier: MPL-2.0`. Do not "fix" this on a future audit.

- [ ] **Step 2: Write the provider**

`internal/provider/provider.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure pkiProvider satisfies the interfaces the framework dispatches on. If a
// method signature drifts, this fails at compile time rather than at plan time.
var (
	_ provider.Provider              = (*pkiProvider)(nil)
	_ provider.ProviderWithFunctions = (*pkiProvider)(nil)
)

// pkiProvider manages a private X.509 certificate authority entirely
// in-process.
type pkiProvider struct {
	// version is injected by main.go from goreleaser's ldflags.
	version string
}

// New returns a provider factory for the given version string.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &pkiProvider{version: version}
	}
}

func (p *pkiProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pki"
	resp.Version = p.version
}

// Schema declares no attributes.
//
// There is no endpoint, no credentials, and no client to configure: every
// resource is self-contained and CA material is passed per-resource as PEM
// strings. That is what lets the externally-owned CA -- delivered from
// Bitwarden via ExternalSecret -- be consumed without a CA resource in the
// graph at all.
func (p *pkiProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage a private X.509 certificate authority in-process. " +
			"No external CA service, no `openssl` binary, no `cfssl` binary.",
	}
}

// Configure is a no-op. There is no client to build and nothing to validate,
// so no ResourceData or DataSourceData is passed down; every resource reads its
// inputs from its own configuration.
func (p *pkiProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *pkiProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *pkiProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *pkiProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{}
}
```

Each later task appends its constructor to the relevant slice. Keep the slices in the same order the docs will render: alphabetical by type name.

- [ ] **Step 3: Write `main.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/nijave/terraform-provider-pki/internal/provider"
)

// Generate the documentation. Run from the tools module so tfplugindocs and its
// dependency graph stay out of this module's go.sum:
//
//	make docs
//
//go:generate echo "run 'make docs' -- generation lives in the tools module"

var (
	// version and commit are set by goreleaser's ldflags.
	version = "dev"
	commit  = ""
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	_ = commit // recorded in the binary for support purposes

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// The OpenTofu registry is the primary distribution channel (spec
		// section 12). This address only affects dev overrides and the
		// reattach output in debug mode; the same binary serves either
		// registry.
		Address: "registry.opentofu.org/nijave/pki",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
```

- [ ] **Step 4: Set up the tools module**

HashiCorp's current scaffolding keeps `tfplugindocs` in a separate module so its dependency graph (go-git, gonum, goldmark, and more) stays out of the provider's `go.sum`. Follow that rather than Go 1.24's `tool` directive, which would pull all of it into this module.

`tools/tools.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build generate

package tools

import (
	// Documentation generation.
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-dir .. --provider-name pki
```

Note the build tag is `generate`, not `tools` — the `tools` spelling appears in plugin-docs' own README but the current scaffolding repository uses `generate`.

```bash
mkdir -p tools && cd tools
go mod init tools
go get github.com/hashicorp/terraform-plugin-docs@v0.25.0
cd ..
```

- [ ] **Step 5: Write the acceptance-test harness**

`internal/provider/provider_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/nijave/terraform-provider-pki/internal/provider"
)

// testAccProtoV6ProviderFactories serves the provider in-process over protocol
// 6. Every acceptance test uses this; there is no external provider to install
// and no registry lookup.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pki": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// testAccVersionChecks pins the floor for every acceptance test.
//
// 1.11 is required because pki_bundle's password_wo is a write-only attribute,
// and older versions error when one is set. OpenTofu 1.11 supports them; the
// check is expressed against the CLI version the harness drives, whichever
// binary TF_ACC_TERRAFORM_PATH points at.
var testAccVersionChecks = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_11_0),
}

// testAccPreCheck fails fast with an actionable message when the harness is
// misconfigured, rather than letting terraform-plugin-testing download a
// Terraform binary. There are no credentials to check: every resource in this
// provider is self-contained, which is also why Dependabot PRs get the full
// test matrix (spec section 12).
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC is not set; skipping the acceptance test")
	}
	path := os.Getenv("TF_ACC_TERRAFORM_PATH")
	if path == "" {
		t.Fatal("TF_ACC_TERRAFORM_PATH is not set. Run `make testacc`, which points it at the tofu binary. " +
			"Without it the harness falls back to downloading Terraform, which is not the tested platform.")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("TF_ACC_TERRAFORM_PATH=%q is not usable: %v", path, err)
	}
}

// TestProviderSchema is a unit test -- no TF_ACC required -- that catches a
// malformed schema at `go test` time instead of at `tofu plan` time. Every
// resource and data source added in a later task is validated by it
// automatically, because it walks whatever the provider registers.
func TestProviderSchema(t *testing.T) {
	t.Parallel()
	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:   `provider "pki" {}` + "\n" + `data "pki_oids" "check" {}`,
			PlanOnly: true,
		}},
	})
}
```

`TestProviderSchema` references `data "pki_oids"`, which does not exist until Task 3. Write the test now with the data source line omitted — `Config: "provider \"pki\" {}"` alone is a valid plan-only step — and add the data source reference in Task 3. Note that in the plan comment so the sequencing is not mistaken for an error.

Using package `provider_test` rather than `provider` is deliberate: it forces the tests to exercise only the exported surface, the same way OpenTofu does.

- [ ] **Step 6: Add the Makefile targets**

Modify `GNUmakefile`: point `testacc` at `tofu` explicitly and add a `docs` target that runs generation from the tools module.

```makefile
.PHONY: testacc
testacc:
	@command -v tofu >/dev/null || (echo "tofu not found in PATH; OpenTofu >= 1.11 is required" && exit 1)
	TF_ACC=1 TF_ACC_TERRAFORM_PATH="$$(command -v tofu)" go test ./... -v $(TESTARGS) -timeout 120m

.PHONY: docs
docs:
	cd tools && go generate ./...
```

- [ ] **Step 7: Verify the provider serves and a plan succeeds**

```bash
gofmt -l . && go vet ./... && go build -v ./... && go test ./internal/... -count=1
```

Then confirm end to end with a real OpenTofu run using a dev override:

```bash
mkdir -p /tmp/pki-devcheck && go build -o /tmp/pki-devcheck/terraform-provider-pki .
cat > /tmp/pki-devcheck/dev.tfrc <<EOF
provider_installation {
  dev_overrides {
    "nijave/pki" = "/tmp/pki-devcheck"
  }
  direct {}
}
EOF
cat > /tmp/pki-devcheck/main.tf <<'EOF'
terraform {
  required_providers {
    pki = { source = "nijave/pki" }
  }
}
provider "pki" {}
EOF
cd /tmp/pki-devcheck && TF_CLI_CONFIG_FILE=/tmp/pki-devcheck/dev.tfrc tofu plan
```

Expected: `tofu plan` reports "No changes" plus the expected dev-override warning. A protocol mismatch or a schema error surfaces here. Keep this scratch directory around — later tasks reuse it for manual checks. Nothing in it is committed.

- [ ] **Step 8: Commit**

```bash
git add main.go internal/provider/provider.go internal/provider/provider_test.go tools/go.mod tools/go.sum tools/tools.go GNUmakefile go.mod go.sum
git commit -m "feat: provider skeleton on terraform-plugin-framework with protocol 6"
```

---

### Task 2: Provider functions `oid` and `oid_name`

The terse inline path from spec §11. Both error on unknown input rather than returning empty, so a typo fails at plan time.

**Files:**
- Create: `internal/provider/functions.go`
- Test: `internal/provider/functions_test.go`
- Modify: `internal/provider/provider.go` (register both)
- Create: `examples/functions/oid/function.tf`, `examples/functions/oid_name/function.tf`

**Interfaces:**
- Consumes: `pki.OIDByName`, `pki.NameByOID` (Plan 1 Task 2).
- Produces: `func NewOIDFunction() function.Function`, `func NewOIDNameFunction() function.Function`.

- [ ] **Step 1: Write the failing acceptance tests**

`internal/provider/functions_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccFunctionOID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "display_name" {
  value = provider::pki::oid("displayName")
}
output "surname" {
  value = provider::pki::oid("surname")
}
output "client_auth" {
  value = provider::pki::oid("clientAuth")
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("display_name", knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				statecheck.ExpectKnownOutputValue("surname", knownvalue.StringExact("2.5.4.4")),
				statecheck.ExpectKnownOutputValue("client_auth", knownvalue.StringExact("1.3.6.1.5.5.7.3.2")),
			},
		}},
	})
}

func TestAccFunctionOIDName(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "surname" {
  value = provider::pki::oid_name("2.5.4.4")
}
output "san" {
  value = provider::pki::oid_name("2.5.29.17")
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("surname", knownvalue.StringExact("surname")),
				statecheck.ExpectKnownOutputValue("san", knownvalue.StringExact("subjectAltName")),
			},
		}},
	})
}

// TestAccFunctionOIDUnknownNameFails is the behavior spec section 11 requires
// explicitly: a typo must fail at plan time, not resolve to an empty string
// that silently produces a certificate with a missing DN attribute.
func TestAccFunctionOIDUnknownNameFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "typo" {
  value = provider::pki::oid("commonNam")
}
`,
			ExpectError: regexp.MustCompile(`(?s)commonNam`),
		}},
	})
}

func TestAccFunctionOIDNameUnknownOIDFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "unknown" {
  value = provider::pki::oid_name("1.2.3.4.5.6.7.8.9")
}
`,
			ExpectError: regexp.MustCompile(`(?s)1\.2\.3\.4\.5\.6\.7\.8\.9`),
		}},
	})
}

// TestAccFunctionsComposeInASubjectBlock is the actual use case from spec
// section 5.1: the function supplies a friendly name for an OID the subject
// block has no named field for.
func TestAccFunctionsComposeInASubjectBlock(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "round_trip" {
  value = provider::pki::oid_name(provider::pki::oid("displayName"))
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("round_trip", knownvalue.StringExact("displayName")),
			},
		}},
	})
	_ = tfjsonpath.New // keep the import honest if assertions change
}
```

Drop the `tfjsonpath` import and the trailing `_ =` line when writing the file if no assertion needs a path; it is listed only because most other test files in this plan do use it.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
make testacc TESTARGS='-run TestAccFunction'
```

Expected: FAIL — OpenTofu reports that the function `provider::pki::oid` is not defined by the provider.

- [ ] **Step 3: Implement `functions.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/function"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var (
	_ function.Function = (*oidFunction)(nil)
	_ function.Function = (*oidNameFunction)(nil)
)

type oidFunction struct{}

func NewOIDFunction() function.Function { return &oidFunction{} }

func (f *oidFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	// The bare name; OpenTofu renders the call as provider::pki::oid(...).
	resp.Name = "oid"
}

func (f *oidFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Look up the dotted OID for a well-known name.",
		MarkdownDescription: "Returns the dotted object identifier for a well-known DN attribute, " +
			"extension, or extended key usage name -- for example `oid(\"displayName\")` returns " +
			"`2.16.840.1.113730.3.1.241`.\n\n" +
			"Errors on an unknown name rather than returning an empty string, so a typo fails at plan " +
			"time instead of silently omitting a DN attribute.\n\n" +
			"Use the `pki_oids` data source when you need to iterate over the table.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "name",
				MarkdownDescription: "A well-known name such as `commonName`, `displayName`, `subjectAltName`, or `clientAuth`.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *oidFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var name string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &name))
	if resp.Error != nil {
		return
	}
	oid, err := pki.OIDByName(name)
	if err != nil {
		// Argument index 0 points the error at the offending expression.
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, err.Error()))
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, oid))
}
```

`oidNameFunction` is the mirror image: name `oid_name`, parameter named `oid`, and `pki.NameByOID` in `Run`. Note two framework details the verified API check confirmed: the definition field is `Return`, not `Result` (the doc comment upstream says otherwise and is stale), and `resp.Error` is a `*function.FuncError`, not `diag.Diagnostics`, so every fallible call is threaded through `function.ConcatFuncErrors`.

Register both in `provider.go`:

```go
func (p *pkiProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{
		NewOIDFunction,
		NewOIDNameFunction,
	}
}
```

- [ ] **Step 4: Write the examples `tfplugindocs` renders**

`examples/functions/oid/function.tf`:

```hcl
# Supply a friendly name for a DN attribute the subject block has no named
# field for.
resource "pki_cert_request" "example" {
  private_key_pem = pki_private_key.example.private_key_pem

  subject {
    common_name = "nick-ipad.ha.apps.somemissing.info"

    extra_attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
  }
}
```

`examples/functions/oid_name/function.tf`:

```hcl
# Render an OID from a decoded certificate as a human-readable name.
data "pki_certificate" "example" {
  content_pem = file("device.crt")
}

output "first_subject_attribute" {
  value = provider::pki::oid_name(data.pki_certificate.example.subject[0].oid)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run TestAccFunction'
```

Expected: PASS for all five tests.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/functions.go internal/provider/functions_test.go internal/provider/provider.go examples/functions/
git commit -m "feat: provider functions oid and oid_name"
```

---

### Task 3: Data source `pki_oids`

The full table as bidirectional maps, grouped, for `for_each` and iteration.

**Files:**
- Create: `internal/provider/data_source_oids.go`
- Test: `internal/provider/data_source_oids_test.go`
- Modify: `internal/provider/provider.go`, `internal/provider/provider_test.go` (restore the `pki_oids` line in `TestProviderSchema`)
- Create: `examples/data-sources/pki_oids/data-source.tf`

**Interfaces:**
- Consumes: `pki.Tables()` (Plan 1 Task 2).
- Produces: `func NewOIDsDataSource() datasource.DataSource`.

- [ ] **Step 1: Write the failing test**

`internal/provider/data_source_oids_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccDataSourceOIDs(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pki_oids" "std" {}`,
			ConfigStateChecks: []statecheck.StateCheck{
				// Spec section 11's exact examples.
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("dn_attributes").AtMapKey("by_name").AtMapKey("displayName"),
					knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("dn_attributes").AtMapKey("by_oid").AtMapKey("2.5.4.4"),
					knownvalue.StringExact("surname")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("extended_key_usages").AtMapKey("by_name").AtMapKey("clientAuth"),
					knownvalue.StringExact("1.3.6.1.5.5.7.3.2")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("extensions").AtMapKey("by_name").AtMapKey("subjectAltName"),
					knownvalue.StringExact("2.5.29.17")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("signature_algorithms").AtMapKey("by_name").AtMapKey("SHA256-RSA"),
					knownvalue.StringExact("1.2.840.113549.1.1.11")),
				// key_usages carries the RFC 5280 bit position rather than an
				// OID, because key usages are bits in a BIT STRING and have no
				// OIDs. Documented on the attribute.
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("key_usages").AtMapKey("by_name").AtMapKey("digitalSignature"),
					knownvalue.StringExact("0")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("key_usages").AtMapKey("by_name").AtMapKey("crlSign"),
					knownvalue.StringExact("6")),
			},
		}},
	})
}

// TestAccDataSourceOIDsSupportsForEach is the capability spec section 11 calls
// out: the maps must be real maps, iterable and usable as a for_each source,
// not opaque strings.
func TestAccDataSourceOIDsSupportsForEach(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pki_oids" "std" {}

output "dn_attribute_count" {
  value = length(data.pki_oids.std.dn_attributes.by_name)
}

output "sorted_eku_names" {
  value = sort(keys(data.pki_oids.std.extended_key_usages.by_name))
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("dn_attribute_count", knownvalue.Int64Func(func(v int64) error {
					if v < 20 {
						return fmt.Errorf("dn_attributes.by_name has %d entries, want at least 20", v)
					}
					return nil
				})),
			},
		}},
	})
}
```

If `knownvalue.Int64Func` does not exist in v1.16.0, replace that check with an output whose value is a boolean comparison (`length(...) >= 20`) and assert `knownvalue.Bool(true)`; check the package's exported surface before writing rather than guessing. The `fmt` import follows whichever form you use.

- [ ] **Step 2: Run the test to verify it fails**

```bash
make testacc TESTARGS='-run TestAccDataSourceOIDs'
```

Expected: FAIL — the provider does not define a data source named `pki_oids`.

- [ ] **Step 3: Implement the data source**

`internal/provider/data_source_oids.go`. The schema is five identically-shaped single-nested attributes, so build them with a helper rather than repeating the literal five times:

```go
// oidGroupAttribute is the schema for one group of the OID table: two maps
// pointing at each other.
func oidGroupAttribute(name, description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Computed:            true,
		MarkdownDescription: description,
		Attributes: map[string]schema.Attribute{
			"by_name": schema.MapAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Keyed by friendly name.",
			},
			"by_oid": schema.MapAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Keyed by dotted OID, the reverse of `by_name`.",
			},
		},
	}
}
```

Note the import is `datasource/schema`, not `resource/schema`. The five groups and their descriptions:

- `dn_attributes` — "Distinguished name attribute types, such as `commonName` and `displayName`."
- `extensions` — "Certificate extension types, such as `subjectAltName` and `basicConstraints`."
- `extended_key_usages` — "Extended key usage purposes, such as `clientAuth`."
- `key_usages` — "Key usage names mapped to their **RFC 5280 bit position**, not to an OID: key usages are bits in a `BIT STRING` and have no object identifiers. `by_oid` is therefore keyed by that same decimal bit position."
- `signature_algorithms` — "Signature algorithm names, spelled as Go's `crypto/x509` spells them, mapped to their algorithm OIDs. **`by_oid` is smaller than `by_name`:** RFC 8017 registers a single OID for RSASSA-PSS (`1.2.840.113549.1.1.10`) across all hash sizes, because the hash is a PSS parameter rather than part of the OID. All three of `SHA256-RSAPSS`, `SHA384-RSAPSS`, and `SHA512-RSAPSS` therefore share that value in `by_name`, and `by_oid` omits it, because that OID alone cannot say which hash is in use."

The bolded asymmetry is not optional wording. `signature_algorithms` is the one group in the table that is not a bijection, a user comparing `length(by_name)` against `length(by_oid)` will notice, and the alternative — inventing a sub-arc per hash size — was tried during Plan 1 Task 2 and rejected precisely because this data source publishes these strings to users who paste them into configuration. A test in Plan 1 (`TestSignatureAlgorithmTableIsNotBijective`) now forbids it.

The `key_usages` description carries the design decision so a user reading generated docs is not surprised; that wording is the resolution of the gap spec §11 left open.

`Read` walks `pki.Tables()` and converts each group. Because the table is static there is no error path worth its own diagnostic — but do not silently ignore a conversion failure either: thread every `types.MapValueFrom` result through `resp.Diagnostics.Append` and return early if it errors, which is the framework's normal idiom and catches a future table entry with a value that cannot convert.

The model struct nests to match:

```go
type oidsDataSourceModel struct {
	DNAttributes        oidGroupModel `tfsdk:"dn_attributes"`
	Extensions          oidGroupModel `tfsdk:"extensions"`
	ExtendedKeyUsages   oidGroupModel `tfsdk:"extended_key_usages"`
	KeyUsages           oidGroupModel `tfsdk:"key_usages"`
	SignatureAlgorithms oidGroupModel `tfsdk:"signature_algorithms"`
}

type oidGroupModel struct {
	ByName types.Map `tfsdk:"by_name"`
	ByOID  types.Map `tfsdk:"by_oid"`
}
```

There is no `id` attribute. The framework does not require one, and adding a synthetic `id` to a data source with no identity is cargo-culted from SDKv2.

Register `NewOIDsDataSource` in `provider.go`'s `DataSources`, and restore the `data "pki_oids" "check" {}` line in `TestProviderSchema` that Task 1 Step 5 deferred.

- [ ] **Step 4: Write the example**

`examples/data-sources/pki_oids/data-source.tf`:

```hcl
data "pki_oids" "std" {}

# Friendly names for OIDs the subject block has no named field for.
resource "pki_cert_request" "example" {
  private_key_pem = pki_private_key.example.private_key_pem

  subject {
    common_name = "nick-ipad.ha.apps.somemissing.info"

    extra_attribute {
      oid   = data.pki_oids.std.dn_attributes.by_name["displayName"]
      value = "Nick V"
    }
  }
}

# The maps are iterable, so they work as a for_each source.
output "extended_key_usage_names" {
  value = sort(keys(data.pki_oids.std.extended_key_usages.by_name))
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run TestAccDataSourceOIDs'
go test ./internal/... -count=1
```

Expected: PASS, and `TestProviderSchema` still passes now that the data source it references exists.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/data_source_oids.go internal/provider/data_source_oids_test.go internal/provider/provider.go internal/provider/provider_test.go examples/data-sources/pki_oids/
git commit -m "feat: pki_oids data source exposing the OID table as maps"
```

---

### Task 4: Shared schema blocks and translation

`subject`, `san`, and the extension blocks, defined once and reused by every resource that accepts them. This is the task that makes the rest of the plan mechanical, and the one place where a mistake propagates to every resource.

**Files:**
- Create: `internal/provider/schema_common.go`
- Create: `internal/provider/model_common.go`
- Test: `internal/provider/model_common_test.go`

**Interfaces:**
- Consumes: `pki.Subject`, `pki.NamedSubject`, `pki.Attribute`, `pki.SAN`, `pki.BasicConstraints`, `pki.KeyUsage`, `pki.ExtKeyUsage`, `pki.NameConstraints`, `pki.ExtraExtension`, `pki.ParseOID`, `pki.ParseIPs`, `pki.ParseDuration` (Plan 1).
- Produces:
  - Schema constructors: `func subjectBlock() schema.Block`, `func sanBlock() schema.Block`, `func basicConstraintsBlock(defaultCA bool) schema.Block`, `func keyUsageBlock() schema.Block`, `func extendedKeyUsageBlock() schema.Block`, `func nameConstraintsBlock() schema.Block`, `func extraExtensionBlock() schema.Block`
  - Models: `subjectModel`, `attributeModel`, `sanModel`, `basicConstraintsModel`, `keyUsageModel`, `extKeyUsageModel`, `nameConstraintsModel`, `extraExtensionModel`
  - Converters, each returning diagnostics rather than errors so the caller can attach them to a path:
    - `func (m *subjectModel) toPKI(ctx context.Context, p path.Path) (pki.Subject, diag.Diagnostics)`
    - `func subjectFromPKI(s pki.Subject) subjectModel` — always the ordered form, for import
    - `func (m *sanModel) toPKI(ctx context.Context, p path.Path) (pki.SAN, diag.Diagnostics)`
    - `func sanFromPKI(s pki.SAN) *sanModel`
    - one `toPKI` and one `fromPKI` per extension model
  - `func parseDurationAttr(value types.String, p path.Path) (time.Duration, diag.Diagnostics)`

- [ ] **Step 1: Write the failing unit tests**

These are unit tests, not acceptance tests: the conversion functions are pure and testing them through Terraform would be slow and would obscure which direction failed.

`internal/provider/model_common_test.go` (package `provider`, not `provider_test`, because these are internal functions):

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

func TestSubjectModelNamedFieldsToPKI(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		CommonName:          types.StringValue("nick-ipad.ha.apps.somemissing.info"),
		UID:                 types.StringValue("nick"),
		GivenName:           types.StringValue("Nick"),
		Surname:             types.StringValue("Venenga"),
		Organization:        types.StringValue("homelab"),
		OrganizationalUnits: mustList(t, []string{"infra", "clients"}),
	}
	got, diags := m.toPKI(context.Background(), path.Root("subject"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	want := pki.NamedSubject{
		CommonName:          "nick-ipad.ha.apps.somemissing.info",
		UID:                 "nick",
		GivenName:           "Nick",
		Surname:             "Venenga",
		Organization:        "homelab",
		OrganizationalUnits: []string{"infra", "clients"},
	}.Expand()
	if !got.Equal(want) {
		t.Fatalf("toPKI produced %s, want %s", got.String(), want.String())
	}
}

// TestSubjectModelOrderedFormToPKI covers the form import always emits and the
// only form that can reproduce engine.py's DN (spec section 5.1).
func TestSubjectModelOrderedFormToPKI(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		Attributes: []attributeModel{
			{OID: types.StringValue("2.5.4.3"), Value: types.StringValue("cn")},
			{OID: types.StringValue("0.9.2342.19200300.100.1.1"), Value: types.StringValue("nick")},
			{OID: types.StringValue("2.16.840.1.113730.3.1.241"), Value: types.StringValue("Nick V")},
		},
	}
	got, diags := m.toPKI(context.Background(), path.Root("subject"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if len(got.Attributes) != 3 {
		t.Fatalf("produced %d attributes, want 3", len(got.Attributes))
	}
	if pki.FormatOID(got.Attributes[2].OID) != "2.16.840.1.113730.3.1.241" || got.Attributes[2].Value != "Nick V" {
		t.Fatalf("attribute 2 = %s/%q, want displayName/\"Nick V\"",
			pki.FormatOID(got.Attributes[2].OID), got.Attributes[2].Value)
	}
	// The ordered form must survive in declaration order, unsorted.
	if pki.FormatOID(got.Attributes[0].OID) != "2.5.4.3" {
		t.Errorf("attribute 0 = %s, want 2.5.4.3; declaration order must be preserved", pki.FormatOID(got.Attributes[0].OID))
	}
}

// TestSubjectModelRejectsMixingForms enforces the mutual exclusivity spec
// section 5.1 requires. The schema-level validator catches this at plan time
// too, but the converter must not silently pick one.
func TestSubjectModelRejectsMixingForms(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		CommonName: types.StringValue("cn"),
		Attributes: []attributeModel{
			{OID: types.StringValue("2.5.4.3"), Value: types.StringValue("cn")},
		},
	}
	_, diags := m.toPKI(context.Background(), path.Root("subject"))
	if !diags.HasError() {
		t.Fatal("toPKI accepted both named fields and the ordered form")
	}
}

func TestSubjectModelRejectsBadOID(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		Attributes: []attributeModel{{OID: types.StringValue("not-an-oid"), Value: types.StringValue("v")}},
	}
	_, diags := m.toPKI(context.Background(), path.Root("subject"))
	if !diags.HasError() {
		t.Fatal("toPKI accepted an unparseable OID")
	}
	// The diagnostic must point at the offending attribute, not at the block.
	if got := diags.Errors()[0].Summary(); got == "" {
		t.Error("the diagnostic has an empty summary")
	}
}

// TestSubjectFromPKIRoundTrip is what import fidelity rests on: state written
// from a parsed certificate must convert back to the identical DN.
func TestSubjectFromPKIRoundTrip(t *testing.T) {
	t.Parallel()
	original := pki.NamedSubject{
		CommonName:          "cn",
		UID:                 "uid",
		Organization:        "o",
		OrganizationalUnits: []string{"a", "b"},
	}.Expand()

	m := subjectFromPKI(original)
	if len(m.Attributes) != len(original.Attributes) {
		t.Fatalf("subjectFromPKI produced %d attributes, want %d", len(m.Attributes), len(original.Attributes))
	}
	// Import always emits the ordered form; the named fields must be null.
	if !m.CommonName.IsNull() {
		t.Error("subjectFromPKI populated common_name; import must emit only the ordered form")
	}
	back, diags := m.toPKI(context.Background(), path.Root("subject"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if !back.Equal(original) {
		t.Fatalf("round trip produced %s, want %s", back.String(), original.String())
	}
}

func TestSANModelToPKI(t *testing.T) {
	t.Parallel()
	m := &sanModel{
		DNSNames:       mustList(t, []string{"a.example"}),
		EmailAddresses: mustList(t, []string{"nick@venenga.com"}),
		IPAddresses:    mustList(t, []string{"10.0.0.5", "fd00::5"}),
		URIs:           mustList(t, []string{"spiffe://homelab/nick-ipad"}),
		Critical:       types.BoolValue(true),
	}
	got, diags := m.toPKI(context.Background(), path.Root("san"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if len(got.DNSNames) != 1 || len(got.EmailAddresses) != 1 || len(got.IPAddresses) != 2 || len(got.URIs) != 1 {
		t.Fatalf("toPKI produced %+v, want one of each type and two IPs", got)
	}
	if !got.Critical {
		t.Error("Critical was not carried through")
	}

	bad := &sanModel{IPAddresses: mustList(t, []string{"10.0.0.256"})}
	if _, diags := bad.toPKI(context.Background(), path.Root("san")); !diags.HasError() {
		t.Error("toPKI accepted an invalid IP address")
	}
}

func TestBasicConstraintsModelPathLenNullHandling(t *testing.T) {
	t.Parallel()
	// The pointer distinction from spec section 5.3 has to survive the
	// framework boundary: a null path_len is "no constraint", and 0 is a real
	// constraint. types.Int64 is the only type that can express both.
	unset := &basicConstraintsModel{CA: types.BoolValue(true), PathLen: types.Int64Null(), Critical: types.BoolValue(true)}
	got, diags := unset.toPKI(path.Root("basic_constraints"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if got.PathLen != nil {
		t.Errorf("a null path_len produced PathLen = %d, want nil", *got.PathLen)
	}

	zero := &basicConstraintsModel{CA: types.BoolValue(true), PathLen: types.Int64Value(0), Critical: types.BoolValue(true)}
	got, diags = zero.toPKI(path.Root("basic_constraints"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if got.PathLen == nil || *got.PathLen != 0 {
		t.Errorf("path_len = 0 produced %v, want a pointer to 0", got.PathLen)
	}
}

func TestParseDurationAttr(t *testing.T) {
	t.Parallel()
	got, diags := parseDurationAttr(types.StringValue("175320h"), path.Root("validity"))
	if diags.HasError() {
		t.Fatalf("parseDurationAttr: %v", diags.Errors())
	}
	if got.Hours() != 175320 {
		t.Errorf("parsed %v, want 175320h", got)
	}
	if _, diags := parseDurationAttr(types.StringValue("forever"), path.Root("validity")); !diags.HasError() {
		t.Error("parseDurationAttr accepted garbage")
	}
	// A null duration is not an error here; the caller decides whether the
	// attribute is required.
	if _, diags := parseDurationAttr(types.StringNull(), path.Root("early_renewal")); diags.HasError() {
		t.Errorf("parseDurationAttr rejected a null value: %v", diags.Errors())
	}
}

// mustList builds a types.List of strings or fails the test.
func mustList(t *testing.T, values []string) types.List {
	t.Helper()
	elems := make([]attr.Value, 0, len(values))
	for _, v := range values {
		elems = append(elems, types.StringValue(v))
	}
	list, diags := types.ListValue(types.StringType, elems)
	if diags.HasError() {
		t.Fatalf("types.ListValue: %v", diags.Errors())
	}
	return list
}
```

The test file imports `github.com/hashicorp/terraform-plugin-framework/attr` for `mustList`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/provider/ -run 'Subject|SAN|BasicConstraints|ParseDuration' -v
```

Expected: FAIL to build with `undefined: subjectModel`.

- [ ] **Step 3: Implement the models**

`internal/provider/model_common.go`. Every field is a framework type (`types.String`, `types.List`, `types.Bool`, `types.Int64`) so null and unknown are representable; never use bare Go types for optional attributes.

```go
// subjectModel is the subject block in both of its forms.
//
// The two forms are mutually exclusive (spec section 5.1): named fields expand
// to a documented canonical order, while the ordered form spells out every
// attribute so a DN that the canonical order cannot produce -- engine.py places
// displayName between UID and GN -- can still be expressed exactly. Import
// always writes the ordered form, which is what makes an adopted certificate
// plan clean.
type subjectModel struct {
	CommonName          types.String `tfsdk:"common_name"`
	Country             types.String `tfsdk:"country"`
	Organization        types.String `tfsdk:"organization"`
	OrganizationalUnits types.List   `tfsdk:"organizational_units"`
	Locality            types.String `tfsdk:"locality"`
	Province            types.String `tfsdk:"province"`
	StreetAddresses     types.List   `tfsdk:"street_addresses"`
	PostalCode          types.String `tfsdk:"postal_code"`

	// SerialNumber is the DN attribute 2.5.4.5, not the certificate serial.
	// The collision exists in hashicorp/tls too and is documented rather than
	// renamed; the certificate's serial is the top-level serial_number
	// attribute on the certificate resources.
	SerialNumber types.String `tfsdk:"serial_number"`

	Surname     types.String `tfsdk:"surname"`
	GivenName   types.String `tfsdk:"given_name"`
	UID         types.String `tfsdk:"uid"`
	DNQualifier types.String `tfsdk:"dn_qualifier"`

	ExtraAttributes []attributeModel `tfsdk:"extra_attribute"`
	Attributes      []attributeModel `tfsdk:"attribute"`
}

type attributeModel struct {
	OID   types.String `tfsdk:"oid"`
	Value types.String `tfsdk:"value"`

	// StringType controls the ASN.1 encoding of Value. It is optional and
	// defaults to utf8, which is what reproduces the certificates the homelab
	// issuer already produced (it runs openssl with string_mask = utf8only).
	// Import populates it from the parsed DER, so a certificate carrying a
	// PrintableString value re-encodes byte-exact.
	StringType types.String `tfsdk:"string_type"`
}
```

The remaining models follow the same pattern; `sanModel` has four `types.List` fields plus `Critical types.Bool`, `keyUsageModel` and `extKeyUsageModel` each have `Usages types.List` plus `Critical types.Bool`, `nameConstraintsModel` has eight `types.List` fields plus `Critical`, and `extraExtensionModel` has `OID`, `ValueBase64`, and `Critical`.

`subjectModel.toPKI` logic:

1. Determine which form is in use: any non-null named field or `extra_attribute` block versus any `attribute` block. If both, add an error at `p` saying the forms are mutually exclusive and naming both — the schema validator catches this too, but a converter that silently prefers one would make a future refactor dangerous.
2. Ordered form: map each `attributeModel` through `pki.ParseOID` and build `pki.Attribute`, attaching a diagnostic at `p.AtName("attribute").AtListIndex(i).AtName("oid")` on failure so the error lands on the exact line.
3. Named form: fill a `pki.NamedSubject`, converting each `types.List` with `ElementsAs`, then call `Expand()`.
4. Either way, map a non-null `string_type` through a small `map[string]pki.StringType`, erroring on an unknown value and listing the accepted ones.

`subjectFromPKI` produces only `Attributes`, leaving every named field null, and sets `string_type` only when the parsed type is not `utf8` — emitting the default explicitly would make hand-written configs and imported state differ cosmetically for no benefit.

`parseDurationAttr` returns `(0, nil)` for a null or unknown value and otherwise threads `pki.ParseDuration`'s error into a diagnostic at the given path.

- [ ] **Step 4: Implement the schema blocks**

`internal/provider/schema_common.go`. Each constructor returns a `schema.Block` from `resource/schema`. `subject` and `san` are `schema.SingleNestedBlock`; `extra_attribute`, `attribute`, and `extra_extension` are `schema.ListNestedBlock` so they repeat in declaration order. Do not use `SetNestedBlock` anywhere — a set discards order, and order is significant for DN attributes.

Descriptions carry the behavioral contract, because generated docs are the only place most users will read it. At minimum:

- `subject`: state the canonical order verbatim (`CN, UID, GN, SN, O, OU..., L, ST, street, postalCode, C, dnQualifier, serialNumber`), state that `extra_attribute` appends after the named fields in declaration order, state that the ordered `attribute` form is mutually exclusive with the named form, and state that drift is compared on the encoded DN bytes so any config encoding to the same DN plans clean.
- `subject.serial_number`: "The `serialNumber` **DN attribute** (OID 2.5.4.5), not the certificate's serial number. The certificate's serial is the top-level `serial_number` attribute."
- `san.critical`: "Defaults to `false`, and is forced to `true` when the subject is empty, as RFC 5280 requires."
- `basic_constraints.path_len`: "Unset and `0` are different. Null means no path length constraint; `0` means this CA may not issue further CA certificates."
- `key_usage.critical`: "Defaults to `true`." `extended_key_usage.critical`: "Defaults to `false`."
- `extra_extension.value_base64`: "Base64 of the raw DER of the extension's `extnValue`. The provider does not interpret it."

`basicConstraintsBlock(defaultCA bool)` takes the default because §6.3 defaults `ca = true` and §6.4 defaults `ca = false`; put the difference in the description text so the generated docs for each resource are accurate.

Defaults use `booldefault.StaticBool` from `resource/schema/booldefault`, which requires the attribute to be `Optional` **and** `Computed`. That pairing is what makes an omitted `critical` show as its default in state rather than as null.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
go test ./internal/provider/ -run 'Subject|SAN|BasicConstraints|ParseDuration' -v
gofmt -l . && go vet ./...
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/schema_common.go internal/provider/model_common.go internal/provider/model_common_test.go
git commit -m "feat: shared subject, san, and extension schema blocks with converters"
```

---

### Task 5: Resource `pki_private_key`

The simplest resource, and the one that establishes the CRUD shape every later resource follows. Import support lands here too, because a key is the smallest thing whose import can be verified end to end.

**Files:**
- Create: `internal/provider/resource_private_key.go`
- Create: `internal/provider/importer.go`
- Test: `internal/provider/resource_private_key_test.go`
- Test: `internal/provider/importer_test.go`
- Modify: `internal/provider/provider.go`
- Create: `examples/resources/pki_private_key/resource.tf`, `examples/resources/pki_private_key/import.sh`

**Interfaces:**
- Consumes: `pki.GenerateKey`, `pki.DescribeKey`, `pki.ParsePrivateKeyPEM`, `pki.EncodePrivateKeyPEM`, `pki.EncodePrivateKeyPKCS8PEM`, `pki.EncodePublicKeyPEM`, `pki.EncodePublicKeyOpenSSH`, `pki.PublicKeyFingerprintSHA256`, `pki.PublicKeyOf` (Plan 1 Task 5).
- Produces:
  - `func NewPrivateKeyResource() resource.Resource`
  - `func resolveImportID(id string) ([]byte, error)` — in `importer.go`, shared by every importable resource. Accepts `file://<path>`, `pem://<inline PEM>`, and `base64://<base64 of PEM>`, and returns the PEM bytes.

- [ ] **Step 1: Write the failing importer unit tests**

`internal/provider/importer_test.go` (package `provider`):

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPEM = "-----BEGIN CERTIFICATE-----\nMIIBAg==\n-----END CERTIFICATE-----\n"

func TestResolveImportIDFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(path, []byte(testPEM), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	got, err := resolveImportID("file://" + path)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the file's contents", got)
	}
}

func TestResolveImportIDPEM(t *testing.T) {
	t.Parallel()
	got, err := resolveImportID("pem://" + testPEM)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the inline PEM", got)
	}
}

func TestResolveImportIDBase64(t *testing.T) {
	t.Parallel()
	encoded := base64.StdEncoding.EncodeToString([]byte(testPEM))
	got, err := resolveImportID("base64://" + encoded)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the decoded PEM", got)
	}
	// Unpadded base64 is what a shell pipeline is most likely to produce, so
	// accept it too.
	if _, err := resolveImportID("base64://" + strings.TrimRight(encoded, "=")); err != nil {
		t.Errorf("resolveImportID rejected unpadded base64: %v", err)
	}
}

func TestResolveImportIDRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, id := range map[string]string{
		"empty":            "",
		"no scheme":        "/tmp/tls.crt",
		"unknown scheme":   "https://example.com/tls.crt",
		"vault scheme":     "vault://secret/tls.crt",
		"empty file path":  "file://",
		"missing file":     "file:///nonexistent/definitely/not/here.crt",
		"empty pem":        "pem://",
		"bad base64":       "base64://!!!!",
		"empty base64":     "base64://",
	} {
		if _, err := resolveImportID(id); err == nil {
			t.Errorf("resolveImportID(%s) returned nil error, want an error", label)
		}
	}
}

// TestResolveImportIDErrorNamesTheSchemes is what makes a mistyped import ID
// self-correcting: hashicorp/tls supports no import at all, so a user has no
// prior expectation of the format and the error is the only documentation they
// will see at that moment.
func TestResolveImportIDErrorNamesTheSchemes(t *testing.T) {
	t.Parallel()
	_, err := resolveImportID("/tmp/tls.crt")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"file://", "pem://", "base64://"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// TestResolveImportIDErrorDoesNotEchoContents matters because a private key can
// be imported inline with pem:// or base64://, and a diagnostic is printed to
// the console and to CI logs.
func TestResolveImportIDErrorDoesNotEchoContents(t *testing.T) {
	t.Parallel()
	const secret = "c3VwZXJzZWNyZXRrZXltYXRlcmlhbA"
	_, err := resolveImportID("base64://" + secret + "!!!")
	if err == nil {
		t.Fatal("expected an error for malformed base64")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error message echoes the payload: %q", err.Error())
	}
}
```

The file imports `encoding/base64` as well.

- [ ] **Step 2: Run them to verify they fail**

```bash
go test ./internal/provider/ -run TestResolveImportID -v
```

Expected: FAIL to build with `undefined: resolveImportID`.

- [ ] **Step 3: Implement `importer.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// resolveImportID turns a scheme-prefixed import ID into PEM bytes.
//
// Terraform import IDs are a single string, and PEM is multi-line, so the
// scheme prefix is how one string can carry either a location or the material
// itself:
//
//	file://<path>       read from disk
//	pem://<pem>         inline PEM
//	base64://<base64>   base64-encoded PEM, for shell pipelines
//
// hashicorp/tls supports no import at all, so there is no prior convention to
// match and the error message has to teach the format.
func resolveImportID(id string) ([]byte, error) {
	const usage = `want an ID of the form "file://<path>", "pem://<pem>", or "base64://<base64-encoded pem>"`

	switch {
	case strings.HasPrefix(id, "file://"):
		path := strings.TrimPrefix(id, "file://")
		if path == "" {
			return nil, fmt.Errorf("import ID has an empty file path; %s", usage)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			// err already names the path and not the contents.
			return nil, fmt.Errorf("reading the import source: %w", err)
		}
		if len(content) == 0 {
			return nil, fmt.Errorf("import source %q is empty", path)
		}
		return content, nil

	case strings.HasPrefix(id, "pem://"):
		content := strings.TrimPrefix(id, "pem://")
		if strings.TrimSpace(content) == "" {
			return nil, fmt.Errorf("import ID has an empty pem:// payload; %s", usage)
		}
		return []byte(content), nil

	case strings.HasPrefix(id, "base64://"):
		payload := strings.TrimPrefix(id, "base64://")
		if payload == "" {
			return nil, fmt.Errorf("import ID has an empty base64:// payload; %s", usage)
		}
		// Accept both padded and unpadded input; a shell pipeline commonly
		// strips padding. Never include the payload in an error: it may be key
		// material, and diagnostics reach the console and CI logs.
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(payload)
		}
		if err != nil {
			return nil, fmt.Errorf("the base64:// payload is not valid base64")
		}
		if len(decoded) == 0 {
			return nil, fmt.Errorf("the base64:// payload decoded to nothing")
		}
		return decoded, nil

	case id == "":
		return nil, fmt.Errorf("import ID is empty; %s", usage)

	default:
		return nil, fmt.Errorf("import ID %q has no recognized scheme; %s", firstSegment(id), usage)
	}
}

// firstSegment returns a short, safe prefix of an ID for use in an error
// message: enough to identify a typo, never enough to leak a payload.
func firstSegment(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[:i+3]
	}
	if len(id) > 16 {
		return id[:16] + "..."
	}
	return id
}
```

- [ ] **Step 4: Write the failing resource acceptance tests**

`internal/provider/resource_private_key_test.go` (package `provider_test`):

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccPrivateKeyRSA(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "test" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("algorithm"), knownvalue.StringExact("RSA")),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("rsa_bits"), knownvalue.Int64Exact(2048)),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("private_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN RSA PRIVATE KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("private_key_pem_pkcs8"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN PRIVATE KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("public_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN PUBLIC KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("public_key_openssh"),
					knownvalue.StringRegexp(regexp.MustCompile(`^ssh-rsa `))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("public_key_fingerprint_sha256"),
					knownvalue.StringRegexp(regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`))),
				// private_key_pem must be marked sensitive or it lands in plan
				// output and CI logs.
				statecheck.ExpectSensitiveValue("pki_private_key.test", tfjsonpath.New("private_key_pem")),
				statecheck.ExpectSensitiveValue("pki_private_key.test", tfjsonpath.New("private_key_pem_pkcs8")),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				// A second plan after apply must be empty. Anything else means a
				// computed attribute is being recomputed, which for a key means
				// a replacement and a new key on every apply.
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccPrivateKeyDefaults(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "rsa" {
  algorithm = "RSA"
}
resource "pki_private_key" "ecdsa" {
  algorithm = "ECDSA"
}
resource "pki_private_key" "ed25519" {
  algorithm = "ED25519"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_private_key.rsa", tfjsonpath.New("rsa_bits"), knownvalue.Int64Exact(2048)),
				statecheck.ExpectKnownValue("pki_private_key.ecdsa", tfjsonpath.New("ecdsa_curve"), knownvalue.StringExact("P256")),
				statecheck.ExpectKnownValue("pki_private_key.ecdsa", tfjsonpath.New("private_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN EC PRIVATE KEY-----`))),
				// Ed25519 has no legacy encoding, so its native form is PKCS#8.
				statecheck.ExpectKnownValue("pki_private_key.ed25519", tfjsonpath.New("private_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN PRIVATE KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.ed25519", tfjsonpath.New("public_key_openssh"),
					knownvalue.StringRegexp(regexp.MustCompile(`^ssh-ed25519 `))),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccPrivateKeyChangingAlgorithmReplaces confirms the RequiresReplace
// modifiers are wired: a key's algorithm cannot be changed in place.
func TestAccPrivateKeyChangingAlgorithmReplaces(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: `resource "pki_private_key" "test" { algorithm = "ECDSA" }`},
			{
				Config: `resource "pki_private_key" "test" { algorithm = "RSA" }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_private_key.test", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}

func TestAccPrivateKeyRejectsInvalidConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"unknown algorithm": {
			config: `resource "pki_private_key" "test" { algorithm = "DSA" }`,
			expect: regexp.MustCompile(`(?s)DSA|Invalid Attribute Value`),
		},
		"rsa too small": {
			config: `resource "pki_private_key" "test" { algorithm = "RSA"
  rsa_bits = 1024 }`,
			expect: regexp.MustCompile(`(?s)2048`),
		},
		"curve on rsa": {
			config: `resource "pki_private_key" "test" { algorithm = "RSA"
  ecdsa_curve = "P256" }`,
			expect: regexp.MustCompile(`(?s)ecdsa_curve|ECDSA`),
		},
		"bits on ed25519": {
			config: `resource "pki_private_key" "test" { algorithm = "ED25519"
  rsa_bits = 2048 }`,
			expect: regexp.MustCompile(`(?s)rsa_bits|RSA`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      tc.config,
					ExpectError: tc.expect,
				}},
			})
		})
	}
}

// TestAccPrivateKeyImport is spec section 8's requirement at its simplest: every
// input attribute is reconstructed from the parsed key, so the plan after import
// is empty.
func TestAccPrivateKeyImport(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tls.key")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Generate a key and write it out, so the import source is a
				// real file rather than a fixture checked into the repository.
				Config: fmt.Sprintf(`
resource "pki_private_key" "origin" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "local_sensitive_file" "key" {
  filename        = %q
  content         = pki_private_key.origin.private_key_pem
  file_permission = "0600"
}
`, keyPath),
				ExternalProviders: map[string]resource.ExternalProvider{
					"local": {Source: "hashicorp/local"},
				},
			},
			{
				// Now import that file into a second resource address.
				Config: `resource "pki_private_key" "imported" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}`,
				ResourceName:      "pki_private_key.imported",
				ImportState:       true,
				ImportStateId:     "file://" + keyPath,
				ImportStateVerify: false, // there is no prior state to compare against
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected 1 imported instance, got %d", len(states))
					}
					attrs := states[0].Attributes
					if attrs["algorithm"] != "ECDSA" {
						return fmt.Errorf("algorithm = %q, want ECDSA", attrs["algorithm"])
					}
					if attrs["ecdsa_curve"] != "P384" {
						return fmt.Errorf("ecdsa_curve = %q, want P384; input attributes must be reconstructed from the key", attrs["ecdsa_curve"])
					}
					if attrs["private_key_pem"] == "" {
						return fmt.Errorf("private_key_pem is empty after import")
					}
					if attrs["public_key_fingerprint_sha256"] == "" {
						return fmt.Errorf("public_key_fingerprint_sha256 is empty after import")
					}
					return nil
				},
			},
		},
	})
}

func TestAccPrivateKeyImportRejectsBadID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:        `resource "pki_private_key" "test" { algorithm = "ECDSA" }`,
			ResourceName:  "pki_private_key.test",
			ImportState:   true,
			ImportStateId: "/tmp/no-scheme.key",
			ExpectError:   regexp.MustCompile(`(?s)file://`),
		}},
	})
	_ = base64.StdEncoding // keep the import honest if the base64 case is added
	_ = os.Getenv
}
```

Drop the two trailing `_ =` lines and the unused imports when writing the file. The test imports `github.com/hashicorp/terraform-plugin-testing/terraform` for `ImportStateCheck`.

Note the `hashicorp/local` external provider in the import test: it is MPL-2.0, is only used at test time, and is never linked into the provider binary, so it does not affect the §13 audit. Record that in a comment in the test.

- [ ] **Step 5: Run them to verify they fail**

```bash
make testacc TESTARGS='-run TestAccPrivateKey'
```

Expected: FAIL — the provider does not define `pki_private_key`.

- [ ] **Step 6: Implement the resource**

`internal/provider/resource_private_key.go`. Schema, per spec §6.1:

| Attribute | Kind | Plan modifiers and validators |
| --- | --- | --- |
| `algorithm` | Required, String | `stringvalidator.OneOf("RSA", "ECDSA", "ED25519")`, `stringplanmodifier.RequiresReplace()` |
| `rsa_bits` | Optional + Computed, Int64 | `int64validator.AtLeast(2048)`, `int64planmodifier.RequiresReplace()`, `int64planmodifier.UseStateForUnknown()` |
| `ecdsa_curve` | Optional + Computed, String | `stringvalidator.OneOf("P224", "P256", "P384", "P521")`, `stringplanmodifier.RequiresReplace()`, `UseStateForUnknown()` |
| `private_key_pem` | Computed, Sensitive, String | `UseStateForUnknown()` |
| `private_key_pem_pkcs8` | Computed, Sensitive, String | `UseStateForUnknown()` |
| `public_key_pem` | Computed, String | `UseStateForUnknown()` |
| `public_key_openssh` | Computed, String | `UseStateForUnknown()` |
| `public_key_fingerprint_sha256` | Computed, String | `UseStateForUnknown()` |
| `id` | Computed, String | `UseStateForUnknown()` — set to the fingerprint |

`UseStateForUnknown` on every computed attribute is not optional here. Without it the framework marks them unknown on every plan, which shows as a diff and — worse — invites a `Read` that regenerates. `rsa_bits` and `ecdsa_curve` are Optional **and** Computed so an omitted value settles to the default in state instead of staying null, which is what makes `TestAccPrivateKeyDefaults` pass and what makes import able to fill them in.

`ConfigValidators` returns `resourcevalidator.Conflicting(path.MatchRoot("rsa_bits"), path.MatchRoot("ecdsa_curve"))`. That catches the "both set" case; the algorithm-specific cases (`ecdsa_curve` with `algorithm = "RSA"`) are caught by `pki.GenerateKey`'s validation surfacing as a diagnostic, so `ValidateConfig` is not needed for them — but the resulting message must name the attribute, so `Create` attaches the error with `resp.Diagnostics.AddAttributeError(path.Root("ecdsa_curve"), ...)` when `pki.GenerateKey` rejects the combination.

`Create`: read the plan into the model, resolve defaults (2048 / `P256`) so the values written to state are concrete, call `pki.GenerateKey`, then fill every computed attribute through a shared helper:

```go
// setKeyAttributes populates every computed attribute of pki_private_key from a
// key. Create and ImportState both use it, which is what guarantees an imported
// key's state is indistinguishable from a generated one -- the property spec
// section 8 needs for the plan after import to be empty.
func setKeyAttributes(m *privateKeyResourceModel, key crypto.Signer) error {
```

It sets `private_key_pem`, `private_key_pem_pkcs8`, `public_key_pem`, `public_key_openssh`, `public_key_fingerprint_sha256`, and `id` (the fingerprint), and also sets `algorithm`, `rsa_bits`, and `ecdsa_curve` from `pki.DescribeKey` — for `Create` those are already correct, and re-deriving them is a cheap self-check that costs nothing and would catch a defaulting bug immediately.

`Read` is a no-op that re-reads state unchanged. There is nothing external to refresh: the key exists only in state. Do not re-derive anything in `Read` — a `Read` that recomputed `private_key_pem` would rotate the key on every refresh. Write that reasoning as a comment, because an empty `Read` looks like an oversight.

`Update` cannot be reached: every input attribute has `RequiresReplace`. Implement it as a diagnostic that says so, rather than leaving it empty, so a future schema change that makes it reachable fails loudly.

`Delete` is a no-op; the framework removes the resource from state.

`ImportState` resolves the ID through `resolveImportID`, parses with `pki.ParsePrivateKeyPEM`, calls `setKeyAttributes`, and writes the whole model to `resp.State`. Not `ImportStatePassthroughID` — the ID is a locator, not the resource's identity.

Register `NewPrivateKeyResource` in `provider.go`.

- [ ] **Step 7: Write the examples**

`examples/resources/pki_private_key/resource.tf`:

```hcl
resource "pki_private_key" "device" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}
```

`examples/resources/pki_private_key/import.sh`:

```shell
# Adopt an existing key from disk.
terraform import pki_private_key.device 'file:///tmp/nick-ipad/tls.key'

# Or inline, for a key already in a variable or piped from another tool.
terraform import pki_private_key.device "base64://$(base64 -w0 < tls.key)"
```

- [ ] **Step 8: Run everything and commit**

```bash
go test ./internal/provider/ -run TestResolveImportID -v
make testacc TESTARGS='-run TestAccPrivateKey'
gofmt -l . && go vet ./...
git add internal/provider/resource_private_key.go internal/provider/importer.go internal/provider/resource_private_key_test.go internal/provider/importer_test.go internal/provider/provider.go examples/resources/pki_private_key/
git commit -m "feat: pki_private_key resource with scheme-prefixed import"
```

---

### Task 6: Resource `pki_cert_request` and data source `pki_cert_request`

The CSR pair. The resource creates one; the data source decodes one that arrived from elsewhere, which spec §11 motivates as "a device or another team hands you a CSR and you want to inspect or assert on it before issuing, rather than signing blind."

**Files:**
- Create: `internal/provider/resource_cert_request.go`
- Create: `internal/provider/data_source_cert_request.go`
- Test: `internal/provider/resource_cert_request_test.go`
- Test: `internal/provider/data_source_cert_request_test.go`
- Modify: `internal/provider/provider.go`
- Create: `examples/resources/pki_cert_request/resource.tf`, `examples/data-sources/pki_cert_request/data-source.tf`

**Interfaces:**
- Consumes: `pki.CreateCertRequest`, `pki.ParseCertRequestPEM`, `pki.CertRequestTemplate` (Plan 1 Task 9); the Task 4 blocks and converters.
- Produces: `func NewCertRequestResource() resource.Resource`, `func NewCertRequestDataSource() datasource.DataSource`.

- [ ] **Step 1: Write the failing tests**

`internal/provider/resource_cert_request_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// testAccKeyConfig is the fragment every certificate-related test starts from.
const testAccKeyConfig = `
resource "pki_private_key" "test" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
`

func TestAccCertRequestNamedSubject(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem

  subject {
    common_name          = "nick-ipad.ha.apps.somemissing.info"
    uid                  = "nick"
    given_name           = "Nick"
    surname              = "Venenga"
    organization         = "homelab"
    organizational_units = ["infra", "clients"]

    extra_attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_cert_request.test", tfjsonpath.New("cert_request_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN CERTIFICATE REQUEST-----`))),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertRequestOrderedSubject exercises the form that reproduces
// engine.py's DN, where displayName sits between UID and GN -- an order the
// canonical named-field expansion cannot produce (spec section 5.1).
func TestAccCertRequestOrderedSubject(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-ipad.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Nick"
    }
  }
}

data "pki_cert_request" "decoded" {
  content_pem = pki_cert_request.test.cert_request_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// The decoded subject must come back in the same order it was
				// declared, with displayName third.
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(2).AtMapKey("oid"),
					knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(2).AtMapKey("value"),
					knownvalue.StringExact("Nick V")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("signature_valid"), knownvalue.Bool(true)),
			},
		}},
	})
}

func TestAccCertRequestRejectsMixedSubjectForms(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem

  subject {
    common_name = "cn"
    attribute {
      oid   = "2.5.4.3"
      value = "cn"
    }
  }
}
`,
			ExpectError: regexp.MustCompile(`(?s)mutually exclusive|attribute`),
		}},
	})
}

// TestAccCertRequestRotatingKeyReplaces confirms a new key means a new CSR:
// a CSR is a signature over a specific public key and cannot outlive it.
func TestAccCertRequestRotatingKeyReplaces(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}
`,
			},
			{
				Config: `
resource "pki_private_key" "test" {
  algorithm = "RSA"
}
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_cert_request.test", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}
```

`internal/provider/data_source_cert_request_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccDataSourceCertRequest(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject {
    common_name  = "nick-ipad.ha.apps.somemissing.info"
    organization = "homelab"
  }
  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com"]
  }
}

data "pki_cert_request" "decoded" {
  content_pem = pki_cert_request.test.cert_request_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("nick-ipad.ha.apps.somemissing.info")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("san").AtMapKey("dns_names").AtSliceIndex(0),
					knownvalue.StringExact("nick-ipad.ha.apps.somemissing.info")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("san").AtMapKey("email_addresses").AtSliceIndex(0),
					knownvalue.StringExact("nick@venenga.com")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("public_key_algorithm"), knownvalue.StringExact("ECDSA")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("signature_valid"), knownvalue.Bool(true)),
			},
		}},
	})
}

// TestAccDataSourceCertRequestAcceptsBase64 covers the ergonomic spec section
// 11 asks for on the certificate data source and which applies equally here:
// material read straight out of a Kubernetes Secret needs no decoding step.
func TestAccDataSourceCertRequestAcceptsBase64(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}

data "pki_cert_request" "decoded" {
  content_base64 = base64encode(pki_cert_request.test.cert_request_pem)
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("cn")),
			},
		}},
	})
}

func TestAccDataSourceCertRequestRejectsBadInput(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"neither input": {
			config: `data "pki_cert_request" "d" {}`,
			expect: regexp.MustCompile(`(?s)content_pem|content_base64`),
		},
		"both inputs": {
			config: `data "pki_cert_request" "d" {
  content_pem    = "x"
  content_base64 = "eA=="
}`,
			expect: regexp.MustCompile(`(?s)cannot be configured together|Invalid Attribute Combination`),
		},
		"not a csr": {
			config: `data "pki_cert_request" "d" { content_pem = "hello" }`,
			expect: regexp.MustCompile(`(?s)certificate request|PEM`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps:                    []resource.TestStep{{Config: tc.config, ExpectError: tc.expect}},
			})
		})
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

```bash
make testacc TESTARGS='-run "TestAccCertRequest|TestAccDataSourceCertRequest"'
```

Expected: FAIL — neither `pki_cert_request` type exists.

- [ ] **Step 3: Implement the resource**

Schema per spec §6.2:

| Attribute | Kind | Notes |
| --- | --- | --- |
| `private_key_pem` | Required, Sensitive, String | `RequiresReplace()` — a CSR signs a specific public key |
| `subject` | Block | `subjectBlock()` from Task 4, `RequiresReplace` on the block |
| `san` | Block | `sanBlock()`, `RequiresReplace` |
| `extra_extension` | Block, repeatable | `extraExtensionBlock()`, `RequiresReplace` |
| `signature_algorithm` | Optional + Computed, String | validated against `pki.SignatureAlgorithmNames`' keys, `RequiresReplace` |
| `cert_request_pem` | Computed, String | `UseStateForUnknown()` |
| `id` | Computed, String | SHA-256 of the DER, hex |

Every input carries `RequiresReplace` because a CSR is an immutable signed object; there is no in-place edit. That makes `Update` unreachable, so implement it as a diagnostic the same way Task 5 does.

`Create`: parse the key with `pki.ParsePrivateKeyPEM` (attaching any error to `path.Root("private_key_pem")`), convert the blocks through their `toPKI` methods, resolve `signature_algorithm` (defaulting through `pki.DefaultSignatureAlgorithm` and writing the resolved name back to state so the attribute is concrete), call `pki.CreateCertRequest`, and set `cert_request_pem` and `id`.

`Read` re-reads state unchanged, with the same comment as Task 5 explaining why.

The resource is deliberately **not** importable. Spec §8 lists only `pki_private_key`, `pki_certificate`, and `pki_certificate_authority`, and a CSR is a transient artifact — adopting one has no value, because the certificate it produced is what matters and that is importable on its own. State that in the resource's `MarkdownDescription` so its absence reads as a decision.

- [ ] **Step 4: Implement the data source**

Schema per spec §11:

| Attribute | Kind | Notes |
| --- | --- | --- |
| `content_pem` | Optional, String | exactly one of this and `content_base64` |
| `content_base64` | Optional, String | so Kubernetes Secret data needs no decode step |
| `subject` | Computed, List of objects `{oid, value, string_type}` | the ordered form |
| `san` | Computed, Object `{dns_names, email_addresses, ip_addresses, uris, critical}` | |
| `requested_extensions` | Computed, List of objects `{oid, critical, value_base64}` | every extension in the CSR, including the SAN, unparsed |
| `public_key_algorithm` | Computed, String | `RSA`, `ECDSA`, or `ED25519` |
| `public_key_pem` | Computed, String | |
| `signature_algorithm` | Computed, String | |
| `signature_valid` | Computed, Bool | |

`ConfigValidators` returns `datasourcevalidator.ExactlyOneOf(path.MatchRoot("content_pem"), path.MatchRoot("content_base64"))` — note the `datasourcevalidator` package, not `resourcevalidator`.

`Read` resolves the input to PEM bytes (base64-decoding when `content_base64` is set), then calls `pki.ParseCertRequestPEM`. One wrinkle: `pki.ParseCertRequestPEM` verifies the signature and errors when it fails, but this data source must report `signature_valid = false` rather than failing — a caller inspecting an untrusted CSR wants the boolean, which is the whole point of the attribute. So parse in two stages here: decode the PEM and call `x509.ParseCertificateRequest`... except `internal/provider` must not import `crypto/x509` logic. Resolve it in `internal/pki` instead by adding one function in this task:

```go
// ParseCertRequestPEMUnverified parses a CSR without checking its signature,
// and reports separately whether the signature verifies.
//
// The verifying ParseCertRequestPEM is the right default for issuance. This
// variant exists for the pki_cert_request data source, whose whole purpose is
// inspecting a CSR that arrived from elsewhere: a caller wants
// signature_valid = false reported as data, not raised as an error.
func ParseCertRequestPEMUnverified(b []byte) (csr *x509.CertificateRequest, signatureValid bool, err error)
```

Add it to `internal/pki/sign.go` with a unit test in `internal/pki/sign_test.go` covering a valid CSR (returns true) and a tampered one (returns false with a nil error). That keeps the crypto in Plan 1's package where the boundary test expects it.

Register both types in `provider.go`.

- [ ] **Step 5: Write the examples**

`examples/resources/pki_cert_request/resource.tf`:

```hcl
resource "pki_private_key" "device" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_cert_request" "device" {
  private_key_pem = pki_private_key.device.private_key_pem

  subject {
    common_name          = "nick-ipad.ha.apps.somemissing.info"
    uid                  = "nick"
    given_name           = "Nick"
    surname              = "Venenga"
    organization         = "homelab"
    organizational_units = ["infra", "clients"]

    # displayName has no named field, so supply it by OID.
    extra_attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }
}
```

`examples/data-sources/pki_cert_request/data-source.tf`:

```hcl
# Inspect a CSR handed over by a device or another team before signing it.
data "pki_cert_request" "incoming" {
  content_pem = file("device.csr")
}

# Refuse to issue against a CSR whose signature does not verify, or whose
# common name is outside the domain this CA is willing to sign for.
resource "pki_certificate" "device" {
  count = data.pki_cert_request.incoming.signature_valid ? 1 : 0

  ca_certificate_pem = var.ca_certificate_pem
  ca_private_key_pem = var.ca_private_key_pem
  csr_pem            = data.pki_cert_request.incoming.content_pem
  validity           = "8760h"

  # Extensions always come from here, never from the CSR.
  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }
  extended_key_usage {
    usages = ["clientAuth"]
  }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run CertRequest -v
make testacc TESTARGS='-run "TestAccCertRequest|TestAccDataSourceCertRequest"'
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/provider/resource_cert_request.go internal/provider/data_source_cert_request.go internal/provider/resource_cert_request_test.go internal/provider/data_source_cert_request_test.go internal/provider/provider.go internal/pki/sign.go internal/pki/sign_test.go examples/resources/pki_cert_request/ examples/data-sources/pki_cert_request/
git commit -m "feat: pki_cert_request resource and data source"
```

---

### Task 7: Data source `pki_certificate`

Decodes any certificate PEM — including the Bitwarden-delivered CA — into its parts. Landing it before the certificate resources means the resource tests can assert on issued certificates through the provider's own surface instead of reaching into Go.

**Files:**
- Create: `internal/provider/data_source_certificate.go`
- Test: `internal/provider/data_source_certificate_test.go`
- Modify: `internal/provider/provider.go`
- Create: `examples/data-sources/pki_certificate/data-source.tf`

**Interfaces:**
- Consumes: `pki.ParseCertificatePEM`, `pki.ParseSubjectDER`, `pki.ParseSANExtension`, `pki.FindExtension`, `pki.FormatSerial`, `pki.SignatureAlgorithmName`, `pki.PublicKeyFingerprintSHA256` (Plan 1).
- Produces: `func NewCertificateDataSource() datasource.DataSource`, plus two helpers Tasks 8 and 9 reuse in their `ImportState` paths, where a parsed certificate has to be turned back into schema values: `func subjectListValue(ctx context.Context, s pki.Subject) (types.List, diag.Diagnostics)` and `func extensionListValue(ctx context.Context, exts []pkix.Extension) (types.List, diag.Diagnostics)`.

- [ ] **Step 1: Write the failing test**

`internal/provider/data_source_certificate_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// testAccCAConfig is a self-signed CA every later test builds on. crlSign is
// included because Go refuses to sign a CRL with a CA that lacks it.
const testAccCAConfig = `
resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "pki_certificate_authority" "root" {
  private_key_pem = pki_private_key.ca.private_key_pem
  validity        = "175320h"

  subject {
    common_name  = "homelab-root"
    organization = "homelab"
  }

  key_usage {
    usages = ["keyCertSign", "crlSign"]
  }
}
`

func TestAccDataSourceCertificate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
data "pki_certificate" "decoded" {
  content_pem = pki_certificate_authority.root.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("oid"),
					knownvalue.StringExact("2.5.4.3")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("homelab-root")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("is_ca"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("public_key_algorithm"), knownvalue.StringExact("ECDSA")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("signature_algorithm"), knownvalue.StringExact("ECDSA-SHA384")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("serial_number"), knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]+$`))),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("not_after"), knownvalue.StringRegexp(regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`))),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject_key_id"), knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]{40}$`))),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("fingerprint_sha256"), knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]{64}$`))),
			},
		}},
	})
}

func TestAccDataSourceCertificateExtensionsAndSAN(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + testAccKeyConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"

  subject {
    common_name = "nick-ipad.ha.apps.somemissing.info"
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com"]
    ip_addresses    = ["10.0.0.5"]
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

data "pki_certificate" "decoded" {
  content_pem = pki_certificate.leaf.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("san").AtMapKey("dns_names").AtSliceIndex(0),
					knownvalue.StringExact("nick-ipad.ha.apps.somemissing.info")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("san").AtMapKey("email_addresses").AtSliceIndex(0),
					knownvalue.StringExact("nick@venenga.com")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("san").AtMapKey("ip_addresses").AtSliceIndex(0),
					knownvalue.StringExact("10.0.0.5")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("key_usage").AtMapKey("usages"),
					knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("digitalSignature"),
						knownvalue.StringExact("keyEncipherment"),
					})),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("extended_key_usage").AtMapKey("usages"),
					knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("clientAuth")})),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("basic_constraints").AtMapKey("ca"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("is_ca"), knownvalue.Bool(false)),
			},
		}},
	})
}

func TestAccDataSourceCertificateAcceptsBase64(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// This is the shape that matters operationally: the CA arrives as
			// base64 in a Kubernetes Secret's data map, and spec section 11
			// requires no decoding step.
			Config: testAccCAConfig + `
data "pki_certificate" "decoded" {
  content_base64 = base64encode(pki_certificate_authority.root.certificate_pem)
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("homelab-root")),
			},
		}},
	})
}

func TestAccDataSourceCertificateRejectsBadInput(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"neither input": {
			config: `data "pki_certificate" "d" {}`,
			expect: regexp.MustCompile(`(?s)content_pem|content_base64`),
		},
		"both inputs": {
			config: `data "pki_certificate" "d" {
  content_pem    = "x"
  content_base64 = "eA=="
}`,
			expect: regexp.MustCompile(`(?s)cannot be configured together|Invalid Attribute Combination`),
		},
		"not a certificate": {
			config: `data "pki_certificate" "d" { content_pem = "hello" }`,
			expect: regexp.MustCompile(`(?s)certificate|PEM`),
		},
		"bad base64": {
			config: `data "pki_certificate" "d" { content_base64 = "!!!!" }`,
			expect: regexp.MustCompile(`(?s)base64`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps:                    []resource.TestStep{{Config: tc.config, ExpectError: tc.expect}},
			})
		})
	}
}
```

**Write only the tests this task can make pass.** Of the four above, `TestAccDataSourceCertificateRejectsBadInput` needs nothing beyond the data source, so it lands here. The other three exercise `pki_certificate_authority` and `pki_certificate`, which do not exist yet — so they do **not** land here. Instead:

- `TestAccDataSourceCertificate` and `TestAccDataSourceCertificateAcceptsBase64` move to Task 8, which introduces `pki_certificate_authority` and the `testAccCAConfig` fragment they depend on. Task 8's Step 1 adds them to `data_source_certificate_test.go`.
- `TestAccDataSourceCertificateExtensionsAndSAN` moves to Task 9, which introduces `pki_certificate`.

The `testAccCAConfig` constant above moves with them: define it in Task 8's `resource_certificate_authority_test.go`, not here. This task's test file therefore contains one test and no references to resources that do not exist, so the suite is green at every commit.

- [ ] **Step 2: Run to verify failure**

```bash
make testacc TESTARGS='-run TestAccDataSourceCertificate'
```

Expected: FAIL — `pki_certificate` data source undefined.

- [ ] **Step 3: Implement the data source**

Schema:

| Attribute | Kind | Notes |
| --- | --- | --- |
| `content_pem` | Optional, String | exactly one of this and `content_base64` |
| `content_base64` | Optional, String | |
| `subject` | Computed, List of `{oid, value, string_type}` | ordered form |
| `issuer` | Computed, List of `{oid, value, string_type}` | ordered form |
| `serial_number` | Computed, String | normalized hex |
| `not_before`, `not_after` | Computed, String | RFC3339 |
| `san` | Computed, Object | `{dns_names, email_addresses, ip_addresses, uris, critical}`; null when the certificate has no SAN |
| `basic_constraints` | Computed, Object | `{ca, path_len, critical}`; `path_len` null when unconstrained |
| `key_usage` | Computed, Object | `{usages, critical}`; null when absent |
| `extended_key_usage` | Computed, Object | `{usages, critical}`; null when absent |
| `name_constraints` | Computed, Object | the eight lists plus `critical`; null when absent |
| `extensions` | Computed, List of `{oid, critical, value_base64}` | **every** extension, including the ones parsed above |
| `is_ca` | Computed, Bool | convenience, from basicConstraints |
| `public_key_algorithm` | Computed, String | |
| `public_key_pem` | Computed, String | |
| `public_key_fingerprint_sha256` | Computed, String | OpenSSH form, matching `pki_private_key` |
| `signature_algorithm` | Computed, String | |
| `fingerprint_sha256` | Computed, String | SHA-256 of the DER, lowercase hex — the certificate's identity, distinct from the public key fingerprint |
| `subject_key_id`, `authority_key_id` | Computed, String | lowercase hex, null when absent |
| `version` | Computed, Int64 | |

Two things worth stating in the descriptions. `extensions` is the complete list including the extensions that also appear in their own parsed attributes, because a caller asserting on an extension the provider has no typed attribute for needs somewhere to look — say so, so the apparent duplication reads as deliberate. And `fingerprint_sha256` versus `public_key_fingerprint_sha256` are different things with confusable names, so each description must say which is which.

`Read` parses and populates. The `subjectListValue` and `extensionListValue` helpers are extracted here rather than inlined because Tasks 8 and 9 need exactly the same conversion when reconstructing state during `ImportState`, and duplicating it is how the two drift apart.

`ExactlyOneOf` on the two inputs via `datasourcevalidator`.

- [ ] **Step 4: Write the example**

`examples/data-sources/pki_certificate/data-source.tf`:

```hcl
# The CA is delivered from Bitwarden into a Kubernetes Secret, so it arrives
# base64-encoded. No decoding step is needed.
data "kubernetes_secret" "ca" {
  metadata {
    name      = "pki-ca"
    namespace = "homelab-pki"
  }
}

data "pki_certificate" "ca" {
  content_base64 = data.kubernetes_secret.ca.binary_data["tls.crt"]
}

# Assert on adopted material before building anything on top of it.
check "ca_can_sign_crls" {
  assert {
    condition     = contains(data.pki_certificate.ca.key_usage.usages, "crlSign")
    error_message = "The CA cannot sign CRLs; pki_crl will fail against it."
  }
}

output "ca_expires" {
  value = data.pki_certificate.ca.not_after
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run TestAccDataSourceCertificate'
go test ./internal/... -count=1
```

Expected: PASS. The whole suite is green — the resource-dependent assertions were deferred to Tasks 8 and 9 rather than landing red here.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/data_source_certificate.go internal/provider/data_source_certificate_test.go internal/provider/provider.go examples/data-sources/pki_certificate/
git commit -m "feat: pki_certificate data source"
```

---

### Task 8: Resource `pki_certificate_authority`

Self-signs a root with no parent; issues an intermediate with one. This collapses `tls_self_signed_cert` and `tls_locally_signed_cert`, because "is this a CA" is the distinction that actually changes the extensions.

**Files:**
- Create: `internal/provider/resource_certificate_authority.go`
- Test: `internal/provider/resource_certificate_authority_test.go`
- Test: `internal/provider/data_source_certificate_test.go` (add the two tests deferred from Task 7, below)
- Modify: `internal/provider/provider.go`
- Create: `examples/resources/pki_certificate_authority/resource.tf`, `examples/resources/pki_certificate_authority/import.sh`

**Deferred from Task 7.** Task 7 built the `pki_certificate` data source but could only test its input validation, because there was no certificate resource to decode. Two of its tests belong here, now that there is one. Add both to `internal/provider/data_source_certificate_test.go` in Step 1, taking their bodies from Task 7's Step 1 verbatim:

- `TestAccDataSourceCertificate` — decodes `pki_certificate_authority.root.certificate_pem` and asserts on subject, `is_ca`, `signature_algorithm`, serial, `not_after`, `subject_key_id`, and `fingerprint_sha256`.
- `TestAccDataSourceCertificateAcceptsBase64` — the same via `content_base64`, which is the shape a Kubernetes Secret delivers.

Both depend on the `testAccCAConfig` constant, which this task defines (see Step 1).

**Interfaces:**
- Consumes: `pki.CreateCertificate`, `pki.CertTemplate`, `pki.ParseCertificatePEM`, `pki.ParseCertificateChainPEM`, `pki.EncodeCertificatePEM`, `pki.RandomSerial`, `pki.ParseSerial`, `pki.FormatSerial`, `pki.ParseDuration`, `pki.CompareValidity`, `pki.DefaultCAKeyUsage` (Plan 1); Task 4's blocks; Task 7's helpers; Task 5's `resolveImportID`.
- Produces: `func NewCertificateAuthorityResource() resource.Resource`, plus two helpers Task 9 reuses:
  - `func issuanceValidity(validity, earlyRenewal types.String, now time.Time, p path.Path) (notBefore, notAfter time.Time, ready bool, diags diag.Diagnostics)`
  - `func resolveSerial(configured types.String, state types.String, p path.Path) (*big.Int, diag.Diagnostics)`

- [ ] **Step 1: Write the failing tests**

`internal/provider/resource_certificate_authority_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccCertificateAuthorityRoot(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("certificate_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN CERTIFICATE-----`))),
				// No parent means no chain.
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("certificate_chain_pem"),
					knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("ready_for_renewal"),
					knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("serial_number"),
					knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]+$`))),
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("subject_key_id"),
					knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]{40}$`))),
				// Self-signed: the authority key id equals the subject key id.
				statecheck.CompareValuePairs(
					"pki_certificate_authority.root", tfjsonpath.New("subject_key_id"),
					"pki_certificate_authority.root", tfjsonpath.New("authority_key_id"),
					compare.ValuesSame()),
				// basic_constraints defaults to ca = true, critical = true.
				statecheck.ExpectKnownValue("pki_certificate_authority.root",
					tfjsonpath.New("basic_constraints").AtSliceIndex(0).AtMapKey("ca"), knownvalue.Bool(true)),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccCertificateAuthorityIntermediate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "intermediate" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "intermediate" {
  private_key_pem        = pki_private_key.intermediate.private_key_pem
  parent_certificate_pem = pki_certificate_authority.root.certificate_pem
  parent_private_key_pem = pki_private_key.ca.private_key_pem
  validity               = "87600h"

  subject {
    common_name  = "homelab-intermediate"
    organization = "homelab"
  }

  basic_constraints {
    ca       = true
    path_len = 0
  }

  key_usage {
    usages = ["keyCertSign", "crlSign"]
  }
}

data "pki_certificate" "intermediate" {
  content_pem = pki_certificate_authority.intermediate.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// A parent means a chain, leaf-adjacent first.
				statecheck.ExpectKnownValue("pki_certificate_authority.intermediate", tfjsonpath.New("certificate_chain_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`(?s)^-----BEGIN CERTIFICATE-----.*-----BEGIN CERTIFICATE-----`))),
				// path_len = 0 must survive as a real constraint, distinct from
				// unset (spec section 5.3).
				statecheck.ExpectKnownValue("data.pki_certificate.intermediate",
					tfjsonpath.New("basic_constraints").AtMapKey("path_len"), knownvalue.Int64Exact(0)),
				statecheck.ExpectKnownValue("data.pki_certificate.intermediate",
					tfjsonpath.New("is_ca"), knownvalue.Bool(true)),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateAuthorityPathLenUnsetVersusZero is the pair of cases spec
// section 5.3 exists for. Unset must produce no pathLenConstraint at all.
func TestAccCertificateAuthorityPathLenUnsetVersusZero(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "unset" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  subject { common_name = "unset" }
  basic_constraints { ca = true }
}

resource "pki_certificate_authority" "zero" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  subject { common_name = "zero" }
  basic_constraints {
    ca       = true
    path_len = 0
  }
}

data "pki_certificate" "unset" {
  content_pem = pki_certificate_authority.unset.certificate_pem
}

data "pki_certificate" "zero" {
  content_pem = pki_certificate_authority.zero.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.unset",
					tfjsonpath.New("basic_constraints").AtMapKey("path_len"), knownvalue.Null()),
				statecheck.ExpectKnownValue("data.pki_certificate.zero",
					tfjsonpath.New("basic_constraints").AtMapKey("path_len"), knownvalue.Int64Exact(0)),
			},
		}},
	})
}

// TestAccCertificateAuthorityExplicitSerial covers spec section 7: an explicit
// hex serial is honored and normalized.
func TestAccCertificateAuthorityExplicitSerial(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  serial_number   = "0x0002ABC"
  subject { common_name = "ca" }
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// Normalized per spec section 7: lowercased, 0x stripped,
				// leading zeros stripped.
				statecheck.ExpectKnownValue("pki_certificate_authority.ca", tfjsonpath.New("serial_number"),
					knownvalue.StringExact("2abc")),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateAuthoritySerialIsStableAcrossPlans is the guarantee that
// keeps a 20-year CA from being replaced. A random serial is drawn once and then
// held in state forever.
func TestAccCertificateAuthoritySerialIsStableAcrossPlans(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: testAccCAConfig},
			{
				// Same config, applied again. Nothing may change.
				Config: testAccCAConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

func TestAccCertificateAuthorityRejectsBadConfig(t *testing.T) {
	const keyConfig = `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
`
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"parent cert without parent key": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem        = pki_private_key.k.private_key_pem
  parent_certificate_pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
  validity               = "8760h"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)parent_private_key_pem`),
		},
		"parent key without parent cert": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem        = pki_private_key.k.private_key_pem
  parent_private_key_pem = pki_private_key.k.private_key_pem
  validity               = "8760h"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)parent_certificate_pem`),
		},
		"bad validity": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "forever"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)validity|duration`),
		},
		"bad serial": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  serial_number   = "not-hex"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)serial|hex`),
		},
		"no subject and no san": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
}`,
			expect: regexp.MustCompile(`(?s)subject|san`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps:                    []resource.TestStep{{Config: tc.config, ExpectError: tc.expect}},
			})
		})
	}
}
```

The test file imports `github.com/hashicorp/terraform-plugin-testing/compare` for `compare.ValuesSame()`.

- [ ] **Step 2: Run to verify failure**

```bash
make testacc TESTARGS='-run TestAccCertificateAuthority'
```

Expected: FAIL — `pki_certificate_authority` undefined.

- [ ] **Step 3: Implement the resource**

Schema per spec §6.3:

| Attribute | Kind | Notes |
| --- | --- | --- |
| `private_key_pem` | Required, Sensitive, String | the CA's own key; `RequiresReplace` |
| `parent_certificate_pem` | Optional, String | absent means self-signed root; `RequiresReplace` |
| `parent_private_key_pem` | Optional, Sensitive, String | required iff `parent_certificate_pem` is set; `RequiresReplace` |
| `subject`, `san` | Blocks | Task 4; no `RequiresReplace` — Task 10's `ModifyPlan` decides |
| `validity` | Required, String | duration |
| `early_renewal` | Optional, String | duration |
| `serial_number` | Optional + Computed, String | `UseStateForUnknown()` |
| `basic_constraints` | Block | defaults `ca = true`, `critical = true` |
| `key_usage` | Block | defaults `keyCertSign`, `crlSign`, critical |
| `extended_key_usage`, `name_constraints`, `extra_extension` | Blocks | |
| `signature_algorithm` | Optional + Computed, String | |
| `certificate_pem` | Computed, String | `UseStateForUnknown()` |
| `certificate_chain_pem` | Computed, String | null when self-signed; `UseStateForUnknown()` |
| `not_before`, `not_after` | Computed, String | RFC3339; `UseStateForUnknown()` |
| `ready_for_renewal` | Computed, Bool | recomputed every `Read`, so **no** `UseStateForUnknown` |
| `subject_key_id`, `authority_key_id` | Computed, String | hex; `UseStateForUnknown()` |
| `id` | Computed, String | SHA-256 of the DER |

`ready_for_renewal` is the one computed attribute that must not use `UseStateForUnknown`: its whole purpose is to flip as wall-clock time passes, so it is recalculated in `Read` from `not_after` and `early_renewal`.

`ConfigValidators`: `resourcevalidator.RequiredTogether(path.MatchRoot("parent_certificate_pem"), path.MatchRoot("parent_private_key_pem"))`, plus `resourcevalidator.AtLeastOneOf(path.MatchRoot("subject"), path.MatchRoot("san"))`.

The defaults for `basic_constraints` and `key_usage` cannot be expressed as schema defaults, because a whole block has no `Default`. Handle them in `Create`: when the block is absent, substitute `pki.BasicConstraints{CA: true, Critical: true}` and `pki.DefaultCAKeyUsage()`. Write the resolved values back into state so the block appears in state populated rather than null, and note in each block's description that omitting it produces those values.

`Create`:

1. Parse `private_key_pem`; error at that attribute path on failure.
2. If a parent is configured, parse `parent_certificate_pem` and `parent_private_key_pem` and verify the parent key matches the parent certificate — a crossed reference here produces a chain that verifies nowhere, and catching it at apply time with a clear message is much cheaper than debugging it later.
3. Resolve validity through `issuanceValidity`, which parses both durations, computes `notBefore = time.Now().UTC().Truncate(time.Second)` and `notAfter = notBefore.Add(validity)`, and returns `ready_for_renewal`. Truncating to a second matters: DER encodes `UTCTime` at second granularity, so an untruncated `notBefore` would not survive a parse-and-compare and Task 10's drift check would fire on every plan.
4. Resolve the serial through `resolveSerial`: use the configured value via `pki.ParseSerial` when set, otherwise reuse the state value when present, otherwise draw `pki.RandomSerial()`. Write the normalized form back with `pki.FormatSerial`.
5. Convert all blocks, build a `pki.CertTemplate`, call `pki.CreateCertificate` with `parent` nil for a root.
6. Set `certificate_pem`, and `certificate_chain_pem` as the parent certificate plus any chain the parent itself carries — leaf-adjacent first — or null when self-signed.
7. Parse the result back and set `not_before`, `not_after`, `subject_key_id`, `authority_key_id`, and `id` from the parsed certificate rather than from the template. Reading them back is a self-check that costs one parse and catches any divergence between what was requested and what was signed.

`Read` re-parses `certificate_pem` from state and recomputes only `ready_for_renewal`. Everything else stays as stored — the certificate cannot change underneath us, and re-deriving it would risk a spurious diff.

`Update` is reachable here (unlike Tasks 5 and 6) and reissues the certificate with the same logic as `Create`, except that the serial is taken from state unless the config changed it. Task 10 adds the `ModifyPlan` that decides *whether* an update happens at all.

`ImportState` resolves the ID, parses the certificate, and reconstructs: the subject in ordered form via `subjectFromPKI`, the SAN, the serial, the validity window, and every extension it can type (basicConstraints, keyUsage, extendedKeyUsage, nameConstraints) with anything left over becoming `extra_extension` blocks. `validity` is set to the certificate's actual lifetime formatted as hours (`fmt.Sprintf("%dh", int(notAfter.Sub(notBefore).Hours()))`), which is exactly why `pki.ParseDuration` must accept `"175320h"` unchanged. `private_key_pem` cannot be recovered and is left null; document in the resource description that the config must supply it and that the first plan after import will show it being set, which is expected and does not replace the certificate because Task 10's comparison excludes it.

- [ ] **Step 4: Write the examples**

`examples/resources/pki_certificate_authority/resource.tf`:

```hcl
# A self-signed root.
resource "pki_private_key" "root" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "pki_certificate_authority" "root" {
  private_key_pem = pki_private_key.root.private_key_pem

  # 20 years, the value cfssl's ca-config.json already used.
  validity      = "175320h"
  early_renewal = "8760h"

  subject {
    common_name  = "homelab-root"
    organization = "homelab"
  }

  # Omitting basic_constraints and key_usage produces ca = true with
  # keyCertSign and crlSign, both critical.
  name_constraints {
    permitted_dns_domains = [".ha.apps.somemissing.info"]
  }
}

# An intermediate under it. path_len = 0 means it may not issue further CAs;
# omitting path_len would leave the depth unconstrained.
resource "pki_private_key" "intermediate" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "intermediate" {
  private_key_pem        = pki_private_key.intermediate.private_key_pem
  parent_certificate_pem = pki_certificate_authority.root.certificate_pem
  parent_private_key_pem = pki_private_key.root.private_key_pem
  validity               = "87600h"

  subject {
    common_name  = "homelab-intermediate"
    organization = "homelab"
  }

  basic_constraints {
    ca       = true
    path_len = 0
  }
}
```

`examples/resources/pki_certificate_authority/import.sh`:

```shell
# Adopt an existing CA. The private key cannot be recovered from a certificate,
# so supply it in configuration; the first plan will show it being set, which
# does not reissue the certificate.
terraform import pki_certificate_authority.root 'file:///tmp/pki-ca/tls.crt'
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run TestAccCertificateAuthority'
make testacc TESTARGS='-run TestAccDataSourceCertificate'
```

Expected: PASS for the CA tests, and `TestAccDataSourceCertificate` now passes too. `TestAccDataSourceCertificateExtensionsAndSAN` still needs Task 9.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/resource_certificate_authority.go internal/provider/resource_certificate_authority_test.go internal/provider/provider.go examples/resources/pki_certificate_authority/
git commit -m "feat: pki_certificate_authority for roots and intermediates"
```

---

### Task 9: Resource `pki_certificate`

Issues a leaf signed by a CA. The CA is supplied as bare PEM, so the Bitwarden-delivered `pki-ca` Secret works with no CA resource in the graph.

**Files:**
- Create: `internal/provider/resource_certificate.go`
- Test: `internal/provider/resource_certificate_test.go`
- Test: `internal/provider/data_source_certificate_test.go` (add `TestAccDataSourceCertificateExtensionsAndSAN`, deferred from Task 7 — take its body verbatim from Task 7's Step 1; it asserts on the SAN's three types, `key_usage`, `extended_key_usage`, `basic_constraints`, and `is_ca` of a decoded leaf)
- Modify: `internal/provider/provider.go`
- Create: `examples/resources/pki_certificate/resource.tf`, `examples/resources/pki_certificate/import.sh`

**Interfaces:**
- Consumes: everything Task 8 consumes, plus `pki.ParseCertRequestPEM` (Plan 1 Task 9); `issuanceValidity` and `resolveSerial` from Task 8.
- Produces: `func NewCertificateResource() resource.Resource`.

- [ ] **Step 1: Write the failing tests**

`internal/provider/resource_certificate_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// testAccLeafFromCSR is the shape the homelab reconciler uses: a key, a CSR,
// and a certificate signed by a CA supplied as bare PEM.
const testAccLeafFromCSR = `
resource "pki_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_cert_request" "leaf" {
  private_key_pem = pki_private_key.leaf.private_key_pem

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-ipad.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Nick"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Venenga"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.leaf.cert_request_pem
  serial_number      = "2001"
  validity           = "175320h"

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}
`

func TestAccCertificateFromCSR(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + testAccLeafFromCSR + `
data "pki_certificate" "leaf" {
  content_pem = pki_certificate.leaf.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_certificate.leaf", tfjsonpath.New("serial_number"),
					knownvalue.StringExact("2001")),
				// The CSR's subject is used when no subject block overrides it,
				// including the ordered form with displayName in the middle.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("subject").AtSliceIndex(2).AtMapKey("oid"),
					knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				// And the CSR's SAN, including both rfc822Name entries -- the
				// capability hashicorp/tls lacks entirely.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("san").AtMapKey("email_addresses"),
					knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("nick@venenga.com"),
						knownvalue.StringExact("nijave@gmail.com"),
					})),
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("is_ca"), knownvalue.Bool(false)),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateInlineMode covers the public_key_pem path: no CSR, with the
// subject and SAN supplied directly.
func TestAccCertificateInlineMode(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + testAccKeyConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"

  subject {
    common_name  = "inline.example"
    organization = "homelab"
  }

  san {
    dns_names = ["inline.example"]
  }
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_certificate.leaf", tfjsonpath.New("certificate_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN CERTIFICATE-----`))),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateSubjectOverridesCSR pins the precedence rule from spec
// section 6.4: an explicitly-set subject replaces the CSR's wholesale, with no
// field-level merging.
func TestAccCertificateSubjectOverridesCSR(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_cert_request" "leaf" {
  private_key_pem = pki_private_key.leaf.private_key_pem
  subject {
    common_name  = "requested.example"
    organization = "requested-org"
  }
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.leaf.cert_request_pem
  validity           = "8760h"

  subject {
    common_name = "issued.example"
  }
}

data "pki_certificate" "leaf" {
  content_pem = pki_certificate.leaf.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("issued.example")),
				// Wholesale replacement: the CSR's organization is NOT merged in.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("subject"),
					knownvalue.ListSizeExact(1)),
			},
		}},
	})
}

// TestAccCertificateNeverCopiesCSRExtensions is the security property spec
// section 6.4 calls out. cfssl's copy_extensions = true let a requester dictate
// its own extensions, which is a well-known escalation hazard: a CSR asking for
// basicConstraints CA:TRUE must not get it.
func TestAccCertificateNeverCopiesCSRExtensions(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_cert_request" "escalating" {
  private_key_pem = pki_private_key.leaf.private_key_pem
  subject { common_name = "wants-to-be-a-ca.example" }

  # The CSR asks for CA:TRUE and keyCertSign. DER for
  # BasicConstraints{cA: TRUE} is 30 03 01 01 FF.
  extra_extension {
    oid          = provider::pki::oid("basicConstraints")
    value_base64 = "MAMBAf8="
    critical     = true
  }
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.escalating.cert_request_pem
  validity           = "8760h"

  key_usage {
    usages = ["digitalSignature"]
  }
}

data "pki_certificate" "leaf" {
  content_pem = pki_certificate.leaf.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// The issued certificate is not a CA, regardless of what the
				// CSR requested.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("is_ca"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("basic_constraints").AtMapKey("ca"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("key_usage").AtMapKey("usages"),
					knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("digitalSignature")})),
			},
		}},
	})
}

func TestAccCertificateRejectsBadConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"csr and public key together": {
			config: testAccCAConfig + testAccKeyConfig + `
resource "pki_cert_request" "r" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.r.cert_request_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"
}`,
			expect: regexp.MustCompile(`(?s)cannot be configured together|Invalid Attribute Combination`),
		},
		"neither csr nor public key": {
			config: testAccCAConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  validity           = "8760h"
  subject { common_name = "cn" }
}`,
			expect: regexp.MustCompile(`(?s)csr_pem|public_key_pem`),
		},
		"inline mode without subject or san": {
			config: testAccCAConfig + testAccKeyConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"
}`,
			expect: regexp.MustCompile(`(?s)subject|san`),
		},
		"ca key does not match ca cert": {
			config: testAccCAConfig + testAccKeyConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.test.private_key_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"
  subject { common_name = "cn" }
}`,
			expect: regexp.MustCompile(`(?s)does not match|ca_private_key_pem`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps:                    []resource.TestStep{{Config: tc.config, ExpectError: tc.expect}},
			})
		})
	}
}

// TestAccCertificateChainVerifies is spec section 10's first acceptance
// criterion, end to end through Terraform: root -> intermediate -> leaf
// verifies with x509.Certificate.Verify.
func TestAccCertificateChainVerifies(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "intermediate" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "intermediate" {
  private_key_pem        = pki_private_key.intermediate.private_key_pem
  parent_certificate_pem = pki_certificate_authority.root.certificate_pem
  parent_private_key_pem = pki_private_key.ca.private_key_pem
  validity               = "87600h"
  subject { common_name = "homelab-intermediate" }
  key_usage { usages = ["keyCertSign", "crlSign"] }
}

resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.intermediate.certificate_pem
  ca_private_key_pem = pki_private_key.intermediate.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  validity           = "8760h"
  subject { common_name = "device.ha.apps.somemissing.info" }
  san { dns_names = ["device.ha.apps.somemissing.info"] }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
  extended_key_usage { usages = ["clientAuth"] }
}

output "root_pem" { value = pki_certificate_authority.root.certificate_pem }
output "intermediate_pem" { value = pki_certificate_authority.intermediate.certificate_pem }
output "leaf_pem" { value = pki_certificate.leaf.certificate_pem }
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				func(s *terraform.State) error {
					rootPEM := s.RootModule().Outputs["root_pem"].Value.(string)
					interPEM := s.RootModule().Outputs["intermediate_pem"].Value.(string)
					leafPEM := s.RootModule().Outputs["leaf_pem"].Value.(string)

					parse := func(p string) (*x509.Certificate, error) {
						block, _ := pem.Decode([]byte(p))
						if block == nil {
							return nil, fmt.Errorf("not PEM")
						}
						return x509.ParseCertificate(block.Bytes)
					}
					root, err := parse(rootPEM)
					if err != nil {
						return fmt.Errorf("parsing the root: %w", err)
					}
					inter, err := parse(interPEM)
					if err != nil {
						return fmt.Errorf("parsing the intermediate: %w", err)
					}
					leaf, err := parse(leafPEM)
					if err != nil {
						return fmt.Errorf("parsing the leaf: %w", err)
					}

					roots := x509.NewCertPool()
					roots.AddCert(root)
					intermediates := x509.NewCertPool()
					intermediates.AddCert(inter)
					if _, err := leaf.Verify(x509.VerifyOptions{
						Roots:         roots,
						Intermediates: intermediates,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					}); err != nil {
						return fmt.Errorf("chain verification failed: %w", err)
					}
					return nil
				},
			),
		}},
	})
}
```

- [ ] **Step 2: Run to verify failure**

```bash
make testacc TESTARGS='-run TestAccCertificate'
```

Expected: FAIL — `pki_certificate` resource undefined.

- [ ] **Step 3: Implement the resource**

Schema per spec §6.4:

| Attribute | Kind | Notes |
| --- | --- | --- |
| `ca_certificate_pem` | Required, String | |
| `ca_private_key_pem` | Required, Sensitive, String | never drift-compared |
| `csr_pem` | Optional, String | conflicts with `public_key_pem` |
| `public_key_pem` | Optional, String | inline mode |
| `subject`, `san` | Blocks | override the CSR's values wholesale when set |
| `validity` | Required, String | |
| `early_renewal` | Optional, String | |
| `serial_number` | Optional + Computed, String | `UseStateForUnknown()` |
| `basic_constraints` | Block | defaults `ca = false`, `critical = true` |
| `key_usage`, `extended_key_usage`, `extra_extension` | Blocks | |
| `signature_algorithm` | Optional + Computed, String | |
| `certificate_pem` | Computed, String | `UseStateForUnknown()` |
| `not_before`, `not_after` | Computed, String | `UseStateForUnknown()` |
| `ready_for_renewal` | Computed, Bool | recomputed each `Read`, no `UseStateForUnknown` |
| `subject_key_id`, `authority_key_id` | Computed, String | |
| `id` | Computed, String | SHA-256 of the DER |

`ConfigValidators`: `resourcevalidator.ExactlyOneOf(path.MatchRoot("csr_pem"), path.MatchRoot("public_key_pem"))`.

`Create`:

1. Parse `ca_certificate_pem` and `ca_private_key_pem`, and verify the key matches the certificate — that is the check `TestAccCertificateRejectsBadConfig`'s last case exercises, and it catches a crossed HCL reference that would otherwise produce a certificate no client trusts.
2. Determine the public key and the default subject/SAN. With `csr_pem`: parse it with `pki.ParseCertRequestPEM` (which verifies the signature and refuses a tampered CSR — the right default when issuing), take its public key, and derive the default subject from `pki.ParseSubjectDER(csr.RawSubject)` and the default SAN from its SAN extension. With `public_key_pem`: parse the key and require a `subject` or `san` block.
3. Apply precedence: an explicitly-set `subject` block replaces the CSR's subject wholesale, and likewise for `san`. No field-level merging. Implement that as a plain "if the block is set, use it; otherwise use the CSR's" — a merge would be both surprising and untestable.
4. **Never** read extensions from the CSR. Build them only from the resource's own blocks. Put the reason in a comment naming `cfssl/ca-config.json`'s `copy_extensions: true` and the escalation hazard, because to a future reader "we already have the CSR's extensions parsed, why not use them" looks like an easy improvement.
5. Default `basic_constraints` to `{CA: false, Critical: true}` when the block is absent. Note that unlike the CA resource, `key_usage` has **no** default: a leaf's usages depend on what the certificate is for, and silently issuing `digitalSignature, keyEncipherment` because that is what the homelab happens to need would be wrong for a server certificate. Document that omitting `key_usage` produces a certificate with no keyUsage extension, which is legal and occasionally intended.
6. Resolve validity and serial with `issuanceValidity` and `resolveSerial` from Task 8, then call `pki.CreateCertificate` with the CA as parent, and read the result back to populate the computed attributes.

`Read` recomputes only `ready_for_renewal`, as in Task 8.

`Update` reissues; Task 10 decides when.

`ImportState` mirrors Task 8's, with two differences: `ca_certificate_pem` and `ca_private_key_pem` cannot be recovered from a leaf and are left null, and the imported subject/SAN are written into the `subject`/`san` blocks in ordered form rather than being left to a CSR. Document that the config must supply the CA attributes and that doing so does not reissue, because Task 10's comparison excludes `ca_private_key_pem` entirely and matches `ca_certificate_pem` against the certificate's issuer rather than treating it as an input diff.

- [ ] **Step 4: Write the examples**

`examples/resources/pki_certificate/resource.tf`:

```hcl
# The CA arrives from Bitwarden via ExternalSecret, so it is bare PEM with no CA
# resource in the graph.
data "kubernetes_secret" "ca" {
  metadata {
    name      = "pki-ca"
    namespace = "homelab-pki"
  }
}

resource "pki_private_key" "device" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_cert_request" "device" {
  private_key_pem = pki_private_key.device.private_key_pem

  subject {
    common_name          = "nick-ipad.ha.apps.somemissing.info"
    uid                  = "nick"
    given_name           = "Nick"
    surname              = "Venenga"
    organization         = "homelab"

    extra_attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }
}

resource "pki_certificate" "device" {
  ca_certificate_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.crt"])
  ca_private_key_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.key"])
  csr_pem            = pki_cert_request.device.cert_request_pem

  # An explicit serial keeps the Kubernetes Secret name stable.
  serial_number = "2001"

  # 20 years, matching the existing certificates.
  validity = "175320h"

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}
```

`examples/resources/pki_certificate/import.sh`:

```shell
# Adopt a device certificate extracted from the cluster. The CA certificate and
# key cannot be recovered from a leaf, so supply them in configuration; doing so
# does not reissue the certificate.
kubectl -n homelab-pki get secret pki-nick-ipad-2001 -o jsonpath='{.data.tls\.crt}' \
  | base64 -d > /tmp/nick-ipad.crt

terraform import 'pki_certificate.device["nick-ipad"]' 'file:///tmp/nick-ipad.crt'
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run "TestAccCertificate|TestAccDataSourceCertificate"'
```

Expected: PASS, including `TestAccDataSourceCertificateExtensionsAndSAN`, which this task adds to `data_source_certificate_test.go` (deferred there from Task 7, which had no `pki_certificate` to exercise).

- [ ] **Step 6: Commit**

```bash
git add internal/provider/resource_certificate.go internal/provider/resource_certificate_test.go internal/provider/provider.go examples/resources/pki_certificate/
git commit -m "feat: pki_certificate leaf issuance with CA supplied as bare PEM"
```

---

### Task 10: Drift detection and import fidelity (`certdrift.go`)

Spec §9, wired into both certificate resources. Until this task, both resources reissue on any input change — the `hashicorp/tls` behavior this design exists to improve on. After it, they reissue only on genuine content drift.

**Files:**
- Create: `internal/provider/certdrift.go`
- Test: `internal/provider/resource_certificate_drift_test.go`
- Modify: `internal/provider/resource_certificate.go`, `internal/provider/resource_certificate_authority.go` (implement `ResourceWithModifyPlan`)

**Interfaces:**
- Consumes: `pki.CompareCertificate`, `pki.CompareInput`, `pki.Drift`, `pki.CompareValidity` (Plan 1 Task 14).
- Produces:
  - `type certModel interface { ... }` — the small surface `modifyCertificatePlan` needs from either resource's model
  - `func modifyCertificatePlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse, build func() (pki.CertTemplate, crypto.PublicKey, *x509.Certificate, diag.Diagnostics))`

- [ ] **Step 1: Write the failing tests**

`internal/provider/resource_certificate_drift_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// TestAccCertificateRotatingCAKeyDoesNotReplace is spec section 10's
// acceptance criterion and the single most valuable test in this plan.
//
// The homelab CA key is delivered from a Bitwarden ExternalSecret. If a
// re-read of that Secret -- with identical key material presented as a
// different string, or simply re-read at a different time -- caused a
// replacement, every 20-year certificate under it would be reissued and every
// phone and tablet would need a manual re-enrollment.
func TestAccCertificateRotatingCAKeyDoesNotReplace(t *testing.T) {
	// The two configs differ only in how ca_private_key_pem is expressed:
	// once directly, once through a round trip that produces the identical
	// bytes by a different expression. Terraform sees a changed configuration
	// expression; the provider must see no content drift.
	const direct = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "175320h"
  subject { common_name = "stable.example" }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
}
`
	const indirect = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

locals {
  ca_key = join("", [pki_private_key.ca.private_key_pem])
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = local.ca_key
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "175320h"
  subject { common_name = "stable.example" }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
}
`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: direct},
			{
				Config: indirect,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateValidityStringRewriteDoesNotReplace covers the same
// principle for a duration: "175320h" and "20y" plus five days are different
// strings, but 175320h expressed as 7305d is the same window. Rewriting the
// expression must not reissue.
func TestAccCertificateValidityStringRewriteDoesNotReplace(t *testing.T) {
	base := func(validity string) string {
		return testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "` + validity + `"
  subject { common_name = "stable.example" }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("175320h")},
			{
				Config: base("7305d"), // 7305 * 24 == 175320
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateSubjectFormRewriteDoesNotReplace is spec section 5.1's
// requirement at the plan level: switching between the named-field form and the
// equivalent ordered form must plan clean, because both encode to the same DN.
func TestAccCertificateSubjectFormRewriteDoesNotReplace(t *testing.T) {
	const named = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "8760h"
  subject {
    common_name  = "cn.example"
    uid          = "nick"
    organization = "homelab"
  }
}
`
	const ordered = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "8760h"
  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "cn.example"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }
}
`
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: named},
			{
				Config: ordered,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateGenuineDriftReissues is the other half: real content
// changes must produce a real update, and the certificate must actually change.
func TestAccCertificateGenuineDriftReissues(t *testing.T) {
	base := func(cn string) string {
		return testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "8760h"
  subject { common_name = "` + cn + `" }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("before.example")},
			{
				Config: base("after.example"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

func TestAccCertificateAuthorityRotatingParentKeyDoesNotReplace(t *testing.T) {
	// The same guarantee for an intermediate: re-reading the parent's key must
	// not reissue the intermediate.
	base := func(indirect bool) string {
		parentKey := "pki_private_key.ca.private_key_pem"
		locals := ""
		if indirect {
			locals = "\nlocals { parent_key = join(\"\", [pki_private_key.ca.private_key_pem]) }\n"
			parentKey = "local.parent_key"
		}
		return testAccCAConfig + locals + `
resource "pki_private_key" "intermediate" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate_authority" "intermediate" {
  private_key_pem        = pki_private_key.intermediate.private_key_pem
  parent_certificate_pem = pki_certificate_authority.root.certificate_pem
  parent_private_key_pem = ` + parentKey + `
  serial_number          = "3001"
  validity               = "87600h"
  subject { common_name = "homelab-intermediate" }
  key_usage { usages = ["keyCertSign", "crlSign"] }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base(false)},
			{
				Config: base(true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate_authority.intermediate", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateReadyForRenewal covers spec section 5.4: ready_for_renewal
// flips true once inside the early-renewal window, and the next plan proposes
// replacement.
func TestAccCertificateReadyForRenewal(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// early_renewal longer than validity puts the resource inside
				// the window immediately, which is the only way to test this
				// without waiting.
				Config: testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  validity           = "1h"
  early_renewal      = "2h"
  subject { common_name = "renewing.example" }
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_certificate.leaf",
						tfjsonpath.New("ready_for_renewal"), knownvalue.Bool(true)),
				},
				ConfigPlanChecks: resource.ConfigPlanChecks{
					// Inside the window, the next plan is not empty: it
					// proposes reissuance, matching hashicorp/tls behavior.
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectNonEmptyPlan()},
				},
			},
		},
	})
	_ = compare.ValuesSame
}
```

Drop the trailing `_ =` line and unused imports when writing the file.

- [ ] **Step 2: Run to verify failure**

```bash
make testacc TESTARGS='-run "RotatingCAKey|ValidityStringRewrite|SubjectFormRewrite|ReadyForRenewal|RotatingParentKey"'
```

Expected: FAIL — without `ModifyPlan`, changing a config expression produces an update, so the `ResourceActionNoop` checks fail.

- [ ] **Step 3: Implement `certdrift.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider

// modifyCertificatePlan decides whether a certificate must be reissued.
//
// Terraform's default is to plan an update whenever any configured value
// differs from state. For certificates that default is wrong in an expensive
// direction: the CA key arrives from a rotating Bitwarden Secret, durations can
// be rewritten ("175320h" and "7305d" are the same window), and a subject can be
// spelled in two forms that encode to identical DER. Under the default, each of
// those reissues every certificate -- and with 20-year certificates installed on
// phones and tablets, a reissue means a manual re-enrollment per device.
//
// So the plan is suppressed unless the desired certificate genuinely differs in
// content from the one in state, as pki.CompareCertificate defines content.
// Inputs that cannot be derived from a certificate -- ca_private_key_pem,
// private_key_pem, csr_pem -- are excluded from the comparison entirely.
//
// The one thing that overrides all of this is the early-renewal window: once
// inside it, the plan is left in place so the certificate is reissued.
func modifyCertificatePlan(...)
```

The mechanics, in order:

1. Return immediately when `req.State.Raw.IsNull()` (a create — nothing to compare against) or `req.Plan.Raw.IsNull()` (a destroy). Both guards are required; a destroy plan has a null `Plan.Raw` and dereferencing it panics.
2. Read the certificate PEM from **state**, not plan, and parse it. If state has no certificate, fall through and let the plan stand.
3. Call the `build` callback to assemble the desired `pki.CertTemplate` from the **plan**, along with the desired public key and the CA certificate. The callback is what differs between the two resources, which is why it is a parameter rather than a type switch. Two details it must handle: the desired `NotBefore` comes from **state**, not from `time.Now()`, since otherwise every plan would drift on the validity window; and `NotAfter` is `stateNotBefore.Add(validity)`, which is what makes a rewritten-but-equivalent duration compare equal.
4. Call `pki.CompareCertificate`. On no drift, copy every computed attribute from state into the plan so the plan is a genuine no-op, and return.
5. On drift, leave the plan in place and add a warning-level diagnostic listing the drift entries, so the plan output says *why* a certificate is being reissued. `pki.Drift.String()` exists for exactly this. A silent reissue of a device certificate is the kind of thing that should never be a surprise in a plan.
6. Independently of the comparison, recompute `ready_for_renewal` with `pki.CompareValidity`. When it is true, leave the plan in place regardless of the comparison result and note in the diagnostic that the early-renewal window is the reason.

Wire it into both resources by implementing `ModifyPlan` and passing a resource-specific `build` closure. Add the interface assertions (`var _ resource.ResourceWithModifyPlan = (*CertificateResource)(nil)`) so a signature drift is a compile error.

One consequence to state in both resources' descriptions, because it is surprising in a good way: changing `validity` on a certificate that is not near expiry does **not** reissue it if the resulting window is unchanged, and changing `ca_private_key_pem` never reissues it at all.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run "TestAccCertificate|TestAccCertificateAuthority"'
```

Expected: PASS for the whole certificate surface, including the five drift tests and the earlier per-resource tests, which must not have regressed — `ModifyPlan` copying computed values from state is the step most likely to break an existing `ExpectEmptyPlan`, so run the full set rather than only the new tests.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/certdrift.go internal/provider/resource_certificate_drift_test.go internal/provider/resource_certificate.go internal/provider/resource_certificate_authority.go
git commit -m "feat: reissue certificates only on genuine content drift"
```

---

### Task 11: Resource `pki_crl`

Replaces `cfssl gencrl` piped through `openssl crl -inform DER`, and replaces the freshness role of the 6-hourly `pki-crl-refresh` CronJob: a periodic apply still drives regeneration, but the staleness logic now lives in the provider.

**Files:**
- Create: `internal/provider/resource_crl.go`
- Test: `internal/provider/resource_crl_test.go`
- Modify: `internal/provider/provider.go`
- Create: `examples/resources/pki_crl/resource.tf`

**Interfaces:**
- Consumes: `pki.CreateCRL`, `pki.CRLTemplate`, `pki.RevokedCert`, `pki.ParseCRLPEM`, `pki.CheckCRLSigner`, `pki.ReasonNames`, `pki.ParseSerial`, `pki.NormalizeSerial`, `pki.ParseDuration` (Plan 1 Task 10).
- Produces: `func NewCRLResource() resource.Resource`.

- [ ] **Step 1: Write the failing tests**

`internal/provider/resource_crl_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const testAccCRLConfig = testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
  early_regenerate   = "24h"

  revoked {
    serial_number = "2001"
    reason        = "keyCompromise"
    revoked_at    = "2026-06-01T00:00:00Z"
  }

  revoked {
    serial_number = "0x2002"
  }
}

output "crl_pem" { value = pki_crl.test.crl_pem }
output "ca_pem"  { value = pki_certificate_authority.root.certificate_pem }
`

// TestAccCRLSignatureVerifiesAndSerialIsPresent is spec section 10's CRL
// acceptance criterion.
func TestAccCRLSignatureVerifiesAndSerialIsPresent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCRLConfig,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("crl_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN X509 CRL-----`))),
				statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"),
					knownvalue.Int64Exact(1)),
				statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("ready_for_regeneration"),
					knownvalue.Bool(false)),
				// The 0x prefix is normalized away, per spec section 7.
				statecheck.ExpectKnownValue("pki_crl.test",
					tfjsonpath.New("revoked").AtSliceIndex(1).AtMapKey("serial_number"),
					knownvalue.StringExact("2002")),
				// revoked_at defaults to the time the entry first appeared and
				// is then held stable, so the CRL does not churn its timestamps.
				statecheck.ExpectKnownValue("pki_crl.test",
					tfjsonpath.New("revoked").AtSliceIndex(1).AtMapKey("revoked_at"),
					knownvalue.NotNull()),
			},
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				crlPEM := s.RootModule().Outputs["crl_pem"].Value.(string)
				caPEM := s.RootModule().Outputs["ca_pem"].Value.(string)

				crlBlock, _ := pem.Decode([]byte(crlPEM))
				if crlBlock == nil {
					return fmt.Errorf("crl_pem is not PEM")
				}
				crl, err := x509.ParseRevocationList(crlBlock.Bytes)
				if err != nil {
					return fmt.Errorf("parsing the CRL: %w", err)
				}
				caBlock, _ := pem.Decode([]byte(caPEM))
				ca, err := x509.ParseCertificate(caBlock.Bytes)
				if err != nil {
					return fmt.Errorf("parsing the CA: %w", err)
				}
				if err := crl.CheckSignatureFrom(ca); err != nil {
					return fmt.Errorf("the CRL signature does not verify against the CA: %w", err)
				}
				if len(crl.RevokedCertificateEntries) != 2 {
					return fmt.Errorf("the CRL has %d entries, want 2", len(crl.RevokedCertificateEntries))
				}
				want := big.NewInt(0x2001)
				if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(want) != 0 {
					return fmt.Errorf("entry 0 serial = %s, want %s", crl.RevokedCertificateEntries[0].SerialNumber, want)
				}
				if crl.RevokedCertificateEntries[0].ReasonCode != 1 {
					return fmt.Errorf("entry 0 reason = %d, want 1 (keyCompromise)", crl.RevokedCertificateEntries[0].ReasonCode)
				}
				return nil
			}),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccCRLEmptyIsValid(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// config.hcl ships revoked_serials = [] and the cluster still needs
			// a fresh, valid CRL for Envoy to load.
			Config: testAccCAConfig + `
resource "pki_crl" "empty" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_crl.empty", tfjsonpath.New("crl_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN X509 CRL-----`))),
				statecheck.ExpectKnownValue("pki_crl.empty", tfjsonpath.New("crl_base64"),
					knownvalue.NotNull()),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCRLNumberIncrementsOnRegeneration covers the RFC 5280 requirement that
// each CRL carry a higher cRLNumber than the last.
func TestAccCRLNumberIncrementsOnRegeneration(t *testing.T) {
	base := func(extra string) string {
		return testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
` + extra + `
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: base(``),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"), knownvalue.Int64Exact(1)),
				},
			},
			{
				Config: base(`  revoked { serial_number = "2001" }`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"), knownvalue.Int64Exact(2)),
				},
			},
			{
				Config: base(`  revoked { serial_number = "2001" }
  revoked { serial_number = "2002" }`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"), knownvalue.Int64Exact(3)),
				},
			},
		},
	})
}

// TestAccCRLRevokedAtIsStable is the anti-churn property from spec section 6.5:
// an unchanged CRL must not rewrite its revocation timestamps on every
// regeneration, or the Kubernetes Secret changes on every apply.
func TestAccCRLRevokedAtIsStable(t *testing.T) {
	config := testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
  revoked { serial_number = "2001" }
}
`
	withSecond := testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
  revoked { serial_number = "2001" }
  revoked { serial_number = "2002" }
}
`
	var firstRevokedAt string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources["pki_crl.test"]
					if !ok {
						return fmt.Errorf("pki_crl.test not in state")
					}
					firstRevokedAt = rs.Primary.Attributes["revoked.0.revoked_at"]
					if firstRevokedAt == "" {
						return fmt.Errorf("revoked.0.revoked_at is empty")
					}
					return nil
				},
			},
			{
				// Adding a second entry regenerates the CRL. The first entry's
				// timestamp must be unchanged.
				Config: withSecond,
				Check: func(s *terraform.State) error {
					rs := s.RootModule().Resources["pki_crl.test"]
					if got := rs.Primary.Attributes["revoked.0.revoked_at"]; got != firstRevokedAt {
						return fmt.Errorf("revoked.0.revoked_at changed from %q to %q on regeneration", firstRevokedAt, got)
					}
					if rs.Primary.Attributes["revoked.1.revoked_at"] == "" {
						return fmt.Errorf("the new entry has no revoked_at")
					}
					return nil
				},
			},
		},
	})
}

// TestAccCRLReadyForRegeneration covers the staleness logic that replaces the
// pki-crl-refresh CronJob's role.
func TestAccCRLReadyForRegeneration(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "1h"
  early_regenerate   = "2h"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_crl.test",
					tfjsonpath.New("ready_for_regeneration"), knownvalue.Bool(true)),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectNonEmptyPlan()},
			},
		}},
	})
}

// TestAccCRLRejectsACAWithoutCRLSign is the migration hazard made visible.
// cfssl signed CRLs with any CA key; Go requires crlSign and a
// subjectKeyIdentifier on the issuer. The externally-owned Bitwarden CA cannot
// be inspected ahead of an apply, so the message must be actionable.
func TestAccCRLRejectsACAWithoutCRLSign(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "no_crlsign" {
  private_key_pem = pki_private_key.ca.private_key_pem
  validity        = "8760h"
  subject { common_name = "no-crlsign" }
  key_usage { usages = ["keyCertSign"] }
}

resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.no_crlsign.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
}
`,
			ExpectError: regexp.MustCompile(`(?s)crlSign`),
		}},
	})
}

func TestAccCRLRejectsBadConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		body   string
		expect *regexp.Regexp
	}{
		"unknown reason": {
			body:   `next_update = "168h"` + "\n" + `  revoked { serial_number = "2001"` + "\n" + `    reason = "becauseISaidSo" }`,
			expect: regexp.MustCompile(`(?s)reason|Invalid Attribute Value`),
		},
		"bad serial": {
			body:   `next_update = "168h"` + "\n" + `  revoked { serial_number = "not-hex" }`,
			expect: regexp.MustCompile(`(?s)serial|hex`),
		},
		"bad next_update": {
			body:   `next_update = "soon"`,
			expect: regexp.MustCompile(`(?s)next_update|duration`),
		},
		"bad revoked_at": {
			body:   `next_update = "168h"` + "\n" + `  revoked { serial_number = "2001"` + "\n" + `    revoked_at = "yesterday" }`,
			expect: regexp.MustCompile(`(?s)revoked_at|RFC3339`),
		},
		"duplicate serial": {
			body:   `next_update = "168h"` + "\n" + `  revoked { serial_number = "2001" }` + "\n" + `  revoked { serial_number = "0x2001" }`,
			expect: regexp.MustCompile(`(?s)duplicate|2001`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config: testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  ` + tc.body + `
}
`,
					ExpectError: tc.expect,
				}},
			})
		})
	}
	_ = base64.StdEncoding
}
```

Drop the trailing `_ =` line and unused imports when writing the file.

- [ ] **Step 2: Run to verify failure**

```bash
make testacc TESTARGS='-run TestAccCRL'
```

Expected: FAIL — `pki_crl` undefined.

- [ ] **Step 3: Implement the resource**

Schema per spec §6.5:

| Attribute | Kind | Notes |
| --- | --- | --- |
| `ca_certificate_pem` | Required, String | |
| `ca_private_key_pem` | Required, Sensitive, String | |
| `next_update` | Required, String | duration, e.g. `"168h"` |
| `early_regenerate` | Optional, String | duration before `next_update` |
| `revoked` | Block, repeatable | `serial_number` required; `reason` and `revoked_at` optional |
| `number` | Computed, Int64 | monotonically incremented; **no** `UseStateForUnknown` |
| `signature_algorithm` | Optional + Computed, String | |
| `crl_pem` | Computed, String | |
| `crl_base64` | Computed, String | feeds `kubernetes_secret.binary_data` |
| `this_update`, `next_update_time` | Computed, String | RFC3339 |
| `ready_for_regeneration` | Computed, Bool | recomputed each `Read` |
| `id` | Computed, String | SHA-256 of the DER |

`revoked.reason` is validated with `stringvalidator.OneOf(pki.ReasonNames()...)`, which is why `ReasonNames` returns them in RFC order — generated docs then list them the way the RFC does.

`revoked.revoked_at` is `Optional + Computed` with `UseStateForUnknown()` **on the nested attribute**. That is the mechanism behind `TestAccCRLRevokedAtIsStable`: an omitted `revoked_at` is filled in on first apply and then preserved from state, so regenerating the CRL for an unrelated reason does not rewrite existing timestamps. Since `revoked` is a `ListNestedBlock`, the state-preservation is positional; document that reordering `revoked` blocks will shuffle the defaulted timestamps, and that supplying `revoked_at` explicitly is the way to pin them if that matters.

`number` starts at 1 and increments on every regeneration. Read it from state in `Update` and add one. Do not use `UseStateForUnknown` on it — it must change.

`Create`/`Update` both:

1. Parse the CA certificate and key, verify they match, and call `pki.CheckCRLSigner` **before** attempting to sign, so the diagnostic is the specific one about `crlSign` or `subjectKeyIdentifier` rather than a generic failure from inside Go. Attach it to `path.Root("ca_certificate_pem")`.
2. Parse `next_update` and `early_regenerate`.
3. Build `[]pki.RevokedCert`, parsing each serial with `pki.ParseSerial` and rejecting duplicates after normalization — which is what makes `"2001"` and `"0x2001"` collide as the test expects.
4. Set `thisUpdate = time.Now().UTC().Truncate(time.Second)` and `nextUpdateTime = thisUpdate.Add(nextUpdate)`.
5. Call `pki.CreateCRL`, then set `crl_pem`, `crl_base64` (`base64.StdEncoding` over the PEM bytes, not the DER — the attribute exists to feed a Kubernetes Secret whose consumers expect a PEM file), `this_update`, `next_update_time`, `number`, `ready_for_regeneration`, and `id`.

State clearly in the `crl_base64` description that it is base64 of the **PEM**, since base64-of-DER would be a reasonable alternative reading and getting it wrong silently produces a file Envoy cannot load.

`Read` recomputes `ready_for_regeneration` from `next_update_time` and `early_regenerate`. Everything else stays.

No `ModifyPlan`: unlike a certificate, regenerating a CRL is cheap and touches no devices, so the default "any input change means regenerate" is correct here. Say so in a comment, since the asymmetry with the certificate resources is otherwise conspicuous.

Not importable: a CRL is regenerated freely, so adopting one has no value.

- [ ] **Step 4: Write the example**

`examples/resources/pki_crl/resource.tf`:

```hcl
resource "pki_crl" "homelab" {
  ca_certificate_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.crt"])
  ca_private_key_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.key"])

  # The CRL claims freshness for a week, and reports itself ready for
  # regeneration a day before that expires. A periodic `tofu apply` is what
  # actually regenerates it -- this replaces the 6-hourly refresh CronJob's
  # staleness logic, not its scheduling.
  next_update      = "168h"
  early_regenerate = "24h"

  revoked {
    serial_number = "2001"
    reason        = "keyCompromise"
  }
}

# content_base64 feeds binary_data directly, with no base64decode round trip.
resource "kubernetes_secret" "crl" {
  metadata {
    name      = "pki-crl"
    namespace = "homelab-pki"
  }
  binary_data = { "crl.pem" = pki_crl.homelab.crl_base64 }
  type        = "Opaque"
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run TestAccCRL'
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/resource_crl.go internal/provider/resource_crl_test.go internal/provider/provider.go examples/resources/pki_crl/
git commit -m "feat: pki_crl resource replacing the cfssl gencrl pipeline"
```

---

### Task 12: Resource `pki_bundle`

The format converter and composer, including the write-only password. This is the resource that closes the `binary_data` workaround at `tofu/main.tf:23-35` and removes the last need for `openssl` in the reconciler image.

**Files:**
- Create: `internal/provider/resource_bundle.go`
- Test: `internal/provider/resource_bundle_test.go`
- Modify: `internal/provider/provider.go`
- Create: `examples/resources/pki_bundle/resource.tf`
- Create: `templates/resources/bundle.md.tmpl`

**Interfaces:**
- Consumes: `pki.EncodeBundle`, `pki.BundleInput`, `pki.Formats`, `pki.PKCS12Encodings`, `pki.Format.IsText`, `pki.ParseCertificatePEM`, `pki.ParseCertificateChainPEM`, `pki.ParsePrivateKeyPEM` (Plan 1 Tasks 11–13).
- Produces: `func NewBundleResource() resource.Resource`.

- [ ] **Step 1: Write the failing tests**

`internal/provider/resource_bundle_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// testAccBundleBase issues a leaf under a root, which every bundle test needs.
const testAccBundleBase = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "175320h"
  subject { common_name = "nick-ipad.ha.apps.somemissing.info" }
  san { dns_names = ["nick-ipad.ha.apps.somemissing.info"] }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
  extended_key_usage { usages = ["clientAuth"] }
}
`

func TestAccBundlePEM(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "full" {
  format          = "pem"
  certificate_pem = pki_certificate.leaf.certificate_pem
  private_key_pem = pki_private_key.leaf.private_key_pem
  chain_pem       = [pki_certificate_authority.root.certificate_pem]
}

# Spec section 6.6: the optional fields are the switches. No private_key_pem
# yields a cert-only bundle; no chain_pem yields no chain.
resource "pki_bundle" "cert_only" {
  format          = "pem"
  certificate_pem = pki_certificate.leaf.certificate_pem
}

output "full_content"      { value = pki_bundle.full.content }
output "cert_only_content" { value = pki_bundle.cert_only.content }
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// content is set for text formats.
				statecheck.ExpectKnownValue("pki_bundle.full", tfjsonpath.New("content"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue("pki_bundle.full", tfjsonpath.New("content_base64"), knownvalue.NotNull()),
				// A bundle carrying a private key must be sensitive in both
				// representations, or it lands in plan output and CI logs.
				statecheck.ExpectSensitiveValue("pki_bundle.full", tfjsonpath.New("content")),
				statecheck.ExpectSensitiveValue("pki_bundle.full", tfjsonpath.New("content_base64")),
			},
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				full := s.RootModule().Outputs["full_content"].Value.(string)
				certOnly := s.RootModule().Outputs["cert_only_content"].Value.(string)

				if n := strings.Count(full, "BEGIN CERTIFICATE"); n != 2 {
					return fmt.Errorf("the full bundle has %d certificates, want 2", n)
				}
				if !strings.Contains(full, "BEGIN RSA PRIVATE KEY") {
					return fmt.Errorf("the full bundle has no private key")
				}
				// Order: certificate, chain, then the key last.
				if strings.Index(full, "BEGIN RSA PRIVATE KEY") < strings.LastIndex(full, "BEGIN CERTIFICATE") {
					return fmt.Errorf("the private key appears before the last certificate; order must be certificate, chain, key")
				}
				if strings.Contains(certOnly, "PRIVATE KEY") {
					return fmt.Errorf("the cert-only bundle contains a private key")
				}
				if n := strings.Count(certOnly, "BEGIN CERTIFICATE"); n != 1 {
					return fmt.Errorf("the cert-only bundle has %d certificates, want 1", n)
				}
				return nil
			}),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccBundleBinaryFormatsHaveNullContent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "der" {
  format          = "der"
  certificate_pem = pki_certificate.leaf.certificate_pem
}

resource "pki_bundle" "pkcs7" {
  format          = "pkcs7"
  certificate_pem = pki_certificate.leaf.certificate_pem
  chain_pem       = [pki_certificate_authority.root.certificate_pem]
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// Spec section 6.6: content is null for binary formats,
				// content_base64 is always set.
				statecheck.ExpectKnownValue("pki_bundle.der", tfjsonpath.New("content"), knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_bundle.der", tfjsonpath.New("content_base64"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue("pki_bundle.pkcs7", tfjsonpath.New("content"), knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_bundle.pkcs7", tfjsonpath.New("content_base64"), knownvalue.NotNull()),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccBundlePKCS12WriteOnlyPassword is the write-only attribute in action:
// password_wo is always null in state, which is why password_wo_version exists.
func TestAccBundlePKCS12WriteOnlyPassword(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "p12" {
  format              = "pkcs12"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  chain_pem           = [pki_certificate_authority.root.certificate_pem]
  friendly_name       = "nick-ipad"
  password_wo         = "password"
  password_wo_version = 1
}

output "p12_base64" { value = pki_bundle.p12.content_base64 }
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// A write-only attribute is never persisted.
				statecheck.ExpectKnownValue("pki_bundle.p12", tfjsonpath.New("password_wo"), knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_bundle.p12", tfjsonpath.New("content"), knownvalue.Null()),
				statecheck.ExpectSensitiveValue("pki_bundle.p12", tfjsonpath.New("content_base64")),
				// modern is the default (spec section 6.6).
				statecheck.ExpectKnownValue("pki_bundle.p12", tfjsonpath.New("pkcs12_encoding"),
					knownvalue.StringExact("modern")),
			},
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				encoded := s.RootModule().Outputs["p12_base64"].Value.(string)
				pfx, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return fmt.Errorf("content_base64 is not base64: %w", err)
				}
				key, cert, chain, err := pkcs12.DecodeChain(pfx, "password")
				if err != nil {
					return fmt.Errorf("the PKCS#12 bundle does not decode with the configured password: %w", err)
				}
				if key == nil || cert == nil {
					return fmt.Errorf("the bundle is missing its key or certificate")
				}
				if len(chain) != 1 {
					return fmt.Errorf("the bundle has %d CA certificates, want 1", len(chain))
				}
				return nil
			}),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				// A write-only value is invisible to drift detection, so a
				// second plan must be empty even though the password is not in
				// state.
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccBundlePasswordVersionForcesReEncryption is why password_wo_version
// exists: with the password absent from state, nothing else can signal that it
// changed.
func TestAccBundlePasswordVersionForcesReEncryption(t *testing.T) {
	base := func(password string, version int) string {
		return testAccBundleBase + fmt.Sprintf(`
resource "pki_bundle" "p12" {
  format              = "pkcs12"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  password_wo         = %q
  password_wo_version = %d
}
`, password, version)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("first-password", 1)},
			{
				// Changing only the password, with the version unchanged, is
				// invisible: this is the documented limitation, not a bug.
				Config: base("second-password", 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_bundle.p12", plancheck.ResourceActionNoop),
					},
				},
			},
			{
				// Bumping the version is what re-encrypts.
				Config: base("second-password", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_bundle.p12", plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

// TestAccBundlePKCS12Encodings covers the matrix from spec section 6.6. The
// algorithm-level assertions live in Plan 1's unit tests; here the concern is
// that the attribute is plumbed through and that all three values work.
func TestAccBundlePKCS12Encodings(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "modern" {
  format              = "pkcs12"
  pkcs12_encoding     = "modern"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  password_wo         = "password"
  password_wo_version = 1
}

# legacy is 3DES with a SHA-1 MAC: the only combination universally importable
# on iOS < 18 and Android < 14.
resource "pki_bundle" "legacy" {
  format              = "pkcs12"
  pkcs12_encoding     = "legacy"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  password_wo         = "password"
  password_wo_version = 1
}

# passwordless has no encryption and no MAC, and requires no password.
resource "pki_bundle" "truststore" {
  format          = "pkcs12"
  pkcs12_encoding = "passwordless"
  certificate_pem = pki_certificate_authority.root.certificate_pem
}

output "legacy_base64"     { value = pki_bundle.legacy.content_base64 }
output "truststore_base64" { value = pki_bundle.truststore.content_base64 }
`,
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				legacy, err := base64.StdEncoding.DecodeString(s.RootModule().Outputs["legacy_base64"].Value.(string))
				if err != nil {
					return err
				}
				if _, _, _, err := pkcs12.DecodeChain(legacy, "password"); err != nil {
					return fmt.Errorf("the legacy bundle does not decode: %w", err)
				}
				trust, err := base64.StdEncoding.DecodeString(s.RootModule().Outputs["truststore_base64"].Value.(string))
				if err != nil {
					return err
				}
				certs, err := pkcs12.DecodeTrustStore(trust, "")
				if err != nil {
					return fmt.Errorf("the passwordless truststore does not decode: %w", err)
				}
				if len(certs) != 1 {
					return fmt.Errorf("the truststore holds %d certificates, want 1", len(certs))
				}
				return nil
			}),
		}},
	})
}

func TestAccBundleJKS(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "jks" {
  format              = "jks"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  chain_pem           = [pki_certificate_authority.root.certificate_pem]
  friendly_name       = "nick-ipad"
  password_wo         = "changeit"
  password_wo_version = 1
}

output "jks_base64" { value = pki_bundle.jks.content_base64 }
`,
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				raw, err := base64.StdEncoding.DecodeString(s.RootModule().Outputs["jks_base64"].Value.(string))
				if err != nil {
					return err
				}
				// The JKS magic bytes.
				if len(raw) < 4 || raw[0] != 0xfe || raw[1] != 0xed || raw[2] != 0xfe || raw[3] != 0xed {
					return fmt.Errorf("the output does not start with the JKS magic 0xfeedfeed")
				}
				return nil
			}),
		}},
	})
}

func TestAccBundleRejectsBadConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		body   string
		expect *regexp.Regexp
	}{
		"unknown format": {
			body:   `format = "pkcs11"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem`,
			expect: regexp.MustCompile(`(?s)pkcs11|Invalid Attribute Value`),
		},
		"nothing to encode": {
			body:   `format = "pem"`,
			expect: regexp.MustCompile(`(?s)certificate_pem|private_key_pem|chain_pem`),
		},
		"der with a key": {
			body: `format = "der"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.leaf.private_key_pem`,
			expect: regexp.MustCompile(`(?s)der|private key`),
		},
		"pkcs7 with a key": {
			body: `format = "pkcs7"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.leaf.private_key_pem`,
			expect: regexp.MustCompile(`(?s)pkcs7|private key`),
		},
		"pkcs12 without a password": {
			body: `format = "pkcs12"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.leaf.private_key_pem`,
			expect: regexp.MustCompile(`(?s)password_wo`),
		},
		"passwordless with a password": {
			body: `format = "pkcs12"` + "\n" + `  pkcs12_encoding = "passwordless"` + "\n" +
				`  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  password_wo = "password"` + "\n" + `  password_wo_version = 1`,
			expect: regexp.MustCompile(`(?s)passwordless`),
		},
		"mismatched key and certificate": {
			body: `format = "pkcs12"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.ca.private_key_pem` + "\n" +
				`  password_wo = "password"` + "\n" + `  password_wo_version = 1`,
			expect: regexp.MustCompile(`(?s)does not match`),
		},
		"pkcs12_encoding on a non-pkcs12 format": {
			body: `format = "pem"` + "\n" + `  pkcs12_encoding = "legacy"` + "\n" +
				`  certificate_pem = pki_certificate.leaf.certificate_pem`,
			expect: regexp.MustCompile(`(?s)pkcs12_encoding|pkcs12`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      testAccBundleBase + "\nresource \"pki_bundle\" \"b\" {\n  " + tc.body + "\n}\n",
					ExpectError: tc.expect,
				}},
			})
		})
	}
}
```

The test file imports `software.sslmate.com/src/go-pkcs12`, which is already a direct dependency from Plan 1.

- [ ] **Step 2: Run to verify failure**

```bash
make testacc TESTARGS='-run TestAccBundle'
```

Expected: FAIL — `pki_bundle` undefined.

- [ ] **Step 3: Implement the resource**

Schema per spec §6.6:

| Attribute | Kind | Notes |
| --- | --- | --- |
| `format` | Required, String | `stringvalidator.OneOf` over `pki.Formats()`; `RequiresReplace` |
| `certificate_pem` | Optional, String | |
| `private_key_pem` | Optional, Sensitive, String | |
| `chain_pem` | Optional, List of String | ordered, leaf-adjacent first |
| `friendly_name` | Optional, String | JKS alias; PKCS#12 alias for a truststore only. **No effect on a keyed PKCS#12 bundle** — `go-pkcs12` cannot set one (spec §6.6). The description must say so, since silently ignoring an attribute is worse than not offering it. |
| `pkcs12_encoding` | Optional + Computed, String | `OneOf` over `pki.PKCS12Encodings()`; defaults to `modern` |
| `password_wo` | Optional, **WriteOnly**, Sensitive, String | never persisted |
| `password_wo_version` | Optional, Int64 | change to force re-encryption |
| `content` | Computed, Sensitive, String | null for binary formats |
| `content_base64` | Computed, Sensitive, String | all formats |
| `id` | Computed, String | SHA-256 of the output |

`password_wo` sets `WriteOnly: true` alongside `Optional: true`. Two framework constraints apply and both are enforced at schema-validation time: a write-only attribute must be `Optional` or `Required`, and it **cannot** be `Computed`. It also requires Terraform/OpenTofu 1.11+, which is why every acceptance test carries the version check.

`content` and `content_base64` are marked `Sensitive` unconditionally, not conditionally on whether a key is present. Sensitivity is a static schema property, so the alternative would be to mark them non-sensitive and leak a key whenever one is included — which is the common case. Note in the descriptions that a cert-only bundle is also marked sensitive as a consequence, and that `nonsensitive()` is the escape hatch if a caller genuinely needs to print one.

`ConfigValidators`:
- `resourcevalidator.AtLeastOneOf` over `certificate_pem`, `private_key_pem`, and `chain_pem` — an empty bundle is meaningless.
- `resourcevalidator.RequiredTogether(path.MatchRoot("password_wo"), path.MatchRoot("password_wo_version"))` — a password with no version can never be rotated, which is a trap worth failing on.

The format-specific rules cannot be expressed with the stock validators, so implement `ValidateConfig` for them: `der` and `pkcs7` reject `private_key_pem`; `pkcs12` with any encoding other than `passwordless` requires `password_wo`; `passwordless` rejects `password_wo`; `jks` requires `password_wo`; and `pkcs12_encoding` on a format other than `pkcs12` is an error rather than being ignored. Each diagnostic must name the attribute and say what to change.

`Create`/`Update`: read the config (not the plan) for `password_wo` — a write-only value is present in `req.Config` and absent from `req.Plan`, and reading the wrong one silently yields an empty password. Parse each PEM input, build a `pki.BundleInput`, call `pki.EncodeBundle`, then set `content_base64` always and `content` only when `pki.Format(format).IsText()`.

`Read` re-reads state unchanged, with the same reasoning as the other resources: the bundle is a pure function of its inputs, and re-deriving it in `Read` would require the password, which is not in state. Write that reasoning down — it is the concrete consequence of write-only attributes and the reason `password_wo_version` exists.

Not importable: a bundle is derived output, so there is nothing to adopt.

- [ ] **Step 4: Write the example and the doc template**

`examples/resources/pki_bundle/resource.tf`:

```hcl
# A PKCS#12 bundle for a device, and the Secret it lands in.
resource "pki_bundle" "device_p12" {
  format          = "pkcs12"
  certificate_pem = pki_certificate.device.certificate_pem
  private_key_pem = pki_private_key.device.private_key_pem
  chain_pem       = [local.ca_certificate_pem]
  friendly_name   = "nick-ipad"

  # modern is AES-256-CBC with a SHA-256 MAC, which is what a bare
  # `openssl pkcs12 -export` produces under OpenSSL 3. Devices older than
  # iOS 18 or Android 14 need "legacy" instead -- see the encoding matrix in
  # this resource's documentation.
  pkcs12_encoding = "modern"

  # Write-only: never stored in state. Bump password_wo_version to re-encrypt
  # with a new password, because a write-only value is invisible to drift
  # detection.
  password_wo         = var.p12_password
  password_wo_version = 1
}

resource "kubernetes_secret" "device" {
  metadata {
    name      = "pki-nick-ipad-2001"
    namespace = "homelab-pki"
    labels = {
      "pki/name"   = "nick-ipad"
      "pki/serial" = pki_certificate.device.serial_number
    }
  }

  # content_base64 goes straight into binary_data. This is what removes the
  # base64decode() round trip that fails on binary PKCS#12 data.
  binary_data = {
    "tls.crt"          = base64encode(pki_certificate.device.certificate_pem)
    "tls.key"          = base64encode(pki_private_key.device.private_key_pem)
    "nick-ipad.p12"    = pki_bundle.device_p12.content_base64
  }
  type = "Opaque"
}

# A cert-only PKCS#12 truststore: no private_key_pem, so it is built as a
# truststore rather than a keystore, and passwordless needs no password.
resource "pki_bundle" "ca_truststore" {
  format          = "pkcs12"
  pkcs12_encoding = "passwordless"
  certificate_pem = local.ca_certificate_pem
  friendly_name   = "homelab-ca"
}
```

`templates/resources/bundle.md.tmpl` exists to carry the PKCS#12 compatibility matrix, which spec §6.6 requires the documentation to include and which `tfplugindocs` cannot generate from the schema. Start from the default template and insert, after the schema section, the two tables verbatim from spec §6.6: the `pkcs12_encoding` to algorithm mapping, and the platform compatibility matrix with its note that Android 12 rejects a SHA-256 MAC even when the content is 3DES, so only `legacy` is universally importable. Also record why `LegacyRC2` and `Modern2026` are not offered.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
make testacc TESTARGS='-run TestAccBundle'
```

Expected: PASS. If `TestAccBundlePKCS12WriteOnlyPassword`'s `ExpectEmptyPlan` fails, the likely cause is `password_wo` being declared `Computed`, which the framework rejects, or `content`/`content_base64` lacking `UseStateForUnknown` — add it to both so an unchanged bundle is not recomputed.

- [ ] **Step 6: Commit**

```bash
git add internal/provider/resource_bundle.go internal/provider/resource_bundle_test.go internal/provider/provider.go examples/resources/pki_bundle/ templates/resources/bundle.md.tmpl
git commit -m "feat: pki_bundle converter with write-only password support"
```

---

### Task 13: Import fidelity and the end-to-end homelab scenario

Spec §10's remaining acceptance criteria, including the one that gates the migration follow-up: an existing device certificate is imported and the subsequent plan is empty.

**Files:**
- Create: `internal/provider/import_fidelity_test.go`
- Create: `internal/provider/testdata/README.md`
- Modify: `GNUmakefile` (add a target for the fidelity test alone)

**Interfaces:**
- Consumes: everything. Produces nothing.

- [ ] **Step 1: Generate a reference certificate the way the existing pipeline does**

The test needs a certificate produced by `engine.py`'s toolchain, not by this provider — otherwise it proves nothing about adoption. Plan 1 Task 15 already generated exactly that into `internal/pki/testdata/`. Reuse those files rather than generating a second set: symlinking across package boundaries is fragile in Go tests, so copy them.

```bash
mkdir -p internal/provider/testdata
cp internal/pki/testdata/ca.crt internal/pki/testdata/ca.key \
   internal/pki/testdata/leaf.crt internal/pki/testdata/leaf.key \
   internal/provider/testdata/
```

Write `internal/provider/testdata/README.md` pointing at `internal/pki/testdata/README.md` for the generation commands, and stating plainly that these are throwaway keys generated for tests, that they sign nothing outside the test suite, and that nothing from the cluster or from Bitwarden may be placed here.

- [ ] **Step 2: Write the import-fidelity test**

`internal/provider/import_fidelity_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// testdataPath returns an absolute path to a file in testdata, since the
// Terraform working directory the harness creates is not the package directory.
func testdataPath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("resolving testdata/%s: %v", name, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("testdata/%s is missing: %v", name, err)
	}
	return abs
}

// TestAccImportFidelity is the gate on the migration follow-up (spec sections 8
// and 10).
//
// It imports a certificate that was produced by openssl the way
// reconcile/engine.py produces one -- ordered DN with displayName between UID
// and GN, UTF8String values, two rfc822Name SANs, an explicit serial -- and
// asserts the subsequent plan is empty. An empty plan means every input
// attribute was reconstructed from the DER exactly: the DN byte-for-byte
// including ASN.1 string types, the SAN, the serial, the validity window, and
// every extension.
//
// If this test fails, the homelab migration cannot proceed: applying would
// reissue 20-year certificates that are installed on phones and tablets, and
// each reissue means a manual re-enrollment.
func TestAccImportFidelity(t *testing.T) {
	caCert := testdataPath(t, "ca.crt")
	caKey := testdataPath(t, "ca.key")
	leafCert := testdataPath(t, "leaf.crt")
	leafKey := testdataPath(t, "leaf.key")

	// The configuration supplies only what cannot be recovered from a
	// certificate: the CA material and the device's own key. Everything else
	// must come from the import.
	//
	// The key is adopted as a pki_private_key in the first step, which is the
	// realistic shape -- a device's key and certificate are adopted together --
	// and it gives public_key_pem something to reference.
	config := fmt.Sprintf(`
resource "pki_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "adopted" {
  ca_certificate_pem = file(%q)
  ca_private_key_pem = file(%q)

  # public_key_pem is required by the schema in inline mode. It comes from the
  # adopted key, and must match the public key inside the imported certificate
  # or the comparison in certdrift.go reports public_key drift.
  public_key_pem = pki_private_key.leaf.public_key_pem

  # Everything below is what import reconstructs. It is spelled out here
  # because a Terraform resource must have a configuration -- and the point of
  # the test is that this configuration matches what import produced.
  validity = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-ipad.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Nick"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Venenga"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  serial_number = "2001"

  basic_constraints {
    ca       = false
    critical = true
  }

  key_usage {
    usages   = ["digitalSignature", "keyEncipherment"]
    critical = true
  }

  extended_key_usage {
    usages   = ["clientAuth"]
    critical = false
  }
}
`, caCert, caKey)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Adopt the device's key first, and persist it so the next step
				// can reference its public key. ImportStatePersist is what
				// carries imported state into the following step.
				Config:             config,
				ResourceName:       "pki_private_key.leaf",
				ImportState:        true,
				ImportStateId:      "file://" + leafKey,
				ImportStatePersist: true,
				ImportStateVerify:  false,
			},
			{
				// Now adopt the certificate. The plan that follows must be
				// empty: this is the assertion the whole test exists for.
				Config:             config,
				ResourceName:       "pki_certificate.adopted",
				ImportState:        true,
				ImportStateId:      "file://" + leafCert,
				ImportStateKind:    resource.ImportBlockWithID,
				ImportStatePersist: true,
				ImportStateVerify:  false,
				ImportPlanChecks: resource.ImportPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
			{
				// And a plain plan over the fully-adopted configuration is empty
				// too, which is the property the migration actually depends on:
				// running `tofu plan` against adopted state proposes nothing.
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

// TestAccImportFidelityDiagnosesTheDifference runs the same import and, when
// the plan is not empty, reports which attribute drifted.
//
// It exists because ExpectEmptyPlan's failure output says only that the plan
// was non-empty, and the interesting question is always *which* field failed to
// round-trip -- almost always the DN's ASN.1 string types or the SAN's
// GeneralName ordering.
func TestAccImportFidelityDiagnosesTheDifference(t *testing.T) {
	leafCert := testdataPath(t, "leaf.crt")
	caCert := testdataPath(t, "ca.crt")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// Decode the reference certificate through the data source and
			// assert on what came back, so a mismatch names the field.
			Config: fmt.Sprintf(`
data "pki_certificate" "reference" {
  content_pem = file(%q)
}

data "pki_certificate" "ca" {
  content_pem = file(%q)
}

output "subject_oids" {
  value = [for a in data.pki_certificate.reference.subject : a.oid]
}
output "subject_string_types" {
  value = [for a in data.pki_certificate.reference.subject : a.string_type]
}
output "san_emails" {
  value = data.pki_certificate.reference.san.email_addresses
}
output "serial" {
  value = data.pki_certificate.reference.serial_number
}
`, leafCert, caCert),
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				out := s.RootModule().Outputs

				oids, ok := out["subject_oids"].Value.([]any)
				if !ok {
					return fmt.Errorf("subject_oids is %T, want a list", out["subject_oids"].Value)
				}
				want := []string{
					"2.5.4.3",                    // CN
					"0.9.2342.19200300.100.1.1",  // UID
					"2.16.840.1.113730.3.1.241",  // displayName -- between UID and GN
					"2.5.4.42",                   // GN
					"2.5.4.4",                    // SN
					"2.5.4.10",                   // O
				}
				if len(oids) != len(want) {
					return fmt.Errorf("subject has %d attributes, want %d: %v", len(oids), len(want), oids)
				}
				for i, w := range want {
					if oids[i].(string) != w {
						return fmt.Errorf("subject attribute %d is %s, want %s; DN order is significant in DER", i, oids[i], w)
					}
				}

				// engine.py runs openssl with string_mask = utf8only, so every
				// value must decode as UTF8String. If this reports "printable",
				// the DN will not re-encode byte-exact.
				types, _ := out["subject_string_types"].Value.([]any)
				for i, st := range types {
					if st.(string) != "utf8" {
						return fmt.Errorf("subject attribute %d has string type %q, want \"utf8\"", i, st)
					}
				}

				emails, _ := out["san_emails"].Value.([]any)
				if len(emails) != 2 || emails[0].(string) != "nick@venenga.com" || emails[1].(string) != "nijave@gmail.com" {
					return fmt.Errorf("SAN emails = %v, want [nick@venenga.com nijave@gmail.com] in that order", emails)
				}

				if got := out["serial"].Value.(string); got != "2001" {
					return fmt.Errorf("serial = %q, want \"2001\"", got)
				}
				return nil
			}),
		}},
	})
}
```

Two notes on the harness mechanics. `ImportStatePersist: true` is what carries the first step's imported key into the second step's state — without it each import step starts from empty state and `pki_private_key.leaf.public_key_pem` would be unresolvable. And the third step's `PlanOnly: true` is not redundant with the second step's `ExpectEmptyPlan`: the second checks the plan Terraform produces *during* an import block's apply, while the third checks an ordinary plan against fully-adopted state, which is the operation the migration will actually run.

If `ImportStateId` cannot be combined with `ImportStateKind: resource.ImportBlockWithID` in v1.16.0, fall back to the default `ImportCommandWithID` kind for the second step and keep the `ImportPlanChecks` block; check the field's behavior on first run rather than assuming, since the verified API notes flag that this combination was not exercised end to end.

- [ ] **Step 3: Run it and fix what it finds**

```bash
make testacc TESTARGS='-run TestAccImportFidelity'
```

Expected: PASS. When it fails, work in this order, because the failure modes are ranked by likelihood:

1. Run `TestAccImportFidelityDiagnosesTheDifference` first — it names the field.
2. If a `string_type` comes back as anything but `utf8`, the bug is in `pki.ParseSubjectDER` or in `subjectFromPKI` dropping the type. This is the failure mode Plan 1's whole `StringType` design exists to prevent.
3. If the subject OID order is wrong, `ParseSubjectDER` is sorting or flattening incorrectly.
4. If the SAN emails are missing or reordered, `pki.SAN`'s fixed dns/email/ip/uri emission order does not match what openssl produced. Fix the order in `internal/pki/san.go` to match openssl's, not the other way around: openssl's order is what is in the certificates already on the devices.
5. If everything decodes correctly and the plan is still non-empty, the gap is in `certdrift.go` — most likely `NotBefore` being taken from `time.Now()` instead of from state, or a computed attribute not being copied from state on a no-drift plan.

Do not relax the test. An empty plan here is the precondition for the migration; a weakened assertion converts a caught problem into a device-re-enrollment incident.

- [ ] **Step 4: Add a Makefile target**

```makefile
.PHONY: test-import-fidelity
test-import-fidelity:
	TF_ACC=1 TF_ACC_TERRAFORM_PATH="$$(command -v tofu)" \
		go test ./internal/provider/ -run TestAccImportFidelity -v -timeout 20m
```

This test is the gate on the migration spec, so it deserves a name someone can run on its own without remembering the `-run` pattern.

- [ ] **Step 5: Commit**

```bash
git add internal/provider/import_fidelity_test.go internal/provider/testdata/ GNUmakefile
git commit -m "test: import fidelity gate for adopting existing certificates"
```

---

### Task 14: Documentation

`tfplugindocs` output, committed, with the PKCS#12 matrix and the OID table's shape carried in templates where the schema cannot express them.

**Files:**
- Create: `templates/index.md.tmpl`
- Create: `examples/provider/provider.tf`
- Modify: `main.go` (make `go generate ./...` actually generate)
- Generated: `docs/**`

**Interfaces:**
- Consumes: every resource, data source, and function registered so far.
- Produces: `docs/index.md`, `docs/resources/*.md`, `docs/data-sources/*.md`, `docs/functions/*.md`.

- [ ] **Step 1: Write the provider example and index template**

`examples/provider/provider.tf`:

```hcl
terraform {
  required_providers {
    pki = {
      source  = "nijave/pki"
      version = "~> 0.1"
    }
  }
}

# The provider takes no configuration. There is no endpoint, no credentials, and
# no client: every resource is self-contained and CA material is passed
# per-resource as PEM strings.
provider "pki" {}
```

`templates/index.md.tmpl` starts from tfplugindocs' default and adds, above the generated schema section:

- The one-paragraph purpose statement from the README.
- The requirements: OpenTofu ≥ 1.11 (the tested platform) or Terraform ≥ 1.11, with the note that `pki_bundle`'s `password_wo` is why the floor is 1.11.
- A short table mapping each `hashicorp/tls` gap to the attribute that closes it: arbitrary DN OIDs and repeated OUs, an explicit certificate serial, `rfc822Name` SANs, PKCS#12 and other bundle formats, CRLs, per-extension criticality, and `basicConstraints` pathLen.
- A statement that GPL-3.0-or-later applies.

Keep the `{{ .SchemaMarkdown }}` and example blocks the default template provides; the point of a template here is additive context, not replacing generation.

- [ ] **Step 2: Fix the generate wiring**

Task 1 left `main.go` with a placeholder `//go:generate echo`. Replace it now that the tools module exists:

```go
// Documentation is generated from the tools module, which keeps tfplugindocs'
// dependency graph out of this module's go.sum. `go generate ./...` at the repo
// root does not descend into it, so the Makefile's docs target is the entry
// point:
//
//	make docs
//
// The generate job in CI runs `make docs` followed by a git diff, so generated
// docs stay committed and current.
```

That is a plain comment, not a `//go:generate` directive: a directive here would either duplicate the tools module's work or fail. The CI job in Task 15 calls `make docs` directly.

- [ ] **Step 3: Generate and review**

```bash
make docs
git status --short
```

Expected: new files under `docs/`. Read each generated page and check three things specifically:

1. **`docs/superpowers/` is untouched.** Spec §3 flags this risk explicitly: tfplugindocs writes into `docs/` and the hand-written specs and plans live under `docs/superpowers/`. Verify with `git status --short docs/superpowers/` returning nothing. If generation clobbered them, move the hand-written content to `.specs/` and `.plans/`, update the references in both plans and the spec, and record the change in spec §3's note.
2. Every attribute has a description. An attribute rendering with an empty description is a schema gap to fix in the resource, not in the generated file.
3. The PKCS#12 matrix appears in `docs/resources/bundle.md` via Task 12's template, and the `key_usages` bit-position note appears in `docs/data-sources/oids.md`.

- [ ] **Step 4: Verify generation is idempotent**

```bash
make docs
git diff --exit-code docs/
```

Expected: no diff on the second run. A non-idempotent generation makes the CI `generate` job fail intermittently, which trains everyone to ignore it.

- [ ] **Step 5: Commit**

```bash
git add templates/ examples/provider/ docs/index.md docs/resources/ docs/data-sources/ docs/functions/ main.go
git commit -m "docs: generate provider documentation with tfplugindocs"
```

Stage the generated `docs/` subdirectories explicitly rather than `git add docs/`, so a stray change under `docs/superpowers/` cannot ride along unnoticed.

---

### Task 15: CI — generate check, OpenTofu acceptance matrix, license gate

Extends the `test.yml` Plan 1 created. Spec §12's shape, with the corrections it specifies relative to the cortextool template.

**Files:**
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: `make docs`, `make testacc`.
- Produces: four jobs — `build`, `unit`, `generate`, `acceptance` — plus `license`.

- [ ] **Step 1: Add the `generate` job**

Append to `.github/workflows/test.yml`:

```yaml
  generate:
    name: Generated Docs Are Current
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: 'go.mod'
          cache: true
      # tfplugindocs formats the examples with `terraform fmt`, and OpenTofu's
      # `tofu fmt` is equivalent for this purpose. Install OpenTofu rather than
      # Terraform, so no BUSL-licensed binary is used anywhere in CI.
      - uses: opentofu/setup-opentofu@v1
        with:
          tofu_version: '1.12.4'
          tofu_wrapper: false
      - name: Generate
        run: make docs
      - name: Check for uncommitted changes
        run: |
          git diff --compact-summary --exit-code || \
            (echo; echo "Generated documentation is out of date. Run 'make docs' and commit the result."; exit 1)
```

- [ ] **Step 2: Add the acceptance matrix**

```yaml
  acceptance:
    name: Acceptance (OpenTofu ${{ matrix.tofu }})
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 25
    strategy:
      fail-fast: false
      matrix:
        # OpenTofu is the primary target and 1.11 is the floor, because
        # pki_bundle's password_wo is a write-only attribute. Terraform is not
        # tested: it is BUSL-licensed and is not the reference platform.
        tofu:
          - '1.11.*'
          - '1.12.*'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: 'go.mod'
          cache: true
      - uses: opentofu/setup-opentofu@v1
        with:
          tofu_version: ${{ matrix.tofu }}
          tofu_wrapper: false
      - run: go mod download
      - name: Acceptance tests
        timeout-minutes: 20
        env:
          TF_ACC: '1'
          # terraform-plugin-testing performs no version check against a binary
          # already present at this path, so the harness drives OpenTofu
          # directly and never downloads Terraform.
          TF_ACC_TERRAFORM_PATH: tofu
        run: go test -v -cover -timeout 20m ./internal/provider/
```

Two details. `TF_ACC_TERRAFORM_PATH: tofu` relies on `setup-opentofu` having put `tofu` on `PATH`; if `terraform-plugin-testing` requires an absolute path, resolve it in a preceding step with `echo "TF_ACC_TERRAFORM_PATH=$(command -v tofu)" >> "$GITHUB_ENV"` — check the behavior on the first CI run rather than assuming. And `tofu_wrapper: false` is required: the wrapper script the action installs by default intercepts output and breaks the harness's parsing.

Note the consequence spec §12 draws out: **the acceptance tests require no secrets**, because every resource is self-contained with no external API. GitHub runs Dependabot PRs with a read-only token and withholds repository secrets, so on a provider needing API credentials those PRs would fail or silently skip coverage. Here they get the full matrix — which is what makes the §13 license gate below operationally meaningful.

- [ ] **Step 3: Add the license-compliance gate**

This is spec §14 follow-up 3, now actionable because the dependency set is final.

```yaml
  license:
    name: Dependency Licenses
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: 'go.mod'
          cache: true
      - name: Install go-licenses
        run: go install github.com/google/go-licenses@latest
      # The project is GPL-3.0-or-later, so every dependency must be
      # GPLv3-compatible. The forbidden set is what actually threatens that:
      # BUSL-1.1 (Terraform CLI since 1.6) and the copyleft-incompatible
      # licenses. Apache-2.0 is allowed because this is GPLv3, not GPLv2 -- if
      # the license is ever downgraded, re-audit spec section 13 first.
      - name: Check licenses
        run: |
          go-licenses check ./... \
            --disallowed_types=forbidden,restricted,unknown \
            --ignore=github.com/nijave/terraform-provider-pki
      - name: Report licenses
        if: always()
        run: go-licenses report ./... --ignore=github.com/nijave/terraform-provider-pki || true
```

**Scan the build graph, not the module graph.** `go-licenses check ./...` walks packages actually imported, which is correct. Do not switch it to anything driven by `go list -m all`: that lists transitive requirements from dependencies' own `go.mod` files even when nothing imports them. Measured at the end of Plan 1 — `golang.org/x/net`, `golang.org/x/term`, and `golang.org/x/text` all appear in `go list -m all` via `golang.org/x/crypto`'s `go.mod`, while `go mod why golang.org/x/text` reports "main module does not need package golang.org/x/text" and none is linked into the build. All three are BSD-3-Clause, so nothing was at risk, but a module-graph-driven gate would have demanded an audit trail for dependencies the binary never contains.

`go-licenses` classifies MPL-2.0 as `reciprocal`, which is not in the disallowed set — correct, because spec §13 establishes that MPL-2.0 §3.3 permits distributing the combined work under GPLv3 and that the framework's sources carry no Exhibit B notice. If `go-licenses check` reports an unexpected classification, read spec §13 before changing the allowlist; the MPL false-positive trap documented there is exactly the kind of finding that looks like a real problem.

The `report` step runs even on failure so the log shows the full license inventory, which is what a human needs to adjudicate a new finding.

- [ ] **Step 4: Verify the workflow locally as far as possible**

The jobs cannot be run without GitHub, but each one's commands can:

```bash
go build -v ./... && test -z "$(gofmt -l .)" && go vet ./...
go test -v -cover ./internal/...
make docs && git diff --exit-code docs/
go install github.com/google/go-licenses@latest && go-licenses check ./... --disallowed_types=forbidden,restricted,unknown --ignore=github.com/nijave/terraform-provider-pki
make testacc
```

Expected: all five succeed. If `go-licenses check` fails on a transitive dependency, do not add an exception — stop and audit that dependency against spec §13, because a GPL-incompatible dependency is a licensing defect, not a CI annoyance.

- [ ] **Step 5: Validate the YAML**

```bash
python3 -c 'import sys,yaml; yaml.safe_load(open(".github/workflows/test.yml")); print("ok")'
```

Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/test.yml
git commit -m "ci: docs generation check, OpenTofu acceptance matrix, license gate"
```

---

### Task 16: Release tooling

goreleaser, the registry manifest, the release workflow, and Dependabot. Modeled on `nijave/terraform-provider-cortextool` with the deviations spec §12 specifies.

**Files:**
- Create: `.goreleaser.yml`
- Create: `terraform-registry-manifest.json`
- Create: `.github/workflows/release.yml`
- Create: `.github/dependabot.yml`
- Modify: `README.md`

**Interfaces:**
- Consumes: `main.go`'s `version` and `commit` variables.
- Produces: a signed, draft GitHub release with per-platform zips, a checksum file, and its detached signature.

- [ ] **Step 1: Write the registry manifest**

`terraform-registry-manifest.json`:

```json
{
    "version": 1,
    "metadata": {
        "protocol_versions": ["6.0"]
    }
}
```

`["6.0"]`, not `["5.0"]`. cortextool declares 5.0 because it is SDKv2; `terraform-plugin-framework` speaks protocol 6, and getting this wrong makes the published provider fail to load with an error that does not obviously point here.

- [ ] **Step 2: Write `.goreleaser.yml`**

```yaml
# https://goreleaser.com
version: 2
before:
  hooks:
    - go mod tidy
builds:
  - env:
      # goreleaser does not work with CGO, and a CGO-free binary is also what
      # lets this provider run in restricted CI environments. Nothing in the
      # dependency set needs cgo: all cryptography is pure Go.
      - CGO_ENABLED=0
    mod_timestamp: '{{ .CommitTimestamp }}'
    flags:
      - -trimpath
    ldflags:
      - '-s -w -X main.version={{.Version}} -X main.commit={{.Commit}}'
    goos:
      - freebsd
      - windows
      - linux
      - darwin
    goarch:
      - amd64
      - arm64
    # No ignore rules. cortextool excludes windows/arm64 because Prometheus'
    # Windows mmap code fails to compile on ARM; this provider has no such
    # dependency, so windows/arm64 ships.
    binary: '{{ .ProjectName }}_v{{ .Version }}'
archives:
  - formats: [zip]
    name_template: '{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}'
checksum:
  extra_files:
    - glob: 'terraform-registry-manifest.json'
      name_template: '{{ .ProjectName }}_{{ .Version }}_manifest.json'
  name_template: '{{ .ProjectName }}_{{ .Version }}_SHA256SUMS'
  algorithm: sha256
signs:
  - artifacts: checksum
    args:
      - "--batch"
      - "--local-user"
      - "{{ .Env.GPG_FINGERPRINT }}"
      - "--output"
      - "${signature}"
      - "--detach-sign"
      - "${artifact}"
release:
  extra_files:
    - glob: 'terraform-registry-manifest.json'
      name_template: '{{ .ProjectName }}_{{ .Version }}_manifest.json'
  # Draft, so the release can be examined before it is published to the
  # registry.
  draft: true
changelog:
  disable: true
```

- [ ] **Step 3: Write the release workflow**

`.github/workflows/release.yml`:

```yaml
# Publishes release assets when a v* tag is pushed.
#
# Requires two repository secrets: GPG_PRIVATE_KEY and PASSPHRASE. The registry
# verifies the detached signature over the checksum file against the public key
# registered with it.
name: release
on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  goreleaser:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Unshallow
        run: git fetch --prune --unshallow
      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version-file: 'go.mod'
          cache: true
      - name: Import GPG key
        uses: crazy-max/ghaction-import-gpg@v6
        id: import_gpg
        with:
          gpg_private_key: ${{ secrets.GPG_PRIVATE_KEY }}
          passphrase: ${{ secrets.PASSPHRASE }}
      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@v6
        with:
          distribution: goreleaser
          version: latest
          args: release --clean
        env:
          GPG_FINGERPRINT: ${{ steps.import_gpg.outputs.fingerprint }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

`contents: write` is required here and only here; `test.yml` stays `contents: read`.

- [ ] **Step 4: Write the Dependabot config**

`.github/dependabot.yml`:

```yaml
# https://docs.github.com/en/code-security/dependabot/dependabot-version-updates
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      actions:
        patterns: ["*"]

  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      # The plugin-framework modules expect to move in lockstep, so grouping
      # them avoids a set of PRs that individually fail to build.
      terraform-plugin:
        patterns: ["github.com/hashicorp/terraform-plugin-*"]
      golang-x:
        patterns: ["golang.org/x/*"]

  # The tools module is separate, so it needs its own entry or tfplugindocs
  # never gets updated.
  - package-ecosystem: "gomod"
    directory: "/tools"
    schedule:
      interval: "weekly"
    groups:
      tools:
        patterns: ["*"]
```

Two deviations from cortextool, both from spec §12: `weekly` rather than `daily`, and grouped updates. Cortextool's ungrouped daily config opens a separate PR per module, which on a repository with the full plugin-framework dependency tree is a lot of noise for changes that should land together. The third ecosystem entry for `/tools` is an addition this plan requires, because Task 1 put `tfplugindocs` in its own module and Dependabot does not discover nested modules on its own.

Dependabot PRs are also the main consumer of the license gate from Task 15: a transitive dependency changing to a GPL-incompatible license is exactly the kind of drift that arrives via an automated bump rather than a human commit.

- [ ] **Step 5: Validate the configuration**

```bash
python3 -c 'import yaml; [yaml.safe_load(open(p)) for p in [".goreleaser.yml", ".github/workflows/release.yml", ".github/dependabot.yml", ".github/workflows/test.yml"]]; print("yaml ok")'
python3 -c 'import json; json.load(open("terraform-registry-manifest.json")); print("json ok")'
```

Then dry-run the build itself, which is where a real mistake would surface:

```bash
command -v goreleaser >/dev/null || go install github.com/goreleaser/goreleaser/v2@latest
goreleaser check
goreleaser build --snapshot --clean --single-target
```

Expected: `goreleaser check` reports no problems and the snapshot build produces a binary under `dist/`. Confirm the version ldflag landed:

```bash
find dist -type f -name 'terraform-provider-pki*' -perm -u+x | head -1 | xargs -I{} {} -h 2>&1 | head -5
```

The binary has no `-h` flag, so expect it to complain about not being run by Terraform — that is a successful launch. `goreleaser check` failing on the `signs` block for want of a GPG key is expected locally and is not a problem.

- [ ] **Step 6: Update the README with installation and release instructions**

Add to `README.md`: an installation block using `nijave/pki` from the OpenTofu registry, a note that an in-cluster filesystem mirror is a supported fallback needing no registry presence, and a `Releasing` section stating that pushing a `v*` tag produces a **draft** release which must be reviewed and published by hand.

- [ ] **Step 7: Commit**

```bash
git add .goreleaser.yml terraform-registry-manifest.json .github/workflows/release.yml .github/dependabot.yml README.md
git commit -m "ci: goreleaser release pipeline, protocol 6 manifest, grouped dependabot"
```

---

## Plan complete

Every spec section this plan covers has an implementing task:

| Spec section | Tasks |
| --- | --- |
| §4 provider configuration (empty) | 1 |
| §5 blocks as schema | 4 |
| §6.1 `pki_private_key` | 5 |
| §6.2 `pki_cert_request` | 6 |
| §6.3 `pki_certificate_authority` | 8 |
| §6.4 `pki_certificate`, CSR precedence, no extension copying | 9 |
| §6.5 `pki_crl` | 11 |
| §6.6 `pki_bundle`, write-only password, PKCS#12 matrix in docs | 12 |
| §7 serial numbers stable in state | 8, 9 |
| §8 import with `file://`, `pem://`, `base64://` | 5, 8, 9, 13 |
| §9 re-signing and drift detection | 10 |
| §10 acceptance tests: chain, CRL, renewal, CA key rotation, import fidelity | 9, 10, 11, 13 |
| §11 `pki_oids`, `pki_certificate`, `pki_cert_request`, functions | 2, 3, 6, 7 |
| §12 CI, acceptance matrix, goreleaser, Dependabot, distribution | 15, 16 |
| §13 GPLv3 headers, dependency audit, CI license gate | 1, 15 |
| §14 follow-up 3 (license gate) | 15 |

Two spec §14 follow-ups remain deliberately out of scope and are unblocked by this plan's completion:

1. **The migration spec** — rewriting `homelab-pki` onto the provider, deleting `reconcile/`, stripping cfssl/openssl/python from the Dockerfile, and collapsing the two-phase apply. Gated on Task 13's import-fidelity test passing.
2. **On-device confirmation** that `modern` PKCS#12 imports on the actual iPad, iPhone, and Pixel 7, or switching those bundles to `legacy`. This is a device test, not a research question, and the `pkcs12_encoding` attribute exists precisely so the answer is a one-line config change either way.
