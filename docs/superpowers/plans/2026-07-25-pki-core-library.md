# PKI Core Library (`internal/pki`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `internal/pki`, a pure-Go X.509 library with zero Terraform imports that performs every cryptographic operation the provider needs, fully unit-tested without a Terraform harness.

**Architecture:** One package, `internal/pki`, split into focused files by responsibility (keys, DN, SANs, extensions, signing, CRL, bundles, OID table, durations, serials, drift comparison). Every certificate field the provider exposes is built explicitly and passed through `x509.Certificate.ExtraExtensions` / `RawSubject` rather than relying on Go's convenience fields, because byte-exact reproduction of existing certificates is a hard requirement (spec §8, §9). The framework layer in Plan 2 consumes this package and stays mechanical.

**Tech Stack:** Go 1.25, `crypto/x509`, `crypto/x509/pkix`, `encoding/asn1`, `software.sslmate.com/src/go-pkcs12`, `github.com/smallstep/pkcs7`, `github.com/pavlo-v-chernykh/keystore-go/v4`, `golang.org/x/crypto/ssh`. Standard `go test`. Cross-validation against the `openssl` and `keytool` binaries when present.

**Source spec:** `docs/superpowers/specs/2026-07-25-terraform-provider-pki-design.md` (approved 2026-07-25). Sections §1–§10 and §13 are in scope for this plan; §11–§12 are Plan 2.

**Follow-on plan:** `docs/superpowers/plans/2026-07-25-pki-provider-layer.md` builds the framework layer, resources, data sources, functions, docs, and release tooling on top of this package.

## Global Constraints

Every task's requirements implicitly include this section.

- **Module path:** `github.com/nijave/terraform-provider-pki`. Go directive `go 1.25`.
- **License: GPLv3.** `LICENSE` holds the full GPL-3.0 text. Every `.go` file starts with the two-line header `// SPDX-License-Identifier: GPL-3.0-or-later` followed by a blank line before `package`. Every dependency must be GPLv3-compatible; the audited set is MPL-2.0, BSD-3-Clause, and MIT only (spec §13). Adding a dependency outside that set requires re-auditing §13 first.
- **Nothing under BUSL-1.1 may be linked in** (spec §13). Terraform CLI is BUSL since 1.6; OpenTofu (MPL-2.0) is the test platform.
- **`internal/pki` imports zero Terraform packages.** No `github.com/hashicorp/terraform-plugin-*` import may appear anywhere under `internal/pki`. Task 16 enforces this with a test.
- **Errors are plain `error` values** with lowercase messages, no `diag.Diagnostics`, no logging. The framework layer converts them to diagnostics.
- **All PEM output uses `\n` line endings and no trailing whitespace**, produced via `pem.EncodeToMemory`.
- **Serial normalization is byte-identical to `reconcile/plan.py:3`**: `strip()`, `lower()`, strip a `0x` prefix, strip leading zeros, empty result becomes `"0"`. Existing cluster Secret names (`pki-<name>-<serial>`) depend on this exactly.
- **Durations accept Go duration syntax plus `d` and `y` suffixes.** `"20y"` is `365 * 24h * 20`, `"90d"` is `90 * 24h`, both calendar-naive. `"175320h"` from `cfssl/ca-config.json` must parse unchanged.
- **Formatter/linter/test runner:** `gofmt -l` must be empty, `go vet ./...` clean, `go test ./...` green. No new linters are introduced by this plan.
- **Commit style:** Conventional Commits (`feat:`, `test:`, `fix:`, `chore:`, `docs:`), matching the existing history on `main`.
- **Stage explicit paths in every commit.** Never `git add -A` or `git add .`.

## Design decisions this plan makes that the spec left open

Three gaps surfaced while turning §5 and §11 into code. Each is resolved here and the resolution is load-bearing for later tasks:

1. **ASN.1 string type is part of a DN attribute's identity.** `engine.py:62` sets `string_mask = utf8only`, so every existing certificate's DN encodes its values as `UTF8String`. Go's `asn1.Marshal` of a Go `string` emits `PrintableString` whenever the value fits, so naively re-encoding a parsed DN produces different bytes and makes every imported certificate plan a replace — defeating spec §8. Therefore `Attribute` carries an explicit `StringType`, defaulting to `UTF8String` on build and preserved verbatim on parse. Task 6 covers this.
2. **`key_usages` has no OID.** Spec §11 shows `key_usages.by_name["digitalSignature"]` in the same `{by_name, by_oid}` shape as the other groups, but RFC 5280 key usages are bits in a `BIT STRING`, not OIDs. Resolution: for the `key_usages` group only, the value is the decimal RFC 5280 bit position (`digitalSignature` → `"0"`), and the reverse map is keyed by that same decimal string. Documented in the data source in Plan 2.
3. **`name_constraints` gets the full symmetric permitted/excluded set.** Spec §5.3 lists `excluded_dns_domains` but omits `excluded_email_domains`, `excluded_ip_ranges`, and `excluded_uri_domains`. The asymmetry is an oversight, not a decision; all four types get both a permitted and an excluded list.

## File Structure

Everything in one package. Files are split so each holds one responsibility and stays small enough to reason about whole.

| File | Responsibility |
| --- | --- |
| `go.mod`, `go.sum` | Module definition and dependency pins |
| `LICENSE` | GPL-3.0 full text |
| `GNUmakefile` | `build`, `test`, `testacc`, `fmt`, `docs`, `release` targets |
| `.github/workflows/test.yml` | Build + unit-test CI (Plan 2 adds the `generate` and acceptance-matrix jobs) |
| `internal/pki/oids.go` | Hardcoded OID tables, name↔OID lookup, dotted-OID parsing |
| `internal/pki/duration.go` | `"175320h"` / `"20y"` / `"90d"` parsing |
| `internal/pki/serial.go` | Serial normalization, hex parse/format, random 128-bit generation |
| `internal/pki/key.go` | Key generation, parsing, PEM/OpenSSH encoding, fingerprints, description |
| `internal/pki/subject.go` | Ordered DN model, canonical named-field expansion, DER encode/decode |
| `internal/pki/san.go` | SAN extension build and parse for the four in-scope GeneralName types |
| `internal/pki/extensions.go` | basicConstraints, keyUsage, extendedKeyUsage, nameConstraints, extra extensions; build and parse |
| `internal/pki/sign.go` | CSR creation, certificate issuance (self-signed and CA-signed), subject key ID |
| `internal/pki/crl.go` | CRL generation and parsing, revocation reason codes |
| `internal/pki/bundle.go` | `pem`, `der`, `pkcs7`, `pkcs12`, `jks` encoders |
| `internal/pki/compare.go` | Content drift comparison between a desired template and an issued certificate |
| `internal/pki/testhelper_test.go` | Shared test fixtures and `openssl`/`keytool` shell-out helpers |
| `internal/pki/golden_test.go` | Cross-validation against `engine.py`'s output for identical inputs |
| `internal/pki/boundary_test.go` | Asserts no Terraform import creeps into the package |

---

### Task 1: Repository foundation

Module, license, Makefile, and a CI job that runs unit tests. Nothing here is provider-specific; it exists so every later task has a green `go test ./...` and a green CI run to land against.

**Files:**
- Create: `go.mod`
- Create: `LICENSE`
- Create: `GNUmakefile`
- Create: `.github/workflows/test.yml`
- Create: `internal/pki/doc.go`
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: module path `github.com/nijave/terraform-provider-pki`; package `pki` at `internal/pki` importable as `github.com/nijave/terraform-provider-pki/internal/pki`.

- [ ] **Step 1: Initialize the module and fetch the verified dependency set**

Run from the repository root:

```bash
go mod init github.com/nijave/terraform-provider-pki
go get software.sslmate.com/src/go-pkcs12@v0.7.3
go get github.com/smallstep/pkcs7@v0.2.2
go get github.com/pavlo-v-chernykh/keystore-go/v4@v4.5.0
go get golang.org/x/crypto@latest
```

The resulting `go.mod` must contain the `go 1.25` directive and these four requires. Do not add `terraform-plugin-*` dependencies in this plan — they arrive in Plan 2 and would break the Task 16 boundary test if imported here.

License check for the record (spec §13): go-pkcs12 is BSD-3-Clause, smallstep/pkcs7 is MIT, keystore-go/v4 is MIT, `golang.org/x/crypto` is BSD-3-Clause. All four are GPLv3-compatible.

- [ ] **Step 2: Add the GPL-3.0 license text**

Write the verbatim, unmodified GPL-3.0 text to `LICENSE`. Fetch it rather than typing it:

```bash
curl -fsSL https://www.gnu.org/licenses/gpl-3.0.txt -o LICENSE
grep -c 'GNU GENERAL PUBLIC LICENSE' LICENSE   # expect at least 1
wc -l LICENSE                                   # expect ~674 lines
```

Do not add a copyright line inside `LICENSE` itself; the per-file SPDX headers carry attribution.

- [ ] **Step 3: Write the package doc file with the SPDX header**

`internal/pki/doc.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

// Package pki implements the X.509 primitives behind terraform-provider-pki.
//
// It imports no Terraform packages. Every cryptographic decision lives here so
// it can be tested without a Terraform harness, and the provider's framework
// layer stays a mechanical translation between Terraform values and these
// types.
//
// Certificate fields are built explicitly and supplied through
// x509.Certificate.RawSubject and x509.Certificate.ExtraExtensions rather than
// through the convenience fields on x509.Certificate, because reproducing an
// existing certificate byte-for-byte is a requirement of the provider's import
// support.
package pki
```

- [ ] **Step 4: Verify the module builds**

Do **not** add a placeholder test file. `go test ./...` succeeds on a package with no test file at all — it reports `?  <package>  [no test files]` and exits zero — so a test that asserts nothing buys nothing, and Task 2 adds real tests to this package immediately.

```bash
gofmt -l . && go vet ./... && go build ./... && go test ./...
```

Expected: `gofmt -l` prints nothing, `go vet` and `go build` are silent, and `go test` reports `?  github.com/nijave/terraform-provider-pki/internal/pki  [no test files]` with exit status 0.

- [ ] **Step 5: Write the GNUmakefile**

`GNUmakefile` (the `docs` and `testacc` targets are placeholders until Plan 2 adds the framework layer, but they belong here so the target names never change):

```makefile
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
```

- [ ] **Step 6: Write the CI workflow**

`.github/workflows/test.yml`. This is the unit-test half of spec §12; Plan 2 adds the `generate` job and the OpenTofu acceptance matrix to this same file. The triggers, `permissions`, and `concurrency` block are already in their final form, per spec §12's correction of cortextool's push-only trigger.

```yaml
# Runs on pull requests and on pushes to main. Scoping push to main avoids a
# duplicate run when a branch in this repo also has an open PR.
name: Tests
on:
  pull_request:
    paths-ignore:
      - 'README.md'
      - 'docs/superpowers/**'
  push:
    branches: [main]
    paths-ignore:
      - 'README.md'
      - 'docs/superpowers/**'

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: 'go.mod'
          cache: true
      - run: go mod download
      - run: go build -v ./...
      - name: gofmt
        run: |
          test -z "$(gofmt -l .)" || (gofmt -l . && echo "run 'make fmt'" && exit 1)
      - run: go vet ./...

  unit:
    name: Unit Tests
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: 'go.mod'
          cache: true
      - run: go mod download
      - name: go test
        run: go test -v -cover ./internal/...
```

The `unit` job deliberately does not set `TF_ACC`, so acceptance tests added in Plan 2 skip here and run only in the matrix job Plan 2 adds.

- [ ] **Step 7: Replace the README stub**

`README.md` currently contains only the title with no trailing newline. Replace it with:

```markdown
# terraform-provider-pki

A Terraform/OpenTofu provider for running a private X.509 certificate
authority entirely in-process. No external CA service, no `openssl` binary, no
`cfssl` binary.

Status: in development. See
[`docs/superpowers/specs/2026-07-25-terraform-provider-pki-design.md`](docs/superpowers/specs/2026-07-25-terraform-provider-pki-design.md)
for the design.

## Why

`hashicorp/tls` cannot express a DN with arbitrary OIDs or repeated OUs, cannot
set a certificate serial, cannot emit `rfc822Name` SANs, and has no PKCS#12 or
CRL support. This provider closes those gaps.

## Requirements

- OpenTofu >= 1.11 (primary target, what CI tests) or Terraform >= 1.11
- Go >= 1.25 to build

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
```

- [ ] **Step 8: Verify and commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add go.mod go.sum LICENSE GNUmakefile README.md .github/workflows/test.yml internal/pki/doc.go
git commit -m "chore: module foundation, GPLv3 license, unit-test CI"
```

---

### Task 2: OID table (`oids.go`)

The hardcoded name↔OID table behind `data "pki_oids"`, `provider::pki::oid()`, and every place a config supplies a friendly name instead of a dotted OID.

**Files:**
- Create: `internal/pki/oids.go`
- Test: `internal/pki/oids_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Table struct { Name string; ByName map[string]string; ByOID map[string]string }`
  - `func Tables() []Table` — the five groups, in a stable order: `dn_attributes`, `extensions`, `extended_key_usages`, `key_usages`, `signature_algorithms`.
  - `func OIDByName(name string) (string, error)` — searches `dn_attributes`, `extensions`, then `extended_key_usages`; returns a dotted string.
  - `func NameByOID(oid string) (string, error)` — reverse, same three groups.
  - `func ParseOID(s string) (asn1.ObjectIdentifier, error)` — dotted string to OID, rejecting empty arcs, non-numeric arcs, and fewer than two arcs.
  - `func FormatOID(oid asn1.ObjectIdentifier) string`
  - `func DNAttributeOID(name string) (asn1.ObjectIdentifier, error)` — `dn_attributes` only.
  - `func ExtKeyUsageOID(nameOrOID string) (asn1.ObjectIdentifier, error)` — accepts either a friendly name or a dotted OID, so `extended_key_usage.usages` can mix them per spec §5.3.
  - `func KeyUsageBit(name string) (int, error)` and `func KeyUsageBitName(bit int) (string, error)`
  - `func SignatureAlgorithmByName(name string) (x509.SignatureAlgorithm, error)` and `func SignatureAlgorithmName(a x509.SignatureAlgorithm) (string, error)`
  - `func SignatureAlgorithmNames() []string` — the accepted names, sorted, for schema validation in Plan 2 (the counterpart of `ReasonNames()` in Task 10)

- [ ] **Step 1: Write the failing tests**

`internal/pki/oids_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"testing"
)

func TestOIDByName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"commonName":         "2.5.4.3",
		"surname":            "2.5.4.4",
		"givenName":          "2.5.4.42",
		"displayName":        "2.16.840.1.113730.3.1.241",
		"uid":                "0.9.2342.19200300.100.1.1",
		"organization":       "2.5.4.10",
		"organizationalUnit": "2.5.4.11",
		"emailAddress":       "1.2.840.113549.1.9.1",
		"subjectAltName":     "2.5.29.17",
		"basicConstraints":   "2.5.29.19",
		"clientAuth":         "1.3.6.1.5.5.7.3.2",
	} {
		got, err := OIDByName(name)
		if err != nil {
			t.Errorf("OIDByName(%q) returned error: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("OIDByName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestOIDByNameUnknownIsAnError(t *testing.T) {
	t.Parallel()
	// Spec section 11: functions must error on unknown input rather than
	// returning empty, so a typo fails at plan time.
	if _, err := OIDByName("commonNam"); err == nil {
		t.Fatal("OIDByName(\"commonNam\") returned nil error, want an error")
	}
}

func TestNameByOID(t *testing.T) {
	t.Parallel()
	got, err := NameByOID("2.5.4.4")
	if err != nil {
		t.Fatalf("NameByOID: %v", err)
	}
	if got != "surname" {
		t.Fatalf("NameByOID(\"2.5.4.4\") = %q, want \"surname\"", got)
	}
	if _, err := NameByOID("1.2.3.4.5.6.7.8.9"); err == nil {
		t.Fatal("NameByOID on an unknown OID returned nil error, want an error")
	}
}

// TestTablesAreBidirectional is the completeness check required by spec
// section 10: every ByName entry must round-trip through ByOID and vice versa,
// so the two halves of every table can never drift apart.
func TestTablesAreBidirectional(t *testing.T) {
	t.Parallel()
	tables := Tables()
	if len(tables) != 5 {
		t.Fatalf("Tables() returned %d groups, want 5", len(tables))
	}
	wantNames := []string{"dn_attributes", "extensions", "extended_key_usages", "key_usages", "signature_algorithms"}
	for i, want := range wantNames {
		if tables[i].Name != want {
			t.Errorf("Tables()[%d].Name = %q, want %q", i, tables[i].Name, want)
		}
	}
	for _, tbl := range tables {
		if len(tbl.ByName) == 0 {
			t.Errorf("table %q has an empty ByName map", tbl.Name)
		}
		// Every entry in ByOID must round-trip back through ByName. This holds
		// for all five groups, including signature_algorithms, where the
		// reverse direction is a strict subset (see below).
		for oid, name := range tbl.ByOID {
			back, ok := tbl.ByName[name]
			if !ok {
				t.Errorf("table %q: ByOID[%q] = %q but ByName is missing that key", tbl.Name, oid, name)
				continue
			}
			if back != oid {
				t.Errorf("table %q: %q -> %q -> %q, want the original OID back", tbl.Name, oid, name, back)
			}
		}
	}

	// Four of the five groups are strict bijections. signature_algorithms is
	// not, and cannot be: see TestSignatureAlgorithmTableIsNotBijective.
	for _, tbl := range tables {
		if tbl.Name == "signature_algorithms" {
			continue
		}
		if len(tbl.ByName) != len(tbl.ByOID) {
			t.Errorf("table %q: ByName has %d entries, ByOID has %d; this group must be a strict bijection",
				tbl.Name, len(tbl.ByName), len(tbl.ByOID))
		}
		for name, oid := range tbl.ByName {
			back, ok := tbl.ByOID[oid]
			if !ok {
				t.Errorf("table %q: ByName[%q] = %q but ByOID is missing that key", tbl.Name, name, oid)
				continue
			}
			if back != name {
				t.Errorf("table %q: %q -> %q -> %q, want the original name back", tbl.Name, name, oid, back)
			}
		}
	}
}

// TestSignatureAlgorithmTableIsNotBijective documents the one place the
// name-to-OID mapping is genuinely many-to-one, so nobody "fixes" it by
// inventing OID arcs that do not exist.
//
// RFC 8017 registers a single OID for RSASSA-PSS, 1.2.840.113549.1.1.10. The
// hash lives in the AlgorithmIdentifier's PSS parameters, not in the OID, so
// SHA256-RSAPSS, SHA384-RSAPSS, and SHA512-RSAPSS all share it. An OID alone
// therefore cannot name a PSS variant, and the reverse map omits it rather
// than guessing a hash or fabricating a sub-arc.
func TestSignatureAlgorithmTableIsNotBijective(t *testing.T) {
	t.Parallel()
	const pssOID = "1.2.840.113549.1.1.10"

	var sigs Table
	for _, tbl := range Tables() {
		if tbl.Name == "signature_algorithms" {
			sigs = tbl
		}
	}
	if sigs.Name == "" {
		t.Fatal("Tables() has no signature_algorithms group")
	}

	// All three PSS names are present in ByName and all three share the one
	// real registered OID.
	for _, name := range []string{"SHA256-RSAPSS", "SHA384-RSAPSS", "SHA512-RSAPSS"} {
		got, ok := sigs.ByName[name]
		if !ok {
			t.Errorf("ByName is missing %q", name)
			continue
		}
		if got != pssOID {
			t.Errorf("ByName[%q] = %q, want the single registered RSASSA-PSS OID %q", name, got, pssOID)
		}
	}

	// The shared OID is absent from the reverse map, because it does not
	// identify one algorithm.
	if name, ok := sigs.ByOID[pssOID]; ok {
		t.Errorf("ByOID[%q] = %q; the shared RSASSA-PSS OID must not appear in the reverse map, because it does not determine the hash", pssOID, name)
	}

	// No fabricated sub-arcs of the PSS OID anywhere in either direction.
	for name, oid := range sigs.ByName {
		if strings.HasPrefix(oid, pssOID+".") {
			t.Errorf("ByName[%q] = %q invents a sub-arc of the RSASSA-PSS OID; no such arc is registered", name, oid)
		}
	}
	for oid := range sigs.ByOID {
		if strings.HasPrefix(oid, pssOID+".") {
			t.Errorf("ByOID has key %q, which invents a sub-arc of the RSASSA-PSS OID", oid)
		}
	}

	// Every non-PSS name still round-trips, so the exception is narrow.
	for _, name := range []string{"SHA256-RSA", "ECDSA-SHA384", "Ed25519"} {
		oid, ok := sigs.ByName[name]
		if !ok {
			t.Errorf("ByName is missing %q", name)
			continue
		}
		if back := sigs.ByOID[oid]; back != name {
			t.Errorf("%q -> %q -> %q, want the original name back", name, oid, back)
		}
	}
}

// TestDNAttributesCoverEnginePy pins the exact set of DN attributes the
// existing homelab issuer emits (reconcile/engine.py lines 45-58). Losing any
// of these breaks adoption of the certificates already on devices.
func TestDNAttributesCoverEnginePy(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"commonName", "uid", "displayName", "givenName", "surname", "organization", "organizationalUnit"} {
		if _, err := DNAttributeOID(name); err != nil {
			t.Errorf("DNAttributeOID(%q): %v", name, err)
		}
	}
}

func TestParseOID(t *testing.T) {
	t.Parallel()
	got, err := ParseOID("2.5.4.3")
	if err != nil {
		t.Fatalf("ParseOID: %v", err)
	}
	if !got.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
		t.Fatalf("ParseOID(\"2.5.4.3\") = %v, want 2.5.4.3", got)
	}
	if FormatOID(got) != "2.5.4.3" {
		t.Fatalf("FormatOID round-trip = %q, want \"2.5.4.3\"", FormatOID(got))
	}
	for _, bad := range []string{"", "2", "2.", ".2.5", "2..5", "2.5.4.x", "2.5.4.-1", "2.5.4.3 "} {
		if _, err := ParseOID(bad); err == nil {
			t.Errorf("ParseOID(%q) returned nil error, want an error", bad)
		}
	}
}

func TestExtKeyUsageOIDAcceptsNamesAndRawOIDs(t *testing.T) {
	t.Parallel()
	// Spec section 5.3: extended_key_usage.usages takes names or raw OIDs.
	byName, err := ExtKeyUsageOID("clientAuth")
	if err != nil {
		t.Fatalf("ExtKeyUsageOID(\"clientAuth\"): %v", err)
	}
	if FormatOID(byName) != "1.3.6.1.5.5.7.3.2" {
		t.Fatalf("clientAuth = %s, want 1.3.6.1.5.5.7.3.2", FormatOID(byName))
	}
	byOID, err := ExtKeyUsageOID("1.3.6.1.4.1.311.20.2.2")
	if err != nil {
		t.Fatalf("ExtKeyUsageOID on a raw OID: %v", err)
	}
	if FormatOID(byOID) != "1.3.6.1.4.1.311.20.2.2" {
		t.Fatalf("raw OID = %s, want it unchanged", FormatOID(byOID))
	}
	if _, err := ExtKeyUsageOID("clientAuthh"); err == nil {
		t.Fatal("ExtKeyUsageOID on an unknown name returned nil error, want an error")
	}
}

func TestKeyUsageBits(t *testing.T) {
	t.Parallel()
	// RFC 5280 4.2.1.3 bit positions.
	for name, want := range map[string]int{
		"digitalSignature": 0,
		"nonRepudiation":   1,
		"keyEncipherment":  2,
		"dataEncipherment": 3,
		"keyAgreement":     4,
		"keyCertSign":      5,
		"crlSign":          6,
		"encipherOnly":     7,
		"decipherOnly":     8,
	} {
		got, err := KeyUsageBit(name)
		if err != nil {
			t.Errorf("KeyUsageBit(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("KeyUsageBit(%q) = %d, want %d", name, got, want)
		}
		back, err := KeyUsageBitName(want)
		if err != nil || back != name {
			t.Errorf("KeyUsageBitName(%d) = %q, %v; want %q, nil", want, back, err, name)
		}
	}
	if _, err := KeyUsageBit("digitalSignatures"); err == nil {
		t.Fatal("KeyUsageBit on an unknown name returned nil error, want an error")
	}
}

func TestSignatureAlgorithmNames(t *testing.T) {
	t.Parallel()
	got, err := SignatureAlgorithmByName("SHA256-RSA")
	if err != nil {
		t.Fatalf("SignatureAlgorithmByName: %v", err)
	}
	if got != x509.SHA256WithRSA {
		t.Fatalf("SHA256-RSA = %v, want x509.SHA256WithRSA", got)
	}
	name, err := SignatureAlgorithmName(x509.ECDSAWithSHA384)
	if err != nil {
		t.Fatalf("SignatureAlgorithmName: %v", err)
	}
	if name != "ECDSA-SHA384" {
		t.Fatalf("ECDSAWithSHA384 = %q, want \"ECDSA-SHA384\"", name)
	}
	if _, err := SignatureAlgorithmByName("MD5-RSA"); err == nil {
		t.Fatal("SignatureAlgorithmByName(\"MD5-RSA\") returned nil error; MD5 must not be offered")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'TestOID|TestName|TestTables|TestDN|TestParseOID|TestExtKeyUsage|TestKeyUsage|TestSignature' -v
```

Expected: FAIL to build with `undefined: OIDByName`, `undefined: Tables`, and so on.

- [ ] **Step 3: Implement `oids.go`**

`internal/pki/oids.go`. Structure: five package-level `map[string]string` literals keyed by friendly name with dotted-OID values, a `Tables()` function that builds the reverse maps once via `sync.OnceValue`, and thin lookup wrappers.

The DN attribute table must contain at minimum: `commonName` 2.5.4.3, `surname` 2.5.4.4, `serialNumber` 2.5.4.5, `country` 2.5.4.6, `locality` 2.5.4.7, `province` 2.5.4.8, `streetAddress` 2.5.4.9, `organization` 2.5.4.10, `organizationalUnit` 2.5.4.11, `title` 2.5.4.12, `description` 2.5.4.13, `postalCode` 2.5.4.17, `name` 2.5.4.41, `givenName` 2.5.4.42, `initials` 2.5.4.43, `generationQualifier` 2.5.4.44, `dnQualifier` 2.5.4.46, `pseudonym` 2.5.4.65, `emailAddress` 1.2.840.113549.1.9.1, `uid` 0.9.2342.19200300.100.1.1, `domainComponent` 0.9.2342.19200300.100.1.25, `displayName` 2.16.840.1.113730.3.1.241, `jurisdictionCountry` 1.3.6.1.4.1.311.60.2.1.3, `organizationIdentifier` 2.5.4.97.

The extensions table: `subjectKeyIdentifier` 2.5.29.14, `keyUsage` 2.5.29.15, `subjectAltName` 2.5.29.17, `issuerAltName` 2.5.29.18, `basicConstraints` 2.5.29.19, `nameConstraints` 2.5.29.30, `crlDistributionPoints` 2.5.29.31, `certificatePolicies` 2.5.29.32, `policyMappings` 2.5.29.33, `authorityKeyIdentifier` 2.5.29.35, `policyConstraints` 2.5.29.36, `extendedKeyUsage` 2.5.29.37, `freshestCRL` 2.5.29.46, `inhibitAnyPolicy` 2.5.29.54, `authorityInfoAccess` 1.3.6.1.5.5.7.1.1, `subjectInfoAccess` 1.3.6.1.5.5.7.1.11, `cRLNumber` 2.5.29.20, `reasonCode` 2.5.29.21, `invalidityDate` 2.5.29.24, `certificateIssuer` 2.5.29.29.

The extended key usages table: `any` 2.5.29.37.0, `serverAuth` 1.3.6.1.5.5.7.3.1, `clientAuth` 1.3.6.1.5.5.7.3.2, `codeSigning` 1.3.6.1.5.5.7.3.3, `emailProtection` 1.3.6.1.5.5.7.3.4, `ipsecEndSystem` 1.3.6.1.5.5.7.3.5, `ipsecTunnel` 1.3.6.1.5.5.7.3.6, `ipsecUser` 1.3.6.1.5.5.7.3.7, `timeStamping` 1.3.6.1.5.5.7.3.8, `ocspSigning` 1.3.6.1.5.5.7.3.9, `microsoftServerGatedCrypto` 1.3.6.1.4.1.311.10.3.3, `netscapeServerGatedCrypto` 2.16.840.1.113730.4.1, `microsoftCommercialCodeSigning` 1.3.6.1.4.1.311.2.1.22, `microsoftKernelCodeSigning` 1.3.6.1.4.1.311.61.1.1, `microsoftSmartcardLogon` 1.3.6.1.4.1.311.20.2.2.

The key usages "OID" side is the decimal RFC 5280 bit position, per the design decision above: `digitalSignature` `"0"` through `decipherOnly` `"8"`.

`SignatureAlgorithmNames` returns the table's keys via `slices.Sorted(maps.Keys(...))`, so the list is stable across runs — an unsorted list would make generated documentation churn between `make docs` invocations and fail the CI diff check in Plan 2.

The signature algorithms table maps the names Go's `x509.SignatureAlgorithm.String()` produces, so `SignatureAlgorithmName` can be implemented as a reverse lookup on `a.String()` and the two directions cannot drift: `SHA256-RSA`, `SHA384-RSA`, `SHA512-RSA`, `SHA256-RSAPSS`, `SHA384-RSAPSS`, `SHA512-RSAPSS`, `ECDSA-SHA256`, `ECDSA-SHA384`, `ECDSA-SHA512`, `Ed25519`. The value side is the OID of the algorithm identifier (for example `SHA256-RSA` is 1.2.840.113549.1.1.11, `ECDSA-SHA256` is 1.2.840.10045.4.3.2, `Ed25519` is 1.3.101.112). Deliberately omit `MD2-RSA`, `MD5-RSA`, `SHA1-RSA`, `ECDSA-SHA1`, and `DSA-*`: SHA-1 and MD5 signatures are not offered, and Go cannot create DSA certificates.

**RSASSA-PSS is the one genuine many-to-one entry, and it must not be papered over.** RFC 8017 registers exactly one OID for PSS — `1.2.840.113549.1.1.10` — and the hash is a PSS *parameter*, not part of the OID. So all three of `SHA256-RSAPSS`, `SHA384-RSAPSS`, and `SHA512-RSAPSS` map to that same value in `ByName`, and `ByOID` **omits** it, because an OID that cannot determine the hash cannot name one algorithm.

Do not resolve this by appending a synthetic arc such as `1.2.840.113549.1.1.10.256`. No such arc is registered, and `data "pki_oids"` publishes this table to users who will paste values from it into configuration — a fabricated OID there produces a certificate no other implementation can interpret. Do not resolve it by picking one PSS name as the reverse value either; that silently misreports the hash. `TestSignatureAlgorithmTableIsNotBijective` pins both prohibitions, and `TestTablesAreBidirectional` exempts this one group from strict bijection while still requiring that every `ByOID` entry round-trips.

The `signature_algorithms` group's description in the Plan 2 data source must state this asymmetry, so a user reading generated documentation is not surprised that `by_oid` is smaller than `by_name`.

`OIDByName` and `NameByOID` search `dn_attributes`, then `extensions`, then `extended_key_usages`, and skip `key_usages` and `signature_algorithms` — the former has no OIDs and the latter's names would collide conceptually with nothing but add no value to the terse `provider::pki::oid()` path. Return an error naming the input on a miss, for example `unknown OID name "commonNam"`.

`ParseOID` must reject anything `asn1.ObjectIdentifier` cannot hold: split on `.`, require at least two arcs, require every arc to be a non-empty run of ASCII digits (so no leading `+`, no whitespace, no negatives), and parse with `strconv.Atoi`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -v
```

Expected: all tests in `oids_test.go` PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/oids.go internal/pki/oids_test.go
git commit -m "feat: hardcoded OID tables with bidirectional lookup"
```

---

### Task 3: Duration parsing (`duration.go`)

**Files:**
- Create: `internal/pki/duration.go`
- Test: `internal/pki/duration_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func ParseDuration(s string) (time.Duration, error)`.

- [ ] **Step 1: Write the failing test**

`internal/pki/duration_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	t.Parallel()
	const day = 24 * time.Hour
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"175320h", 175320 * time.Hour}, // pastes in unchanged from cfssl/ca-config.json
		{"20y", 20 * 365 * day},         // calendar-naive by definition
		{"1y", 365 * day},
		{"90d", 90 * day},
		{"1d", day},
		{"720h", 720 * time.Hour},
		{"90m", 90 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"1s", time.Second},
	} {
		got, err := ParseDuration(tc.in)
		if err != nil {
			t.Errorf("ParseDuration(%q) returned error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestParseDurationEquivalences pins the exact calendar-naive definitions, so a
// later "improvement" to real calendar math fails loudly instead of silently
// shifting every certificate's notAfter.
func TestParseDurationEquivalences(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{
		{"1y", "8760h"},
		{"1y", "365d"},
		{"1d", "24h"},
		{"20y", "175200h"}, // note: NOT 175320h; cfssl's value is 20y plus 5 days
	} {
		a, err := ParseDuration(pair[0])
		if err != nil {
			t.Fatalf("ParseDuration(%q): %v", pair[0], err)
		}
		b, err := ParseDuration(pair[1])
		if err != nil {
			t.Fatalf("ParseDuration(%q): %v", pair[1], err)
		}
		if a != b {
			t.Errorf("ParseDuration(%q) = %v but ParseDuration(%q) = %v; want equal", pair[0], a, pair[1], b)
		}
	}
}

func TestParseDurationRejectsGarbage(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",         // empty
		"   ",      // whitespace only
		"forever",  // not a duration
		"20 y",     // internal space
		"1y6m",     // mixed year and Go duration syntax is not supported
		"1d12h",    // mixed day and Go duration syntax is not supported
		"-720h",    // negative
		"0h",       // zero
		"0d",       // zero
		"1.5y",     // fractional years
		"y",        // suffix with no number
		"d",        // suffix with no number
		"175320",   // no unit
		"175320hh", // doubled unit
		"1Y",       // uppercase suffix is not accepted
	} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) returned nil error, want an error", bad)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/pki/ -run TestParseDuration -v
```

Expected: FAIL to build with `undefined: ParseDuration`.

- [ ] **Step 3: Implement `duration.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// day is the fixed length this package assigns to "d" and, multiplied by 365,
// to "y". Both suffixes are calendar-naive: no leap years, no DST, no month
// arithmetic. That is a documented property of the provider's validity
// attribute, not an approximation to be fixed later.
const day = 24 * time.Hour

// suffixPattern matches a whole-string count plus a "d" or "y" suffix. The
// anchors matter: they are what reject "1y6m" and "1d12h", which would
// otherwise be silently truncated.
var suffixPattern = regexp.MustCompile(`^([0-9]+)([dy])$`)

// ParseDuration parses a positive duration written either in Go's time.Duration
// syntax or as an integer count with a "d" (day) or "y" (365-day year) suffix.
//
// The "d" and "y" extensions exist because certificate lifetimes are naturally
// written in days and years, and Go's syntax stops at hours. Go durations pass
// straight through, so "175320h" from a cfssl signing profile parses unchanged.
//
// Zero and negative durations are rejected: every caller uses the result as a
// certificate or CRL lifetime, and neither is meaningful at or below zero.
func ParseDuration(s string) (time.Duration, error) {
	if m := suffixPattern.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		unit := day
		if m[2] == "y" {
			unit = 365 * day
		}
		d := time.Duration(n) * unit
		if d <= 0 {
			return 0, fmt.Errorf("invalid duration %q: must be positive", s)
		}
		return d, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: want a Go duration such as \"175320h\" or a count with a \"d\" or \"y\" suffix such as \"90d\" or \"20y\"", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid duration %q: must be positive", s)
	}
	return d, nil
}
```

Note the multiplication order in `time.Duration(n) * unit`: converting `n` to a `time.Duration` before multiplying keeps the arithmetic in int64 nanoseconds and overflows predictably rather than wrapping through a smaller int.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run TestParseDuration -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/duration.go internal/pki/duration_test.go
git commit -m "feat: duration parsing with d and y suffixes"
```

---

### Task 4: Serial numbers (`serial.go`)

Normalization here must match `reconcile/plan.py:3` exactly, because the cluster's existing Secret names embed the normalized form.

**Files:**
- Create: `internal/pki/serial.go`
- Test: `internal/pki/serial_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func NormalizeSerial(s string) string`
  - `func ParseSerial(s string) (*big.Int, error)`
  - `func FormatSerial(n *big.Int) string`
  - `func RandomSerial() (*big.Int, error)`

- [ ] **Step 1: Write the failing test**

`internal/pki/serial_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"math/big"
	"testing"
)

// TestNormalizeSerialMatchesPlanPy pins the behavior of reconcile/plan.py's
// norm_serial: strip, lower, drop an "0x" prefix, drop leading zeros, and map
// the empty result to "0". Cluster Secret names are pki-<name>-<serial> using
// this exact form, so a change here renames live objects.
func TestNormalizeSerialMatchesPlanPy(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"2001":       "2001",
		"2ABC":       "2abc",
		"0x2abc":     "2abc",
		"0X2ABC":     "2abc",
		"  2abc  ":   "2abc",
		"\t2abc\n":   "2abc",
		"0002abc":    "2abc",
		"0x0002abc":  "2abc",
		"0":          "0",
		"0000":       "0",
		"0x0":        "0",
		"0x":         "0",
		"":           "0",
		"   ":        "0",
		"ffffffffff": "ffffffffff",
	} {
		if got := NormalizeSerial(in); got != want {
			t.Errorf("NormalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSerial(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]int64{
		"2001":      0x2001,
		"0x2001":    0x2001,
		"0002001":   0x2001,
		"  2001  ":  0x2001,
		"0":         0,
		"":          0,
		"deadbeef":  0xdeadbeef,
		"DEADBEEF":  0xdeadbeef,
	} {
		got, err := ParseSerial(in)
		if err != nil {
			t.Errorf("ParseSerial(%q): %v", in, err)
			continue
		}
		if got.Int64() != want {
			t.Errorf("ParseSerial(%q) = %d, want %d", in, got.Int64(), want)
		}
	}
	for _, bad := range []string{"nope", "0xzz", "12g4", "-1", "1.0", "0x 1"} {
		if _, err := ParseSerial(bad); err == nil {
			t.Errorf("ParseSerial(%q) returned nil error, want an error", bad)
		}
	}
}

func TestParseSerialHandlesValuesBeyondInt64(t *testing.T) {
	t.Parallel()
	// A random 128-bit serial does not fit in an int64; big.Int is not
	// decoration here.
	//
	// The input deliberately has no leading zero, so it is already in
	// canonical form and must round-trip to itself byte-for-byte. (Using a
	// leading-zero input here would only re-assert what
	// TestFormatSerialIsNormalizeSerialFixedPoint already covers, and would
	// not show that a large value survives the round trip intact.)
	const in = "102030405060708090a0b0c0d0e0f10"
	got, err := ParseSerial(in)
	if err != nil {
		t.Fatalf("ParseSerial: %v", err)
	}
	if got.BitLen() != 121 {
		t.Fatalf("BitLen = %d, want 121", got.BitLen())
	}
	if FormatSerial(got) != in {
		t.Fatalf("FormatSerial round-trip = %q, want %q", FormatSerial(got), in)
	}
}

func TestFormatSerial(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{0x2001, "2001"},
		{0xdeadbeef, "deadbeef"},
	} {
		if got := FormatSerial(big.NewInt(tc.in)); got != tc.want {
			t.Errorf("FormatSerial(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestFormatSerialIsNormalizeSerialFixedPoint is the property that keeps the
// two functions consistent: formatting a parsed serial must produce the same
// string normalization produces, or state would churn between the two paths.
func TestFormatSerialIsNormalizeSerialFixedPoint(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"2001", "0x0002ABC", "0", "", "deadbeef", "0102030405060708090a0b0c0d0e0f10"} {
		n, err := ParseSerial(in)
		if err != nil {
			t.Fatalf("ParseSerial(%q): %v", in, err)
		}
		if got, want := FormatSerial(n), NormalizeSerial(in); got != want {
			t.Errorf("input %q: FormatSerial(ParseSerial(x)) = %q but NormalizeSerial(x) = %q", in, got, want)
		}
	}
}

func TestRandomSerial(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		n, err := RandomSerial()
		if err != nil {
			t.Fatalf("RandomSerial: %v", err)
		}
		if n.Sign() <= 0 {
			t.Fatalf("RandomSerial returned %v; RFC 5280 requires a positive serial", n)
		}
		if n.BitLen() > 128 {
			t.Fatalf("RandomSerial returned a %d-bit value, want at most 128", n.BitLen())
		}
		s := FormatSerial(n)
		if seen[s] {
			t.Fatalf("RandomSerial returned duplicate %q within 32 draws", s)
		}
		seen[s] = true
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/pki/ -run Serial -v
```

Expected: FAIL to build with `undefined: NormalizeSerial`.

- [ ] **Step 3: Implement `serial.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// NormalizeSerial reduces a hex serial to the canonical form the homelab
// reconciler uses (reconcile/plan.py norm_serial): trimmed, lowercased, with
// any "0x" prefix and leading zeros removed, and with the empty result mapped
// to "0".
//
// This is deliberately total rather than validating: it mirrors a Python
// function that never rejected input, and the Kubernetes Secret names already
// in the cluster are pki-<name>-<serial> using exactly this form. Use
// ParseSerial when the input needs to be rejected as invalid.
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// ParseSerial parses a hex serial number, tolerating the same surface forms
// NormalizeSerial accepts, and rejecting anything that is not hex. An empty or
// all-zero input parses to zero.
func ParseSerial(s string) (*big.Int, error) {
	norm := NormalizeSerial(s)

	// big.Int.SetString accepts a leading sign, so SetString("-1", 16)
	// succeeds and yields -1. A negative serial is invalid under RFC 5280 and
	// some parsers reject such a certificate outright, so the digits are
	// checked explicitly first rather than trusting SetString's ok result.
	for _, c := range norm {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, fmt.Errorf("invalid serial number %q: want a hexadecimal string, optionally prefixed with 0x", s)
		}
	}

	n, ok := new(big.Int).SetString(norm, 16)
	if !ok {
		return nil, fmt.Errorf("invalid serial number %q: want a hexadecimal string, optionally prefixed with 0x", s)
	}
	return n, nil
}

// FormatSerial renders a serial as lowercase hex with no "0x" prefix and no
// leading zeros. FormatSerial(ParseSerial(x)) equals NormalizeSerial(x) for
// every x ParseSerial accepts.
func FormatSerial(n *big.Int) string {
	return n.Text(16)
}

// RandomSerial draws a random positive 128-bit serial.
//
// 128 bits is the CA/Browser Forum's floor for unpredictability and is what
// hashicorp/tls uses. The value is generated once at create time and then held
// in state; it is never recomputed on a later plan, because a changed serial
// means a replaced certificate and, for the 20-year certs on the devices in
// question, a manual re-enrollment.
func RandomSerial() (*big.Int, error) {
	// 1 << 128 as the exclusive upper bound, then add 1 so zero is impossible.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	limit.Sub(limit, big.NewInt(1))
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating a random serial number: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run Serial -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/serial.go internal/pki/serial_test.go
git commit -m "feat: serial normalization matching the reconciler's form"
```

---

### Task 5: Keys (`key.go`)

Everything `pki_private_key` needs, plus the parse path every other resource uses to turn a PEM string from config into a `crypto.Signer`.

**Files:**
- Create: `internal/pki/key.go`
- Test: `internal/pki/key_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Algorithm string` with `AlgorithmRSA Algorithm = "RSA"`, `AlgorithmECDSA = "ECDSA"`, `AlgorithmED25519 = "ED25519"`
  - `type KeyParams struct { Algorithm Algorithm; RSABits int; ECDSACurve string }`
  - `func GenerateKey(p KeyParams) (crypto.Signer, error)` — applies the defaults `RSABits` 2048 and `ECDSACurve` `"P256"` when the fields are zero
  - `func DescribeKey(k crypto.Signer) (KeyParams, error)` — the inverse, for reconstructing input attributes on import
  - `func ParsePrivateKeyPEM(b []byte) (crypto.Signer, error)` — accepts PKCS#1, SEC1, and PKCS#8
  - `func ParsePublicKeyPEM(b []byte) (crypto.PublicKey, error)`
  - `func EncodePrivateKeyPEM(k crypto.Signer) ([]byte, error)` — PKCS#1 for RSA, SEC1 for ECDSA, PKCS#8 for Ed25519
  - `func EncodePrivateKeyPKCS8PEM(k crypto.Signer) ([]byte, error)`
  - `func EncodePrivateKeyPKCS8DER(k crypto.Signer) ([]byte, error)` — the JKS encoder in Task 13 requires PKCS#8 DER
  - `func EncodePublicKeyPEM(pub crypto.PublicKey) ([]byte, error)`
  - `func EncodePublicKeyOpenSSH(pub crypto.PublicKey) ([]byte, error)`
  - `func PublicKeyFingerprintSHA256(pub crypto.PublicKey) (string, error)` — the OpenSSH `SHA256:base64` form, matching `hashicorp/tls`
  - `func PublicKeyOf(k crypto.Signer) crypto.PublicKey`
  - `func PublicKeysEqual(a, b crypto.PublicKey) bool`

- [ ] **Step 1: Write the failing tests**

`internal/pki/key_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestGenerateKeyDefaults(t *testing.T) {
	t.Parallel()

	rsaKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey(RSA): %v", err)
	}
	rk, ok := rsaKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("GenerateKey(RSA) returned %T, want *rsa.PrivateKey", rsaKey)
	}
	if got := rk.N.BitLen(); got != 2048 {
		t.Errorf("default RSA size = %d bits, want 2048", got)
	}

	ecKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey(ECDSA): %v", err)
	}
	ek, ok := ecKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("GenerateKey(ECDSA) returned %T, want *ecdsa.PrivateKey", ecKey)
	}
	if got := ek.Curve.Params().Name; got != "P-256" {
		t.Errorf("default ECDSA curve = %q, want \"P-256\"", got)
	}

	edKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmED25519})
	if err != nil {
		t.Fatalf("GenerateKey(ED25519): %v", err)
	}
	if _, ok := edKey.(ed25519.PrivateKey); !ok {
		t.Fatalf("GenerateKey(ED25519) returned %T, want ed25519.PrivateKey", edKey)
	}
}

func TestGenerateKeyExplicitParams(t *testing.T) {
	t.Parallel()

	k, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA, RSABits: 3072})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if got := k.(*rsa.PrivateKey).N.BitLen(); got != 3072 {
		t.Errorf("RSA size = %d, want 3072", got)
	}

	for _, curve := range []struct{ name, want string }{
		{"P224", "P-224"},
		{"P256", "P-256"},
		{"P384", "P-384"},
		{"P521", "P-521"},
	} {
		k, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: curve.name})
		if err != nil {
			t.Errorf("GenerateKey(%s): %v", curve.name, err)
			continue
		}
		if got := k.(*ecdsa.PrivateKey).Curve.Params().Name; got != curve.want {
			t.Errorf("curve %s produced %q, want %q", curve.name, got, curve.want)
		}
	}
}

func TestGenerateKeyRejectsBadParams(t *testing.T) {
	t.Parallel()
	for _, p := range []KeyParams{
		{Algorithm: "DSA"},
		{Algorithm: ""},
		{Algorithm: "rsa"}, // case-sensitive: the schema surfaces RSA/ECDSA/ED25519
		{Algorithm: AlgorithmRSA, RSABits: 512},   // below the 2048 floor
		{Algorithm: AlgorithmRSA, RSABits: 2047},  // not a multiple of 8 and below floor
		{Algorithm: AlgorithmECDSA, ECDSACurve: "P192"},
		{Algorithm: AlgorithmECDSA, ECDSACurve: "p256"},
		{Algorithm: AlgorithmED25519, RSABits: 2048}, // rsa_bits is meaningless here
		{Algorithm: AlgorithmED25519, ECDSACurve: "P256"},
		{Algorithm: AlgorithmRSA, ECDSACurve: "P256"}, // ecdsa_curve is meaningless here
	} {
		if _, err := GenerateKey(p); err == nil {
			t.Errorf("GenerateKey(%+v) returned nil error, want an error", p)
		}
	}
}

// TestDescribeKeyRoundTrip is what makes pki_private_key import cleanly: every
// input attribute must be recoverable from the parsed key, or the first plan
// after import proposes a replacement.
func TestDescribeKeyRoundTrip(t *testing.T) {
	t.Parallel()
	for _, want := range []KeyParams{
		{Algorithm: AlgorithmRSA, RSABits: 2048},
		{Algorithm: AlgorithmRSA, RSABits: 3072},
		{Algorithm: AlgorithmECDSA, ECDSACurve: "P256"},
		{Algorithm: AlgorithmECDSA, ECDSACurve: "P384"},
		{Algorithm: AlgorithmED25519},
	} {
		k, err := GenerateKey(want)
		if err != nil {
			t.Fatalf("GenerateKey(%+v): %v", want, err)
		}
		got, err := DescribeKey(k)
		if err != nil {
			t.Errorf("DescribeKey(%+v): %v", want, err)
			continue
		}
		if got != want {
			t.Errorf("DescribeKey round-trip = %+v, want %+v", got, want)
		}
	}
}

func TestEncodePrivateKeyPEMUsesTheExpectedBlockTypes(t *testing.T) {
	t.Parallel()
	// The block type is what openssl and every other consumer keys off, and it
	// differs per algorithm: PKCS#1 for RSA, SEC1 for ECDSA, PKCS#8 for
	// Ed25519 (which has no legacy format).
	for _, tc := range []struct {
		params    KeyParams
		wantBlock string
	}{
		{KeyParams{Algorithm: AlgorithmRSA}, "RSA PRIVATE KEY"},
		{KeyParams{Algorithm: AlgorithmECDSA}, "EC PRIVATE KEY"},
		{KeyParams{Algorithm: AlgorithmED25519}, "PRIVATE KEY"},
	} {
		k, err := GenerateKey(tc.params)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		out, err := EncodePrivateKeyPEM(k)
		if err != nil {
			t.Errorf("EncodePrivateKeyPEM(%s): %v", tc.params.Algorithm, err)
			continue
		}
		block, rest := pem.Decode(out)
		if block == nil {
			t.Errorf("EncodePrivateKeyPEM(%s) produced undecodable PEM", tc.params.Algorithm)
			continue
		}
		if block.Type != tc.wantBlock {
			t.Errorf("%s block type = %q, want %q", tc.params.Algorithm, block.Type, tc.wantBlock)
		}
		if len(rest) != 0 {
			t.Errorf("%s: %d trailing bytes after the PEM block, want 0", tc.params.Algorithm, len(rest))
		}
		if !strings.HasSuffix(string(out), "\n") {
			t.Errorf("%s: PEM output does not end in a newline", tc.params.Algorithm)
		}
	}
}

func TestEncodePrivateKeyPKCS8PEM(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		k, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		out, err := EncodePrivateKeyPKCS8PEM(k)
		if err != nil {
			t.Errorf("EncodePrivateKeyPKCS8PEM(%s): %v", alg, err)
			continue
		}
		block, _ := pem.Decode(out)
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Errorf("%s: PKCS#8 block type is not \"PRIVATE KEY\"", alg)
			continue
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Errorf("%s: emitted PKCS#8 does not parse: %v", alg, err)
		}
	}
}

// TestParsePrivateKeyPEMAcceptsAllThreeEncodings matters because CA keys arrive
// from outside the provider -- a Bitwarden-delivered Secret can hold any of
// these forms and the provider must not care which.
func TestParsePrivateKeyPEMAcceptsAllThreeEncodings(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		orig, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		native, err := EncodePrivateKeyPEM(orig)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM: %v", err)
		}
		pkcs8, err := EncodePrivateKeyPKCS8PEM(orig)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8PEM: %v", err)
		}
		for label, encoded := range map[string][]byte{"native": native, "pkcs8": pkcs8} {
			parsed, err := ParsePrivateKeyPEM(encoded)
			if err != nil {
				t.Errorf("%s/%s: ParsePrivateKeyPEM: %v", alg, label, err)
				continue
			}
			if !PublicKeysEqual(PublicKeyOf(parsed), PublicKeyOf(orig)) {
				t.Errorf("%s/%s: parsed key's public key differs from the original", alg, label)
			}
		}
	}
}

func TestParsePrivateKeyPEMRejectsBadInput(t *testing.T) {
	t.Parallel()
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	for label, in := range map[string]string{
		"empty":            "",
		"not pem":          "hello",
		"wrong block type": certPEM,
		"truncated body":   "-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n",
	} {
		if _, err := ParsePrivateKeyPEM([]byte(in)); err == nil {
			t.Errorf("ParsePrivateKeyPEM(%s) returned nil error, want an error", label)
		}
	}
}

func TestParsePrivateKeyPEMErrorDoesNotLeakKeyMaterial(t *testing.T) {
	t.Parallel()
	// Errors from this function reach Terraform diagnostics, which are printed
	// to the console and to CI logs. The message must never echo the input.
	const secret = "-----BEGIN RSA PRIVATE KEY-----\nc3VwZXJzZWNyZXQ=\n-----END RSA PRIVATE KEY-----\n"
	_, err := ParsePrivateKeyPEM([]byte(secret))
	if err == nil {
		t.Fatal("expected an error for a malformed key")
	}
	if strings.Contains(err.Error(), "c3VwZXJzZWNyZXQ") || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error message contains key material: %q", err.Error())
	}
}

func TestEncodePublicKeyPEMAndParseRoundTrip(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		k, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		encoded, err := EncodePublicKeyPEM(PublicKeyOf(k))
		if err != nil {
			t.Errorf("EncodePublicKeyPEM(%s): %v", alg, err)
			continue
		}
		block, _ := pem.Decode(encoded)
		if block == nil || block.Type != "PUBLIC KEY" {
			t.Errorf("%s: public key block type is not \"PUBLIC KEY\"", alg)
			continue
		}
		parsed, err := ParsePublicKeyPEM(encoded)
		if err != nil {
			t.Errorf("%s: ParsePublicKeyPEM: %v", alg, err)
			continue
		}
		if !PublicKeysEqual(parsed, PublicKeyOf(k)) {
			t.Errorf("%s: public key did not survive the PEM round trip", alg)
		}
	}
}

func TestEncodePublicKeyOpenSSHAndFingerprint(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		alg        Algorithm
		wantPrefix string
	}{
		{AlgorithmRSA, "ssh-rsa "},
		{AlgorithmECDSA, "ecdsa-sha2-nistp256 "},
		{AlgorithmED25519, "ssh-ed25519 "},
	} {
		k, err := GenerateKey(KeyParams{Algorithm: tc.alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		authorized, err := EncodePublicKeyOpenSSH(PublicKeyOf(k))
		if err != nil {
			t.Errorf("EncodePublicKeyOpenSSH(%s): %v", tc.alg, err)
			continue
		}
		if !strings.HasPrefix(string(authorized), tc.wantPrefix) {
			t.Errorf("%s: openssh output %q does not start with %q", tc.alg, authorized, tc.wantPrefix)
		}
		if !strings.HasSuffix(string(authorized), "\n") {
			t.Errorf("%s: openssh output does not end in a newline", tc.alg)
		}

		fp, err := PublicKeyFingerprintSHA256(PublicKeyOf(k))
		if err != nil {
			t.Errorf("PublicKeyFingerprintSHA256(%s): %v", tc.alg, err)
			continue
		}
		// The OpenSSH form: "SHA256:" plus unpadded standard base64 of the
		// SHA-256 of the wire-format public key. This is what hashicorp/tls
		// emits, and configs may already depend on the exact shape.
		if !strings.HasPrefix(fp, "SHA256:") {
			t.Errorf("%s: fingerprint %q does not start with \"SHA256:\"", tc.alg, fp)
		}
		if strings.Contains(fp, "=") {
			t.Errorf("%s: fingerprint %q is padded; OpenSSH uses unpadded base64", tc.alg, fp)
		}
		if len(fp) != len("SHA256:")+43 {
			t.Errorf("%s: fingerprint %q has length %d, want %d", tc.alg, fp, len(fp), len("SHA256:")+43)
		}
	}
}

func TestPublicKeysEqual(t *testing.T) {
	t.Parallel()
	a, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !PublicKeysEqual(PublicKeyOf(a), PublicKeyOf(a)) {
		t.Error("PublicKeysEqual said a key differs from itself")
	}
	if PublicKeysEqual(PublicKeyOf(a), PublicKeyOf(b)) {
		t.Error("PublicKeysEqual said two independently generated keys match")
	}
	if PublicKeysEqual(nil, PublicKeyOf(a)) || PublicKeysEqual(PublicKeyOf(a), nil) {
		t.Error("PublicKeysEqual matched a nil key against a real one")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'Key|Encode|Parse|Describe|Generate' -v
```

Expected: FAIL to build with `undefined: GenerateKey`, `undefined: KeyParams`, and so on.

- [ ] **Step 3: Implement `key.go`**

Import set: `crypto`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/elliptic`, `crypto/rand`, `crypto/rsa`, `crypto/sha256`, `crypto/x509`, `encoding/base64`, `encoding/pem`, `fmt`, `golang.org/x/crypto/ssh`.

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

// Algorithm names a private key algorithm as the provider's schema spells it.
// The values are uppercase and matched case-sensitively, so a config typo fails
// at plan time rather than silently generating a different kind of key.
type Algorithm string

const (
	AlgorithmRSA     Algorithm = "RSA"
	AlgorithmECDSA   Algorithm = "ECDSA"
	AlgorithmED25519 Algorithm = "ED25519"
)

// minRSABits is the floor for generated RSA keys. 2048 is the NIST and
// CA/Browser Forum minimum; anything smaller is not worth the support burden of
// offering.
const minRSABits = 2048

// KeyParams describes a key to generate, or the shape of a key that was parsed.
// Zero values mean "use the default": 2048 bits for RSA, P-256 for ECDSA.
// Fields that do not apply to the chosen algorithm must be left zero, so a
// config that sets rsa_bits on an Ed25519 key is rejected instead of ignored.
type KeyParams struct {
	Algorithm  Algorithm
	RSABits    int
	ECDSACurve string
}
```

Implementation notes, in the order a reader will want them:

- `GenerateKey` validates first, then generates. Validation rejects an unknown `Algorithm`; rejects `RSABits` below `minRSABits` or not a multiple of 8; rejects an `ECDSACurve` outside `P224`/`P256`/`P384`/`P521`; and rejects a non-zero `RSABits` for a non-RSA algorithm or a non-empty `ECDSACurve` for a non-ECDSA algorithm. That last pair of checks is what makes `TestGenerateKeyRejectsBadParams`'s final three cases pass, and it exists so a copy-pasted config block cannot quietly produce a key with settings the author thinks are in effect.
- `curveByName` is a small `map[string]elliptic.Curve` covering the four accepted names; do not use `elliptic.P224().Params().Name` style reverse lookups for validation, because the schema's names (`P256`) and Go's names (`P-256`) differ.
- `DescribeKey` type-switches on `*rsa.PrivateKey` (returning `RSABits: k.N.BitLen()`), `*ecdsa.PrivateKey` (mapping `k.Curve.Params().Name` back through a reverse map to `P256` form), and `ed25519.PrivateKey` (returning only the algorithm). An unrecognized signer type is an error naming the Go type.
- `ParsePrivateKeyPEM` decodes the first PEM block, errors if there is none, then tries `x509.ParsePKCS8PrivateKey`, `x509.ParsePKCS1PrivateKey`, and `x509.ParseECPrivateKey` in that order, returning the first success asserted to `crypto.Signer`. Order matters only for speed, not correctness — the three formats are mutually unparseable. Two constraints on the error paths: never include `block.Bytes` or the input in a message (that is what `TestParsePrivateKeyPEMErrorDoesNotLeakKeyMaterial` enforces), and reject a successfully-parsed key that is not a `crypto.Signer` — for instance an RSA key parsed out of PKCS#8 always is, but a DSA key is not, and the assertion is what turns that into a clear error instead of a panic later.
- `EncodePrivateKeyPEM` type-switches: RSA to block type `RSA PRIVATE KEY` with `x509.MarshalPKCS1PrivateKey`, ECDSA to `EC PRIVATE KEY` with `x509.MarshalECPrivateKey`, Ed25519 to `PRIVATE KEY` with `x509.MarshalPKCS8PrivateKey`. Ed25519 has no legacy encoding, which is why it lands on PKCS#8 in the "native" encoder.
- `EncodePrivateKeyPKCS8DER` is `x509.MarshalPKCS8PrivateKey(k)` and `EncodePrivateKeyPKCS8PEM` wraps its output in a `PRIVATE KEY` block. Task 13 calls the DER form directly, because keystore-go accepts a raw byte slice and silently produces a JKS that Java cannot read if it is handed SEC1 instead.
- `EncodePublicKeyPEM` is `x509.MarshalPKIXPublicKey` in a `PUBLIC KEY` block; `ParsePublicKeyPEM` is the inverse via `x509.ParsePKIXPublicKey`.
- `EncodePublicKeyOpenSSH` calls `ssh.NewPublicKey(pub)` and then `ssh.MarshalAuthorizedKey`, which already appends the newline. `ssh.NewPublicKey` rejects key types OpenSSH has no wire format for, so its error can be returned as-is with context.
- `PublicKeyFingerprintSHA256` calls `ssh.NewPublicKey`, hashes `sshPub.Marshal()` with `sha256.Sum256`, and renders `"SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])`. Use `RawStdEncoding`, not `StdEncoding`: OpenSSH omits the padding and the test asserts on that.
- `PublicKeyOf` type-switches over the three signer types and returns `k.Public()`; it exists only to keep call sites free of that switch.
- `PublicKeysEqual` returns false if either side is nil, then uses the `Equal` method every stdlib public key type implements: assert `a` to `interface{ Equal(crypto.PublicKey) bool }` and call it. Do not use `reflect.DeepEqual` — for ECDSA keys it compares unexported curve internals and gives false negatives across otherwise-identical keys.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -v
```

Expected: PASS, including every subcase of the three-algorithm loops.

- [ ] **Step 5: Cross-validate against `openssl`**

The unit tests prove Go can read what Go wrote. This step proves an outside consumer can too. Add a test that shells out to `openssl pkey -check`.

Create `internal/pki/testhelper_test.go` in this task with the shared `requireOpenSSL` helper; Tasks 6, 9, 10, 11, and 12 extend the same file with their own fixtures:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"os/exec"
	"testing"
)

// requireOpenSSL returns the path to the openssl binary, skipping the test when
// it is not installed. Cross-validation against a real parser is valuable but
// must never be the reason a contributor's test run fails.
func requireOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH; skipping cross-validation")
	}
	return path
}
```

The test, in `key_test.go`:

```go
func TestEmittedKeysAreReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	bin := requireOpenSSL(t)

	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		k, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		native, err := EncodePrivateKeyPEM(k)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM(%s): %v", alg, err)
		}
		pkcs8, err := EncodePrivateKeyPKCS8PEM(k)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8PEM(%s): %v", alg, err)
		}
		for label, encoded := range map[string][]byte{"native": native, "pkcs8": pkcs8} {
			cmd := exec.Command(bin, "pkey", "-noout", "-check")
			cmd.Stdin = bytes.NewReader(encoded)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("openssl pkey -check rejected the %s/%s key: %v\n%s", alg, label, err, out)
			}
		}
	}
}
```

`key_test.go` gains `bytes` and `os/exec` imports. Expected: PASS for all six combinations, or a clean skip where openssl is absent. If Ed25519's encoding were wrong, this is where it surfaces — `x509.MarshalPKCS8PrivateKey` is the only correct route for it, and a hand-rolled block type would fail here.

- [ ] **Step 6: Commit**

```bash
git add internal/pki/key.go internal/pki/key_test.go internal/pki/testhelper_test.go go.mod go.sum
git commit -m "feat: key generation, parsing, and encoding for RSA, ECDSA, Ed25519"
```

---

### Task 6: Subject DN (`subject.go`)

The highest-risk file in the package. DN attribute order and ASN.1 string type are both significant in DER, and byte-exact reproduction of the certificates already installed on devices depends on both.

**Files:**
- Create: `internal/pki/subject.go`
- Test: `internal/pki/subject_test.go`
- Modify: `internal/pki/testhelper_test.go` (add the `mustDNOID` fixture; Task 5 created the file)

**Interfaces:**
- Consumes: `ParseOID`, `FormatOID`, `DNAttributeOID` (Task 2).
- Produces:
  - `type StringType string` with `StringTypeUTF8 StringType = "utf8"`, `StringTypePrintable = "printable"`, `StringTypeIA5 = "ia5"`, `StringTypeBMP = "bmp"`, `StringTypeT61 = "t61"`
  - `type Attribute struct { OID asn1.ObjectIdentifier; Value string; StringType StringType }`
  - `type Subject struct { Attributes []Attribute }`
  - `type NamedSubject struct { CommonName, UID, GivenName, Surname, Organization, Locality, Province, PostalCode, Country, DNQualifier, SerialNumber string; OrganizationalUnits, StreetAddresses []string; ExtraAttributes []Attribute }`
  - `func (n NamedSubject) Expand() Subject` — canonical order
  - `func (s Subject) EncodeDER() ([]byte, error)`
  - `func ParseSubjectDER(der []byte) (Subject, error)`
  - `func (s Subject) IsEmpty() bool`
  - `func (s Subject) String() string` — RFC 4514-ish, for error messages and drift reports only
  - `func (s Subject) Equal(other Subject) bool` — compares encoded DER, not the struct

- [ ] **Step 1: Write the failing tests**

`internal/pki/subject_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func attr(t *testing.T, name, value string) Attribute {
	t.Helper()
	oid, err := DNAttributeOID(name)
	if err != nil {
		t.Fatalf("DNAttributeOID(%q): %v", name, err)
	}
	return Attribute{OID: oid, Value: value}
}

// TestNamedSubjectExpandCanonicalOrder pins the documented canonical order from
// spec section 5.1: CN, UID, GN, SN, O, OU..., L, ST, street, postalCode, C,
// dnQualifier, serialNumber. Changing this order changes every DN produced from
// a named-field config, which means every certificate replaces.
func TestNamedSubjectExpandCanonicalOrder(t *testing.T) {
	t.Parallel()
	n := NamedSubject{
		CommonName:          "cn",
		UID:                 "uid",
		GivenName:           "gn",
		Surname:             "sn",
		Organization:        "o",
		OrganizationalUnits: []string{"ou1", "ou2"},
		Locality:            "l",
		Province:            "st",
		StreetAddresses:     []string{"street1", "street2"},
		PostalCode:          "postal",
		Country:             "US",
		DNQualifier:         "dnq",
		SerialNumber:        "dnserial",
	}
	want := []string{
		"commonName", "uid", "givenName", "surname", "organization",
		"organizationalUnit", "organizationalUnit",
		"locality", "province", "streetAddress", "streetAddress",
		"postalCode", "country", "dnQualifier", "serialNumber",
	}
	got := n.Expand()
	if len(got.Attributes) != len(want) {
		t.Fatalf("Expand produced %d attributes, want %d: %s", len(got.Attributes), len(want), got.String())
	}
	for i, wantName := range want {
		gotName, err := NameByOID(FormatOID(got.Attributes[i].OID))
		if err != nil {
			t.Errorf("attribute %d has unknown OID %s", i, FormatOID(got.Attributes[i].OID))
			continue
		}
		if gotName != wantName {
			t.Errorf("attribute %d = %q, want %q", i, gotName, wantName)
		}
	}
	// Repeated attributes keep declaration order.
	if got.Attributes[5].Value != "ou1" || got.Attributes[6].Value != "ou2" {
		t.Errorf("OU order = %q, %q; want ou1, ou2", got.Attributes[5].Value, got.Attributes[6].Value)
	}
	if got.Attributes[9].Value != "street1" || got.Attributes[10].Value != "street2" {
		t.Errorf("street order = %q, %q; want street1, street2", got.Attributes[9].Value, got.Attributes[10].Value)
	}
}

func TestNamedSubjectExpandOmitsUnsetFields(t *testing.T) {
	t.Parallel()
	n := NamedSubject{CommonName: "only-cn"}
	got := n.Expand()
	if len(got.Attributes) != 1 {
		t.Fatalf("Expand produced %d attributes, want 1: %s", len(got.Attributes), got.String())
	}
	// An empty string is "unset", not "present and empty": openssl's config
	// format cannot express an empty DN value either, and emitting one would
	// produce a DN no other tool can reproduce.
	n2 := NamedSubject{CommonName: "cn", Organization: "", OrganizationalUnits: []string{"ou", "", "ou2"}}
	got2 := n2.Expand()
	if len(got2.Attributes) != 3 {
		t.Fatalf("Expand produced %d attributes, want 3 (cn, ou, ou2): %s", len(got2.Attributes), got2.String())
	}
}

func TestNamedSubjectExpandAppendsExtraAttributes(t *testing.T) {
	t.Parallel()
	// Spec section 5.1: extra_attribute blocks append after the named fields,
	// in declaration order.
	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	n := NamedSubject{
		CommonName:      "cn",
		Organization:    "o",
		ExtraAttributes: []Attribute{{OID: display, Value: "Nick V"}, {OID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "custom"}},
	}
	got := n.Expand()
	if len(got.Attributes) != 4 {
		t.Fatalf("Expand produced %d attributes, want 4: %s", len(got.Attributes), got.String())
	}
	if !got.Attributes[2].OID.Equal(display) || got.Attributes[2].Value != "Nick V" {
		t.Errorf("attribute 2 = %v/%q, want displayName/\"Nick V\"", got.Attributes[2].OID, got.Attributes[2].Value)
	}
	if !got.Attributes[3].OID.Equal(asn1.ObjectIdentifier{1, 2, 3, 4}) {
		t.Errorf("attribute 3 = %v, want 1.2.3.4", got.Attributes[3].OID)
	}
}

// TestExpandCannotReproduceEnginePyOrder documents the exact limitation that
// forces the ordered form to exist (spec section 5.1). engine.py emits
// displayName between UID and GN; the canonical order cannot, because
// displayName has no named field and therefore appends last.
func TestExpandCannotReproduceEnginePyOrder(t *testing.T) {
	t.Parallel()
	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	named := NamedSubject{
		CommonName:      "nick-ipad.ha.apps.somemissing.info",
		UID:             "nick",
		GivenName:       "Nick",
		Surname:         "Venenga",
		Organization:    "homelab",
		ExtraAttributes: []Attribute{{OID: display, Value: "Nick V"}},
	}.Expand()

	// The ordered form places displayName where engine.py puts it: after UID,
	// before GN (reconcile/engine.py lines 49-55).
	ordered := Subject{Attributes: []Attribute{
		attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
		attr(t, "uid", "nick"),
		{OID: display, Value: "Nick V"},
		attr(t, "givenName", "Nick"),
		attr(t, "surname", "Venenga"),
		attr(t, "organization", "homelab"),
	}}

	if named.Equal(ordered) {
		t.Fatal("named-field expansion matched engine.py's DN order; if the canonical order ever gains a displayName slot, update spec section 5.1 and this test together")
	}
}

// TestEncodeDEROneAttributePerRDN pins the structure: each attribute is its own
// single-element RDN SET, matching what openssl produces from a [dn] section.
// A multi-valued RDN would encode the same attributes into different bytes.
func TestEncodeDEROneAttributePerRDN(t *testing.T) {
	t.Parallel()
	s := Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		attr(t, "organization", "o"),
	}}
	der, err := s.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdns); err != nil {
		t.Fatalf("emitted DN does not unmarshal as an RDNSequence: %v", err)
	}
	if len(rdns) != 2 {
		t.Fatalf("DN has %d RDNs, want 2", len(rdns))
	}
	for i, rdn := range rdns {
		if len(rdn) != 1 {
			t.Errorf("RDN %d holds %d attributes, want exactly 1", i, len(rdn))
		}
	}
}

// TestEncodeDERDefaultsToUTF8String is the single most consequential assertion
// in this file. engine.py sets string_mask = utf8only (reconcile/engine.py line
// 62), so every certificate already on a device has a UTF8String DN. Go's
// asn1.Marshal of a Go string emits PrintableString when the value fits, which
// would produce different bytes for the same DN and make every imported
// certificate plan a replace.
func TestEncodeDERDefaultsToUTF8String(t *testing.T) {
	t.Parallel()
	s := Subject{Attributes: []Attribute{attr(t, "commonName", "plain-ascii")}}
	der, err := s.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	// ASN.1 tag 12 (0x0c) is UTF8String; tag 19 (0x13) is PrintableString.
	if bytes.IndexByte(der, 0x13) != -1 {
		t.Errorf("DN contains a PrintableString tag (0x13); every value must encode as UTF8String by default:\n% x", der)
	}
	if bytes.IndexByte(der, 0x0c) == -1 {
		t.Errorf("DN contains no UTF8String tag (0x0c):\n% x", der)
	}
}

func TestEncodeDERHonorsExplicitStringType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stringType StringType
		wantTag    byte
	}{
		{StringTypeUTF8, 0x0c},
		{StringTypePrintable, 0x13},
		{StringTypeIA5, 0x16},
	} {
		oid, err := DNAttributeOID("commonName")
		if err != nil {
			t.Fatalf("DNAttributeOID: %v", err)
		}
		s := Subject{Attributes: []Attribute{{OID: oid, Value: "value", StringType: tc.stringType}}}
		der, err := s.EncodeDER()
		if err != nil {
			t.Errorf("EncodeDER(%s): %v", tc.stringType, err)
			continue
		}
		if bytes.IndexByte(der, tc.wantTag) == -1 {
			t.Errorf("string type %s did not produce tag 0x%02x:\n% x", tc.stringType, tc.wantTag, der)
		}
	}
}

func TestEncodeDERRejectsInvalidStringTypeAndValue(t *testing.T) {
	t.Parallel()
	oid, err := DNAttributeOID("commonName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	for label, s := range map[string]Subject{
		"unknown string type": {Attributes: []Attribute{{OID: oid, Value: "v", StringType: "ebcdic"}}},
		"non-ascii in ia5":    {Attributes: []Attribute{{OID: oid, Value: "nïck", StringType: StringTypeIA5}}},
		"non-printable in printable": {Attributes: []Attribute{{OID: oid, Value: "a@b", StringType: StringTypePrintable}}},
		"nil oid":                    {Attributes: []Attribute{{Value: "v"}}},
		"empty value":                {Attributes: []Attribute{{OID: oid, Value: ""}}},
	} {
		if _, err := s.EncodeDER(); err == nil {
			t.Errorf("EncodeDER(%s) returned nil error, want an error", label)
		}
	}
}

// TestParseSubjectDERRoundTripsByteExact is the property spec section 8 needs:
// import parses a DN out of DER, and re-encoding what was parsed must produce
// the identical bytes -- otherwise the first plan after import is a replace.
func TestParseSubjectDERRoundTripsByteExact(t *testing.T) {
	t.Parallel()
	for label, original := range map[string]Subject{
		"utf8 default": {Attributes: []Attribute{
			attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
			attr(t, "uid", "nick"),
			attr(t, "givenName", "Nick"),
			attr(t, "surname", "Venenga"),
			attr(t, "organization", "homelab"),
		}},
		"mixed string types": {Attributes: []Attribute{
			{OID: mustDNOID(t, "commonName"), Value: "cn", StringType: StringTypePrintable},
			{OID: mustDNOID(t, "emailAddress"), Value: "nick@venenga.com", StringType: StringTypeIA5},
			{OID: mustDNOID(t, "organization"), Value: "homelab", StringType: StringTypeUTF8},
		}},
		"non-ascii value": {Attributes: []Attribute{
			attr(t, "commonName", "nïck-ipåd"),
			attr(t, "surname", "Venenga"),
		}},
		"repeated ou": {Attributes: []Attribute{
			attr(t, "commonName", "cn"),
			attr(t, "organizationalUnit", "infra"),
			attr(t, "organizationalUnit", "clients"),
		}},
		"unknown oid": {Attributes: []Attribute{
			attr(t, "commonName", "cn"),
			{OID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: "vendor-specific"},
		}},
	} {
		der, err := original.EncodeDER()
		if err != nil {
			t.Errorf("%s: EncodeDER: %v", label, err)
			continue
		}
		parsed, err := ParseSubjectDER(der)
		if err != nil {
			t.Errorf("%s: ParseSubjectDER: %v", label, err)
			continue
		}
		if len(parsed.Attributes) != len(original.Attributes) {
			t.Errorf("%s: parsed %d attributes, want %d", label, len(parsed.Attributes), len(original.Attributes))
			continue
		}
		for i := range parsed.Attributes {
			if !parsed.Attributes[i].OID.Equal(original.Attributes[i].OID) {
				t.Errorf("%s: attribute %d OID = %v, want %v", label, i, parsed.Attributes[i].OID, original.Attributes[i].OID)
			}
			if parsed.Attributes[i].Value != original.Attributes[i].Value {
				t.Errorf("%s: attribute %d value = %q, want %q", label, i, parsed.Attributes[i].Value, original.Attributes[i].Value)
			}
		}
		reencoded, err := parsed.EncodeDER()
		if err != nil {
			t.Errorf("%s: re-encoding a parsed subject: %v", label, err)
			continue
		}
		if !bytes.Equal(der, reencoded) {
			t.Errorf("%s: re-encode is not byte-exact\n original: % x\nre-encoded: % x", label, der, reencoded)
		}
	}
}

func TestParseSubjectDERFlattensMultiValuedRDNs(t *testing.T) {
	t.Parallel()
	// A DN produced elsewhere may pack several attributes into one RDN SET.
	// Parsing must not lose them; the ordered form flattens them in the
	// order they appear ON THE WIRE, which is not necessarily the order the
	// literal below declares -- see the sort note in the assertion.
	// Re-encoding will produce single-attribute RDNs, so this case is
	// deliberately NOT byte-exact -- it is the one shape import cannot
	// reproduce, and callers detect it by comparing the DER themselves.
	rdns := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			{Type: mustDNOID(t, "organization"), Value: "homelab"},
			{Type: mustDNOID(t, "organizationalUnit"), Value: "infra"},
		},
		pkix.RelativeDistinguishedNameSET{
			{Type: mustDNOID(t, "commonName"), Value: "cn"},
		},
	}
	der, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	parsed, err := ParseSubjectDER(der)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	if len(parsed.Attributes) != 3 {
		t.Fatalf("parsed %d attributes, want 3", len(parsed.Attributes))
	}

	// The expected order is infra, homelab, cn -- NOT the declaration order
	// above. DER requires the members of a SET OF to be sorted by their
	// encodings (X.690 11.6), and asn1.Marshal enforces it, so the
	// organizationalUnit ATV (which encodes to 30 0c ...) sorts before the
	// organization ATV (30 0e ...). The bytes this fixture produces really do
	// carry infra first, whatever the literal says.
	if parsed.Attributes[0].Value != "infra" || parsed.Attributes[1].Value != "homelab" || parsed.Attributes[2].Value != "cn" {
		t.Fatalf("flattened order = %q, %q, %q; want infra, homelab, cn (DER sorts SET OF members)",
			parsed.Attributes[0].Value, parsed.Attributes[1].Value, parsed.Attributes[2].Value)
	}

	// Guard the fixture itself: if a future edit collapses the first RDN to a
	// single attribute, the assertions above would still pass while no longer
	// testing a multi-valued RDN at all.
	var check rawRDNSequence
	if _, err := asn1.Unmarshal(der, &check); err != nil {
		t.Fatalf("re-parsing the fixture: %v", err)
	}
	if len(check) != 2 || len(check[0]) != 2 {
		t.Fatalf("fixture is no longer a 2-RDN sequence whose first RDN is multi-valued: %d RDNs, first holds %d",
			len(check), len(check[0]))
	}
}

func TestParseSubjectDERRejectsGarbage(t *testing.T) {
	t.Parallel()
	for label, in := range map[string][]byte{
		"empty":     {},
		"not asn1":  []byte("hello"),
		"truncated": {0x30, 0x10, 0x31},
	} {
		if _, err := ParseSubjectDER(in); err == nil {
			t.Errorf("ParseSubjectDER(%s) returned nil error, want an error", label)
		}
	}
}

func TestSubjectIsEmpty(t *testing.T) {
	t.Parallel()
	if !(Subject{}).IsEmpty() {
		t.Error("a zero Subject is not reported empty")
	}
	if !(Subject{Attributes: []Attribute{}}).IsEmpty() {
		t.Error("a Subject with an empty attribute slice is not reported empty")
	}
	if (Subject{Attributes: []Attribute{attr(t, "commonName", "cn")}}).IsEmpty() {
		t.Error("a Subject with one attribute is reported empty")
	}
}

// TestSubjectEqualComparesEncodedBytes is what makes a hand-written
// named-field config plan clean against an imported ordered-form state, per
// spec section 5.1: any config that encodes to the same DN must compare equal.
func TestSubjectEqualComparesEncodedBytes(t *testing.T) {
	t.Parallel()
	named := NamedSubject{CommonName: "cn", UID: "uid", GivenName: "gn", Surname: "sn", Organization: "o"}.Expand()
	ordered := Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		attr(t, "uid", "uid"),
		attr(t, "givenName", "gn"),
		attr(t, "surname", "sn"),
		attr(t, "organization", "o"),
	}}
	if !named.Equal(ordered) {
		t.Error("a named-field subject and the equivalent ordered subject did not compare equal")
	}

	reordered := Subject{Attributes: []Attribute{
		attr(t, "uid", "uid"),
		attr(t, "commonName", "cn"),
		attr(t, "givenName", "gn"),
		attr(t, "surname", "sn"),
		attr(t, "organization", "o"),
	}}
	if named.Equal(reordered) {
		t.Error("subjects differing only in attribute order compared equal; DN order is significant in DER")
	}

	differentStringType := Subject{Attributes: []Attribute{
		{OID: mustDNOID(t, "commonName"), Value: "cn", StringType: StringTypePrintable},
	}}
	sameValueUTF8 := Subject{Attributes: []Attribute{attr(t, "commonName", "cn")}}
	if differentStringType.Equal(sameValueUTF8) {
		t.Error("subjects differing only in ASN.1 string type compared equal; they encode to different bytes")
	}
}

func TestSubjectString(t *testing.T) {
	t.Parallel()
	// String() is for diagnostics only. It must render unknown OIDs in dotted
	// form rather than dropping them, so a drift report never hides an
	// attribute.
	s := Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		{OID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "custom"},
	}}
	got := s.String()
	if got != "CN=cn,1.2.3.4=custom" {
		t.Fatalf("String() = %q, want \"CN=cn,1.2.3.4=custom\"", got)
	}
	if (Subject{}).String() != "" {
		t.Fatalf("String() on an empty subject = %q, want \"\"", (Subject{}).String())
	}
}
```

Add this helper to `internal/pki/testhelper_test.go`, which Task 5 created (its import block gains `encoding/asn1`):

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"encoding/asn1"
	"testing"
)

// mustDNOID looks up a DN attribute OID or fails the test. It exists so table
// literals can stay expressions.
func mustDNOID(t *testing.T, name string) asn1.ObjectIdentifier {
	t.Helper()
	oid, err := DNAttributeOID(name)
	if err != nil {
		t.Fatalf("DNAttributeOID(%q): %v", name, err)
	}
	return oid
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'Subject|NamedSubject|Expand|EncodeDER|ParseSubjectDER' -v
```

Expected: FAIL to build with `undefined: Subject`, `undefined: NamedSubject`, `undefined: StringType`.

- [ ] **Step 3: Implement the types and `Expand`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"unicode"
)

// StringType names the ASN.1 string encoding used for a DN attribute value.
//
// This is not a cosmetic detail. The homelab issuer runs openssl with
// string_mask = utf8only, so every certificate already installed on a device
// encodes its DN values as UTF8String. Go's asn1.Marshal, handed a Go string,
// emits PrintableString whenever the value fits -- so re-encoding a parsed DN
// without remembering its original string type produces different bytes for the
// same logical name, and every imported certificate would plan a replace.
type StringType string

const (
	StringTypeUTF8      StringType = "utf8"
	StringTypePrintable StringType = "printable"
	StringTypeIA5       StringType = "ia5"
	StringTypeBMP       StringType = "bmp"
	StringTypeT61       StringType = "t61"
)

// asn1Tag maps a StringType to its ASN.1 universal tag number.
var asn1Tag = map[StringType]int{
	StringTypeUTF8:      asn1.TagUTF8String,      // 12
	StringTypePrintable: asn1.TagPrintableString, // 19
	StringTypeIA5:       asn1.TagIA5String,       // 22
	StringTypeBMP:       asn1.TagBMPString,       // 30 -- NOT 28, which is UniversalString (UCS-4)
	StringTypeT61:       asn1.TagT61String,       // 20
}

// Attribute is one DN attribute: an OID, a value, and the ASN.1 string type the
// value encodes as. A zero StringType means StringTypeUTF8.
type Attribute struct {
	OID        asn1.ObjectIdentifier
	Value      string
	StringType StringType
}

// Subject is a distinguished name as an ordered list of attributes, each of
// which becomes its own single-element RDN SET on encode.
//
// Order is significant in DER, so this type is a slice and never a map. The
// provider's ordered subject form maps to it directly; the named-field form
// reaches it through NamedSubject.Expand.
type Subject struct {
	Attributes []Attribute
}
```

`NamedSubject` holds the named fields plus `ExtraAttributes`. `Expand` appends in exactly the canonical order from spec §5.1 — `CN, UID, GN, SN, O, OU..., L, ST, street, postalCode, C, dnQualifier, serialNumber` — then appends `ExtraAttributes` verbatim. Write it as a linear sequence of appends with a tiny local closure that skips empty strings, and a loop for each repeatable field; do not build a map and sort it. Every attribute gets a zero `StringType`, which `EncodeDER` resolves to UTF8String.

The empty-string-is-unset rule from `TestNamedSubjectExpandOmitsUnsetFields` applies to list elements too: the `OrganizationalUnits` and `StreetAddresses` loops skip empty entries, matching `engine.py:57`'s `for ou in ous if ou`.

- [ ] **Step 4: Implement `EncodeDER` and `ParseSubjectDER`**

`EncodeDER` builds a `pkix.RDNSequence` with one `pkix.RelativeDistinguishedNameSET` per attribute, each holding one `pkix.AttributeTypeAndValue` whose `Value` is an `asn1.RawValue` carrying the chosen tag:

```go
// EncodeDER encodes the subject as a DER RDNSequence, the form that goes into
// x509.Certificate.RawSubject.
//
// Each attribute becomes its own single-element RDN SET. Multi-valued RDNs are
// not produced: openssl's [dn] config section cannot express them, so no
// certificate this provider needs to reproduce contains one. ParseSubjectDER
// still reads them, flattening in wire order.
func (s Subject) EncodeDER() ([]byte, error) {
	if len(s.Attributes) == 0 {
		// An empty DN is legal DER (an empty SEQUENCE) and is what a
		// subject-less certificate carries, so this is not an error.
		return asn1.Marshal(pkix.RDNSequence{})
	}

	rdns := make(pkix.RDNSequence, 0, len(s.Attributes))
	for i, a := range s.Attributes {
		if len(a.OID) == 0 {
			return nil, fmt.Errorf("subject attribute %d has no OID", i)
		}
		if a.Value == "" {
			return nil, fmt.Errorf("subject attribute %d (%s) has an empty value", i, FormatOID(a.OID))
		}
		st := a.StringType
		if st == "" {
			st = StringTypeUTF8
		}
		tag, ok := asn1Tag[st]
		if !ok {
			return nil, fmt.Errorf("subject attribute %d (%s): unknown string type %q", i, FormatOID(a.OID), a.StringType)
		}
		raw, err := encodeDirectoryString(st, tag, a.Value)
		if err != nil {
			return nil, fmt.Errorf("subject attribute %d (%s): %w", i, FormatOID(a.OID), err)
		}
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{
			{Type: a.OID, Value: raw},
		})
	}
	return asn1.Marshal(rdns)
}
```

`encodeDirectoryString` returns an `asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: ...}` after validating the value against the chosen type, and this validation is the part worth getting right:

- `StringTypeUTF8`: bytes are `[]byte(value)`; validate `utf8.ValidString`.
- `StringTypePrintable`: bytes are `[]byte(value)`; reject any rune outside the PrintableString repertoire (`A-Z`, `a-z`, `0-9`, space, and `'()+,-./:=?`). This is what rejects `"a@b"` in the test.
- `StringTypeIA5`: reject any rune above `unicode.MaxASCII`.
- `StringTypeT61`: reject any rune above `unicode.MaxASCII` as an approximation; T.61's full repertoire is not worth implementing and no input this provider handles needs it. Say so in a comment.
- `StringTypeBMP`: encode as big-endian UTF-16 (`unicode/utf16.Encode` over the runes, then two bytes per code unit); reject anything outside the BMP, meaning any code unit that came from a surrogate pair.

**Add tests for `bmp`, `t61`, and the unknown-tag parse path.** The test file above exercises only `utf8`, `printable`, and `ia5`, which means an incorrect tag number for `bmp` or `t61` would ship green — and the first draft of this plan did in fact specify the wrong tag for `bmp` (28, which is UniversalString, rather than 30). Three cases close that hole:

1. Encode a value as `StringTypeBMP` and as `StringTypeT61`, and assert the tag actually present in the emitted DER is 30 and 20 respectively. Read the tag off the wire rather than comparing against the `asn1Tag` map, or the test just restates the map to itself.
2. Assert the repertoire rejections: a non-ASCII rune under `t61`, and a rune outside the BMP (any astral character, which UTF-16 encodes as a surrogate pair) under `bmp`.
3. Assert `ParseSubjectDER` errors on an attribute whose value carries a string tag outside the five supported ones — construct one with an `asn1.RawValue` using, for instance, tag 27 (`GeneralString`). The prose already requires this rejection but nothing above exercises it.

Setting `Bytes` on an `asn1.RawValue` (rather than `FullBytes`) makes `asn1.Marshal` write the tag and length itself, which is what keeps the output canonical DER.

`ParseSubjectDER` cannot use `pkix.RDNSequence`. Its `pkix.AttributeTypeAndValue.Value` is an `any` that `encoding/asn1` fills with a plain Go `string`, discarding the tag — exactly the information this design exists to preserve. So parse into a parallel set of types that keep the value as an `asn1.RawValue`:

```go
// rawAttributeTypeAndValue mirrors pkix.AttributeTypeAndValue but keeps the
// value's ASN.1 tag, which pkix's `Value any` field throws away.
type rawAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// The "SET" suffix on this type name is load-bearing, not decoration:
// encoding/asn1's parseField decides whether a slice is a SET OF or a SEQUENCE
// OF by testing whether the type's name ends in "SET". Rename this and the
// parse fails with a tag mismatch. pkix.RelativeDistinguishedNameSET is named
// for the same reason.
type rawRelativeDistinguishedNameSET []rawAttributeTypeAndValue

type rawRDNSequence []rawRelativeDistinguishedNameSET
```

Unmarshal with a plain `asn1.Unmarshal(der, &seq)`, error on trailing bytes, then walk the sequence and each SET in order, appending one `Attribute` per entry — which is what flattens a multi-valued RDN in declaration order.

For each value, map `Value.Tag` back through a reverse of `asn1Tag` to a `StringType` and decode the bytes per type (UTF-16 big-endian for BMP, direct for the rest). An unrecognized tag is an error, not a passthrough: silently dropping a value's string type is precisely the failure mode that would make every imported certificate plan a replace.

- [ ] **Step 5: Implement `IsEmpty`, `Equal`, and `String`**

`IsEmpty` is `len(s.Attributes) == 0`.

`Equal` encodes both sides and compares bytes, returning false if either encode fails:

```go
// Equal reports whether two subjects encode to identical DER.
//
// Comparing encoded bytes rather than struct fields is what lets a
// hand-written named-field config plan clean against state imported in the
// ordered form: any two configs that produce the same DN are the same DN.
func (s Subject) Equal(other Subject) bool {
	a, err := s.EncodeDER()
	if err != nil {
		return false
	}
	b, err := other.EncodeDER()
	if err != nil {
		return false
	}
	return bytes.Equal(a, b)
}
```

`String` joins `SHORTNAME=value` pairs with `,`, using a small `map[string]string` from friendly name to the conventional RFC 4514 short form (`commonName` to `CN`, `organization` to `O`, `organizationalUnit` to `OU`, `country` to `C`, `locality` to `L`, `province` to `ST`, `streetAddress` to `STREET`, `serialNumber` to `SERIALNUMBER`, `surname` to `SN`, `givenName` to `GN`, `uid` to `UID`, `dnQualifier` to `DNQ`, `postalCode` to `POSTALCODE`, `emailAddress` to `EMAIL`), falling back to the dotted OID when there is no short form. No escaping of `,` or `=` in values: this output is for human-readable diagnostics only and is never parsed. Say that in the doc comment so nobody builds on it.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run 'Subject|NamedSubject|Expand|EncodeDER|ParseSubjectDER' -v
go test ./internal/pki/
```

Expected: PASS. If `TestEncodeDERDefaultsToUTF8String` fails, the `asn1.RawValue` is not being used and `asn1.Marshal` has fallen back to its own string-type selection — that is the bug this whole design decision exists to prevent, so fix it rather than relaxing the test.

- [ ] **Step 7: Commit**

```bash
git add internal/pki/subject.go internal/pki/subject_test.go internal/pki/testhelper_test.go
git commit -m "feat: ordered DN model with explicit ASN.1 string types"
```

---

### Task 7: Subject alternative names (`san.go`)

**Files:**
- Create: `internal/pki/san.go`
- Test: `internal/pki/san_test.go`

**Interfaces:**
- Consumes: `ParseOID`/`FormatOID` (Task 2), `Subject.IsEmpty` (Task 6).
- Produces:
  - `type SAN struct { DNSNames []string; EmailAddresses []string; IPAddresses []net.IP; URIs []string; Critical bool }`
  - `func (s SAN) IsEmpty() bool`
  - `func (s SAN) Extension(subjectEmpty bool) (pkix.Extension, error)` — returns the `2.5.29.17` extension, forcing `Critical` true when `subjectEmpty` is true
  - `func ParseSANExtension(ext pkix.Extension) (SAN, error)`
  - `func FindExtension(exts []pkix.Extension, oid asn1.ObjectIdentifier) (pkix.Extension, bool)` — shared helper used by Tasks 8, 9, and 14
  - `func ParseIPs(values []string) ([]net.IP, error)` — for the framework layer's string-typed config

- [ ] **Step 1: Write the failing tests**

`internal/pki/san_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"encoding/asn1"
	"net"
	"testing"
)

func TestSANExtensionOIDAndEmptiness(t *testing.T) {
	t.Parallel()
	if !(SAN{}).IsEmpty() {
		t.Error("a zero SAN is not reported empty")
	}
	// Critical alone does not make a SAN non-empty; there would be nothing to
	// mark critical.
	if !(SAN{Critical: true}).IsEmpty() {
		t.Error("a SAN with only Critical set is not reported empty")
	}
	if (SAN{DNSNames: []string{"a"}}).IsEmpty() {
		t.Error("a SAN with a DNS name is reported empty")
	}

	ext, err := SAN{DNSNames: []string{"a.example"}}.Extension(false)
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if got := FormatOID(ext.Id); got != "2.5.29.17" {
		t.Fatalf("SAN extension OID = %s, want 2.5.29.17", got)
	}
}

// TestSANRoundTripsAllFourTypes covers every GeneralName the provider supports
// (spec section 5.2). otherName, registeredID, and directoryName are out of
// scope and belong in extra_extension.
func TestSANRoundTripsAllFourTypes(t *testing.T) {
	t.Parallel()
	original := SAN{
		DNSNames:       []string{"nick-ipad.ha.apps.somemissing.info", "alt.example"},
		EmailAddresses: []string{"nick@venenga.com", "nijave@gmail.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.5"), net.ParseIP("fd00::5")},
		URIs:           []string{"spiffe://homelab/nick-ipad"},
	}
	ext, err := original.Extension(false)
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	parsed, err := ParseSANExtension(ext)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}

	if len(parsed.DNSNames) != 2 || parsed.DNSNames[0] != original.DNSNames[0] || parsed.DNSNames[1] != original.DNSNames[1] {
		t.Errorf("DNS names = %v, want %v", parsed.DNSNames, original.DNSNames)
	}
	if len(parsed.EmailAddresses) != 2 || parsed.EmailAddresses[0] != original.EmailAddresses[0] || parsed.EmailAddresses[1] != original.EmailAddresses[1] {
		t.Errorf("email addresses = %v, want %v", parsed.EmailAddresses, original.EmailAddresses)
	}
	if len(parsed.IPAddresses) != 2 {
		t.Fatalf("IP addresses = %v, want 2 entries", parsed.IPAddresses)
	}
	if !parsed.IPAddresses[0].Equal(original.IPAddresses[0]) || !parsed.IPAddresses[1].Equal(original.IPAddresses[1]) {
		t.Errorf("IP addresses = %v, want %v", parsed.IPAddresses, original.IPAddresses)
	}
	if len(parsed.URIs) != 1 || parsed.URIs[0] != original.URIs[0] {
		t.Errorf("URIs = %v, want %v", parsed.URIs, original.URIs)
	}
}

// TestSANPreservesWithinTypeOrder pins the ordering guarantee from spec section
// 5.2. Entries keep their declared order within a type, and types are emitted
// in the fixed order dns, email, ip, uri -- which is what both openssl's config
// ordering and Go's x509 marshaller produce for the homelab certificates
// (reconcile/engine.py lines 71-78 lists DNS first, then emails).
func TestSANPreservesWithinTypeOrder(t *testing.T) {
	t.Parallel()
	s := SAN{
		DNSNames:       []string{"z.example", "a.example", "m.example"},
		EmailAddresses: []string{"z@example.com", "a@example.com"},
	}
	ext, err := s.Extension(false)
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	parsed, err := ParseSANExtension(ext)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	for i, want := range s.DNSNames {
		if parsed.DNSNames[i] != want {
			t.Errorf("DNS name %d = %q, want %q; sorting is not permitted", i, parsed.DNSNames[i], want)
		}
	}
	for i, want := range s.EmailAddresses {
		if parsed.EmailAddresses[i] != want {
			t.Errorf("email %d = %q, want %q; sorting is not permitted", i, parsed.EmailAddresses[i], want)
		}
	}
}

// TestSANCriticalityForcedWhenSubjectEmpty implements RFC 5280 4.2.1.6: if the
// subject is empty the SAN must be marked critical, because it is then the only
// identity in the certificate.
func TestSANCriticalityForcedWhenSubjectEmpty(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		configured   bool
		subjectEmpty bool
		want         bool
	}{
		{configured: false, subjectEmpty: false, want: false},
		{configured: true, subjectEmpty: false, want: true},
		{configured: false, subjectEmpty: true, want: true}, // forced
		{configured: true, subjectEmpty: true, want: true},
	} {
		ext, err := SAN{DNSNames: []string{"a.example"}, Critical: tc.configured}.Extension(tc.subjectEmpty)
		if err != nil {
			t.Errorf("Extension(configured=%v, subjectEmpty=%v): %v", tc.configured, tc.subjectEmpty, err)
			continue
		}
		if ext.Critical != tc.want {
			t.Errorf("Extension(configured=%v, subjectEmpty=%v).Critical = %v, want %v",
				tc.configured, tc.subjectEmpty, ext.Critical, tc.want)
		}
	}
}

func TestSANExtensionRejectsEmptyAndInvalid(t *testing.T) {
	t.Parallel()
	// An empty SAN extension is invalid DER per RFC 5280 (GeneralNames must
	// have at least one entry); callers must omit the extension instead.
	if _, err := (SAN{}).Extension(false); err == nil {
		t.Error("Extension on an empty SAN returned nil error, want an error")
	}
	for label, s := range map[string]SAN{
		"nil ip":          {IPAddresses: []net.IP{nil}},
		"malformed ip":     {IPAddresses: []net.IP{{1, 2, 3}}},
		"empty dns":        {DNSNames: []string{""}},
		"empty email":      {EmailAddresses: []string{""}},
		"empty uri":        {URIs: []string{""}},
		"non-ascii dns":    {DNSNames: []string{"nïck.example"}},
		"non-ascii email":  {EmailAddresses: []string{"nïck@example.com"}},
		"unparseable uri":  {URIs: []string{":://nope"}},
		"relative uri":     {URIs: []string{"/just/a/path"}},
	} {
		if _, err := s.Extension(false); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestParseSANExtensionRejectsGarbage(t *testing.T) {
	t.Parallel()
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	for label, ext := range map[string]pkix.Extension{
		"wrong oid": {Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0x00}},
		"not asn1":  {Id: sanOID, Value: []byte("hello")},
		"empty":     {Id: sanOID, Value: nil},
	} {
		if _, err := ParseSANExtension(ext); err == nil {
			t.Errorf("ParseSANExtension(%s) returned nil error, want an error", label)
		}
	}
}

// TestParseSANExtensionIgnoresUnsupportedGeneralNames matters for import: a
// certificate issued elsewhere may carry an otherName. Parsing must not fail --
// that would make the certificate unimportable -- but the value cannot be
// represented, so the caller needs to know it was dropped.
func TestParseSANExtensionIgnoresUnsupportedGeneralNames(t *testing.T) {
	t.Parallel()
	// GeneralNames containing one dNSName [2] and one registeredID [8].
	value, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("a.example")},
		{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: []byte{0x2a, 0x03, 0x04}},
	})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	parsed, err := ParseSANExtension(pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value})
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "a.example" {
		t.Fatalf("DNS names = %v, want [a.example]", parsed.DNSNames)
	}
}

func TestParseIPs(t *testing.T) {
	t.Parallel()
	got, err := ParseIPs([]string{"10.0.0.5", "fd00::5"})
	if err != nil {
		t.Fatalf("ParseIPs: %v", err)
	}
	if len(got) != 2 || !got[0].Equal(net.ParseIP("10.0.0.5")) || !got[1].Equal(net.ParseIP("fd00::5")) {
		t.Fatalf("ParseIPs = %v, want [10.0.0.5 fd00::5]", got)
	}
	for _, bad := range [][]string{{"10.0.0.256"}, {"not-an-ip"}, {""}, {"10.0.0.0/24"}} {
		if _, err := ParseIPs(bad); err == nil {
			t.Errorf("ParseIPs(%v) returned nil error, want an error", bad)
		}
	}
}

func TestFindExtension(t *testing.T) {
	t.Parallel()
	exts := []pkix.Extension{
		{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{1}},
		{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{2}},
	}
	got, ok := FindExtension(exts, asn1.ObjectIdentifier{2, 5, 29, 17})
	if !ok || got.Value[0] != 2 {
		t.Fatalf("FindExtension returned %v, %v; want the SAN extension", got, ok)
	}
	if _, ok := FindExtension(exts, asn1.ObjectIdentifier{2, 5, 29, 19}); ok {
		t.Fatal("FindExtension found an extension that is not present")
	}
	if _, ok := FindExtension(nil, asn1.ObjectIdentifier{2, 5, 29, 19}); ok {
		t.Fatal("FindExtension on a nil slice reported a hit")
	}
}
```

`san_test.go` needs `crypto/x509/pkix` in its import block alongside `encoding/asn1` and `net`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'SAN|ParseIPs|FindExtension' -v
```

Expected: FAIL to build with `undefined: SAN`.

- [ ] **Step 3: Implement `san.go`**

Build the `GeneralNames` DER by hand rather than borrowing `x509`'s unexported marshaller. The four in-scope context-specific tags are `rfc822Name [1]`, `dNSName [2]`, `uniformResourceIdentifier [6]`, and `iPAddress [7]`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"unicode"
)

// GeneralName context-specific tags from RFC 5280 4.2.1.6. otherName [0],
// x400Address [3], directoryName [4], ediPartyName [5], and registeredID [8]
// are out of scope for this provider; extra_extension is the escape hatch if
// one is ever needed.
const (
	sanTagEmail = 1
	sanTagDNS   = 2
	sanTagURI   = 6
	sanTagIP    = 7
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// SAN is a subjectAltName extension in the four GeneralName types Go's
// x509.Certificate represents natively.
//
// Entry order within a type is preserved on encode; types are emitted in the
// fixed order dns, email, ip, uri. That order matches what openssl produces
// from an [alt] config section listing DNS before email, which is what the
// certificates this provider must adopt contain.
type SAN struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []string
	Critical       bool
}
```

`Extension` validates, then marshals:

- Error if `IsEmpty()`: an empty `GeneralNames` is invalid DER and the caller must omit the extension entirely.
- DNS names and email addresses are `IA5String` per RFC 5280, so reject any rune above `unicode.MaxASCII` and reject the empty string. Do not attempt to validate hostname or mailbox syntax beyond that — `engine.py` did not, and rejecting a name the existing setup issued would block adoption.
- URIs must parse with `url.Parse` and must be absolute (`u.IsAbs()`), which is what rejects `"/just/a/path"`. The bytes written are the original string, not `u.String()`, so a URI survives a round trip unchanged.
- IPs must be non-nil and must convert to either 4 or 16 bytes: use `ip.To4()` first and fall back to `ip.To16()`, erroring if both are nil. Writing the 4-byte form for IPv4 is what openssl and Go both do; writing the 16-byte IPv4-mapped form instead would produce a SAN that renders as `::ffff:10.0.0.5`.
- Each entry becomes an `asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: <tag>, Bytes: <payload>}`, and the whole list is `asn1.Marshal([]asn1.RawValue{...})`. The result is the extension's `Value`.
- `Critical` is `s.Critical || subjectEmpty`.

`ParseSANExtension` checks the OID matches, unmarshals into `[]asn1.RawValue` with a trailing-bytes check, then switches on `Tag` for the four supported values and appends to the matching slice. `IP` entries take `net.IP(rv.Bytes)` after checking the length is 4 or 16. Any other tag is skipped silently — a certificate issued elsewhere may carry an `otherName`, and failing to parse would make it unimportable, which is worse than dropping a name the provider cannot represent. Note in the doc comment that a dropped name means re-encoding will not be byte-exact, and that Task 14's comparison catches this by comparing the raw extension bytes rather than the parsed struct.

`ParseIPs` maps strings through `net.ParseIP`, erroring with the offending value on any failure. `net.ParseIP` rejects CIDR notation and empty strings already.

`FindExtension` is a linear scan returning the first match; extensions are a handful of entries, so no indexing.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run 'SAN|ParseIPs|FindExtension' -v
go test ./internal/pki/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/san.go internal/pki/san_test.go
git commit -m "feat: SAN extension build and parse for dns, email, ip, uri"
```

---

### Task 8: Extensions (`extensions.go`)

Full control over basicConstraints, keyUsage, extendedKeyUsage, nameConstraints, and arbitrary extensions — including criticality, which `hashicorp/tls` hardcodes.

**Files:**
- Create: `internal/pki/extensions.go`
- Test: `internal/pki/extensions_test.go`

**Interfaces:**
- Consumes: `KeyUsageBit`, `ExtKeyUsageOID`, `ParseOID`, `FormatOID` (Task 2); `FindExtension` (Task 7).
- Produces:
  - `type BasicConstraints struct { CA bool; PathLen *int; Critical bool }`
  - `type KeyUsage struct { Usages []string; Critical bool }`
  - `type ExtKeyUsage struct { Usages []string; Critical bool }`
  - `type NameConstraints struct { PermittedDNSDomains, ExcludedDNSDomains, PermittedEmailDomains, ExcludedEmailDomains, PermittedIPRanges, ExcludedIPRanges, PermittedURIDomains, ExcludedURIDomains []string; Critical bool }`
  - `type ExtraExtension struct { OID asn1.ObjectIdentifier; Value []byte; Critical bool }`
  - `func (bc BasicConstraints) Extension() (pkix.Extension, error)` and the same method on `KeyUsage`, `ExtKeyUsage`, `NameConstraints`, `ExtraExtension`
  - `func ParseBasicConstraints(ext pkix.Extension) (BasicConstraints, error)`, `func ParseKeyUsage(ext pkix.Extension) (KeyUsage, error)`, `func ParseExtKeyUsage(ext pkix.Extension) (ExtKeyUsage, error)`, `func ParseNameConstraints(ext pkix.Extension) (NameConstraints, error)`
  - `func DefaultCAKeyUsage() KeyUsage` — `keyCertSign`, `crlSign`, critical
  - `func DefaultLeafKeyUsage() KeyUsage` — `digitalSignature`, `keyEncipherment`, critical (matching `engine.py:84`)
  - `func SubjectKeyIDExtension(pub crypto.PublicKey) (pkix.Extension, error)`
  - Package-level OID vars: `oidBasicConstraints`, `oidKeyUsage`, `oidExtKeyUsage`, `oidNameConstraints`, `oidSubjectKeyID`, `oidAuthorityKeyID`

- [ ] **Step 1: Write the failing tests**

`internal/pki/extensions_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func intPtr(n int) *int { return &n }

// TestBasicConstraintsPathLenNullVersusZero is the distinction spec section 5.3
// calls out: X.509 draws a real difference between pathLenConstraint = 0 (this
// CA may not issue further CAs) and no constraint at all (unlimited depth).
// A zero-defaulted int cannot express it.
func TestBasicConstraintsPathLenNullVersusZero(t *testing.T) {
	t.Parallel()

	unlimited, err := BasicConstraints{CA: true, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension (unlimited): %v", err)
	}
	zero, err := BasicConstraints{CA: true, PathLen: intPtr(0), Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension (pathLen 0): %v", err)
	}
	if string(unlimited.Value) == string(zero.Value) {
		t.Fatal("pathLen unset and pathLen 0 encoded to the same bytes; they are different constraints")
	}

	back, err := ParseBasicConstraints(unlimited)
	if err != nil {
		t.Fatalf("ParseBasicConstraints (unlimited): %v", err)
	}
	if back.PathLen != nil {
		t.Errorf("unlimited round-tripped to PathLen = %d, want nil", *back.PathLen)
	}
	back, err = ParseBasicConstraints(zero)
	if err != nil {
		t.Fatalf("ParseBasicConstraints (pathLen 0): %v", err)
	}
	if back.PathLen == nil || *back.PathLen != 0 {
		t.Errorf("pathLen 0 round-tripped to %v, want a pointer to 0", back.PathLen)
	}
}

func TestBasicConstraintsRoundTrip(t *testing.T) {
	t.Parallel()
	for label, bc := range map[string]BasicConstraints{
		"ca unlimited":  {CA: true, Critical: true},
		"ca pathlen 0":  {CA: true, PathLen: intPtr(0), Critical: true},
		"ca pathlen 3":  {CA: true, PathLen: intPtr(3), Critical: true},
		"leaf":          {CA: false, Critical: true},
		"leaf noncrit":  {CA: false, Critical: false},
	} {
		ext, err := bc.Extension()
		if err != nil {
			t.Errorf("%s: Extension: %v", label, err)
			continue
		}
		if FormatOID(ext.Id) != "2.5.29.19" {
			t.Errorf("%s: OID = %s, want 2.5.29.19", label, FormatOID(ext.Id))
		}
		if ext.Critical != bc.Critical {
			t.Errorf("%s: Critical = %v, want %v", label, ext.Critical, bc.Critical)
		}
		got, err := ParseBasicConstraints(ext)
		if err != nil {
			t.Errorf("%s: ParseBasicConstraints: %v", label, err)
			continue
		}
		if got.CA != bc.CA || got.Critical != bc.Critical {
			t.Errorf("%s: round-tripped to %+v, want CA=%v Critical=%v", label, got, bc.CA, bc.Critical)
		}
	}
}

func TestBasicConstraintsRejectsPathLenOnNonCA(t *testing.T) {
	t.Parallel()
	// pathLenConstraint is meaningful only when cA is true (RFC 5280 4.2.1.9).
	// Silently dropping it would hide a config error.
	if _, err := (BasicConstraints{CA: false, PathLen: intPtr(0)}).Extension(); err == nil {
		t.Error("Extension with pathLen on a non-CA returned nil error, want an error")
	}
	if _, err := (BasicConstraints{CA: true, PathLen: intPtr(-1)}).Extension(); err == nil {
		t.Error("Extension with a negative pathLen returned nil error, want an error")
	}
}

func TestKeyUsageRoundTrip(t *testing.T) {
	t.Parallel()
	ku := KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment", "keyCertSign", "crlSign"}, Critical: true}
	ext, err := ku.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.15" {
		t.Fatalf("OID = %s, want 2.5.29.15", FormatOID(ext.Id))
	}
	if !ext.Critical {
		t.Error("Critical = false, want true")
	}
	got, err := ParseKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseKeyUsage: %v", err)
	}
	// Parsing returns usages in RFC 5280 bit order, which is canonical and
	// independent of config order.
	want := []string{"digitalSignature", "keyEncipherment", "keyCertSign", "crlSign"}
	if len(got.Usages) != len(want) {
		t.Fatalf("parsed usages = %v, want %v", got.Usages, want)
	}
	for i := range want {
		if got.Usages[i] != want[i] {
			t.Errorf("usage %d = %q, want %q", i, got.Usages[i], want[i])
		}
	}
}

// TestKeyUsageConfigOrderDoesNotChangeBytes prevents a spurious replace when
// someone reorders the usages list in HCL. Key usage is a BIT STRING; order is
// not representable and must not be treated as significant.
func TestKeyUsageConfigOrderDoesNotChangeBytes(t *testing.T) {
	t.Parallel()
	a, err := KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	b, err := KeyUsage{Usages: []string{"keyEncipherment", "digitalSignature"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if string(a.Value) != string(b.Value) {
		t.Fatal("reordering the usages list changed the encoded bytes")
	}
}

func TestKeyUsageRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, ku := range map[string]KeyUsage{
		"empty":     {Usages: nil, Critical: true},
		"unknown":   {Usages: []string{"digitalSignatures"}},
		"duplicate": {Usages: []string{"crlSign", "crlSign"}},
		"blank":     {Usages: []string{""}},
	} {
		if _, err := ku.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestKeyUsageDecipherOnlyCrossesTheByteBoundary(t *testing.T) {
	t.Parallel()
	// decipherOnly is bit 8, the first bit in the second octet. A BIT STRING
	// encoder that assumes one byte silently drops it.
	ext, err := KeyUsage{Usages: []string{"decipherOnly"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	got, err := ParseKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseKeyUsage: %v", err)
	}
	if len(got.Usages) != 1 || got.Usages[0] != "decipherOnly" {
		t.Fatalf("round-tripped to %v, want [decipherOnly]", got.Usages)
	}
}

func TestExtKeyUsageRoundTripWithNamesAndRawOIDs(t *testing.T) {
	t.Parallel()
	// Spec section 5.3 mixes both forms in one list.
	eku := ExtKeyUsage{Usages: []string{"clientAuth", "1.3.6.1.4.1.311.20.2.2"}, Critical: false}
	ext, err := eku.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.37" {
		t.Fatalf("OID = %s, want 2.5.29.37", FormatOID(ext.Id))
	}
	if ext.Critical {
		t.Error("Critical = true, want false; extendedKeyUsage defaults to non-critical")
	}
	got, err := ParseExtKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}
	// Parsing renders a known OID as its friendly name and an unknown one in
	// dotted form, preserving the order the extension carries.
	if len(got.Usages) != 2 || got.Usages[0] != "clientAuth" || got.Usages[1] != "microsoftSmartcardLogon" {
		t.Fatalf("parsed usages = %v, want [clientAuth microsoftSmartcardLogon]", got.Usages)
	}
}

func TestExtKeyUsageParsesTrulyUnknownOIDAsDotted(t *testing.T) {
	t.Parallel()
	ext, err := ExtKeyUsage{Usages: []string{"1.3.6.1.4.1.99999.7"}}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	got, err := ParseExtKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}
	if len(got.Usages) != 1 || got.Usages[0] != "1.3.6.1.4.1.99999.7" {
		t.Fatalf("parsed usages = %v, want [1.3.6.1.4.1.99999.7]", got.Usages)
	}
}

func TestExtKeyUsageRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, eku := range map[string]ExtKeyUsage{
		"empty":       {Usages: nil},
		"unknown name": {Usages: []string{"clientAuthh"}},
		"bad oid":      {Usages: []string{"1.2.x"}},
		"duplicate":    {Usages: []string{"clientAuth", "clientAuth"}},
	} {
		if _, err := eku.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestNameConstraintsRoundTrip(t *testing.T) {
	t.Parallel()
	nc := NameConstraints{
		PermittedDNSDomains:   []string{".ha.apps.somemissing.info"},
		ExcludedDNSDomains:    []string{"bad.example"},
		PermittedEmailDomains: []string{"venenga.com"},
		PermittedIPRanges:     []string{"10.0.0.0/8", "fd00::/8"},
		PermittedURIDomains:   []string{".homelab"},
		Critical:              true,
	}
	ext, err := nc.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.30" {
		t.Fatalf("OID = %s, want 2.5.29.30", FormatOID(ext.Id))
	}
	if !ext.Critical {
		t.Error("Critical = false, want true; nameConstraints defaults to critical")
	}
	got, err := ParseNameConstraints(ext)
	if err != nil {
		t.Fatalf("ParseNameConstraints: %v", err)
	}
	if len(got.PermittedDNSDomains) != 1 || got.PermittedDNSDomains[0] != ".ha.apps.somemissing.info" {
		t.Errorf("permitted DNS = %v, want [.ha.apps.somemissing.info]", got.PermittedDNSDomains)
	}
	if len(got.ExcludedDNSDomains) != 1 || got.ExcludedDNSDomains[0] != "bad.example" {
		t.Errorf("excluded DNS = %v, want [bad.example]", got.ExcludedDNSDomains)
	}
	if len(got.PermittedIPRanges) != 2 {
		t.Errorf("permitted IP ranges = %v, want 2 entries", got.PermittedIPRanges)
	}
}

func TestNameConstraintsRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, nc := range map[string]NameConstraints{
		"all empty":      {Critical: true},
		"bad cidr":       {PermittedIPRanges: []string{"10.0.0.0/33"}},
		"bare ip":        {PermittedIPRanges: []string{"10.0.0.1"}},
		"empty dns":      {PermittedDNSDomains: []string{""}},
	} {
		if _, err := nc.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestExtraExtension(t *testing.T) {
	t.Parallel()
	// Spec section 5.3's example: raw DER of the extnValue, supplied base64 in
	// HCL and decoded before it reaches this type.
	value := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	ext, err := ExtraExtension{OID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: value, Critical: false}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "1.3.6.1.5.5.7.1.24" {
		t.Errorf("OID = %s, want 1.3.6.1.5.5.7.1.24", FormatOID(ext.Id))
	}
	if string(ext.Value) != string(value) {
		t.Errorf("Value = % x, want % x; the DER must pass through untouched", ext.Value, value)
	}
	for label, e := range map[string]ExtraExtension{
		"no oid":    {Value: value},
		"no value":  {OID: asn1.ObjectIdentifier{1, 2, 3}},
		"short oid": {OID: asn1.ObjectIdentifier{1}, Value: value},
	} {
		if _, err := e.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestDefaultKeyUsages(t *testing.T) {
	t.Parallel()
	ca := DefaultCAKeyUsage()
	if !ca.Critical {
		t.Error("the default CA key usage is not critical")
	}
	if len(ca.Usages) != 2 || ca.Usages[0] != "keyCertSign" || ca.Usages[1] != "crlSign" {
		t.Errorf("default CA usages = %v, want [keyCertSign crlSign]", ca.Usages)
	}

	// The leaf default reproduces reconcile/engine.py line 84:
	// keyUsage = critical, digitalSignature, keyEncipherment
	leaf := DefaultLeafKeyUsage()
	if !leaf.Critical {
		t.Error("the default leaf key usage is not critical")
	}
	if len(leaf.Usages) != 2 || leaf.Usages[0] != "digitalSignature" || leaf.Usages[1] != "keyEncipherment" {
		t.Errorf("default leaf usages = %v, want [digitalSignature keyEncipherment]", leaf.Usages)
	}
}

// TestSubjectKeyIDExtension pins the RFC 5280 method 1 computation: the SHA-1
// of the subjectPublicKey BIT STRING contents. engine.py asks openssl for
// "subjectKeyIdentifier = hash", which is the same algorithm, so an imported
// certificate's SKI must match what this produces.
func TestSubjectKeyIDExtension(t *testing.T) {
	t.Parallel()
	k, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ext, err := SubjectKeyIDExtension(PublicKeyOf(k))
	if err != nil {
		t.Fatalf("SubjectKeyIDExtension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.14" {
		t.Errorf("OID = %s, want 2.5.29.14", FormatOID(ext.Id))
	}
	if ext.Critical {
		t.Error("Critical = true; subjectKeyIdentifier must be non-critical per RFC 5280 4.2.1.2")
	}
	var ski []byte
	if _, err := asn1.Unmarshal(ext.Value, &ski); err != nil {
		t.Fatalf("SKI value does not unmarshal as an OCTET STRING: %v", err)
	}
	if len(ski) != 20 {
		t.Fatalf("SKI is %d bytes, want 20 (SHA-1)", len(ski))
	}
	// Deterministic for a given key.
	again, err := SubjectKeyIDExtension(PublicKeyOf(k))
	if err != nil {
		t.Fatalf("SubjectKeyIDExtension (second call): %v", err)
	}
	if string(again.Value) != string(ext.Value) {
		t.Fatal("SubjectKeyIDExtension is not deterministic for the same key")
	}
}

// TestParsersRejectWrongOID confirms each parser checks the extension's OID.
//
// Each case must carry a value that is VALID for that parser's own extension,
// presented under the wrong OID. Sharing one placeholder value across all four
// -- an empty SEQUENCE, say -- makes the test near-vacuous: every parser then
// fails on the malformed value rather than on the OID, so deleting three of the
// four OID guards leaves the suite green. Verified by doing exactly that.
func TestParsersRejectWrongOID(t *testing.T) {
	t.Parallel()
	const wrongOID = "2.5.29.99"

	// A valid basicConstraints value: SEQUENCE { cA TRUE }.
	bcValue, err := (BasicConstraints{CA: true, Critical: true}).Extension()
	if err != nil {
		t.Fatalf("building a valid basicConstraints value: %v", err)
	}
	// A valid keyUsage BIT STRING.
	kuValue, err := (KeyUsage{Usages: []string{"digitalSignature"}, Critical: true}).Extension()
	if err != nil {
		t.Fatalf("building a valid keyUsage value: %v", err)
	}
	// A valid extendedKeyUsage SEQUENCE OF OID.
	ekuValue, err := (ExtKeyUsage{Usages: []string{"clientAuth"}}).Extension()
	if err != nil {
		t.Fatalf("building a valid extendedKeyUsage value: %v", err)
	}
	// A valid nameConstraints SEQUENCE with one permitted subtree.
	ncValue, err := (NameConstraints{PermittedDNSDomains: []string{".example"}, Critical: true}).Extension()
	if err != nil {
		t.Fatalf("building a valid nameConstraints value: %v", err)
	}

	misfiled := func(v pkix.Extension) pkix.Extension {
		return pkix.Extension{Id: mustOID(t, wrongOID), Critical: v.Critical, Value: v.Value}
	}

	if _, err := ParseBasicConstraints(misfiled(bcValue)); err == nil {
		t.Error("ParseBasicConstraints accepted a valid value under the wrong OID")
	}
	if _, err := ParseKeyUsage(misfiled(kuValue)); err == nil {
		t.Error("ParseKeyUsage accepted a valid value under the wrong OID")
	}
	if _, err := ParseExtKeyUsage(misfiled(ekuValue)); err == nil {
		t.Error("ParseExtKeyUsage accepted a valid value under the wrong OID")
	}
	if _, err := ParseNameConstraints(misfiled(ncValue)); err == nil {
		t.Error("ParseNameConstraints accepted a valid value under the wrong OID")
	}

	// Sanity check the fixtures: each value must parse cleanly under its own
	// OID, or the assertions above would pass for the wrong reason.
	if _, err := ParseBasicConstraints(bcValue); err != nil {
		t.Errorf("the basicConstraints fixture does not parse under its own OID: %v", err)
	}
	if _, err := ParseKeyUsage(kuValue); err != nil {
		t.Errorf("the keyUsage fixture does not parse under its own OID: %v", err)
	}
	if _, err := ParseExtKeyUsage(ekuValue); err != nil {
		t.Errorf("the extendedKeyUsage fixture does not parse under its own OID: %v", err)
	}
	if _, err := ParseNameConstraints(ncValue); err != nil {
		t.Errorf("the nameConstraints fixture does not parse under its own OID: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'BasicConstraints|KeyUsage|ExtKeyUsage|NameConstraints|ExtraExtension|SubjectKeyID|Parsers' -v
```

Expected: FAIL to build with `undefined: BasicConstraints`.

- [ ] **Step 3: Implement the extension builders**

Every `Extension()` method returns a `pkix.Extension` whose `Value` is the DER of the extension's `extnValue` content — not the wrapping OCTET STRING, which `x509.CreateCertificate` adds.

- `BasicConstraints.Extension` marshals `struct { IsCA bool "asn1:\"optional\""; MaxPathLen int "asn1:\"optional,default:-1\"" }`. Do not use that stdlib-style struct: with `default:-1` the encoder omits the field when it equals -1, which conflates "unset" with a real -1. Instead define two local structs, one with the pathLen field and one without, and choose based on `PathLen == nil`. That is the mechanism that makes `TestBasicConstraintsPathLenNullVersusZero` pass. Validate that `PathLen` is nil when `CA` is false, and non-negative when set.
- `KeyUsage.Extension` maps names through `KeyUsageBit`, rejecting an empty list, an unknown name, and a duplicate (track seen bits in a `map[int]bool`). Build an `asn1.BitString` whose `Bytes` is `(maxBit/8)+1` octets with each used bit set most-significant-first, and whose `BitLength` is `maxBit+1`. Trim trailing all-zero octets so the encoding is canonical: RFC 5280 requires the DER minimal form, and `openssl x509 -text` renders a non-minimal BIT STRING differently. Setting `BitLength` from the highest set bit rather than from a fixed 9 is what makes `TestKeyUsageConfigOrderDoesNotChangeBytes` and `TestKeyUsageDecipherOnlyCrossesTheByteBoundary` both pass.
- `ExtKeyUsage.Extension` maps each entry through `ExtKeyUsageOID` (which accepts a name or a dotted OID), rejects empty and duplicates, and marshals `[]asn1.ObjectIdentifier` preserving list order.
- `NameConstraints.Extension` marshals RFC 5280's `NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }` where each `GeneralSubtree ::= SEQUENCE { base GeneralName, ... }`. Model it with local structs and `asn1.RawValue` bases carrying the same context-specific tags Task 7 defined, plus tag 7 for IP ranges, whose payload is the 4-or-16-byte address followed by the equal-length mask (8 or 32 bytes total) per RFC 5280 4.2.1.10. Parse CIDRs with `net.ParseCIDR` and reject a bare IP — `net.ParseCIDR` already does. Error when every list is empty.
- `ExtraExtension.Extension` validates the OID has at least two arcs and the value is non-empty, then passes the bytes through verbatim. No parsing or re-encoding: the whole point is that the provider does not need to understand the extension.
- `SubjectKeyIDExtension` marshals the public key with `x509.MarshalPKIXPublicKey`, unmarshals it into `struct { Algo pkix.AlgorithmIdentifier; SubjectPublicKey asn1.BitString }`, takes `sha1.Sum` of `SubjectPublicKey.Bytes`, and marshals that 20-byte digest as an OCTET STRING. Add a comment that SHA-1 here is a key identifier, not a signature, and is RFC 5280's method 1 — required for interoperability with the certificates already issued, and not a security decision open to revision.

The parsers are the mirror image: verify the OID, unmarshal, check for trailing bytes, and map back to names. `ParseKeyUsage` walks bits 0 through 8 and emits names in bit order. `ParseExtKeyUsage` renders each OID through `NameByOID`, falling back to `FormatOID` on a miss.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run 'BasicConstraints|KeyUsage|ExtKeyUsage|NameConstraints|ExtraExtension|SubjectKeyID|Parsers' -v
go test ./internal/pki/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/extensions.go internal/pki/extensions_test.go
git commit -m "feat: extension builders with explicit criticality and pathLen null handling"
```

---

### Task 9: Signing (`sign.go`)

CSR creation and certificate issuance. Every field is supplied explicitly through `RawSubject` and `ExtraExtensions`; none of `x509.Certificate`'s convenience fields are used for anything the provider exposes, because Go would then emit a second copy of the same extension with its own criticality.

**Files:**
- Create: `internal/pki/sign.go`
- Test: `internal/pki/sign_test.go`
- Modify: `internal/pki/testhelper_test.go` (add certificate fixtures and the `openssl x509 -text` helper)
- Modify: `internal/pki/subject_test.go` (fill in `TestSubjectDERIsReadableByOpenSSL`, which Task 6 left skipped)

**Interfaces:**
- Consumes: everything from Tasks 2 through 8.
- Produces:
  - `type CertRequestTemplate struct { Subject Subject; SAN SAN; ExtraExtensions []ExtraExtension; SignatureAlgorithm x509.SignatureAlgorithm }`
  - `func CreateCertRequest(key crypto.Signer, t CertRequestTemplate) ([]byte, error)` — returns PEM
  - `func ParseCertRequestPEM(b []byte) (*x509.CertificateRequest, error)` — verifies the signature and returns an error if it does not check out
  - `type CertTemplate struct { Subject Subject; SAN SAN; Serial *big.Int; NotBefore, NotAfter time.Time; BasicConstraints *BasicConstraints; KeyUsage *KeyUsage; ExtKeyUsage *ExtKeyUsage; NameConstraints *NameConstraints; ExtraExtensions []ExtraExtension; SignatureAlgorithm x509.SignatureAlgorithm }`
  - `func (t CertTemplate) Extensions(pub crypto.PublicKey) ([]pkix.Extension, error)` — the ordered extension list, exported because Task 14 compares against it
  - `func CreateCertificate(t CertTemplate, pub crypto.PublicKey, parent *x509.Certificate, signerKey crypto.Signer) ([]byte, error)` — `parent == nil` self-signs
  - `func ParseCertificatePEM(b []byte) (*x509.Certificate, error)`
  - `func ParseCertificateChainPEM(b []byte) ([]*x509.Certificate, error)`
  - `func EncodeCertificatePEM(der []byte) []byte`
  - `func DefaultSignatureAlgorithm(k crypto.Signer) (x509.SignatureAlgorithm, error)`

- [ ] **Step 1: Write the failing tests**

`internal/pki/sign_test.go`. This is the longest test file in the package; the cases below are the ones that catch real failures rather than restating the implementation.

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestCreateCertRequestRoundTrip(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	subject := NamedSubject{
		CommonName:   "nick-ipad.ha.apps.somemissing.info",
		UID:          "nick",
		GivenName:    "Nick",
		Surname:      "Venenga",
		Organization: "homelab",
	}.Expand()
	san := SAN{
		DNSNames:       []string{"nick-ipad.ha.apps.somemissing.info"},
		EmailAddresses: []string{"nick@venenga.com", "nijave@gmail.com"},
	}

	csrPEM, err := CreateCertRequest(key, CertRequestTemplate{Subject: subject, SAN: san})
	if err != nil {
		t.Fatalf("CreateCertRequest: %v", err)
	}
	csr, err := ParseCertRequestPEM(csrPEM)
	if err != nil {
		t.Fatalf("ParseCertRequestPEM: %v", err)
	}

	wantDN, err := subject.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	if !bytes.Equal(csr.RawSubject, wantDN) {
		t.Errorf("CSR subject is not byte-identical to the template's DN\n want: % x\n  got: % x", wantDN, csr.RawSubject)
	}

	parsedSubject, err := ParseSubjectDER(csr.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	if !parsedSubject.Equal(subject) {
		t.Errorf("CSR subject = %s, want %s", parsedSubject.String(), subject.String())
	}

	sanExt, ok := FindExtension(csr.Extensions, oidSubjectAltName)
	if !ok {
		t.Fatal("CSR carries no subjectAltName extension")
	}
	parsedSAN, err := ParseSANExtension(sanExt)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	if len(parsedSAN.EmailAddresses) != 2 {
		t.Errorf("CSR SAN email addresses = %v, want 2 entries", parsedSAN.EmailAddresses)
	}
}

func TestParseCertRequestPEMRejectsABrokenSignature(t *testing.T) {
	t.Parallel()
	// data "pki_cert_request" reports signature_valid, and a CSR handed over by
	// a device or another team is exactly where a bad signature shows up.
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrPEM, err := CreateCertRequest(key, CertRequestTemplate{
		Subject: NamedSubject{CommonName: "cn"}.Expand(),
	})
	if err != nil {
		t.Fatalf("CreateCertRequest: %v", err)
	}
	// Flip a byte in the middle of the base64 body.
	tampered := append([]byte(nil), csrPEM...)
	mid := len(tampered) / 2
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}
	if _, err := ParseCertRequestPEM(tampered); err == nil {
		t.Fatal("ParseCertRequestPEM accepted a tampered CSR")
	}
}

func TestCreateCertificateSelfSigned(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial := big.NewInt(0x2001)
	notBefore := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	tmpl := CertTemplate{
		Subject:          NamedSubject{CommonName: "homelab-ca", Organization: "homelab"}.Expand(),
		Serial:           serial,
		NotBefore:        notBefore,
		NotAfter:         notBefore.Add(175320 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"keyCertSign", "crlSign"}, Critical: true},
	}
	certPEM, err := CreateCertificate(tmpl, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	if cert.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("serial = %s, want %s", cert.SerialNumber, serial)
	}
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		t.Error("a self-signed certificate's subject and issuer differ")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("self-signature does not verify: %v", err)
	}
	if !cert.IsCA {
		t.Error("IsCA = false, want true")
	}
	if len(cert.SubjectKeyId) != 20 {
		t.Errorf("SubjectKeyId is %d bytes, want 20; a CA needs one to sign CRLs", len(cert.SubjectKeyId))
	}
	if !cert.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %s, want %s", cert.NotBefore, notBefore)
	}
}

func TestCreateCertificateCASignedChainVerifies(t *testing.T) {
	t.Parallel()
	// Spec section 10's first acceptance criterion, proven at the library level:
	// root -> intermediate -> leaf verifies with x509.Certificate.Verify.
	root, rootKey := testCA(t, nil, nil, "homelab-root")
	inter, interKey := testCA(t, root, rootKey, "homelab-intermediate")

	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leafPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "nick-ipad.ha.apps.somemissing.info"}.Expand(),
		SAN:              SAN{DNSNames: []string{"nick-ipad.ha.apps.somemissing.info"}},
		Serial:           big.NewInt(0x2002),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}, PublicKeyOf(leafKey), inter, interKey)
	if err != nil {
		t.Fatalf("CreateCertificate (leaf): %v", err)
	}
	leaf, err := ParseCertificatePEM(leafPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
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
		t.Fatalf("chain verification failed: %v", err)
	}

	if !bytes.Equal(leaf.AuthorityKeyId, inter.SubjectKeyId) {
		t.Error("leaf authorityKeyIdentifier does not match the issuer's subjectKeyIdentifier")
	}
	if len(leaf.SubjectKeyId) != 20 {
		t.Error("leaf has no subjectKeyIdentifier; engine.py emitted one, so an imported leaf would drift")
	}
}

// TestCreateCertificateEmitsExactlyOneOfEachExtension asserts every extension
// appears exactly once and that the expected set is present.
//
// Note what this test does NOT prove, despite an earlier draft of this plan
// claiming it did. It cannot catch a template field being set on both
// x509.Certificate's convenience field and ExtraExtensions, because
// crypto/x509 guards every one of those fields with
// !oidInExtensions(oid, template.ExtraExtensions) -- see x509.go around lines
// 1187-1269. Double emission is therefore impossible by construction, and
// setting BasicConstraintsValid, IsCA, KeyUsage and DNSNames alongside the
// extension list leaves this test green. Verified by doing exactly that.
//
// The real hazard is an extension appearing that the template never asked for,
// which a count cannot see. TestCreateCertificateEmitsNothingBeyondTheTemplate
// below is what covers it.
func TestCreateCertificateEmitsExactlyOneOfEachExtension(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "leaf"}.Expand(),
		SAN:              SAN{DNSNames: []string{"leaf.example"}},
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}, PublicKeyOf(leafKey), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	counts := map[string]int{}
	for _, ext := range cert.Extensions {
		counts[FormatOID(ext.Id)]++
	}
	for oid, n := range counts {
		if n != 1 {
			t.Errorf("extension %s appears %d times, want exactly 1", oid, n)
		}
	}
	for _, want := range []string{"2.5.29.19", "2.5.29.15", "2.5.29.37", "2.5.29.17", "2.5.29.14", "2.5.29.35"} {
		if counts[want] == 0 {
			t.Errorf("extension %s is missing", want)
		}
	}
}

// TestCreateCertificateHonorsCriticality is the capability hashicorp/tls lacks:
// it hardcodes criticality, so a config that needs a non-critical keyUsage or a
// critical extendedKeyUsage cannot be expressed there.
func TestCreateCertificateHonorsCriticality(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	leafKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "leaf"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: false},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature"}, Critical: false},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}, Critical: true},
	}, PublicKeyOf(leafKey), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	for oid, wantCritical := range map[string]bool{
		"2.5.29.19": false, // basicConstraints, non-critical by explicit request
		"2.5.29.15": false, // keyUsage, non-critical by explicit request
		"2.5.29.37": true,  // extendedKeyUsage, critical by explicit request
	} {
		parsed, err := ParseOID(oid)
		if err != nil {
			t.Fatalf("ParseOID: %v", err)
		}
		ext, ok := FindExtension(cert.Extensions, parsed)
		if !ok {
			t.Errorf("extension %s is missing", oid)
			continue
		}
		if ext.Critical != wantCritical {
			t.Errorf("extension %s Critical = %v, want %v", oid, ext.Critical, wantCritical)
		}
	}
}

func TestCreateCertificateExtensionOrderIsStable(t *testing.T) {
	t.Parallel()
	// A stable order is what lets Task 14 compare extension lists positionally
	// and lets an imported certificate re-encode byte-exact.
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := CertTemplate{
		Subject:          NamedSubject{CommonName: "cn"}.Expand(),
		SAN:              SAN{DNSNames: []string{"a.example"}},
		Serial:           big.NewInt(1),
		NotBefore:        time.Now(),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"keyCertSign"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
		NameConstraints:  &NameConstraints{PermittedDNSDomains: []string{".example"}, Critical: true},
		ExtraExtensions:  []ExtraExtension{{OID: mustOID(t, "1.3.6.1.4.1.99999.1"), Value: []byte{0x05, 0x00}}},
	}
	exts, err := tmpl.Extensions(PublicKeyOf(key))
	if err != nil {
		t.Fatalf("Extensions: %v", err)
	}
	want := []string{
		"2.5.29.19", // basicConstraints
		"2.5.29.15", // keyUsage
		"2.5.29.37", // extendedKeyUsage
		"2.5.29.17", // subjectAltName
		"2.5.29.30", // nameConstraints
		"2.5.29.14", // subjectKeyIdentifier
		"1.3.6.1.4.1.99999.1",
	}
	if len(exts) != len(want) {
		t.Fatalf("Extensions returned %d extensions, want %d", len(exts), len(want))
	}
	for i, oid := range want {
		if got := FormatOID(exts[i].Id); got != oid {
			t.Errorf("extension %d = %s, want %s", i, got, oid)
		}
	}
}

func TestCreateCertificateRejectsBadTemplates(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := PublicKeyOf(key)
	base := func() CertTemplate {
		return CertTemplate{
			Subject:   NamedSubject{CommonName: "cn"}.Expand(),
			Serial:    big.NewInt(1),
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		}
	}
	cases := map[string]func(CertTemplate) CertTemplate{
		"nil serial":         func(c CertTemplate) CertTemplate { c.Serial = nil; return c },
		"negative serial":    func(c CertTemplate) CertTemplate { c.Serial = big.NewInt(-1); return c },
		"zero notBefore":     func(c CertTemplate) CertTemplate { c.NotBefore = time.Time{}; return c },
		"zero notAfter":      func(c CertTemplate) CertTemplate { c.NotAfter = time.Time{}; return c },
		"notAfter before":    func(c CertTemplate) CertTemplate { c.NotAfter = c.NotBefore.Add(-time.Hour); return c },
		"empty subject and san": func(c CertTemplate) CertTemplate { c.Subject = Subject{}; c.SAN = SAN{}; return c },
	}
	for label, mutate := range cases {
		if _, err := CreateCertificate(mutate(base()), pub, ca, caKey); err == nil {
			t.Errorf("CreateCertificate(%s) returned nil error, want an error", label)
		}
	}
}

// TestCreateCertificateWithEmptySubjectForcesCriticalSAN ties Task 7's rule into
// issuance: a certificate with no DN must carry a critical SAN or it identifies
// nothing (RFC 5280 4.2.1.6).
func TestCreateCertificateWithEmptySubjectForcesCriticalSAN(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		SAN:       SAN{DNSNames: []string{"only-a-san.example"}, Critical: false},
		Serial:    big.NewInt(1),
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	ext, ok := FindExtension(cert.Extensions, oidSubjectAltName)
	if !ok {
		t.Fatal("no subjectAltName extension")
	}
	if !ext.Critical {
		t.Fatal("SAN is not critical on a certificate with an empty subject")
	}
}

func TestDefaultSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		params KeyParams
		want   x509.SignatureAlgorithm
	}{
		{KeyParams{Algorithm: AlgorithmRSA}, x509.SHA256WithRSA},
		{KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: "P256"}, x509.ECDSAWithSHA256},
		{KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: "P384"}, x509.ECDSAWithSHA384},
		{KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: "P521"}, x509.ECDSAWithSHA512},
		{KeyParams{Algorithm: AlgorithmED25519}, x509.PureEd25519},
	} {
		k, err := GenerateKey(tc.params)
		if err != nil {
			t.Fatalf("GenerateKey(%+v): %v", tc.params, err)
		}
		got, err := DefaultSignatureAlgorithm(k)
		if err != nil {
			t.Errorf("DefaultSignatureAlgorithm(%+v): %v", tc.params, err)
			continue
		}
		if got != tc.want {
			t.Errorf("DefaultSignatureAlgorithm(%+v) = %v, want %v", tc.params, got, tc.want)
		}
	}
}

// TestCreateCertificateRejectsMismatchedSignatureAlgorithm catches the config
// error of asking for an RSA signature algorithm with an ECDSA CA key, which
// Go would otherwise report as an opaque failure deep inside CreateCertificate.
func TestCreateCertificateRejectsMismatchedSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca") // ECDSA by default in testCA
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, err = CreateCertificate(CertTemplate{
		Subject:            NamedSubject{CommonName: "cn"}.Expand(),
		Serial:             big.NewInt(1),
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, PublicKeyOf(key), ca, caKey)
	if err == nil {
		t.Fatal("CreateCertificate accepted an RSA signature algorithm with an ECDSA signing key")
	}
}

func TestParseCertificateChainPEM(t *testing.T) {
	t.Parallel()
	root, rootKey := testCA(t, nil, nil, "root")
	inter, _ := testCA(t, root, rootKey, "intermediate")
	chain := append(EncodeCertificatePEM(inter.Raw), EncodeCertificatePEM(root.Raw)...)

	got, err := ParseCertificateChainPEM(chain)
	if err != nil {
		t.Fatalf("ParseCertificateChainPEM: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d certificates, want 2", len(got))
	}
	if !bytes.Equal(got[0].Raw, inter.Raw) || !bytes.Equal(got[1].Raw, root.Raw) {
		t.Error("chain order was not preserved; leaf-adjacent must come first")
	}
	for label, in := range map[string][]byte{
		"empty":        nil,
		"not pem":      []byte("hello"),
		"key in chain": EncodeCertificatePEM(root.Raw),
	} {
		if label == "key in chain" {
			continue // covered below with a real key block
		}
		if _, err := ParseCertificateChainPEM(in); err == nil {
			t.Errorf("ParseCertificateChainPEM(%s) returned nil error, want an error", label)
		}
	}
	keyPEM, err := EncodePrivateKeyPEM(rootKey)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	if _, err := ParseCertificateChainPEM(append(append([]byte(nil), chain...), keyPEM...)); err == nil {
		t.Error("ParseCertificateChainPEM accepted a chain containing a private key block")
	}
}
```

Add these fixtures to `internal/pki/testhelper_test.go`:

```go
// testCA issues a CA certificate and returns it with its key. With a nil parent
// it self-signs a root; otherwise it issues an intermediate under the parent.
// The key is ECDSA P-256 because these fixtures are created in almost every
// test and RSA generation dominates the suite's runtime otherwise.
func testCA(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signerKey := key
	if parentKey != nil {
		signerKey = parentKey
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: cn, Organization: "homelab"}.Expand(),
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}, PublicKeyOf(key), parent, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(%s): %v", cn, err)
	}
	return cert, key
}

// mustOID parses a dotted OID or fails the test.
//
// NOTE: Task 8 already added this helper to testhelper_test.go, because its
// wrong-OID test needs it. Do not add it again -- a second declaration in the
// same package will not compile. Check the file first; if it is present, use
// it as is.
func mustOID(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	oid, err := ParseOID(s)
	if err != nil {
		t.Fatalf("ParseOID(%q): %v", s, err)
	}
	return oid
}

// opensslText runs `openssl x509 -text -noout` over a PEM certificate and
// returns its output, so tests can assert that a real parser agrees with what
// this package produced.
func opensslText(t *testing.T, certPEM []byte) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, "x509", "-noout", "-text")
	cmd.Stdin = bytes.NewReader(certPEM)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text failed: %v\n%s", err, out)
	}
	return string(out)
}
```

`testCA` calls `DefaultCAKeyUsagePtr()`, a one-line addition to `extensions.go` returning `&KeyUsage{...}` from `DefaultCAKeyUsage()`; add it in this task since `CertTemplate.KeyUsage` is a pointer. `testhelper_test.go`'s import block grows to `bytes`, `crypto`, `crypto/x509`, `encoding/asn1`, `os/exec`, `testing`, `time`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'CertRequest|CreateCertificate|DefaultSignature|ParseCertificate' -v
```

Expected: FAIL to build with `undefined: CreateCertRequest`, `undefined: CertTemplate`.

- [ ] **Step 3: Implement `CertTemplate.Extensions`**

This method is the heart of the file and the reason Task 14 can compare desired against actual without duplicating logic. It returns extensions in the fixed order asserted by `TestCreateCertificateExtensionOrderIsStable`: basicConstraints, keyUsage, extendedKeyUsage, subjectAltName, nameConstraints, subjectKeyIdentifier, then `ExtraExtensions` in declaration order. Each optional pointer contributes nothing when nil; the SAN contributes nothing when empty; `SubjectKeyIDExtension` always contributes.

Reject a duplicate OID across the whole list — an `extra_extension` block whose OID collides with a managed extension is a config error, not a silent override. That check belongs here rather than in `CreateCertificate` so both the issuance path and the comparison path see it.

- [ ] **Step 4: Implement `CreateCertRequest`, `CreateCertificate`, and the parsers**

`CreateCertRequest` builds an `x509.CertificateRequest` with only `RawSubject`, `ExtraExtensions`, and `SignatureAlgorithm` set. The SAN goes into `ExtraExtensions`, not into the `DNSNames`/`EmailAddresses` fields, for the same double-emission reason as certificates. Resolve `SignatureAlgorithm` through `DefaultSignatureAlgorithm(key)` when the template leaves it zero. Then `x509.CreateCertificateRequest` and wrap in a `CERTIFICATE REQUEST` PEM block.

`CreateCertificate` validates the template first: non-nil positive serial, non-zero `NotBefore` and `NotAfter` with `NotAfter` after `NotBefore`, and a non-empty subject or non-empty SAN. Then:

```go
// buildTemplate assembles the x509.Certificate Go needs. Note what is NOT set:
// Subject, DNSNames, EmailAddresses, IPAddresses, URIs, KeyUsage,
// ExtKeyUsage, BasicConstraintsValid, IsCA, MaxPathLen, and the name
// constraint fields are all left zero.
//
// The reason is single-source-of-truth, not double emission. crypto/x509
// guards each of those fields with !oidInExtensions(oid, ExtraExtensions), so
// setting one alongside the extension list is silently ignored rather than
// duplicated. Leaving them zero means t.Extensions() is the only thing that
// decides what a certificate carries -- which is what lets Task 14 compare
// against that same function instead of reimplementing the rules.
//
// One consequence of never setting IsCA: Go's automatic SubjectKeyId
// generation is gated on it, so the RFC 7093 path described in the SubjectKeyId
// note below is unreachable in this design. The note stands anyway, because the
// gate is Go's implementation detail and not a promise.
```

Set `SerialNumber`, `RawSubject`, `NotBefore`, `NotAfter`, `SignatureAlgorithm`, `ExtraExtensions`, and `SubjectKeyId`.

**`SubjectKeyId` must always be set explicitly, from the same computation `SubjectKeyIDExtension` uses. Leaving it empty is a correctness bug, not a stylistic choice.** Two independent reasons, and the second is the dangerous one:

- Go skips its own SKI synthesis when `ExtraExtensions` already contains OID 2.5.29.14, but it still reads the `SubjectKeyId` field to build the `authorityKeyIdentifier` it writes into children. An empty field yields children with no AKI.
- **Go's automatic SKI is not RFC 5280's algorithm.** Since **Go 1.25** (`internal/godebugs/table.go` records `{Name: "x509sha256skid", Changed: 25}`), `x509.CreateCertificate` fills an empty `SubjectKeyId` on a CA using RFC 7093 method 1 — SHA-256 truncated to 160 bits — and only falls back to RFC 5280's SHA-1 under `GODEBUG=x509sha256skid=0`. Note that pinning an older toolchain is therefore *not* a workaround worth considering: this plan's floor is Go 1.25, and relying on pre-1.25 behavior would make the output depend on the build toolchain. Both are 20 bytes, so the mistake is invisible to a length check. Verified directly on Go 1.25.12 for one ECDSA key: Go's automatic value was `17 5b 2e 7a 33 d6 c4 10 47 a5 38 05 68 98 4b 92 60 a8 60 b1` while RFC 5280's SHA-1 of the same key is `00 3b 02 f3 25 82 61 90 74 1b 54 b8 e0 57 d3 4f a2 a4 b7 99`.

  The consequence is exactly the failure this whole design exists to prevent. The certificates being adopted carry SHA-1 SKIs, because `openssl`'s `subjectKeyIdentifier = hash` computes RFC 5280 method 1. If issuance produced RFC 7093 values instead, every adopted certificate would differ from its reissued form in the SKI alone, Task 14 would report drift on every plan, and the drift would never converge no matter how many times it was applied. Task 15's golden comparison against real `openssl` output is what would catch it, one task too late to be cheap.

This finding came from Task 8's implementer, which confirmed it by re-running under `GODEBUG=x509sha256skid=0`.

Self-signing: when `parent` is nil, Go requires the template itself as the parent, so pass a locally-built `x509.Certificate` that carries `RawSubject` and `SubjectKeyId`. Building it explicitly rather than reusing the template variable makes the intent legible and avoids Go's `RawSubject`-as-issuer path silently picking up a stale field.

Before calling `x509.CreateCertificate`, check that the requested `SignatureAlgorithm` is compatible with `signerKey`: compare against `DefaultSignatureAlgorithm(signerKey)`'s public key family. That is what turns `TestCreateCertificateRejectsMismatchedSignatureAlgorithm`'s case into a clear error instead of Go's `x509: requested SignatureAlgorithm does not match private key type`.

`ParseCertificatePEM` decodes one `CERTIFICATE` block and calls `x509.ParseCertificate`, erroring on trailing data. `ParseCertificateChainPEM` loops `pem.Decode`, requires at least one block, and errors on any block whose type is not `CERTIFICATE` — that is what rejects a chain with a key block spliced in, which would otherwise leak a private key into a `certificate_chain_pem` attribute. `ParseCertRequestPEM` additionally calls `csr.CheckSignature()` and returns an error when it fails.

`EncodeCertificatePEM` wraps DER in a `CERTIFICATE` block.

`DefaultSignatureAlgorithm` type-switches: RSA to `x509.SHA256WithRSA`, Ed25519 to `x509.PureEd25519`, and ECDSA to the curve-matched hash (`P-224`/`P-256` to SHA-256, `P-384` to SHA-384, `P-521` to SHA-512), which is what RFC 5480 §4 recommends and what openssl picks.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -v
```

Expected: PASS.

- [ ] **Step 6: Cross-validate the DN against `openssl`**

Task 6 could not do this: rendering a DN through an outside parser needs a certificate to put it in, and `CreateCertificate` did not exist yet. Add it now, to `subject_test.go` alongside the rest of the DN tests:

```go
// TestSubjectDERIsReadableByOpenSSL confirms an outside parser renders the DN
// the way this package intends, including the attributes openssl has no short
// name for. Byte-level assertions can pass while producing a DN nothing else
// reads correctly.
func TestSubjectDERIsReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)

	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	subject := Subject{Attributes: []Attribute{
		attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
		attr(t, "uid", "nick"),
		{OID: display, Value: "Nick V"},
		attr(t, "givenName", "Nick"),
		attr(t, "surname", "Venenga"),
		attr(t, "organization", "homelab"),
		attr(t, "organizationalUnit", "infra"),
		attr(t, "organizationalUnit", "clients"),
	}}

	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:   subject,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	text := opensslText(t, certPEM)
	for _, want := range []string{
		"CN = nick-ipad.ha.apps.somemissing.info",
		"UID = nick",
		"2.16.840.1.113730.3.1.241 = Nick V",
		"GN = Nick",
		"SN = Venenga",
		"O = homelab",
		"OU = infra",
		"OU = clients",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl output does not contain %q; full Subject line:\n%s", want, subjectLine(text))
		}
	}
}

// subjectLine extracts the Subject: line from openssl x509 -text output, for
// readable failure messages.
func subjectLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Subject:") {
			return strings.TrimSpace(line)
		}
	}
	return "(no Subject line found)"
}
```

`subject_test.go` gains `math/big`, `strings`, and `time` imports. If openssl renders `displayName` by a name rather than the dotted OID in this build, adjust the expected string and note the openssl version in a comment — the assertion's purpose is that the attribute is present and correctly typed, not that openssl's naming table matches ours.

- [ ] **Step 7: Run everything and commit**

```bash
gofmt -l . && go vet ./... && go test ./internal/pki/ -v
git add internal/pki/sign.go internal/pki/sign_test.go internal/pki/testhelper_test.go internal/pki/subject_test.go internal/pki/extensions.go
git commit -m "feat: CSR and certificate issuance with explicit extension control"
```

---

### Task 10: CRLs (`crl.go`)

Replaces `cfssl gencrl` piped through `openssl crl -inform DER` (`engine.py:123-135`). Note the failure mode this task must surface clearly: Go's `x509.CreateRevocationList` refuses to sign unless the issuer certificate has `KeyUsageCRLSign` set and a non-empty `SubjectKeyId`. cfssl had no such requirement, so a CA that worked with the old pipeline can fail here, and the externally-owned Bitwarden CA cannot be inspected in advance.

**Files:**
- Create: `internal/pki/crl.go`
- Test: `internal/pki/crl_test.go`

**Interfaces:**
- Consumes: `ParseSerial` (Task 4), `testCA` fixtures and `CreateCertificate` (Task 9).
- Produces:
  - `type RevokedCert struct { Serial *big.Int; Reason string; RevokedAt time.Time }`
  - `type CRLTemplate struct { Number *big.Int; ThisUpdate, NextUpdate time.Time; Revoked []RevokedCert; SignatureAlgorithm x509.SignatureAlgorithm }`
  - `func CreateCRL(t CRLTemplate, caCert *x509.Certificate, caKey crypto.Signer) ([]byte, error)` — returns PEM
  - `func ParseCRLPEM(b []byte) (*x509.RevocationList, error)`
  - `func ReasonCode(name string) (int, error)` and `func ReasonName(code int) (string, error)`
  - `func ReasonNames() []string` — for schema validation in Plan 2
  - `func CheckCRLSigner(caCert *x509.Certificate) error` — the precondition check, exported so the framework layer can report it before attempting to sign

- [ ] **Step 1: Write the failing tests**

`internal/pki/crl_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCreateCRLRoundTripAndSignature(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")

	thisUpdate := time.Now().Truncate(time.Second).UTC()
	tmpl := CRLTemplate{
		Number:     big.NewInt(1),
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(168 * time.Hour),
		Revoked: []RevokedCert{
			{Serial: big.NewInt(0x2001), Reason: "keyCompromise", RevokedAt: thisUpdate.Add(-24 * time.Hour)},
			{Serial: big.NewInt(0x2002), RevokedAt: thisUpdate.Add(-time.Hour)},
		},
	}
	crlPEM, err := CreateCRL(tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	crl, err := ParseCRLPEM(crlPEM)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}

	// Spec section 10: the CRL signature verifies against the CA and a revoked
	// serial is present.
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Errorf("CRL signature does not verify against the issuing CA: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("CRL number = %s, want 1", crl.Number)
	}
	if len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("CRL has %d entries, want 2", len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(0x2001)) != 0 {
		t.Errorf("entry 0 serial = %s, want 8193 (0x2001)", crl.RevokedCertificateEntries[0].SerialNumber)
	}
	if crl.RevokedCertificateEntries[0].ReasonCode != 1 {
		t.Errorf("entry 0 reason code = %d, want 1 (keyCompromise)", crl.RevokedCertificateEntries[0].ReasonCode)
	}
	// An omitted reason must not become "unspecified with an explicit code": RFC
	// 5280 says omit the extension entirely, and code 0 is how Go signals that.
	if crl.RevokedCertificateEntries[1].ReasonCode != 0 {
		t.Errorf("entry 1 reason code = %d, want 0 (no reasonCode extension)", crl.RevokedCertificateEntries[1].ReasonCode)
	}
	if !crl.ThisUpdate.Equal(thisUpdate) {
		t.Errorf("thisUpdate = %s, want %s", crl.ThisUpdate, thisUpdate)
	}
}

func TestCreateCRLWithNoRevocations(t *testing.T) {
	t.Parallel()
	// An empty CRL is the normal steady state: config.hcl ships
	// revoked_serials = [] and the cluster still needs a fresh, valid CRL for
	// Envoy to load.
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	crlPEM, err := CreateCRL(CRLTemplate{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(168 * time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL with no revocations: %v", err)
	}
	crl, err := ParseCRLPEM(crlPEM)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatalf("empty CRL has %d entries, want 0", len(crl.RevokedCertificateEntries))
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Errorf("empty CRL signature does not verify: %v", err)
	}
}

func TestCreateCRLPEMBlockType(t *testing.T) {
	t.Parallel()
	// engine.py converted cfssl's DER output to PEM specifically so downstream
	// consumers (Envoy, HTTPProxy) get a standard file. The block type is what
	// they key on.
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now()
	crlPEM, err := CreateCRL(CRLTemplate{
		Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	if !strings.HasPrefix(string(crlPEM), "-----BEGIN X509 CRL-----") {
		t.Fatalf("CRL PEM starts with %q, want \"-----BEGIN X509 CRL-----\"", string(crlPEM[:30]))
	}
}

// TestCheckCRLSignerRejectsACAWithoutCRLSign is the guard on the migration
// hazard: cfssl signed CRLs with any CA key, but Go requires the issuer to
// carry keyUsage crlSign and a subjectKeyIdentifier. The externally-owned
// Bitwarden CA cannot be inspected ahead of time, so the error must say exactly
// what is wrong and what to do.
func TestCheckCRLSignerRejectsACAWithoutCRLSign(t *testing.T) {
	t.Parallel()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// A CA whose keyUsage omits crlSign.
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "no-crlsign-ca"}.Expand(),
		Serial:           big.NewInt(1),
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"keyCertSign"}, Critical: true},
	}, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	ca, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	err = CheckCRLSigner(ca)
	if err == nil {
		t.Fatal("CheckCRLSigner accepted a CA without crlSign")
	}
	if !strings.Contains(err.Error(), "crlSign") {
		t.Errorf("error message %q does not mention crlSign; a caller cannot act on it", err.Error())
	}

	now := time.Now()
	if _, err := CreateCRL(CRLTemplate{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)}, ca, key); err == nil {
		t.Fatal("CreateCRL signed with a CA that lacks crlSign")
	}
}

func TestCreateCRLRejectsBadTemplates(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	base := func() CRLTemplate {
		return CRLTemplate{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(168 * time.Hour)}
	}
	for label, mutate := range map[string]func(CRLTemplate) CRLTemplate{
		"nil number":            func(c CRLTemplate) CRLTemplate { c.Number = nil; return c },
		"negative number":       func(c CRLTemplate) CRLTemplate { c.Number = big.NewInt(-1); return c },
		"zero thisUpdate":       func(c CRLTemplate) CRLTemplate { c.ThisUpdate = time.Time{}; return c },
		"zero nextUpdate":       func(c CRLTemplate) CRLTemplate { c.NextUpdate = time.Time{}; return c },
		"nextUpdate before":     func(c CRLTemplate) CRLTemplate { c.NextUpdate = c.ThisUpdate.Add(-time.Hour); return c },
		"nil entry serial":      func(c CRLTemplate) CRLTemplate { c.Revoked = []RevokedCert{{RevokedAt: now}}; return c },
		"zero revokedAt":        func(c CRLTemplate) CRLTemplate { c.Revoked = []RevokedCert{{Serial: big.NewInt(1)}}; return c },
		"unknown reason":        func(c CRLTemplate) CRLTemplate { c.Revoked = []RevokedCert{{Serial: big.NewInt(1), RevokedAt: now, Reason: "becauseIFeltLikeIt"}}; return c },
		"duplicate serial":      func(c CRLTemplate) CRLTemplate {
			c.Revoked = []RevokedCert{{Serial: big.NewInt(1), RevokedAt: now}, {Serial: big.NewInt(1), RevokedAt: now}}
			return c
		},
	} {
		if _, err := CreateCRL(mutate(base()), ca, caKey); err == nil {
			t.Errorf("CreateCRL(%s) returned nil error, want an error", label)
		}
	}
}

func TestReasonCodes(t *testing.T) {
	t.Parallel()
	// RFC 5280 5.3.1. Note that 7 is unused and must not be accepted.
	for name, want := range map[string]int{
		"unspecified":          0,
		"keyCompromise":        1,
		"cACompromise":         2,
		"affiliationChanged":   3,
		"superseded":           4,
		"cessationOfOperation": 5,
		"certificateHold":      6,
		"removeFromCRL":        8,
		"privilegeWithdrawn":   9,
		"aACompromise":         10,
	} {
		got, err := ReasonCode(name)
		if err != nil {
			t.Errorf("ReasonCode(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ReasonCode(%q) = %d, want %d", name, got, want)
		}
		back, err := ReasonName(want)
		if err != nil || back != name {
			t.Errorf("ReasonName(%d) = %q, %v; want %q, nil", want, back, err, name)
		}
	}
	if _, err := ReasonCode("keycompromise"); err == nil {
		t.Error("ReasonCode is case-insensitive; the schema's values are the RFC's exact spellings")
	}
	if _, err := ReasonName(7); err == nil {
		t.Error("ReasonName(7) succeeded; 7 is unused in RFC 5280")
	}
	if names := ReasonNames(); len(names) != 10 {
		t.Errorf("ReasonNames returned %d names, want 10", len(names))
	}
}

// TestCreateCRLIsDeterministicForTheSameTemplate keeps regeneration from
// producing gratuitously different bytes, which would churn the Kubernetes
// Secret on every apply even when nothing changed.
func TestCreateCRLIsDeterministicForTheSameTemplate(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	tmpl := CRLTemplate{
		Number:     big.NewInt(7),
		ThisUpdate: now,
		NextUpdate: now.Add(168 * time.Hour),
		Revoked:    []RevokedCert{{Serial: big.NewInt(0x2001), RevokedAt: now.Add(-time.Hour)}},
	}
	a, err := CreateCRL(tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	b, err := CreateCRL(tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	// ECDSA signatures are randomized, so the signature bytes differ by design.
	// The signed content must not.
	first, err := ParseCRLPEM(a)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	second, err := ParseCRLPEM(b)
	if err != nil {
		t.Fatalf("ParseCRLPEM: %v", err)
	}
	if string(first.RawTBSRevocationList) != string(second.RawTBSRevocationList) {
		t.Fatal("the same template produced different signed content across two calls")
	}
}

func TestParseCRLPEMRejectsGarbage(t *testing.T) {
	t.Parallel()
	for label, in := range map[string][]byte{
		"empty":       nil,
		"not pem":     []byte("hello"),
		"wrong block": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
	} {
		if _, err := ParseCRLPEM(in); err == nil {
			t.Errorf("ParseCRLPEM(%s) returned nil error, want an error", label)
		}
	}
}

func TestCRLIsReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	ca, caKey := testCA(t, nil, nil, "ca")
	now := time.Now().Truncate(time.Second).UTC()
	crlPEM, err := CreateCRL(CRLTemplate{
		Number:     big.NewInt(3),
		ThisUpdate: now,
		NextUpdate: now.Add(168 * time.Hour),
		Revoked:    []RevokedCert{{Serial: big.NewInt(0x2001), Reason: "keyCompromise", RevokedAt: now.Add(-time.Hour)}},
	}, ca, caKey)
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}
	text := opensslCRLText(t, crlPEM)
	for _, want := range []string{"Serial Number: 2001", "Key Compromise"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl crl output does not contain %q:\n%s", want, text)
		}
	}
	// The CRL number needs a whitespace-tolerant match: openssl 3.5.7 always
	// prints an extension's name and its value on separate lines, so the
	// literal "CRL Number: 3" never appears.
	if !regexp.MustCompile(`(?s)X509v3 CRL Number:\s*3`).MatchString(text) {
		t.Errorf("openssl crl output does not show CRL number 3:\n%s", text)
	}
	_ = x509.RevocationList{} // keep the x509 import honest if assertions change
}
```

Add to `internal/pki/testhelper_test.go`:

```go
// opensslCRLText runs `openssl crl -text -noout` over a PEM CRL.
func opensslCRLText(t *testing.T, crlPEM []byte) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, "crl", "-noout", "-text")
	cmd.Stdin = bytes.NewReader(crlPEM)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl crl -text failed: %v\n%s", err, out)
	}
	return string(out)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'CRL|Reason' -v
```

Expected: FAIL to build with `undefined: CreateCRL`.

- [ ] **Step 3: Implement `crl.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

// reasonCodes maps the RFC 5280 5.3.1 CRLReason names to their enumeration
// values. Value 7 is unused in the RFC and is deliberately absent, so a config
// cannot request it.
var reasonCodes = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"cACompromise":         2,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
	"certificateHold":      6,
	"removeFromCRL":        8,
	"privilegeWithdrawn":   9,
	"aACompromise":         10,
}
```

`ReasonNames` returns the keys sorted by code, not alphabetically, so generated documentation reads in the RFC's order. `ReasonCode` and `ReasonName` are exact-match lookups returning an error naming the input.

`CheckCRLSigner` returns a specific, actionable error for each precondition:

```go
// CheckCRLSigner reports whether a certificate can sign a CRL.
//
// Go's x509.CreateRevocationList enforces two preconditions that cfssl did
// not, and both produce opaque errors from deep inside the standard library.
// The homelab CA is delivered from Bitwarden and cannot be inspected before an
// apply, so a caller needs to be told exactly which property is missing and
// that the fix is to reissue the CA, not to retry.
func CheckCRLSigner(caCert *x509.Certificate) error {
	if caCert == nil {
		return errors.New("no CA certificate supplied")
	}
	if caCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("CA certificate %q cannot sign CRLs: its keyUsage extension does not include crlSign; reissue the CA with crlSign in key_usage.usages", caCert.Subject.String())
	}
	if len(caCert.SubjectKeyId) == 0 {
		return fmt.Errorf("CA certificate %q cannot sign CRLs: it has no subjectKeyIdentifier extension, which RFC 5280 requires for the CRL's authorityKeyIdentifier; reissue the CA with this provider, which always emits one", caCert.Subject.String())
	}
	return nil
}
```

`CreateCRL` validates the template (positive non-nil `Number`; non-zero `ThisUpdate` and `NextUpdate` with `NextUpdate` after `ThisUpdate`; every entry has a non-nil positive serial and a non-zero `RevokedAt`; reasons resolve; no duplicate serials), calls `CheckCRLSigner`, resolves the signature algorithm through `DefaultSignatureAlgorithm(caKey)` when zero, builds `x509.RevocationList` with `RevokedCertificateEntries`, calls `x509.CreateRevocationList`, and wraps the DER in an `X509 CRL` PEM block.

Three details that the verified API notes make load-bearing. First, put the reason in `RevocationListEntry.ReasonCode` and never in `ExtraExtensions` — Go rejects a reasonCode OID appearing there. Second, `ReasonCode` 0 makes Go omit the extension entirely, which is the RFC-correct encoding for an unspecified reason and is what the test asserts; do not special-case it. Third, `Number` is required and must fit in 20 octets — but **do not validate it as `Number.BitLen() <= 160`**. That misses the boundary: a positive `Number` with `BitLen() == 160` has its top byte's high bit set, so the DER INTEGER encoding prepends a sign-padding octet and the value still exceeds 20 octets. `2^159` is exactly such a case — 20 bytes from `Bytes()`, rejected by Go. A `BitLen()` check would pass it through and Go would then fail with its own opaque `x509: CRL number exceeds 20 octets`, which is precisely the outcome this pre-validation exists to avoid.

Replicate Go's own condition instead, which is `len(numBytes) > 20 || (len(numBytes) == 20 && numBytes[0]&0x80 != 0)` over `Number.Bytes()` (see `x509.go`'s `CreateRevocationList`), and give an error mentioning the 20-octet limit. Add a regression test at the boundary — `2^159` must be rejected — because nothing else in this task's tests exercises an oversized CRL number at all.

Duplicate-serial rejection is not RFC-mandated but is always a config error, and a CRL with the same serial twice makes downstream revocation checks ambiguous.

`ParseCRLPEM` decodes one `X509 CRL` block and calls `x509.ParseRevocationList`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run 'CRL|Reason' -v
go test ./internal/pki/
```

Expected: PASS, including `TestCRLIsReadableByOpenSSL` (or a skip if openssl is absent).

- [ ] **Step 5: Commit**

```bash
git add internal/pki/crl.go internal/pki/crl_test.go internal/pki/testhelper_test.go
git commit -m "feat: CRL generation replacing the cfssl gencrl pipeline"
```

---

### Task 11: Text and PKCS#7 bundles (`bundle.go`, part 1)

The `pem`, `der`, and `pkcs7` formats, plus the shared input type and validation the PKCS#12 and JKS encoders in Tasks 12 and 13 build on.

**Files:**
- Create: `internal/pki/bundle.go`
- Test: `internal/pki/bundle_test.go`

**Interfaces:**
- Consumes: `EncodePrivateKeyPEM` (Task 5), `EncodeCertificatePEM`, `ParseCertificatePEM` (Task 9).
- Produces:
  - `type Format string` with `FormatPEM Format = "pem"`, `FormatDER = "der"`, `FormatPKCS7 = "pkcs7"`, `FormatPKCS12 = "pkcs12"`, `FormatJKS = "jks"`
  - `func Formats() []Format` — for schema validation in Plan 2
  - `func (f Format) IsText() bool` — true for `pem` only; drives whether the `content` attribute is set or null
  - `type BundleInput struct { Format Format; Certificate *x509.Certificate; PrivateKey crypto.Signer; Chain []*x509.Certificate; FriendlyName string; PKCS12Encoding PKCS12Encoding; Password string; Rand io.Reader }`
  - `func EncodeBundle(in BundleInput) ([]byte, error)` — dispatches on `Format`
  - `type PKCS12Encoding string` (declared here, implemented in Task 12)

- [ ] **Step 1: Write the failing tests**

`internal/pki/bundle_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// testLeaf issues a leaf under a fresh CA and returns the leaf, its key, and the
// CA certificate, which is the shape every bundle test needs.
func TestEncodeBundlePEMOrdering(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format:      FormatPEM,
		Certificate: leaf,
		PrivateKey:  leafKey,
		Chain:       []*x509.Certificate{ca},
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	// Order is certificate, then chain leaf-adjacent first, then the private
	// key last. Documented and asserted because consumers that read only the
	// first block must get the end-entity certificate.
	var types []string
	rest := out
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		types = append(types, block.Type)
	}
	if len(rest) != 0 {
		t.Errorf("%d trailing bytes after the last PEM block", len(rest))
	}
	want := []string{"CERTIFICATE", "CERTIFICATE", "EC PRIVATE KEY"}
	if len(types) != len(want) {
		t.Fatalf("block types = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Errorf("block %d = %q, want %q", i, types[i], want[i])
		}
	}
}

func TestEncodeBundlePEMOmitsAbsentParts(t *testing.T) {
	t.Parallel()
	// Spec section 6.6: the optional fields are the switches. No private_key_pem
	// yields a cert-only bundle; no chain_pem yields no chain.
	leaf, leafKey, ca := testLeaf(t)

	certOnly, err := EncodeBundle(BundleInput{Format: FormatPEM, Certificate: leaf})
	if err != nil {
		t.Fatalf("EncodeBundle (cert only): %v", err)
	}
	if strings.Contains(string(certOnly), "PRIVATE KEY") {
		t.Error("a bundle with no private key contains a PRIVATE KEY block")
	}
	if n := strings.Count(string(certOnly), "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("cert-only bundle has %d certificates, want 1", n)
	}

	keyOnly, err := EncodeBundle(BundleInput{Format: FormatPEM, PrivateKey: leafKey})
	if err != nil {
		t.Fatalf("EncodeBundle (key only): %v", err)
	}
	if strings.Contains(string(keyOnly), "BEGIN CERTIFICATE") {
		t.Error("a bundle with no certificate contains a CERTIFICATE block")
	}

	noChain, err := EncodeBundle(BundleInput{Format: FormatPEM, Certificate: leaf, PrivateKey: leafKey})
	if err != nil {
		t.Fatalf("EncodeBundle (no chain): %v", err)
	}
	if n := strings.Count(string(noChain), "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("no-chain bundle has %d certificates, want 1", n)
	}
	_ = ca
}

func TestEncodeBundleRejectsEmptyInput(t *testing.T) {
	t.Parallel()
	// Every field being optional does not make an empty bundle meaningful.
	for _, f := range Formats() {
		if _, err := EncodeBundle(BundleInput{Format: f}); err == nil {
			t.Errorf("EncodeBundle(%s) with nothing to encode returned nil error, want an error", f)
		}
	}
	if _, err := EncodeBundle(BundleInput{Format: "pkcs11"}); err == nil {
		t.Error("EncodeBundle accepted an unknown format")
	}
}

func TestEncodeBundleDER(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{Format: FormatDER, Certificate: leaf})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	if !bytes.Equal(out, leaf.Raw) {
		t.Error("DER output is not the certificate's raw DER")
	}
	parsed, err := x509.ParseCertificate(out)
	if err != nil {
		t.Fatalf("emitted DER does not parse: %v", err)
	}
	if !bytes.Equal(parsed.RawSubject, leaf.RawSubject) {
		t.Error("round-tripped DER has a different subject")
	}

	// DER holds exactly one certificate and no key. Silently dropping the
	// extra parts would produce a bundle that looks fine and is missing half
	// its contents, so both are errors.
	for label, in := range map[string]BundleInput{
		"with key":   {Format: FormatDER, Certificate: leaf, PrivateKey: leafKey},
		"with chain": {Format: FormatDER, Certificate: leaf, Chain: []*x509.Certificate{ca}},
		"key only":   {Format: FormatDER, PrivateKey: leafKey},
	} {
		if _, err := EncodeBundle(in); err == nil {
			t.Errorf("EncodeBundle(der, %s) returned nil error, want an error", label)
		}
	}
}

func TestEncodeBundlePKCS7(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format:      FormatPKCS7,
		Certificate: leaf,
		Chain:       []*x509.Certificate{ca},
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	p7, err := pkcs7.Parse(out)
	if err != nil {
		t.Fatalf("emitted PKCS#7 does not parse: %v", err)
	}
	if len(p7.Certificates) != 2 {
		t.Fatalf("PKCS#7 holds %d certificates, want 2", len(p7.Certificates))
	}
	if !bytes.Equal(p7.Certificates[0].Raw, leaf.Raw) {
		t.Error("the first certificate in the PKCS#7 bundle is not the leaf")
	}
	if !bytes.Equal(p7.Certificates[1].Raw, ca.Raw) {
		t.Error("the second certificate in the PKCS#7 bundle is not the CA")
	}

	// PKCS#7 as produced here is a degenerate certs-only structure. It cannot
	// carry a private key, and quietly discarding one would be a data-loss bug.
	if _, err := EncodeBundle(BundleInput{Format: FormatPKCS7, Certificate: leaf, PrivateKey: leafKey}); err == nil {
		t.Error("EncodeBundle(pkcs7) accepted a private key, which the format cannot carry")
	}
}

func TestEncodeBundlePKCS7IsReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	leaf, _, ca := testLeaf(t)
	out, err := EncodeBundle(BundleInput{Format: FormatPKCS7, Certificate: leaf, Chain: []*x509.Certificate{ca}})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	text := opensslRun(t, out, "pkcs7", "-inform", "DER", "-print_certs", "-noout")
	if n := strings.Count(text, "subject="); n != 2 {
		t.Fatalf("openssl pkcs7 -print_certs found %d certificates, want 2:\n%s", n, text)
	}
}

func TestFormatIsText(t *testing.T) {
	t.Parallel()
	// Spec section 6.6: content is set for text formats and null for binary
	// ones; content_base64 is always set.
	for f, want := range map[Format]bool{
		FormatPEM:    true,
		FormatDER:    false,
		FormatPKCS7:  false,
		FormatPKCS12: false,
		FormatJKS:    false,
	} {
		if got := f.IsText(); got != want {
			t.Errorf("Format(%s).IsText() = %v, want %v", f, got, want)
		}
	}
}
```

Add to `internal/pki/testhelper_test.go`:

```go
// testLeaf issues a leaf certificate under a fresh CA and returns the leaf, the
// leaf's key, and the CA certificate.
func testLeaf(t *testing.T) (*x509.Certificate, crypto.Signer, *x509.Certificate) {
	t.Helper()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "nick-ipad.ha.apps.somemissing.info"}.Expand(),
		SAN:              SAN{DNSNames: []string{"nick-ipad.ha.apps.somemissing.info"}, EmailAddresses: []string{"nick@venenga.com"}},
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	return leaf, key, ca
}

// opensslRun pipes input to openssl with the given arguments and returns
// combined output, failing the test if openssl exits non-zero.
func opensslRun(t *testing.T, input []byte, args ...string) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
```

`DefaultLeafKeyUsagePtr` is the pointer-returning companion to `DefaultLeafKeyUsage`, added to `extensions.go` in this task alongside the `DefaultCAKeyUsagePtr` from Task 9. `bundle_test.go` imports `github.com/smallstep/pkcs7`; `testhelper_test.go` gains `strings`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'Bundle|Format' -v
```

Expected: FAIL to build with `undefined: EncodeBundle`.

- [ ] **Step 3: Implement the shared types and dispatch**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

// Format names an output encoding for a certificate bundle.
type Format string

const (
	FormatPEM    Format = "pem"
	FormatDER    Format = "der"
	FormatPKCS7  Format = "pkcs7"
	FormatPKCS12 Format = "pkcs12"
	FormatJKS    Format = "jks"
)

// BundleInput describes what to encode. Which fields are set is the interface:
// omitting PrivateKey produces a certificate-only bundle, and omitting Chain
// produces one with no chain. There is no include_chain-style boolean, because
// a field's presence already carries that information.
//
// Not every format accepts every combination. der holds exactly one
// certificate, and pkcs7 as produced here is a degenerate certs-only
// structure; supplying a private key to either is an error rather than a
// silent omission, because silently dropping a key produces a bundle that
// looks complete and is not.
type BundleInput struct {
	Format         Format
	Certificate    *x509.Certificate
	PrivateKey     crypto.Signer
	Chain          []*x509.Certificate
	FriendlyName   string
	PKCS12Encoding PKCS12Encoding
	Password       string

	// Rand overrides the entropy source. Leave nil for crypto/rand; tests set
	// it to make PKCS#12 salt and IV generation reproducible.
	Rand io.Reader
}
```

`EncodeBundle` validates that at least one of `Certificate`, `PrivateKey`, or `Chain` is set, then switches on `Format` to `encodePEM`, `encodeDER`, `encodePKCS7`, `encodePKCS12` (Task 12), or `encodeJKS` (Task 13), and returns an error naming the format for an unknown value. `Formats()` returns the five constants in that order. `IsText` returns `f == FormatPEM`.

`encodePEM` concatenates, in order: the certificate, each chain entry, then the private key via `EncodePrivateKeyPEM`. `encodeDER` errors if a key or chain is present or the certificate is absent, then returns `in.Certificate.Raw`. `encodePKCS7` errors if a key is present, concatenates `Certificate.Raw` followed by each chain entry's `Raw` into one buffer, and passes it to `pkcs7.DegenerateCertificate` — which takes the whole chain's concatenated DER, not one certificate, as verified against smallstep/pkcs7 v0.2.2.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run 'Bundle|Format' -v
go test ./internal/pki/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/bundle.go internal/pki/bundle_test.go internal/pki/testhelper_test.go internal/pki/extensions.go go.mod go.sum
git commit -m "feat: pem, der, and pkcs7 bundle encoders"
```

---

### Task 12: PKCS#12 bundles (`bundle.go`, part 2)

The highest-stakes encoder in the package. Spec §6.6 is explicit that the tests must assert the *emitted algorithms*, not merely that decoding succeeds: a silent shift between `modern` and `legacy` is exactly what locks a phone out of the network, and the failure is only discoverable on the device.

**Files:**
- Modify: `internal/pki/bundle.go`
- Test: `internal/pki/bundle_pkcs12_test.go`

**Interfaces:**
- Consumes: `BundleInput`, `EncodeBundle` dispatch (Task 11); `EncodePrivateKeyPKCS8DER` (Task 5).
- Produces:
  - `const PKCS12Modern PKCS12Encoding = "modern"`, `PKCS12Legacy = "legacy"`, `PKCS12Passwordless = "passwordless"`
  - `func PKCS12Encodings() []PKCS12Encoding` — for schema validation in Plan 2
  - `encodePKCS12(in BundleInput) ([]byte, error)` — unexported, reached through `EncodeBundle`

- [ ] **Step 1: Write the failing tests**

`internal/pki/bundle_pkcs12_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const testPassword = "password" // matches engine.py's default p12_password

func TestEncodePKCS12RoundTripsAllKeyAlgorithms(t *testing.T) {
	t.Parallel()
	// Spec section 10 requires all three algorithms, with and without a chain.
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		for _, withChain := range []bool{false, true} {
			leaf, key, ca := testLeafWithAlgorithm(t, alg)
			in := BundleInput{
				Format:      FormatPKCS12,
				Certificate: leaf,
				PrivateKey:  key,
				Password:    testPassword,
			}
			if withChain {
				in.Chain = []*x509.Certificate{ca}
			}
			out, err := EncodeBundle(in)
			if err != nil {
				t.Errorf("%s chain=%v: EncodeBundle: %v", alg, withChain, err)
				continue
			}
			gotKey, gotCert, gotChain, err := pkcs12.DecodeChain(out, testPassword)
			if err != nil {
				t.Errorf("%s chain=%v: DecodeChain: %v", alg, withChain, err)
				continue
			}
			if !bytes.Equal(gotCert.Raw, leaf.Raw) {
				t.Errorf("%s chain=%v: decoded certificate differs from the input", alg, withChain)
			}
			signer, ok := gotKey.(interface{ Public() crypto.PublicKey })
			if !ok {
				t.Errorf("%s chain=%v: decoded key %T is not a signer", alg, withChain, gotKey)
				continue
			}
			if !PublicKeysEqual(signer.Public(), PublicKeyOf(key)) {
				t.Errorf("%s chain=%v: decoded key does not match the input key", alg, withChain)
			}
			wantChain := 0
			if withChain {
				wantChain = 1
			}
			if len(gotChain) != wantChain {
				t.Errorf("%s chain=%v: decoded %d CA certificates, want %d", alg, withChain, len(gotChain), wantChain)
			}
		}
	}
}

func TestEncodePKCS12DefaultsToModern(t *testing.T) {
	t.Parallel()
	// Spec section 6.6: modern is the default because it is what engine.py's
	// bare `openssl pkcs12 -export` already produces under OpenSSL 3, making
	// the migration behavior-preserving.
	leaf, key, _ := testLeaf(t)
	withDefault, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (default encoding): %v", err)
	}
	explicit, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword,
		PKCS12Encoding: PKCS12Modern,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (explicit modern): %v", err)
	}
	// Salts and IVs are random, so compare the algorithms rather than the bytes.
	if a, b := pkcs12Algorithms(t, withDefault), pkcs12Algorithms(t, explicit); a != b {
		t.Fatalf("the default encoding produced %q but explicit modern produced %q", a, b)
	}
}

// TestEncodePKCS12EmittedAlgorithms is the assertion spec section 6.6 demands.
// Encryption and MAC are independent failure axes on mobile platforms: Android
// 12 rejects a SHA-256 MAC even when the content is 3DES, so a bundle that
// merely decodes in Go can still be unimportable on a device.
func TestEncodePKCS12EmittedAlgorithms(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	leaf, key, ca := testLeaf(t)

	for _, tc := range []struct {
		encoding      PKCS12Encoding
		password      string
		wantInOutput  []string
		notInOutput   []string
	}{
		{
			encoding: PKCS12Modern,
			password: testPassword,
			// AES-256-CBC content encryption with PBKDF2, and an HMAC-SHA256
			// MAC. The MAC assertion pins the "MAC:" line specifically, not a
			// bare "sha256" -- modern's PRF line also mentions SHA-256, so a
			// bare substring would pass even if the MAC were SHA-1.
			wantInOutput: []string{"PBES2", "PBKDF2", "AES-256-CBC", "MAC: sha256"},
			notInOutput:  []string{"TripleDES", "RC2", "MAC: sha1"},
		},
		{
			encoding: PKCS12Legacy,
			password: testPassword,
			// 3DES content encryption with a SHA-1 MAC -- the only combination
			// universally importable on iOS < 18 and Android < 14.
			wantInOutput: []string{"pbeWithSHA1And3-KeyTripleDES-CBC", "MAC: sha1"},
			notInOutput:  []string{"AES-256-CBC", "PBES2", "RC2", "sha256"},
		},
	} {
		out, err := EncodeBundle(BundleInput{
			Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
			Chain: []*x509.Certificate{ca}, Password: tc.password, PKCS12Encoding: tc.encoding,
		})
		if err != nil {
			t.Errorf("%s: EncodeBundle: %v", tc.encoding, err)
			continue
		}
		// `openssl pkcs12 -info -nokeys -nocerts` prints the algorithm
		// identifiers for each SafeBag and the MAC without needing to decrypt
		// anything beyond the structure.
		text := opensslRun(t, out, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+tc.password)
		lower := strings.ToLower(text)
		for _, want := range tc.wantInOutput {
			if !strings.Contains(lower, strings.ToLower(want)) {
				t.Errorf("%s: openssl pkcs12 -info output does not mention %q:\n%s", tc.encoding, want, text)
			}
		}
		for _, unwanted := range tc.notInOutput {
			if strings.Contains(lower, strings.ToLower(unwanted)) {
				t.Errorf("%s: openssl pkcs12 -info output unexpectedly mentions %q:\n%s", tc.encoding, unwanted, text)
			}
		}
	}
}

// TestEncodePKCS12ModernAndLegacyDifferInBothAxes guards against a partial
// implementation that switches the content cipher but leaves the MAC alone.
// Android 12 would reject the result even though the content is 3DES.
func TestEncodePKCS12ModernAndLegacyDifferInBothAxes(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	leaf, key, _ := testLeaf(t)

	modern, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
		Password: testPassword, PKCS12Encoding: PKCS12Modern,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (modern): %v", err)
	}
	legacy, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
		Password: testPassword, PKCS12Encoding: PKCS12Legacy,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (legacy): %v", err)
	}

	modernText := strings.ToLower(opensslRun(t, modern, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+testPassword))
	legacyText := strings.ToLower(opensslRun(t, legacy, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+testPassword))

	// Pin the MAC line on each side, positively. An earlier draft used the
	// conjunction `Contains(modernText, "sha1") && !Contains(modernText,
	// "sha256")`, which can never fire: modern always contains "sha256" via
	// its PRF line, so the second clause is always false. Matching "mac: "
	// specifically is what distinguishes the MAC from the PRF.
	if !strings.Contains(modernText, "mac: sha256") {
		t.Error("modern did not emit a SHA-256 MAC")
	}
	if strings.Contains(modernText, "mac: sha1") {
		t.Error("modern emitted a SHA-1 MAC; it must be SHA-256")
	}
	if !strings.Contains(legacyText, "mac: sha1") {
		t.Error("legacy did not emit a SHA-1 MAC; Android 12 rejects SHA-256 even with 3DES content")
	}
	if strings.Contains(legacyText, "mac: sha256") {
		t.Error("legacy emitted a SHA-256 MAC; only SHA-1 is universally importable")
	}
}

func TestEncodePKCS12Passwordless(t *testing.T) {
	t.Parallel()
	// The Passwordless encoder has no encryption and no MAC, and go-pkcs12
	// rejects a non-empty password with it. The provider must translate that
	// into a clear error rather than passing the confusion through.
	leaf, _, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, Chain: []*x509.Certificate{ca},
		PKCS12Encoding: PKCS12Passwordless,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (passwordless truststore): %v", err)
	}
	certs, err := pkcs12.DecodeTrustStore(out, "")
	if err != nil {
		t.Fatalf("DecodeTrustStore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("passwordless truststore holds %d certificates, want 2", len(certs))
	}

	_, err = EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf,
		PKCS12Encoding: PKCS12Passwordless, Password: testPassword,
	})
	if err == nil {
		t.Fatal("EncodeBundle accepted a password with the passwordless encoding")
	}
	if !strings.Contains(err.Error(), "passwordless") {
		t.Errorf("error %q does not mention the passwordless encoding", err.Error())
	}
}

// TestEncodePKCS12WithoutKeyBuildsATrustStore covers the structural distinction
// spec section 6.6 calls out: a PKCS#12 truststore is a different artifact from
// a cert-only keystore, and go-pkcs12 has a separate encoder for it.
func TestEncodePKCS12WithoutKeyBuildsATrustStore(t *testing.T) {
	t.Parallel()
	leaf, _, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, Chain: []*x509.Certificate{ca},
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	certs, err := pkcs12.DecodeTrustStore(out, testPassword)
	if err != nil {
		t.Fatalf("a keyless PKCS#12 bundle did not decode as a truststore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("truststore holds %d certificates, want 2", len(certs))
	}
	// DecodeChain expects a key entry and must fail on a truststore, which is
	// what proves the two artifacts really are structurally different.
	if _, _, _, err := pkcs12.DecodeChain(out, testPassword); err == nil {
		t.Error("DecodeChain succeeded on a truststore; the keyless path is not producing a truststore")
	}
}

func TestEncodePKCS12FriendlyName(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)

	// With a key, the friendly name is the keystore alias.
	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
		Password: testPassword, FriendlyName: "nick-ipad",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	// A keyed PKCS#12 bundle has NO settable alias. go-pkcs12 v0.7.3's
	// Encoder.Encode writes only localKeyId; oidFriendlyName is emitted solely
	// by EncodeTrustStoreEntries. keytool therefore shows the alias as "1"
	// regardless of FriendlyName. Ruled 2026-07-25: accept and document.
	//
	// This assertion is deliberately negative and self-expiring: if go-pkcs12
	// ever honors the name here, it fails and tells you to delete it and
	// restore a positive assertion.
	if requireKeytool(t, false) != "" {
		text := strings.ToLower(keytoolList(t, out, testPassword))
		if strings.Contains(text, "nick-ipad") {
			t.Errorf("keytool -list now shows the friendly name on a KEYED pkcs12 bundle, "+
				"which go-pkcs12 v0.7.3 could not do. Upstream has gained support: drop this "+
				"negative assertion, assert the alias positively instead, and update the "+
				"friendly_name documentation in spec section 6.6.\n%s", text)
		}
	}

	// Without a key, distinct aliases still matter: go-pkcs12's
	// EncodeTrustStore derives names from each certificate's subject, so two
	// certificates sharing a subject collide into one entry. The truststore
	// path must use EncodeTrustStoreEntries with explicit names.
	out, err = EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, Chain: []*x509.Certificate{ca},
		Password: testPassword, FriendlyName: "homelab",
	})
	if err != nil {
		t.Fatalf("EncodeBundle (truststore with friendly name): %v", err)
	}
	certs, err := pkcs12.DecodeTrustStore(out, testPassword)
	if err != nil {
		t.Fatalf("DecodeTrustStore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("truststore holds %d certificates, want 2; distinct aliases were not preserved", len(certs))
	}
}

func TestEncodePKCS12RejectsBadInput(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	for label, in := range map[string]BundleInput{
		"unknown encoding": {Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword, PKCS12Encoding: "ancient"},
		"legacy rc2":       {Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword, PKCS12Encoding: "legacy-rc2"},
		"key without cert": {Format: FormatPKCS12, PrivateKey: key, Password: testPassword},
		"empty password":   {Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, PKCS12Encoding: PKCS12Modern},
	} {
		if _, err := EncodeBundle(in); err == nil {
			t.Errorf("EncodeBundle(pkcs12, %s) returned nil error, want an error", label)
		}
	}
}

// TestEncodePKCS12MismatchedKeyAndCertificateIsRejected catches a wiring error
// in HCL -- pairing one device's key with another's certificate -- that would
// otherwise produce a bundle the device installs and then fails TLS with.
func TestEncodePKCS12MismatchedKeyAndCertificateIsRejected(t *testing.T) {
	t.Parallel()
	leaf, _, _ := testLeaf(t)
	otherKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: otherKey, Password: testPassword,
	}); err == nil {
		t.Fatal("EncodeBundle accepted a private key that does not match the certificate")
	}
}

func TestPKCS12EncodingsList(t *testing.T) {
	t.Parallel()
	got := PKCS12Encodings()
	want := []PKCS12Encoding{PKCS12Modern, PKCS12Legacy, PKCS12Passwordless}
	if len(got) != len(want) {
		t.Fatalf("PKCS12Encodings() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PKCS12Encodings()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// LegacyRC2 must not be reachable: it emits RC2-40, which OpenSSL 3 cannot
	// decrypt (spec section 6.6). Modern2026 uses PBMAC1 and no mobile platform
	// reads it.
	for _, forbidden := range []PKCS12Encoding{"legacy-rc2", "legacyrc2", "rc2", "modern2026"} {
		for _, allowed := range got {
			if allowed == forbidden {
				t.Errorf("PKCS12Encodings() exposes %q, which must not be offered", forbidden)
			}
		}
	}
}
```

Add to `internal/pki/testhelper_test.go`:

```go
// testLeafWithAlgorithm is testLeaf with a caller-chosen key algorithm for the
// leaf. The CA stays ECDSA; the two are independent.
func testLeafWithAlgorithm(t *testing.T, alg Algorithm) (*x509.Certificate, crypto.Signer, *x509.Certificate) {
	t.Helper()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")
	key, err := GenerateKey(KeyParams{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", alg, err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "leaf-" + string(alg)}.Expand(),
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
	}, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", alg, err)
	}
	leaf, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	return leaf, key, ca
}

// pkcs12Algorithms summarizes a PKCS#12 file's algorithm identifiers, so tests
// can compare two files whose salts and IVs necessarily differ.
func pkcs12Algorithms(t *testing.T, pfx []byte) string {
	t.Helper()
	text := opensslRun(t, pfx, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+testPassword)
	var kept []string
	for _, line := range strings.Split(text, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(l, "encryption") || strings.Contains(l, "mac") || strings.Contains(l, "pbe") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "|")
}

// requireKeytool returns the path to keytool, or "" when it is absent. Pass
// mustHave = true to skip the test instead of returning empty.
func requireKeytool(t *testing.T, mustHave bool) string {
	t.Helper()
	path, err := exec.LookPath("keytool")
	if err != nil {
		if mustHave {
			t.Skip("keytool not found in PATH; skipping cross-validation")
		}
		return ""
	}
	return path
}

// keytoolList runs `keytool -list` over a PKCS#12 or JKS file.
func keytoolList(t *testing.T, store []byte, password string) string {
	t.Helper()
	bin := requireKeytool(t, true)
	dir := t.TempDir()
	path := filepath.Join(dir, "store")
	if err := os.WriteFile(path, store, 0o600); err != nil {
		t.Fatalf("writing the keystore: %v", err)
	}
	cmd := exec.Command(bin, "-list", "-keystore", path, "-storepass", password)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keytool -list failed: %v\n%s", err, out)
	}
	return string(out)
}
```

`testhelper_test.go` gains `os`, `path/filepath`; `bundle_pkcs12_test.go` needs `crypto` in its imports for the signer assertion.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run PKCS12 -v
```

Expected: FAIL to build with `undefined: PKCS12Modern`, `undefined: PKCS12Encodings`.

- [ ] **Step 3: Implement `encodePKCS12`**

```go
// PKCS12Encoding selects the algorithm suite for a PKCS#12 bundle.
//
// Only three of go-pkcs12's encoders are exposed, and the omissions are
// deliberate. LegacyRC2 emits RC2-40, which OpenSSL 3 refuses to decrypt.
// Modern2026 uses PBMAC1, which needs OpenSSL 3.4+ or Java 26+ and which no
// mobile platform reads.
type PKCS12Encoding string

const (
	// PKCS12Modern is AES-256-CBC content encryption with PBKDF2 and an
	// HMAC-SHA256 MAC. It is the default because it is what a bare
	// `openssl pkcs12 -export` produces under OpenSSL 3, which is what the
	// homelab reconciler already emits, so migrating to this provider does not
	// change what lands on a device.
	//
	// Requires iOS/iPadOS 18+, macOS 15+, or Android 14+ (Android 12-13 depends
	// on the device's Play system update).
	PKCS12Modern PKCS12Encoding = "modern"

	// PKCS12Legacy is 3DES content encryption with a SHA-1 MAC. It is the only
	// combination that is universally importable on older devices. Encryption
	// and MAC are independent failure axes: Android 12 rejects a SHA-256 MAC
	// even when the content is 3DES, so switching only the cipher is not
	// enough.
	PKCS12Legacy PKCS12Encoding = "legacy"

	// PKCS12Passwordless has no encryption and no MAC. go-pkcs12 requires the
	// password to be empty with it, and it is really only useful for Java
	// truststores.
	PKCS12Passwordless PKCS12Encoding = "passwordless"
)

// pkcs12Encoders maps the exposed encodings to go-pkcs12's encoders.
var pkcs12Encoders = map[PKCS12Encoding]*pkcs12.Encoder{
	PKCS12Modern:       pkcs12.Modern2023,
	PKCS12Legacy:       pkcs12.LegacyDES,
	PKCS12Passwordless: pkcs12.Passwordless,
}
```

`encodePKCS12` in order:

1. Default `PKCS12Encoding` to `PKCS12Modern` when empty, then look up the encoder and error naming the input on a miss. Do not fall through to a default on an unknown value — a typo must fail, not silently produce `modern`.
2. Apply `Rand` when set, via `encoder.WithRand(in.Rand)`. Note that `WithRand` has a value receiver returning a new `*Encoder`, so this does not mutate the package-level variable.
3. **Reject `passwordless` together with a `PrivateKey`.** The combination encodes an unshrouded key bag that Java's `PKCS12KeyStore` will not load: `openssl pkcs12 -info` shows the key and both certificates, and `pkcs12.DecodeChain` reads it back fine, but `keytool -list` reports **0 entries** — measured. Since `passwordless` exists for Java truststores, silently emitting a bundle the one target consumer reads as empty is the sort of quiet breakage this plan exists to avoid. Error naming `pkcs12_encoding` and `private_key_pem`, and say that an unencrypted key belongs in `format = "pem"` instead.

4. Validate the password against the encoding: `PKCS12Passwordless` requires an empty password (go-pkcs12 errors with `pkcs12: password must be empty`, which is accurate but does not tell the user which attribute to change, so pre-empt it with a message naming `pkcs12_encoding` and `password_wo`). The other two encodings require a non-empty password — an empty password with `modern` produces a file whose MAC is keyed on the empty string, which some tools accept and others reject, and no caller wants that ambiguity.
5. When `PrivateKey` is nil, build a truststore. Use `EncodeTrustStoreEntries` with one `pkcs12.TrustStoreEntry` per certificate rather than `EncodeTrustStore`, because `EncodeTrustStore` derives each friendly name from the certificate's subject and two certificates sharing a subject then collapse into one keytool entry.

   **De-duplicate the derived aliases case-insensitively.** Java folds PKCS#12 aliases to lowercase, so `Root` and `root` are the same alias and one trust anchor is silently dropped — measured with `keytool -list`, which reported one entry for two distinct self-signed roots. Key the seen-set on `strings.ToLower(candidate)`, not the raw string. A test using two certificates whose CNs differ only in case is required; identical subjects do not cover this. The same applies to Task 13, since `keystore-go` lowercases aliases too, where a collision overwrites rather than merges. Name the entries from `FriendlyName` when set — suffixing `-1`, `-2` and so on across multiple certificates — and otherwise from each certificate's `Subject.CommonName`, falling back to the serial when the CN is empty.
6. When `PrivateKey` is set, require `Certificate` to be non-nil and require the key to match the certificate.

   **This asymmetry with `pkcs7` is deliberate.** A degenerate PKCS#7 is a flat bag of certificates with no designated end entity, so Task 11 correctly allows a chain-only bundle — that is how a trust bundle is distributed. PKCS#12 and JKS are different: a keystore entry pairs one specific certificate with the key, so with a key present the certificate is not optional. Without a key both become truststores, where every certificate is a peer and no leaf is designated. Task 11's reviewer asked whether the two behaviours were consistent; they differ because the formats differ.

   The check itself: compare `PublicKeyOf(in.PrivateKey)` against `in.Certificate.PublicKey` with `PublicKeysEqual`. This is the check that catches a crossed-wires HCL reference before a device does.
7. Call `encoder.Encode(in.PrivateKey, in.Certificate, in.Chain, in.Password)`. go-pkcs12 accepts `crypto.Signer` for all three key types, so no PKCS#8 conversion is needed here — that is only the JKS path.

`PKCS12Encodings()` returns the three constants in declaration order.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run PKCS12 -v
```

Expected: PASS. `TestEncodePKCS12EmittedAlgorithms` skips if openssl is absent; on this machine (OpenSSL 3.5.7) it runs.

**The substrings above are what OpenSSL 3.5.7 actually prints, measured.** An earlier draft of this plan expected `des-ede3-cbc` for `legacy`, which OpenSSL never emits — it prints `pbeWithSHA1And3-KeyTripleDES-CBC`. That error was worse than a failing test: `legacy`'s assertion would have failed always, while `modern`'s `notInOutput: ["des-ede3-cbc"]` passed **vacuously**, because that string appears in no output at all. So `modern` could have silently emitted 3DES and no test would have noticed — exactly the device-lockout bug these assertions exist to prevent. Verified observed output, OpenSSL 3.5.7:

```
modern:  MAC: sha256, Iteration 2048
         PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256
legacy:  MAC: sha1, Iteration 1
         PKCS7 Encrypted data: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
```

Two lessons encoded in the assertions above. Match the `MAC:` line rather than a bare hash name, because `modern`'s PRF line also says SHA-256 and a bare match would not distinguish MAC from PRF. And put a *positive* assertion on each axis for both encodings, so neither can pass by the absence of a string that never appears.

If a future OpenSSL changes these labels, read the real output and re-pin — but never weaken an assertion to "it decoded". Go decodes both encodings happily; only an external tool can tell them apart, which is the entire reason this test exists.

- [ ] **Step 5: Verify against a real device path, manually, once**

This step is not automatable and is spec §14 follow-up 2 in miniature. Generate one `legacy` and one `modern` bundle for a throwaway leaf, and confirm both import where they are expected to:

```bash
openssl pkcs12 -in modern.p12 -info -nokeys -nocerts -passin pass:password
openssl pkcs12 -in legacy.p12 -info -nokeys -nocerts -passin pass:password
keytool -list -keystore modern.p12 -storetype PKCS12 -storepass password
```

Record the observed algorithm lines in a comment above `TestEncodePKCS12EmittedAlgorithms` with the OpenSSL and keytool versions, so a future failure can be attributed to a tool change rather than a code change. On-device confirmation on the actual iPad, iPhone, and Pixel 7 stays a follow-up in the spec; it is not a gate on this task.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./... && go test ./internal/pki/
git add internal/pki/bundle.go internal/pki/bundle_pkcs12_test.go internal/pki/testhelper_test.go
git commit -m "feat: pkcs12 encoder with modern, legacy, and passwordless suites"
```

---

### Task 13: JKS bundles (`bundle.go`, part 3)

**Files:**
- Modify: `internal/pki/bundle.go`
- Test: `internal/pki/bundle_jks_test.go`

**Interfaces:**
- Consumes: `BundleInput` (Task 11), `EncodePrivateKeyPKCS8DER` (Task 5).
- Produces: `encodeJKS(in BundleInput) ([]byte, error)` — unexported, reached through `EncodeBundle`.

- [ ] **Step 1: Write the failing tests**

`internal/pki/bundle_jks_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestEncodeJKSWithPrivateKeyEntry(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, PrivateKey: key,
		Chain: []*x509.Certificate{ca}, Password: testPassword, FriendlyName: "nick-ipad",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	// A JKS starts with the magic bytes 0xfeedfeed.
	if len(out) < 4 || !bytes.Equal(out[:4], []byte{0xfe, 0xed, 0xfe, 0xed}) {
		t.Fatalf("output does not start with the JKS magic 0xfeedfeed: % x", out[:min(4, len(out))])
	}

	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(out), []byte(testPassword)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 1 || aliases[0] != "nick-ipad" {
		t.Fatalf("aliases = %v, want [nick-ipad]", aliases)
	}
	if !ks.IsPrivateKeyEntry("nick-ipad") {
		t.Fatal("the entry is not a private key entry")
	}
	entry, err := ks.GetPrivateKeyEntry("nick-ipad", []byte(testPassword))
	if err != nil {
		t.Fatalf("GetPrivateKeyEntry: %v", err)
	}
	if len(entry.CertificateChain) != 2 {
		t.Fatalf("certificate chain has %d entries, want 2", len(entry.CertificateChain))
	}
	if !bytes.Equal(entry.CertificateChain[0].Content, leaf.Raw) {
		t.Error("the first chain entry is not the leaf certificate")
	}
	for i, c := range entry.CertificateChain {
		// keystore-go's own decoder writes "X509"; anything else is unreadable
		// by Java.
		if c.Type != "X509" {
			t.Errorf("chain entry %d has certificate type %q, want \"X509\"", i, c.Type)
		}
	}
}

// TestEncodeJKSStoresPKCS8PrivateKey is the assertion that catches the trap in
// keystore-go: it does not validate the key encoding, so storing a SEC1 blob
// succeeds and produces a file only Java rejects.
func TestEncodeJKSStoresPKCS8PrivateKey(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		leaf, key, _ := testLeafWithAlgorithm(t, alg)
		out, err := EncodeBundle(BundleInput{
			Format: FormatJKS, Certificate: leaf, PrivateKey: key,
			Password: testPassword, FriendlyName: "alias",
		})
		if err != nil {
			t.Errorf("%s: EncodeBundle: %v", alg, err)
			continue
		}
		ks := keystore.New()
		if err := ks.Load(bytes.NewReader(out), []byte(testPassword)); err != nil {
			t.Errorf("%s: Load: %v", alg, err)
			continue
		}
		entry, err := ks.GetPrivateKeyEntry("alias", []byte(testPassword))
		if err != nil {
			t.Errorf("%s: GetPrivateKeyEntry: %v", alg, err)
			continue
		}
		if _, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey); err != nil {
			t.Errorf("%s: the stored private key is not PKCS#8 DER, which Java requires: %v", alg, err)
		}
	}
}

func TestEncodeJKSTrustedCertificateEntries(t *testing.T) {
	t.Parallel()
	leaf, _, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, Chain: []*x509.Certificate{ca},
		Password: testPassword, FriendlyName: "homelab",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(out), []byte(testPassword)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 2 {
		t.Fatalf("aliases = %v, want 2 distinct entries", aliases)
	}
	for _, a := range aliases {
		if !ks.IsTrustedCertificateEntry(a) {
			t.Errorf("alias %q is not a trusted certificate entry", a)
		}
	}
}

func TestEncodeJKSRejectsBadInput(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	for label, in := range map[string]BundleInput{
		"no password":      {Format: FormatJKS, Certificate: leaf, PrivateKey: key, FriendlyName: "a"},
		"short password":   {Format: FormatJKS, Certificate: leaf, PrivateKey: key, Password: "12345", FriendlyName: "a"},
		"key without cert": {Format: FormatJKS, PrivateKey: key, Password: testPassword, FriendlyName: "a"},
		"mismatched key":   {Format: FormatJKS, Certificate: leaf, PrivateKey: mustOtherKey(nil), Password: testPassword, FriendlyName: "a"},
	} {
		if label == "mismatched key" {
			continue // exercised separately below, where a *testing.T is available
		}
		if _, err := EncodeBundle(in); err == nil {
			t.Errorf("EncodeBundle(jks, %s) returned nil error, want an error", label)
		}
	}

	other, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, PrivateKey: other,
		Password: testPassword, FriendlyName: "a",
	}); err == nil {
		t.Error("EncodeBundle(jks) accepted a private key that does not match the certificate")
	}
}

func TestEncodeJKSIsReadableByKeytool(t *testing.T) {
	t.Parallel()
	requireKeytool(t, true)
	leaf, key, ca := testLeaf(t)
	out, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, PrivateKey: key,
		Chain: []*x509.Certificate{ca}, Password: testPassword, FriendlyName: "nick-ipad",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	text := keytoolList(t, out, testPassword)
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "nick-ipad") {
		t.Errorf("keytool -list does not show the alias:\n%s", text)
	}
	if !strings.Contains(lower, "privatekeyentry") {
		t.Errorf("keytool -list does not report a PrivateKeyEntry:\n%s", text)
	}
}
```

Delete the `mustOtherKey` reference and the guarded loop entry when writing the file — it is left here only to show why that case is exercised separately; write the file with the loop covering the first three labels and the mismatched-key case standing alone. `bundle_jks_test.go` needs no `mustOtherKey` helper.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run JKS -v
```

Expected: FAIL to build with `undefined: encodeJKS` reached through `EncodeBundle`, or a "not implemented" error from the dispatch stub.

- [ ] **Step 3: Implement `encodeJKS`**

```go
// encodeJKS builds a Java keystore.
//
// Two properties of keystore-go make this less mechanical than it looks. It
// does not validate the private key encoding, so handing it a SEC1 blob
// produces a file that Store() accepts and Java rejects -- the key must be
// PKCS#8 DER. And its default minimum password length is zero, so a two-
// character store password is accepted silently; JKS's own floor is six, which
// this function enforces.
func encodeJKS(in BundleInput) ([]byte, error) {
```

Steps:

1. Require a non-empty `Password` of at least six characters, the JKS minimum, and construct the store with `keystore.New(keystore.WithOrderedAliases(), keystore.WithMinPasswordLen(6))`. Ordered aliases make the output deterministic for a given input, which keeps a Kubernetes Secret from churning on every apply.
2. `creationTime` must be a fixed value, not `time.Now()`, for the same determinism reason. Use `in.Certificate.NotBefore` when a certificate is present, and the first chain entry's `NotBefore` otherwise. Say why in a comment: a wall-clock timestamp in the file makes every apply produce different bytes.
3. When `PrivateKey` is set: require `Certificate`, require the key to match it via `PublicKeysEqual`, convert with `EncodePrivateKeyPKCS8DER`, build the `[]keystore.Certificate` chain with `Type: "X509"` and `Content: cert.Raw` for the certificate followed by each chain entry, and call `SetPrivateKeyEntry(alias, entry, []byte(in.Password))`. The alias is `FriendlyName` when set, otherwise the certificate's CN, otherwise `"key"`.
4. When `PrivateKey` is nil: add one `SetTrustedCertificateEntry` per certificate, deriving distinct aliases the same way the PKCS#12 truststore path does — `FriendlyName` with a numeric suffix across multiple entries, or each certificate's CN. Duplicate aliases silently overwrite in keystore-go, which is why the alias derivation cannot just use the CN when subjects can repeat.
5. `Store` into a `bytes.Buffer` and return its bytes.

Note in the doc comment that the literal `"X509"` is required: keystore-go's decoder writes exactly that string and `"X.509"` produces an entry Java does not recognize.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run JKS -v
go test ./internal/pki/
```

Expected: PASS. `TestEncodeJKSIsReadableByKeytool` runs on this machine (keytool is present) and skips elsewhere.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/bundle.go internal/pki/bundle_jks_test.go
git commit -m "feat: jks bundle encoder with pkcs8 keys and deterministic output"
```

---

### Task 14: Drift comparison (`compare.go`)

Spec §9's comparison, implemented against parsed DER. This is the library half of the provider's `ModifyPlan`; Plan 2 wires it in. The bias is explicit: with 20-year certificates installed on phones, a false positive costs a manual device re-enrollment, so anything not derivable from a certificate is excluded from the comparison entirely.

**Files:**
- Create: `internal/pki/compare.go`
- Test: `internal/pki/compare_test.go`

**Interfaces:**
- Consumes: `CertTemplate.Extensions`, `ParseCertificatePEM` (Task 9); `Subject.EncodeDER` (Task 6).
- Produces:
  - `type Drift struct { Field string; Want string; Got string }`
  - `func (d Drift) String() string`
  - `type CompareInput struct { Desired CertTemplate; DesiredPublicKey crypto.PublicKey; Actual *x509.Certificate; CA *x509.Certificate }`
  - `func CompareCertificate(in CompareInput) ([]Drift, error)` — empty slice means no drift
  - `func CompareValidity(actual *x509.Certificate, earlyRenewal time.Duration, now time.Time) (readyForRenewal bool)`

- [ ] **Step 1: Write the failing tests**

`internal/pki/compare_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

// desiredFor rebuilds the template that produced a fixture leaf, so a
// comparison against the issued certificate reports no drift.
func desiredFor(t *testing.T, leaf *x509.Certificate) CertTemplate {
	t.Helper()
	subject, err := ParseSubjectDER(leaf.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	sanExt, ok := FindExtension(leaf.Extensions, oidSubjectAltName)
	var san SAN
	if ok {
		san, err = ParseSANExtension(sanExt)
		if err != nil {
			t.Fatalf("ParseSANExtension: %v", err)
		}
		san.Critical = sanExt.Critical
	}
	return CertTemplate{
		Subject:          subject,
		SAN:              san,
		Serial:           leaf.SerialNumber,
		NotBefore:        leaf.NotBefore,
		NotAfter:         leaf.NotAfter,
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}
}

// TestCompareCertificateNoDriftOnAnUnchangedCertificate is the property that
// makes the whole design work: reparsing an issued certificate and comparing it
// to the template that produced it must report nothing.
func TestCompareCertificateNoDriftOnAnUnchangedCertificate(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	drift, err := CompareCertificate(CompareInput{
		Desired:          desiredFor(t, leaf),
		DesiredPublicKey: PublicKeyOf(key),
		Actual:           leaf,
		CA:               ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("reported drift on an unchanged certificate: %v", drift)
	}
}

// TestCompareCertificateIgnoresRotatingCAKey is spec section 9's headline
// guarantee and spec section 10's acceptance criterion: re-reading a rotating
// Bitwarden Secret must not trigger a replacement. ca_private_key_pem is not
// derivable from a certificate and therefore is not in CompareInput at all --
// this test documents that absence deliberately.
func TestCompareCertificateIgnoresRotatingCAKey(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	desired := desiredFor(t, leaf)

	// Two comparisons, structurally identical, with nothing about the CA key
	// available to either. If a future refactor adds a key field to
	// CompareInput, this test stops compiling, which is the intent.
	for i := 0; i < 2; i++ {
		drift, err := CompareCertificate(CompareInput{
			Desired: desired, DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: ca,
		})
		if err != nil {
			t.Fatalf("CompareCertificate: %v", err)
		}
		if len(drift) != 0 {
			t.Fatalf("iteration %d reported drift: %v", i, drift)
		}
	}
}

func TestCompareCertificateDetectsEachKindOfDrift(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	pub := PublicKeyOf(key)

	for label, tc := range map[string]struct {
		mutate    func(CertTemplate) CertTemplate
		wantField string
	}{
		"subject": {
			mutate:    func(c CertTemplate) CertTemplate { c.Subject = NamedSubject{CommonName: "different"}.Expand(); return c },
			wantField: "subject",
		},
		"san": {
			mutate:    func(c CertTemplate) CertTemplate { c.SAN = SAN{DNSNames: []string{"other.example"}}; return c },
			wantField: "san",
		},
		"serial": {
			mutate:    func(c CertTemplate) CertTemplate { c.Serial = big.NewInt(0x9999); return c },
			wantField: "serial_number",
		},
		"notAfter": {
			mutate:    func(c CertTemplate) CertTemplate { c.NotAfter = c.NotAfter.Add(24 * time.Hour); return c },
			wantField: "not_after",
		},
		"notBefore": {
			mutate:    func(c CertTemplate) CertTemplate { c.NotBefore = c.NotBefore.Add(-24 * time.Hour); return c },
			wantField: "not_before",
		},
		"key usage bits": {
			mutate: func(c CertTemplate) CertTemplate {
				c.KeyUsage = &KeyUsage{Usages: []string{"digitalSignature"}, Critical: true}
				return c
			},
			wantField: "2.5.29.15",
		},
		"key usage criticality": {
			mutate: func(c CertTemplate) CertTemplate {
				c.KeyUsage = &KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: false}
				return c
			},
			wantField: "2.5.29.15",
		},
		"extended key usage": {
			mutate: func(c CertTemplate) CertTemplate {
				c.ExtKeyUsage = &ExtKeyUsage{Usages: []string{"serverAuth"}}
				return c
			},
			wantField: "2.5.29.37",
		},
		"basic constraints ca flag": {
			mutate: func(c CertTemplate) CertTemplate {
				c.BasicConstraints = &BasicConstraints{CA: true, Critical: true}
				return c
			},
			wantField: "2.5.29.19",
		},
		"added extension": {
			mutate: func(c CertTemplate) CertTemplate {
				c.ExtraExtensions = []ExtraExtension{{OID: mustOID(t, "1.3.6.1.4.1.99999.1"), Value: []byte{0x05, 0x00}}}
				return c
			},
			wantField: "1.3.6.1.4.1.99999.1",
		},
		"removed extension": {
			mutate:    func(c CertTemplate) CertTemplate { c.ExtKeyUsage = nil; return c },
			wantField: "2.5.29.37",
		},
	} {
		drift, err := CompareCertificate(CompareInput{
			Desired: tc.mutate(desiredFor(t, leaf)), DesiredPublicKey: pub, Actual: leaf, CA: ca,
		})
		if err != nil {
			t.Errorf("%s: CompareCertificate: %v", label, err)
			continue
		}
		if len(drift) == 0 {
			t.Errorf("%s: reported no drift, want drift on %q", label, tc.wantField)
			continue
		}
		found := false
		for _, d := range drift {
			if d.Field == tc.wantField {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: drift = %v, want an entry for %q", label, drift, tc.wantField)
		}
	}
}

// TestCompareCertificateIgnoresKeyUsageOrder confirms the comparison inherits
// the encoding's insensitivity to config order. Reordering a usages list in HCL
// must not replace a certificate.
func TestCompareCertificateIgnoresKeyUsageOrder(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	desired := desiredFor(t, leaf)
	desired.KeyUsage = &KeyUsage{Usages: []string{"keyEncipherment", "digitalSignature"}, Critical: true}
	drift, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("reordering the key usage list reported drift: %v", drift)
	}
}

// TestCompareCertificateIgnoresNamedVersusOrderedSubjectForm is spec section
// 5.1's requirement: any config that encodes to the same DN plans clean.
func TestCompareCertificateIgnoresNamedVersusOrderedSubjectForm(t *testing.T) {
	t.Parallel()
	ca, caKey := testCA(t, nil, nil, "ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	named := NamedSubject{CommonName: "cn", UID: "uid", GivenName: "gn", Surname: "sn", Organization: "o"}.Expand()
	tmpl := CertTemplate{
		Subject:   named,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:  time.Now().Add(time.Hour).Truncate(time.Second),
	}
	certPEM, err := CreateCertificate(tmpl, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	// Now compare with the ordered form spelled out attribute by attribute.
	ordered := tmpl
	ordered.Subject = Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		attr(t, "uid", "uid"),
		attr(t, "givenName", "gn"),
		attr(t, "surname", "sn"),
		attr(t, "organization", "o"),
	}}
	drift, err := CompareCertificate(CompareInput{
		Desired: ordered, DesiredPublicKey: PublicKeyOf(key), Actual: cert, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("the ordered form of the same DN reported drift: %v", drift)
	}
}

func TestCompareCertificateDetectsPublicKeyMismatch(t *testing.T) {
	t.Parallel()
	// A rotated private_key_pem means the certificate no longer matches its
	// key and must be reissued. This is drift the comparison must catch, in
	// contrast to a rotated CA key, which it must ignore.
	leaf, _, ca := testLeaf(t)
	other, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(other), Actual: leaf, CA: ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) == 0 {
		t.Fatal("a public key mismatch reported no drift")
	}
	found := false
	for _, d := range drift {
		if d.Field == "public_key" {
			found = true
		}
	}
	if !found {
		t.Errorf("drift = %v, want an entry for \"public_key\"", drift)
	}
}

func TestCompareCertificateDetectsWrongIssuer(t *testing.T) {
	t.Parallel()
	// Spec section 9 compares the issuer DN and the signature against
	// ca_certificate_pem. Pointing a resource at a different CA must reissue.
	leaf, key, _ := testLeaf(t)
	otherCA, _ := testCA(t, nil, nil, "a-different-ca")
	drift, err := CompareCertificate(CompareInput{
		Desired: desiredFor(t, leaf), DesiredPublicKey: PublicKeyOf(key), Actual: leaf, CA: otherCA,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) == 0 {
		t.Fatal("comparing against a different CA reported no drift")
	}
	found := false
	for _, d := range drift {
		if d.Field == "issuer" || d.Field == "signature" {
			found = true
		}
	}
	if !found {
		t.Errorf("drift = %v, want an entry for \"issuer\" or \"signature\"", drift)
	}
}

func TestCompareCertificateSelfSignedIssuerCheck(t *testing.T) {
	t.Parallel()
	// A self-signed root has no separate CA, so CompareInput.CA is nil and the
	// signature is checked against the certificate itself.
	ca, caKey := testCA(t, nil, nil, "root")
	subject, err := ParseSubjectDER(ca.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	desired := CertTemplate{
		Subject:          subject,
		Serial:           ca.SerialNumber,
		NotBefore:        ca.NotBefore,
		NotAfter:         ca.NotAfter,
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}
	drift, err := CompareCertificate(CompareInput{
		Desired: desired, DesiredPublicKey: PublicKeyOf(caKey), Actual: ca, CA: nil,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("a self-signed root reported drift against its own template: %v", drift)
	}
}

func TestCompareCertificateRejectsMissingActual(t *testing.T) {
	t.Parallel()
	if _, err := CompareCertificate(CompareInput{}); err == nil {
		t.Fatal("CompareCertificate with no actual certificate returned nil error, want an error")
	}
}

func TestDriftString(t *testing.T) {
	t.Parallel()
	// Drift strings end up in a Terraform plan explanation, so they must name
	// the field and both sides.
	got := Drift{Field: "serial_number", Want: "2001", Got: "2002"}.String()
	for _, want := range []string{"serial_number", "2001", "2002"} {
		if !strings.Contains(got, want) {
			t.Errorf("Drift.String() = %q, want it to contain %q", got, want)
		}
	}
}

func TestCompareValidity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	leaf, _, _ := testLeaf(t)
	cert := *leaf
	cert.NotBefore = now.Add(-24 * time.Hour)
	cert.NotAfter = now.Add(48 * time.Hour)

	for label, tc := range map[string]struct {
		earlyRenewal time.Duration
		want         bool
	}{
		"no early renewal":            {0, false},
		"outside the window":          {24 * time.Hour, false},
		"exactly at the boundary":     {48 * time.Hour, true},
		"inside the window":           {72 * time.Hour, true},
		"longer than the lifetime":    {365 * 24 * time.Hour, true},
	} {
		if got := CompareValidity(&cert, tc.earlyRenewal, now); got != tc.want {
			t.Errorf("%s: CompareValidity = %v, want %v", label, got, tc.want)
		}
	}

	// An already-expired certificate is ready for renewal regardless.
	expired := cert
	expired.NotAfter = now.Add(-time.Hour)
	if !CompareValidity(&expired, 0, now) {
		t.Error("an expired certificate is not reported ready for renewal")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test ./internal/pki/ -run 'Compare|Drift' -v
```

Expected: FAIL to build with `undefined: CompareCertificate`.

- [ ] **Step 3: Implement `compare.go`**

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

// Drift is one difference between a desired certificate and the one in state.
// Field is either an attribute name from the provider's schema ("subject",
// "serial_number") or, for extensions, the extension's dotted OID.
type Drift struct {
	Field string
	Want  string
	Got   string
}

// CompareInput is everything needed to decide whether a certificate must be
// reissued.
//
// Note what is absent. There is no field for the CA's private key, the
// certificate subject's private key, or the CSR, because none of those can be
// derived from an issued certificate. Spec section 9 excludes them by design:
// the homelab CA key arrives from a rotating Bitwarden Secret, and a comparison
// that noticed the rotation would replace every certificate under it -- which,
// for 20-year certificates installed on phones and tablets, means a manual
// re-enrollment per device. False positives are the expensive failure here, so
// unavailable inputs are omitted from the type rather than defaulted.
type CompareInput struct {
	Desired          CertTemplate
	DesiredPublicKey crypto.PublicKey
	Actual           *x509.Certificate

	// CA is the issuer to verify the signature against. Nil means the
	// certificate is expected to be self-signed.
	CA *x509.Certificate
}
```

`CompareCertificate` returns drift entries in a stable order, checking:

1. `Actual` non-nil, else an error (not drift — a caller with no certificate has a bug, not a diff). **`DesiredPublicKey` must also be non-nil**, and a nil one is likewise an error rather than drift: `CertTemplate.Extensions` needs the public key to compute the subjectKeyIdentifier and fails without it, so step 6 could not run. Every real caller has one — from the CSR in `csr_pem` mode, or from `public_key_pem` inline — so requiring it costs nothing and turns an unexplained `Extensions()` error into a clear precondition. Task 9's reviewer raised this.
2. **Subject**: `Desired.Subject.EncodeDER()` against `Actual.RawSubject`, compared as bytes. Report `Field: "subject"` with both sides rendered through `Subject.String()` for readability.

   **If `EncodeDER` fails, return the error — do not report it as drift.** This matters more than it looks. `Subject.Equal` (Task 6) swallows an encode failure and returns `false`, which is right for a boolean but wrong here: a subject that cannot be encoded would then be reported as permanently drifting with no stated cause, and the operator would watch Terraform propose the same replacement on every plan with no way to see why. The realistic trigger is an adopted certificate whose DN carries a value that violates its own declared string type — a `PrintableString` containing a character outside that repertoire, which Task 6's parser accepts but its encoder refuses. Surfacing the error names the attribute and turns unexplained churn into an actionable adoption failure. Task 6's implementer identified this and handed it forward specifically.
3. **Public key**: `PublicKeysEqual(in.DesiredPublicKey, in.Actual.PublicKey)`. Report `Field: "public_key"` with the fingerprints, never the keys. No nil guard is needed here — step 1 already rejected a nil `DesiredPublicKey`.
4. **Serial**: `Desired.Serial.Cmp(Actual.SerialNumber)`, reported as `serial_number` with `FormatSerial` on both sides.
5. **Validity**: `NotBefore` and `NotAfter` compared with `Time.Equal` after truncating both to a second, because DER encodes `UTCTime` at second granularity and a template carrying sub-second precision would otherwise always differ. Report `not_before` and `not_after` in RFC3339.
6. **Extensions**: build the desired list with `Desired.Extensions(in.DesiredPublicKey)` and index the actual certificate's `Extensions` by OID string.

   **Index by OID; never compare positionally.** `Extensions()` returns its documented order, but the order in an *issued* certificate is not the same: `x509.CreateCertificate` prepends the `authorityKeyIdentifier` it synthesizes from the parent. Measured directly — a template yielding `[2.5.29.19, 2.5.29.15, 2.5.29.37, 2.5.29.17, 2.5.29.14]` produces a certificate carrying `[2.5.29.35, 2.5.29.19, 2.5.29.15, 2.5.29.37, 2.5.29.17, 2.5.29.14]`. A positional comparison would report drift on every extension of every certificate. Task 9's implementer found this. For each desired extension, report drift when it is absent, when `Critical` differs, or when the DER value differs. Then report every actual extension not in the desired set — that catches a removed `extra_extension`, and the `authorityKeyIdentifier` Go adds must be excluded from that sweep since the template never contains it. Use the extension's dotted OID as `Field` so the message is unambiguous even for extensions the provider has no friendly name for; the SAN is the one exception, reported as `san` because that is the schema block a user would edit.
7. **Issuer and signature**: when `CA` is non-nil, compare `CA.RawSubject` against `Actual.RawIssuer` (`Field: "issuer"`) and call `Actual.CheckSignatureFrom(in.CA)` (`Field: "signature"`). When `CA` is nil, call `Actual.CheckSignatureFrom(in.Actual)` to confirm it really is self-signed.

Render extension values as hex, truncated to 64 characters with an ellipsis, so a drift message stays readable in a plan.

`CompareValidity` returns `now.Add(earlyRenewal).After(actual.NotAfter) || now.Equal(actual.NotAfter.Add(-earlyRenewal))`, expressed simply as `!now.Add(earlyRenewal).Before(actual.NotAfter)`. That single form covers the boundary case and the already-expired case, and matches `hashicorp/tls`'s semantics.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/pki/ -run 'Compare|Drift' -v
go test ./internal/pki/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/compare.go internal/pki/compare_test.go
git commit -m "feat: content drift comparison excluding non-derivable inputs"
```

---

### Task 15: Cross-validation against the Python issuer (`golden_test.go`)

Spec §10's cross-validation golden test. This proves the provider is a drop-in for `engine.py` before anything is cut over, and it is the last chance to catch a DN or extension divergence before the migration spec depends on it.

**Files:**
- Create: `internal/pki/golden_test.go`
- Create: `internal/pki/testdata/README.md`

**Interfaces:**
- Consumes: everything. Produces nothing the package exports.

- [ ] **Step 1: Generate the reference certificate with the existing toolchain**

The test compares against real `openssl` output produced the way `engine.py` produces it, so the reference must be generated by that path rather than described. Reproduce `engine.py`'s two invocations by hand, using `nick-ipad` and the identity from `config.hcl`:

```bash
mkdir -p /tmp/pki-golden && cd /tmp/pki-golden

# A CA to sign with. engine.py takes this as input; any CA with crlSign works.
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -out ca.crt -days 7300 -subj "/CN=homelab-golden-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# engine.py's _dn(): CN, UID, displayName (by OID), GN, SN, O -- utf8only.
cat > csr.cnf <<'EOF'
[req]
prompt = no
distinguished_name = dn
string_mask = utf8only
utf8 = yes
[dn]
CN = nick-ipad.ha.apps.somemissing.info
UID = nick
OID.2.16.840.1.113730.3.1.241 = Nick V
GN = Nick
SN = Venenga
O = homelab
EOF

# engine.py's _ext().
cat > ext.cnf <<'EOF'
[e]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName = @alt
[alt]
DNS.1 = nick-ipad.ha.apps.somemissing.info
email.1 = nick@venenga.com
email.2 = nijave@gmail.com
EOF

openssl genrsa -out leaf.key 2048
openssl req -new -key leaf.key -config csr.cnf -out leaf.csr
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key \
  -set_serial $((0x2001)) -days 7305 -sha256 \
  -extfile ext.cnf -extensions e -out leaf.crt
```

Copy the four files the test needs into the repository:

```bash
mkdir -p "$OLDPWD/internal/pki/testdata"
cp ca.crt ca.key leaf.key leaf.crt "$OLDPWD/internal/pki/testdata/"
```

These are throwaway keys generated for the test, not secrets: they sign nothing outside the test and are regenerable from the commands above. Record that in `internal/pki/testdata/README.md` along with the exact commands and the `openssl version` output, so a future reader knows they are safe to delete and how to recreate them. Do not copy any material from the cluster or from Bitwarden into `testdata/`.

- [ ] **Step 2: Write the golden test**

`internal/pki/golden_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"math/big"
	"os"
	"testing"
)

// TestGoldenMatchesThePythonIssuer reproduces the certificate that
// reconcile/engine.py produces for nick-ipad from config.hcl's identity, and
// asserts field-by-field equality against the openssl-generated reference in
// testdata/.
//
// This is spec section 10's cross-validation test. Its purpose is to prove the
// provider is a drop-in replacement for the Python issuer before the migration
// spec cuts anything over. See testdata/README.md for how leaf.crt was
// generated.
func TestGoldenMatchesThePythonIssuer(t *testing.T) {
	t.Parallel()

	caCertPEM, err := os.ReadFile("testdata/ca.crt")
	if err != nil {
		t.Fatalf("reading testdata/ca.crt: %v", err)
	}
	caKeyPEM, err := os.ReadFile("testdata/ca.key")
	if err != nil {
		t.Fatalf("reading testdata/ca.key: %v", err)
	}
	leafKeyPEM, err := os.ReadFile("testdata/leaf.key")
	if err != nil {
		t.Fatalf("reading testdata/leaf.key: %v", err)
	}
	referencePEM, err := os.ReadFile("testdata/leaf.crt")
	if err != nil {
		t.Fatalf("reading testdata/leaf.crt: %v", err)
	}

	ca, err := ParseCertificatePEM(caCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(ca): %v", err)
	}
	caKey, err := ParsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM(ca): %v", err)
	}
	leafKey, err := ParsePrivateKeyPEM(leafKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM(leaf): %v", err)
	}
	reference, err := ParseCertificatePEM(referencePEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(reference): %v", err)
	}

	// The ordered subject form is required here: engine.py places displayName
	// between UID and GN, which the canonical named-field order cannot produce.
	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	subject := Subject{Attributes: []Attribute{
		attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
		attr(t, "uid", "nick"),
		{OID: display, Value: "Nick V"},
		attr(t, "givenName", "Nick"),
		attr(t, "surname", "Venenga"),
		attr(t, "organization", "homelab"),
	}}

	certPEM, err := CreateCertificate(CertTemplate{
		Subject: subject,
		SAN: SAN{
			DNSNames:       []string{"nick-ipad.ha.apps.somemissing.info"},
			EmailAddresses: []string{"nick@venenga.com", "nijave@gmail.com"},
		},
		Serial:           big.NewInt(0x2001),
		NotBefore:        reference.NotBefore,
		NotAfter:         reference.NotAfter,
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         &KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: true},
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}, Critical: false},
	}, PublicKeyOf(leafKey), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	got, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}

	// The subject DN must be byte-identical. This is the assertion that
	// justifies the StringType design: openssl emitted UTF8String because of
	// string_mask = utf8only, and Go's default would have emitted
	// PrintableString.
	if !bytes.Equal(got.RawSubject, reference.RawSubject) {
		t.Errorf("subject DN is not byte-identical to openssl's\n openssl: % x\n    ours: % x", reference.RawSubject, got.RawSubject)
	}
	if !bytes.Equal(got.RawIssuer, reference.RawIssuer) {
		t.Errorf("issuer DN is not byte-identical to openssl's\n openssl: % x\n    ours: % x", reference.RawIssuer, got.RawIssuer)
	}
	if got.SerialNumber.Cmp(reference.SerialNumber) != 0 {
		t.Errorf("serial = %s, want %s", got.SerialNumber, reference.SerialNumber)
	}
	if got.SignatureAlgorithm != reference.SignatureAlgorithm {
		t.Errorf("signature algorithm = %v, want %v", got.SignatureAlgorithm, reference.SignatureAlgorithm)
	}

	// Every extension openssl emitted must be present with the same
	// criticality and the same value. authorityKeyIdentifier is compared
	// separately below because openssl's "keyid, issuer" form and Go's keyid
	// form can differ in what they include.
	//
	// Note both maps are keyed by OID rather than compared positionally. That
	// is required, not stylistic: x509.CreateCertificate prepends the AKI it
	// synthesizes, so the issued order differs from CertTemplate.Extensions()'
	// order, and openssl's order differs from both. Only the set and the
	// per-OID values are comparable.
	akiOID := "2.5.29.35"
	refExts := map[string]pkix.Extension{}
	for _, e := range reference.Extensions {
		refExts[FormatOID(e.Id)] = e
	}
	gotExts := map[string]pkix.Extension{}
	for _, e := range got.Extensions {
		gotExts[FormatOID(e.Id)] = e
	}
	for oid, want := range refExts {
		if oid == akiOID {
			continue
		}
		have, ok := gotExts[oid]
		if !ok {
			t.Errorf("extension %s is present in openssl's output and missing from ours", oid)
			continue
		}
		if have.Critical != want.Critical {
			t.Errorf("extension %s Critical = %v, want %v", oid, have.Critical, want.Critical)
		}
		if !bytes.Equal(have.Value, want.Value) {
			t.Errorf("extension %s value differs\n openssl: % x\n    ours: % x", oid, want.Value, have.Value)
		}
	}
	for oid := range gotExts {
		if oid == akiOID {
			continue
		}
		if _, ok := refExts[oid]; !ok {
			t.Errorf("extension %s is present in ours and absent from openssl's output", oid)
		}
	}
	// The AKI must at least carry the issuer's key identifier.
	if !bytes.Equal(got.AuthorityKeyId, reference.AuthorityKeyId) {
		t.Errorf("authorityKeyIdentifier keyid = % x, want % x", got.AuthorityKeyId, reference.AuthorityKeyId)
	}
	if !bytes.Equal(got.SubjectKeyId, reference.SubjectKeyId) {
		t.Errorf("subjectKeyIdentifier = % x, want % x; both should be the RFC 5280 method 1 SHA-1", got.SubjectKeyId, reference.SubjectKeyId)
	}
}

// TestGoldenImportPlansClean is the library-level rehearsal of spec section 8's
// import-fidelity requirement: parse the openssl-generated certificate, rebuild
// a template from what was parsed, and confirm the comparison reports nothing.
// Plan 2's acceptance test does the same thing through Terraform.
func TestGoldenImportPlansClean(t *testing.T) {
	t.Parallel()

	referencePEM, err := os.ReadFile("testdata/leaf.crt")
	if err != nil {
		t.Fatalf("reading testdata/leaf.crt: %v", err)
	}
	caCertPEM, err := os.ReadFile("testdata/ca.crt")
	if err != nil {
		t.Fatalf("reading testdata/ca.crt: %v", err)
	}
	reference, err := ParseCertificatePEM(referencePEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	ca, err := ParseCertificatePEM(caCertPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(ca): %v", err)
	}

	subject, err := ParseSubjectDER(reference.RawSubject)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	// Re-encoding the parsed DN must reproduce the original bytes, or nothing
	// downstream can plan clean.
	reencoded, err := subject.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	if !bytes.Equal(reencoded, reference.RawSubject) {
		t.Fatalf("re-encoding openssl's DN is not byte-exact\n original: % x\n re-encoded: % x", reference.RawSubject, reencoded)
	}

	sanExt, ok := FindExtension(reference.Extensions, oidSubjectAltName)
	if !ok {
		t.Fatal("the reference certificate has no SAN extension")
	}
	san, err := ParseSANExtension(sanExt)
	if err != nil {
		t.Fatalf("ParseSANExtension: %v", err)
	}
	san.Critical = sanExt.Critical
	// Re-encoding the parsed SAN must also be byte-exact, which is what proves
	// the fixed dns/email/ip/uri emission order matches openssl's.
	rebuilt, err := san.Extension(subject.IsEmpty())
	if err != nil {
		t.Fatalf("SAN Extension: %v", err)
	}
	if !bytes.Equal(rebuilt.Value, sanExt.Value) {
		t.Fatalf("re-encoding openssl's SAN is not byte-exact\n original: % x\n re-encoded: % x", sanExt.Value, rebuilt.Value)
	}

	bc, err := ParseBasicConstraints(mustFindExt(t, reference.Extensions, "2.5.29.19"))
	if err != nil {
		t.Fatalf("ParseBasicConstraints: %v", err)
	}
	ku, err := ParseKeyUsage(mustFindExt(t, reference.Extensions, "2.5.29.15"))
	if err != nil {
		t.Fatalf("ParseKeyUsage: %v", err)
	}
	eku, err := ParseExtKeyUsage(mustFindExt(t, reference.Extensions, "2.5.29.37"))
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}

	drift, err := CompareCertificate(CompareInput{
		Desired: CertTemplate{
			Subject:          subject,
			SAN:              san,
			Serial:           reference.SerialNumber,
			NotBefore:        reference.NotBefore,
			NotAfter:         reference.NotAfter,
			BasicConstraints: &bc,
			KeyUsage:         &ku,
			ExtKeyUsage:      &eku,
		},
		DesiredPublicKey: reference.PublicKey,
		Actual:           reference,
		CA:               ca,
	})
	if err != nil {
		t.Fatalf("CompareCertificate: %v", err)
	}
	if len(drift) != 0 {
		t.Fatalf("an imported openssl-issued certificate reported drift: %v", drift)
	}
}
```

Add to `internal/pki/testhelper_test.go`:

```go
// mustFindExt returns the extension with the given dotted OID or fails.
func mustFindExt(t *testing.T, exts []pkix.Extension, oid string) pkix.Extension {
	t.Helper()
	parsed, err := ParseOID(oid)
	if err != nil {
		t.Fatalf("ParseOID(%q): %v", oid, err)
	}
	ext, ok := FindExtension(exts, parsed)
	if !ok {
		t.Fatalf("extension %s not found", oid)
	}
	return ext
}
```

`golden_test.go` and `testhelper_test.go` both need `crypto/x509/pkix` imported.

- [ ] **Step 3: Run the golden test**

```bash
go test ./internal/pki/ -run Golden -v
```

Expected: PASS. If the subject DN comparison fails, the difference is almost certainly the ASN.1 string type or the attribute order — dump both with `openssl asn1parse` and fix `subject.go`, not the test:

```bash
openssl x509 -in internal/pki/testdata/leaf.crt -noout -text | head -20
```

If `TestGoldenImportPlansClean`'s SAN assertion fails, openssl emitted the GeneralNames in a different order than Task 7's fixed dns/email/ip/uri emission. That is a real finding about import fidelity, not a test bug: record the observed order in a comment and adjust `san.go`'s emission order to match, because openssl's order is the one already in the certificates on the devices.

- [ ] **Step 4: Commit**

```bash
git add internal/pki/golden_test.go internal/pki/testdata/ internal/pki/testhelper_test.go
git commit -m "test: cross-validate certificate issuance against the openssl pipeline"
```

---

### Task 16: Package boundary and completeness

The architectural invariant from spec §3, enforced rather than documented, plus a final sweep.

**Files:**
- Create: `internal/pki/boundary_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Write the boundary test**

`internal/pki/boundary_test.go`:

```go
// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImportsNoTerraform enforces the boundary spec section 3 draws:
// internal/pki is pure Go and imports zero Terraform packages, so every
// cryptographic decision is testable without a plugin harness and the framework
// layer stays a mechanical translation.
//
// This is a test rather than a convention because the pressure to violate it is
// real and arrives gradually -- one diag.Diagnostics here, one types.String
// there -- and each individual step looks harmless.
func TestPackageImportsNoTerraform(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	forbidden := []string{
		"github.com/hashicorp/terraform-plugin-",
		"github.com/hashicorp/terraform-",
		"github.com/opentofu/",
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parsing %s: %v", e.Name(), err)
			continue
		}
		checked++
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.HasPrefix(path, bad) {
					t.Errorf("%s imports %q; internal/pki must not depend on Terraform packages", e.Name(), path)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files were checked; the test is not doing what it claims")
	}
}

// TestEveryFileHasTheSPDXHeader keeps the GPLv3 licensing consistent, which
// matters because a file without the header is ambiguously licensed.
func TestEveryFileHasTheSPDXHeader(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	const want = "// SPDX-License-Identifier: GPL-3.0-or-later"
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		content, err := os.ReadFile(e.Name())
		if err != nil {
			t.Errorf("reading %s: %v", e.Name(), err)
			continue
		}
		if !strings.HasPrefix(string(content), want) {
			t.Errorf("%s does not start with %q", e.Name(), want)
		}
	}
}
```

- [ ] **Step 2: Run it and fix anything it finds**

```bash
go test ./internal/pki/ -run 'Boundary|Package|SPDX' -v
```

Expected: PASS. If `TestEveryFileHasTheSPDXHeader` fails, add the missing headers rather than relaxing the test.

- [ ] **Step 3: Verify the whole package, including race and coverage**

```bash
gofmt -l .
go vet ./...
go test ./internal/pki/ -count=1
go test ./internal/pki/ -race -count=1
go test ./internal/pki/ -cover
```

Expected: `gofmt -l` silent, `go vet` silent, all three test runs green. Coverage should be above 85% for the package; if any file is far below that, the gap is a missing test case, not a reason to lower the bar. Note the actual number in the commit message.

- [ ] **Step 4: Confirm the dependency licenses one final time**

The dependency set is now final for this plan, so run the audit spec §13 requires:

```bash
go list -m all | grep -Ev '^github.com/nijave/terraform-provider-pki'
```

For each module, confirm the license is one of MPL-2.0, BSD-3-Clause, MIT, or Apache-2.0. The expected set at the end of this plan is `software.sslmate.com/src/go-pkcs12` (BSD-3-Clause), `github.com/smallstep/pkcs7` (MIT), `github.com/pavlo-v-chernykh/keystore-go/v4` (MIT), and `golang.org/x/crypto` plus its `golang.org/x/sys` dependency (both BSD-3-Clause). Anything else is a finding: stop and re-audit against spec §13 before continuing.

Note that the automated `go-licenses` gate is spec §14 follow-up 3 and lands in Plan 2's CI task, once the full dependency set including the plugin framework is present.

- [ ] **Step 5: Commit**

```bash
git add internal/pki/boundary_test.go
git commit -m "test: enforce the no-Terraform-imports boundary and SPDX headers"
```

---

## Plan complete

At this point `internal/pki` is a working, fully tested X.509 library with no Terraform dependency. Every spec section this plan covers has an implementing task:

| Spec section | Tasks |
| --- | --- |
| §3 repository layout, `internal/pki` boundary | 1, 16 |
| §5.1 `subject`, ordered form, canonical order, DN drift on encoded bytes | 6 |
| §5.2 `san`, four types, order, empty-subject criticality | 7 |
| §5.3 extension blocks, pathLen null vs 0, criticality | 8 |
| §5.4 validity, duration parsing, `ready_for_renewal` | 3, 14 |
| §6.1 `pki_private_key` crypto | 5 |
| §6.2 `pki_cert_request` crypto | 9 |
| §6.3 / §6.4 CA and leaf issuance | 9 |
| §6.5 `pki_crl` crypto | 10 |
| §6.6 `pki_bundle`, all five formats, PKCS#12 matrix | 11, 12, 13 |
| §7 serial numbers | 4 |
| §8 import parsing and byte-exact re-encoding | 6, 9, 15 |
| §9 re-signing and drift detection | 14 |
| §10 unit tests, openssl/keytool cross-validation, golden test | every task; 12, 15 specifically |
| §11 OID table behind the data source and functions | 2 |
| §12 CI (unit half) | 1 |
| §13 GPLv3, dependency audit | 1, 16 |

Plan 2 (`docs/superpowers/plans/2026-07-25-pki-provider-layer.md`) covers §4, the resource and data source surface of §6 and §11, §8's import ID schemes, §12's acceptance matrix and release tooling, and §13's CI license gate.
