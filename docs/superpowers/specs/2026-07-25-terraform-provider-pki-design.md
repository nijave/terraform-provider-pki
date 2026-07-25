# terraform-provider-pki — design

Date: 2026-07-25
Status: approved for planning

## 1. Motivation

`homelab-pki` (in `infra/k8s-manifests/vmubtkube-a/homelab-pki`) issues mTLS
client certificates for Home Assistant. It cannot express its PKI in Terraform,
so it wraps OpenTofu in a Python reconciler that shells out to `openssl` and
`cfssl`. Every workaround there maps to a specific gap in `hashicorp/tls` or in
core Terraform:

| Workaround | Missing capability |
| --- | --- |
| `_dn()` writes an `openssl req` config with `UID`, `GN`, `SN`, `OID.2.16.840.1.113730.3.1.241`, numbered `N.OU` (`engine.py:37`) | `tls_cert_request` subject supports only CN/O/one-OU/street/locality/province/country/postal. No surname, givenName, uid, arbitrary OIDs, or repeated OUs. |
| `openssl x509 -req -set_serial` (`engine.py:112`) | `tls_locally_signed_cert` picks a random serial with no way to set one. |
| `email.N =` in the SAN extfile (`engine.py:78`) | `tls_*` supports dns_names/ip_addresses/uris but not rfc822Name. |
| `openssl pkcs12 -export` (`engine.py:118`) | No PKCS#12 resource or function in any first-party provider. |
| `cfssl gencrl` piped through `openssl crl -inform DER` (`engine.py:123`) | No CRL resource in any first-party provider. |
| The whole `reconcile/` package and the two-phase `python -m reconcile.main && tofu apply` | Terraform cannot own issuance state, so real state lives in Kubernetes Secret labels (`pki/name`, `pki/serial`) and serial allocation happens in Python (`plan.py:23`). |
| `binary_data` instead of `data` (`tofu/main.tf:23-35`) | HCL `base64decode()` requires valid UTF-8, so binary PKCS#12 cannot round-trip. |
| `_profile_expiry_days()` parsing `175320h` out of cfssl's JSON (`engine.py:24`) | Validity lives in a cfssl config file, duplicated away from Terraform. |
| `revoked_serials = []` as a bare list (`config.hcl:22`) | Revocation is not a first-class concept. |
| `allowed_uses = [...]` in `hashicorp/tls` | Key usage and extended key usage are flattened into one list, criticality is hardcoded, and basicConstraints pathLen is unreachable. |

The provider closes these gaps directly. All cryptography runs in-process via
`crypto/x509`; there is no external CA service, no `openssl` binary, and no
`cfssl` binary. The reconciler image's entire toolchain dependency disappears.

## 2. Scope

**In scope:** the provider itself — resources, data sources, functions, import,
tests, docs, release tooling.

**Out of scope, deferred to a follow-up spec:** rewriting `homelab-pki` to use
the provider (deleting `reconcile/`, stripping cfssl/openssl/python from the
Dockerfile, collapsing the two-phase apply). That migration is gated on the
import-fidelity acceptance test in §10 passing against a real in-cluster
certificate.

**Explicit non-goals:**

- Talking to an external CA backend (Vault PKI, step-ca, cfssl serve).
- ACME, OCSP responders, or certificate transparency.
- Exotic SAN GeneralName types (`otherName`, `registeredID`, `directoryName`).
  See §6.3.
- Managing the CA key's lifecycle. The homelab CA is delivered from Bitwarden
  via ExternalSecret (`homelab-pki.yaml:53-71`) and stays externally owned.

## 3. Stack and repository layout

Go with `terraform-plugin-framework`. SDKv2 is not an option: write-only
attributes and provider-defined functions are framework-only.

**OpenTofu is the primary target.** OpenTofu ≥ 1.11 is required and is what CI
tests against; `tofu/main.tf:3` already pins that floor and the reconciler image
runs 1.12. OpenTofu 1.11 supports write-only attributes, which `password_wo`
depends on. The provider speaks plugin protocol 6 and works with Terraform
≥ 1.11 too, but Terraform is not tested and not the reference implementation.

There is no OpenTofu fork of `terraform-plugin-framework` or `tfplugindocs`, and
none is needed — OpenTofu implements the same plugin protocol and consumes the
same `docs/` layout. Those remain HashiCorp/IBM-published MPL-2.0 libraries; see
§13 for why that is license-compatible.

```
terraform-provider-pki/
  main.go
  internal/
    pki/                    # pure Go, zero Terraform imports
      key.go                # generate/parse/encode RSA, ECDSA, Ed25519
      subject.go            # ordered DN build, encode, decode
      san.go                # SAN extension build and parse
      extensions.go         # basicConstraints, KU, EKU, nameConstraints, extra
      sign.go               # CSR creation, self-signed and CA-signed issuance
      crl.go                # CRL generation
      bundle.go             # pem, der, pkcs7, pkcs12, jks encoders
      oids.go               # hardcoded OID table
      duration.go           # "20y" / "90d" / "175320h" parsing
      serial.go             # serial normalization
      compare.go            # content drift comparison
    provider/               # framework layer, thin
      provider.go
      resource_*.go
      data_source_*.go
      functions.go
  docs/                     # tfplugindocs output (index, resources, ...)
  examples/
  templates/
```

The `internal/pki` boundary matters: every cryptographic decision is testable
without a Terraform harness, and the framework layer stays mechanical.

> Note: `docs/superpowers/specs/` shares a parent with tfplugindocs output.
> Verify the first `go generate` run does not clobber it; if it does, move specs
> to `.specs/` and record that here.

## 4. Provider configuration

The provider block takes no configuration. There is no endpoint, no
credentials, and no client. Every resource is self-contained, and CA material is
passed per-resource as PEM strings.

## 5. Common schema blocks

### 5.1 `subject`

DN attribute order is significant in DER, so byte-exact import depends on
getting it right. `engine.py:37` emits CN, UID, displayName, GN, SN, O, then OUs.

```hcl
subject {
  common_name          = "nick-ipad.ha.apps.somemissing.info"
  country              = "US"
  organization         = "homelab"
  organizational_units = ["infra", "clients"]   # repeatable
  locality             = "..."
  province             = "..."
  street_addresses     = ["..."]
  postal_code          = "..."
  serial_number        = "..."                  # DN attribute 2.5.4.5
  surname              = "Venenga"              # 2.5.4.4
  given_name           = "Nick"                 # 2.5.4.42
  uid                  = "nick"                 # 0.9.2342.19200300.100.1.1

  extra_attribute {
    oid   = provider::pki::oid("displayName")   # 2.16.840.1.113730.3.1.241
    value = "Nick V"
  }
}
```

Named fields expand to a documented canonical order:
`CN, UID, GN, SN, O, OU..., L, ST, street, postalCode, C, dnQualifier, serialNumber`.
`extra_attribute` blocks append after them, in declaration order.

**That default order cannot reproduce every existing DN.** `engine.py:52` emits
`displayName` between `UID` and `GN`, but `displayName` has no named field, so
under the rule above it would encode last and produce a different DN — making
every imported certificate plan a replace. The `subject` block therefore also
accepts a fully ordered form, and the two forms are mutually exclusive:

```hcl
subject {
  attribute { oid = provider::pki::oid("commonName"), value = "nick-ipad.ha.apps.somemissing.info" }
  attribute { oid = provider::pki::oid("uid"),         value = "nick" }
  attribute { oid = provider::pki::oid("displayName"), value = "Nick V" }
  attribute { oid = provider::pki::oid("givenName"),   value = "Nick" }
  attribute { oid = provider::pki::oid("surname"),     value = "Venenga" }
  attribute { oid = provider::pki::oid("organization"), value = "homelab" }
}
```

Import always emits the ordered form, guaranteeing a byte-exact DN regardless of
how the original was produced. Hand-written config should prefer named fields.

`subject.serial_number` is the DN attribute; the certificate serial is the
top-level `serial_number` on the certificate resources. This collision exists in
`hashicorp/tls` too and is documented rather than renamed.

Drift is compared on the **encoded DN bytes**, not on the config shape. Any
config that encodes to the same DN plans clean — including a named-field config
whose canonical order happens to match an ordered-form original. This is what
makes import work.

### 5.2 `san`

Four GeneralName types, all natively representable in Go's `x509.Certificate`:

```hcl
san {
  dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
  email_addresses = ["nick@venenga.com", "nijave@gmail.com"]   # rfc822Name
  ip_addresses    = ["10.0.0.5", "fd00::5"]
  uris            = ["spiffe://homelab/nick-ipad"]

  critical = false   # auto-forced true when the subject is empty, per RFC 5280
}
```

Entry order is preserved. `otherName`, `registeredID`, and `directoryName` are
out of scope; `extra_extension` is the escape hatch if one is ever needed.

### 5.3 Extension blocks

```hcl
basic_constraints {
  ca       = true
  path_len = 0        # unset and 0 are different; null means no constraint
  critical = true     # default true
}

key_usage {
  usages   = ["digitalSignature", "keyEncipherment", "keyCertSign", "crlSign"]
  critical = true     # default true
}

extended_key_usage {
  usages   = ["clientAuth", "1.3.6.1.4.1.311.20.2.2"]   # names or raw OIDs
  critical = false    # default false
}

name_constraints {                                       # CA resources only
  permitted_dns_domains   = [".ha.apps.somemissing.info"]
  excluded_dns_domains    = []
  permitted_email_domains = []
  permitted_ip_ranges     = []
  permitted_uri_domains   = []
  critical                = true    # default true
}

extra_extension {
  oid          = "1.3.6.1.5.5.7.1.24"
  value_base64 = "MAMCAQU="         # raw DER of the extnValue
  critical     = false
}
```

`path_len` is `Int64` with null handling, not a zero-defaulted int: X.509 draws
a real distinction between `pathLenConstraint = 0` and no constraint at all.

### 5.4 Validity

```hcl
validity      = "175320h"   # accepts Go durations plus "d" and "y" suffixes
early_renewal = "720h"      # optional
```

`"175320h"` from `cfssl/ca-config.json` pastes in unchanged. `"20y"` is
365 × 24h, `"90d"` is 90 × 24h — both documented as calendar-naive.

Computed: `not_before`, `not_after` (RFC3339), `ready_for_renewal` (bool).
`ready_for_renewal` flips true once inside the early-renewal window; the next
plan proposes replacement, matching `hashicorp/tls` behavior.

## 6. Resources

### 6.1 `pki_private_key`

| Attribute | Kind | Notes |
| --- | --- | --- |
| `algorithm` | required | `RSA`, `ECDSA`, `ED25519` |
| `rsa_bits` | optional | default 2048 |
| `ecdsa_curve` | optional | `P224`/`P256`/`P384`/`P521`, default `P256` |
| `private_key_pem` | computed, sensitive | PKCS#1 for RSA, SEC1 for ECDSA |
| `private_key_pem_pkcs8` | computed, sensitive | |
| `public_key_pem` | computed | |
| `public_key_openssh` | computed | |
| `public_key_fingerprint_sha256` | computed | |

Importable (§8). All input attributes are reconstructed from the parsed key, so
import plans clean.

### 6.2 `pki_cert_request`

| Attribute | Kind | Notes |
| --- | --- | --- |
| `private_key_pem` | required, sensitive | |
| `subject` | block | §5.1 |
| `san` | block | §5.2 |
| `extra_extension` | block, repeatable | requested extensions |
| `signature_algorithm` | optional | defaults per key type |
| `cert_request_pem` | computed | |

### 6.3 `pki_certificate_authority`

Issues a CA certificate. With no parent it self-signs a root; with a parent it
issues an intermediate. This collapses `tls_self_signed_cert` and
`tls_locally_signed_cert`, because "is this a CA" is the distinction that
actually changes the extensions.

| Attribute | Kind | Notes |
| --- | --- | --- |
| `private_key_pem` | required, sensitive | the CA's own key |
| `parent_certificate_pem` | optional | absent → self-signed root |
| `parent_private_key_pem` | optional, sensitive | required iff parent cert set |
| `subject`, `san` | block | |
| `validity`, `early_renewal` | | §5.4 |
| `serial_number` | optional | hex; omit → random 128-bit, stable in state |
| `basic_constraints` | block | defaults `ca = true`, `critical = true` |
| `key_usage` | block | defaults `keyCertSign`, `crlSign`, critical |
| `extended_key_usage`, `name_constraints`, `extra_extension` | block | |
| `signature_algorithm` | optional | |
| `certificate_pem` | computed | |
| `certificate_chain_pem` | computed | leaf-to-root, when a parent is set |
| `not_before`, `not_after`, `ready_for_renewal` | computed | |
| `subject_key_id`, `authority_key_id` | computed | hex |

Importable (§8) — the read path is identical to `pki_certificate`'s.

### 6.4 `pki_certificate`

Issues a leaf signed by a CA. The CA is supplied as bare PEM, so the
Bitwarden-delivered `pki-ca` Secret works with no CA resource in the graph.

| Attribute | Kind | Notes |
| --- | --- | --- |
| `ca_certificate_pem` | required | |
| `ca_private_key_pem` | required, sensitive | |
| `csr_pem` | optional | mutually exclusive with `public_key_pem` |
| `public_key_pem` | optional | inline mode; pair with `subject`/`san` |
| `subject`, `san` | block | overrides the CSR's values when both are set |
| `validity`, `early_renewal` | | §5.4 |
| `serial_number` | optional | hex; omit → random 128-bit, stable in state |
| `basic_constraints` | block | defaults `ca = false`, `critical = true` |
| `key_usage`, `extended_key_usage`, `extra_extension` | block | |
| `signature_algorithm` | optional | |
| `certificate_pem` | computed | |
| `not_before`, `not_after`, `ready_for_renewal`, `serial_number` | computed | |

Precedence when `csr_pem` is supplied: subject and SAN default to the CSR's
values, and an explicitly-set `subject` or `san` block replaces the
corresponding CSR value wholesale (no field-level merging).

**Extensions are never copied from the CSR.** cfssl's `copy_extensions: true`
(`cfssl/ca-config.json:8`) lets a requester dictate its own extensions, which is
a well-known escalation hazard. Extensions always come from the resource config.

Importable (§8).

### 6.5 `pki_crl`

| Attribute | Kind | Notes |
| --- | --- | --- |
| `ca_certificate_pem` | required | |
| `ca_private_key_pem` | required, sensitive | |
| `next_update` | required | duration, e.g. `"168h"` |
| `early_regenerate` | optional | duration before `next_update` |
| `revoked` | block, repeatable | see below |
| `number` | computed | CRL number, monotonically incremented in state |
| `signature_algorithm` | optional | |
| `crl_pem`, `crl_base64` | computed | |
| `this_update`, `next_update_time` | computed | RFC3339 |
| `ready_for_regeneration` | computed | |

```hcl
revoked {
  serial_number = "2001"                    # hex, normalized per §7
  reason        = "keyCompromise"           # optional, RFC 5280 reason code
  revoked_at    = "2026-06-01T00:00:00Z"    # optional, defaults to first apply
}
```

`revoked_at` defaults to the time the entry first appears and is then held
stable in state, so an unchanged CRL does not churn its revocation timestamps on
every regeneration. `number` increments on each regeneration, as RFC 5280
requires.

`next_update` + `early_regenerate` replace the freshness role of the 6-hourly
`pki-crl-refresh` CronJob (`homelab-pki.yaml:188-235`) — a periodic `terraform
apply` still drives it, but the staleness logic is now in the provider.

### 6.6 `pki_bundle`

Format converter and composer. Optional fields are the switches: no
`private_key_pem` yields a cert-only bundle, no `chain_pem` yields no chain.

| Attribute | Kind | Notes |
| --- | --- | --- |
| `format` | required | `pem`, `der`, `pkcs7`, `pkcs12`, `jks` |
| `certificate_pem` | optional | |
| `private_key_pem` | optional, sensitive | |
| `chain_pem` | optional, list | ordered, leaf-adjacent first |
| `friendly_name` | optional | PKCS#12 / JKS alias |
| `pkcs12_encoding` | optional | `modern` (default), `legacy`, `passwordless` |
| `password_wo` | write-only, sensitive | never persisted to state |
| `password_wo_version` | optional | change to force re-encryption |
| `content` | computed | text formats only; null for binary |
| `content_base64` | computed | all formats |

`content_base64` feeds `kubernetes_secret.binary_data` directly, closing the
workaround documented at `tofu/main.tf:23-35`.

Write-only attributes are always null in state and therefore invisible to drift
detection, which is why `password_wo_version` exists — the standard framework
pattern for rotating a write-only value.

#### PKCS#12 encoding

`go-pkcs12` covers every needed variant in pure Go — no cgo, no `openssl`. RSA,
ECDSA, and Ed25519 keys all encode, with chains. Verified output, checked
against OpenSSL 3.5.7:

| `pkcs12_encoding` | go-pkcs12 encoder | Content encryption | MAC |
| --- | --- | --- | --- |
| `modern` (default) | `Modern2023` | AES-256-CBC + PBKDF2, iter 2048 | SHA-256 |
| `legacy` | `LegacyDES` | 3DES, iter 2048 | SHA-1 |
| `passwordless` | `Passwordless` | none | none |

`LegacyRC2` is deliberately **not** exposed. It emits RC2-40, which OpenSSL 3
cannot decrypt — verified by round-tripping a generated file back through
`openssl pkcs12 -info`, which fails with
`unsupported ... Algorithm (RC2-40-CBC)`. `Modern2026` (PBMAC1) is also omitted;
it requires OpenSSL ≥ 3.4 or Java ≥ 26 and no mobile platform reads it.

Client-certificate consumers are the reason `legacy` must stay available.
Encryption and MAC are **independent** failure axes:

| Platform | AES-256-CBC content | SHA-256 MAC |
| --- | --- | --- |
| iOS/iPadOS ≤ 17, macOS ≤ 14 | rejected (`Unknown format in import`) | rejected (`-25264 MAC verification failed`) |
| iOS/iPadOS 18+, macOS 15+ | accepted | accepted |
| Android ≤ 11 | rejected | rejected |
| Android 12–13 | conditional — the BouncyCastle PBES2 fix ships in the ART mainline module (~April 2023), so it depends on the device's Play system update | conditional |
| Android 14+ | accepted | accepted |

Android 12 rejects a SHA-256 MAC even when the content is 3DES, so choosing
`legacy` for the content alone is not sufficient — only `legacy`, which also
uses a SHA-1 MAC, is universally importable.

`modern` is the default because it is what `engine.py:118`'s bare
`openssl pkcs12 -export` already produces under OpenSSL 3, making the migration
behavior-preserving. Devices older than iOS 18 or Android 12 need
`pkcs12_encoding = "legacy"`, and the provider documentation must carry this
matrix.

When `private_key_pem` is omitted for `format = "pkcs12"`, the bundle is built
with `EncodeTrustStore` rather than `Encode` with a nil key — a PKCS#12
truststore is a structurally different artifact from a cert-only keystore.

Dependencies: `software.sslmate.com/src/go-pkcs12` (v0.7.3+),
`github.com/smallstep/pkcs7`, `github.com/pavlo-v-chernykh/keystore-go/v4`.

## 7. Serial numbers

`serial_number` is a hex string, normalized exactly as `plan.py:3` does:
lowercased, `0x` prefix stripped, leading zeros stripped, empty becomes `"0"`.
This keeps `pki-<name>-<serial>` Secret names byte-identical to the ones already
in the cluster.

When omitted, a random 128-bit serial is generated once at create and held
stable in state — never recomputed on subsequent plans.

Terraform state owns issuance. There is no serial-allocation counter, no
Kubernetes label discovery, and no next-serial arithmetic; `plan.py` disappears
entirely.

## 8. Import

`pki_private_key`, `pki_certificate`, and `pki_certificate_authority` support
import with scheme-prefixed IDs:

```hcl
import {
  to = pki_certificate.leaf["nick-ipad"]
  id = "file:///tmp/nick-ipad/tls.crt"
}

import {
  to = pki_private_key.leaf["nick-ipad"]
  id = "base64://LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQo..."
}
```

Supported schemes: `file://` (read from disk), `pem://` (inline PEM),
`base64://` (base64-encoded PEM). `hashicorp/tls` supports no import at all, so
this is net-new capability.

`Read` reconstructs every input attribute from the DER: subject (in the ordered
form of §5.1), SANs, serial, validity window, and all extensions. Because the
certificates in question are
20-year certs (`175320h`), they will never age out — adoption must preserve them
exactly rather than wait them out.

`ca_private_key_pem` cannot be recovered from a certificate and is therefore
config-only, never drift-compared. See §9.

## 9. Re-signing and drift detection

Certificates are re-signed only on genuine content drift. At plan time
`ModifyPlan` parses the stored DER and compares desired against actual on:

- encoded subject DN bytes
- encoded SAN extension bytes
- serial number
- every extension's OID, criticality, and DER value
- validity window (subject to the early-renewal check)
- issuer DN and signature validity against `ca_certificate_pem`

Attributes that cannot be derived from a certificate — `ca_private_key_pem`,
`private_key_pem`, `csr_pem` — are excluded from the comparison. Re-reading a
rotating Bitwarden Secret therefore cannot trigger a replacement.

This is deliberately stronger than `hashicorp/tls`, which replaces on any input
change. With 20-year certs installed on phones and tablets, a spurious replace
costs a manual device re-enrollment, so false positives are the expensive
failure mode.

## 10. Testing

**Unit tests, `internal/pki`, no Terraform harness:**

- DN attribute ordering and canonical expansion
- SAN encoding for all four types, including empty-subject criticality
- Extension encoding: pathLen null vs 0, KU/EKU bit and OID mapping,
  criticality flags
- Serial normalization against `plan.py:3` behavior, including `0x` and
  leading-zero cases
- Duration parsing: `"175320h"`, `"20y"`, `"90d"`, and rejection of garbage
- Each bundle format round-tripping, cross-validated by shelling out to
  `openssl` and `keytool` where available (skipped when absent). For PKCS#12
  this must assert the *emitted algorithms*, not just that decoding succeeds:
  `legacy` must produce 3DES with a SHA-1 MAC and `modern` must produce
  AES-256-CBC with a SHA-256 MAC, since a silent shift between them is exactly
  what locks a phone out.
- PKCS#12 encoding for all three key algorithms (RSA, ECDSA, Ed25519), with and
  without a chain, and cert-only truststore mode
- OID table completeness and bidirectional consistency

**Acceptance tests, `terraform-plugin-testing` under `TF_ACC`:**

- Root → intermediate → leaf chain verifies with `x509.Certificate.Verify`
- CRL signature verifies against the CA; a revoked serial is present
- `ready_for_renewal` flips inside the early-renewal window
- Rotating `ca_private_key_pem`'s value in config produces no replacement
- **Import fidelity**: a real device certificate extracted from the cluster is
  imported and the subsequent plan is empty. This test is the gate on the
  migration follow-up.

**Cross-validation golden test:** reproduce a certificate from `config.hcl`
inputs and assert its DER matches the one `engine.py` produces for the same
inputs, field by field. This proves the provider is a drop-in for the Python
issuer before anything is cut over.

## 11. Data sources and functions

### `data "pki_oids"`

No arguments. Exposes the hardcoded table as bidirectional maps, grouped:

```hcl
data "pki_oids" "std" {}

data.pki_oids.std.dn_attributes.by_name["displayName"]   # "2.16.840.1.113730.3.1.241"
data.pki_oids.std.dn_attributes.by_oid["2.5.4.4"]        # "surname"
data.pki_oids.std.extended_key_usages.by_name["clientAuth"]
data.pki_oids.std.key_usages.by_name["digitalSignature"]
data.pki_oids.std.extensions.by_name["subjectAltName"]
data.pki_oids.std.signature_algorithms.by_name["SHA256-RSA"]
```

Maps support iteration and `for_each`; the functions below cover terse inline use.

### `data "pki_certificate"`

Decodes any certificate PEM — including the Bitwarden CA — into subject, SANs,
serial, validity, extensions, key algorithm, and fingerprints. Useful for
introspection and for asserting on adopted material.

Accepts either `content_pem` or `content_base64`, so material read straight out
of a Kubernetes Secret needs no decoding step.

### `data "pki_cert_request"`

Decodes a CSR PEM into subject (ordered form), SANs, requested extensions,
public key algorithm, and a `signature_valid` boolean. Needed when signing a CSR
generated off-box — a device or another team hands you a CSR and you want to
inspect or assert on it before issuing, rather than signing blind.

### Provider functions

```hcl
provider::pki::oid("displayName")            # -> "2.16.840.1.113730.3.1.241"
provider::pki::oid_name("2.5.4.4")           # -> "surname"
```

Both error on unknown input rather than returning empty, so a typo fails at plan
time.

## 12. Release and CI

Modeled on `github.com/nijave/terraform-provider-cortextool`, with deliberate
deviations noted below.

### `.goreleaser.yml`

goreleaser v2 config, matching cortextool's: `CGO_ENABLED=0`, `-trimpath`,
`mod_timestamp` pinned to the commit timestamp, ldflags injecting
`main.version` and `main.commit`, `goos` of freebsd/windows/linux/darwin ×
`goarch` of amd64/arm64, zip archives, a `_SHA256SUMS` checksum file, GPG
detached signature over the checksums via `--batch --local-user
{{ .Env.GPG_FINGERPRINT }}`, `terraform-registry-manifest.json` attached as an
extra file, `draft: true`, and `changelog.disable: true`.

Two deviations from cortextool:

- **No `windows/arm64` ignore rule.** cortextool excludes it because Prometheus'
  Windows mmap code fails to compile on ARM. This provider has no such
  dependency, so windows/arm64 ships.
- **`terraform-registry-manifest.json` declares `protocol_versions: ["6.0"]`,
  not `["5.0"]`.** cortextool is SDKv2 and speaks protocol 5;
  terraform-plugin-framework speaks protocol 6. Getting this wrong makes the
  published provider fail to load.

### `.github/workflows/release.yml`

Unchanged in shape from cortextool: triggers on `v*` tags, `contents: write`,
checkout → `git fetch --prune --unshallow` → `actions/setup-go@v5` with
`go-version-file: go.mod` → `crazy-max/ghaction-import-gpg@v6` reading
`secrets.GPG_PRIVATE_KEY` and `secrets.PASSPHRASE` → `goreleaser-action@v6` with
`args: release --clean`, passing `GPG_FINGERPRINT` and `GITHUB_TOKEN`.

### `.github/workflows/test.yml`

Same three-job shape as cortextool — `build`, `generate`, `test` — with
OpenTofu substituted for Terraform throughout:

- `opentofu/setup-opentofu` replaces `hashicorp/setup-terraform`.
- The acceptance matrix runs OpenTofu `1.11.*` and `1.12.*` rather than
  Terraform 1.10–1.14.
- Acceptance tests set `TF_ACC=1` plus `TF_ACC_TERRAFORM_PATH` pointing at the
  `tofu` binary. `terraform-plugin-testing` performs no version check against a
  binary already present at that path, so the harness drives OpenTofu directly
  and never downloads Terraform.
- The `generate` job still runs `go generate ./...` and fails on a `git diff`,
  keeping `tfplugindocs` output committed and current.

**Triggers must cover pull requests, which cortextool's do not.** Its
`test.yml` has only a `push` trigger despite a header comment claiming "each
commit push and/or PR", so fork PRs are never tested. This provider uses both:

```yaml
on:
  pull_request:
    paths-ignore: ['README.md', 'docs/superpowers/**']
  push:
    branches: [main]
    paths-ignore: ['README.md', 'docs/superpowers/**']

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Scoping `push` to `main` avoids duplicate runs when a branch in this repo also
has an open PR. `permissions: contents: read` is least-privilege; only
`release.yml` needs `contents: write`. The concurrency group cancels superseded
runs on force-push.

There is no upstream SaaS API to drift against, so the scheduled-cron trigger
cortextool suggests stays disabled.

One consequence worth stating: **the acceptance tests require no secrets.**
Every resource is self-contained with no external API, so there is nothing to
authenticate against. That matters for Dependabot — GitHub runs Dependabot PRs
with a read-only token and withholds normal repository secrets, so on a provider
that needed API credentials those PRs would fail or silently skip coverage.
Here they get the full matrix.

### `.github/dependabot.yml`

Two ecosystems, matching cortextool:

```yaml
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
      terraform-plugin:
        patterns: ["github.com/hashicorp/terraform-plugin-*"]
      golang-x:
        patterns: ["golang.org/x/*"]
```

Two deviations from cortextool: `weekly` rather than `daily`, and grouped
updates. cortextool's ungrouped daily config opens a separate PR per module,
which on a repo with the full plugin-framework dependency tree is a lot of noise
for changes that should land together — the `terraform-plugin-*` modules in
particular expect to move in lockstep.

Dependabot PRs are also the main consumer of the license gate in §13: a
transitive dependency changing to a GPL-incompatible license is exactly the kind
of drift that arrives via an automated bump rather than a human commit.

### Distribution

Publish to the **OpenTofu registry**. An in-cluster filesystem mirror remains
available as a fallback for the homelab and needs no registry presence at all.

## 13. Licensing

**The project is licensed GPLv3.** A `LICENSE` file containing the full GPL-3.0
text goes in the repository root, with `SPDX-License-Identifier: GPL-3.0-or-later`
headers on source files.

Every dependency must be GPLv3-compatible. Verified for the dependencies this
design introduces:

| Dependency | License | GPLv3-compatible |
| --- | --- | --- |
| `hashicorp/terraform-plugin-framework` | MPL-2.0 | yes |
| `hashicorp/terraform-plugin-testing` | MPL-2.0 | yes |
| `hashicorp/terraform-plugin-docs` | MPL-2.0 | yes |
| `software.sslmate.com/src/go-pkcs12` | BSD-3-Clause | yes |
| `github.com/smallstep/pkcs7` | MIT | yes |
| `github.com/pavlo-v-chernykh/keystore-go/v4` | MIT | yes |

The MPL-2.0 entries deserve a note, because a naive `grep` of their `LICENSE`
files for "Incompatible With Secondary Licenses" produces a **false positive** —
that phrase appears four times in MPL-2.0's own boilerplate (§1.5's definition,
§3.3, §10.4, and the Exhibit B template heading) in every copy of the license,
applied or not. The real test is whether source files carry the Exhibit B
notice. They do not: HashiCorp/IBM's framework, testing, and docs sources all
carry a bare `// SPDX-License-Identifier: MPL-2.0`. MPL-2.0 §3.3 therefore
permits distributing the combined work under a Secondary License, and §1.12
defines Secondary License to include "any later versions" of GPL-2.0 — which
covers GPLv3.

Two constraints to enforce going forward:

- **Nothing under BUSL-1.1 may be linked in.** Terraform CLI has been BUSL since
  1.6. This is not a problem in practice: a provider runs as a separate process
  speaking gRPC, so it is neither linked to nor a derivative work of the CLI.
  Targeting OpenTofu (MPL-2.0) as the primary platform removes the question
  entirely, including at test time.
- **Apache-2.0 transitive dependencies are acceptable** because the project is
  GPLv3, not GPLv2 — Apache-2.0 is compatible with the former and not the
  latter. If the license is ever downgraded to GPLv2, this table must be
  re-audited.

A CI license-compliance check (`go-licenses` or equivalent) that fails the build
on a non-compatible transitive dependency should be added to `test.yml`.

## 14. Follow-ups

1. Migration spec: rewrite `homelab-pki` onto the provider, delete `reconcile/`,
   strip cfssl/openssl/python from the Dockerfile, collapse the two-phase apply.
2. Confirm on-device that `modern` imports on the actual iPad, iPhone, and
   Pixel 7, or switch those bundles to `legacy`. The version cutoffs in §6.6 say
   it should work on iOS 18+/Android 14+, but the iOS Configuration Profile
   install path may use a different parser than `SecPKCS12Import` and the
   evidence there is thin. This is a device test, not a research question.
3. Add a `go-licenses` compliance gate to `test.yml` once the dependency set is
   final, so a GPL-incompatible transitive dependency fails CI rather than
   shipping.
