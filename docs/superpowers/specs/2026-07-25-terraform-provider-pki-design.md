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
attributes and provider-defined functions are framework-only. Terraform and
OpenTofu ≥ 1.11 (OpenTofu 1.11 is already pinned in `tofu/main.tf:3`).

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
| `pkcs12_encoding` | optional | `modern` (default) or `legacy` |
| `password_wo` | write-only, sensitive | never persisted to state |
| `password_wo_version` | optional | change to force re-encryption |
| `content` | computed | text formats only; null for binary |
| `content_base64` | computed | all formats |

`content_base64` feeds `kubernetes_secret.binary_data` directly, closing the
workaround documented at `tofu/main.tf:23-35`.

Write-only attributes are always null in state and therefore invisible to drift
detection, which is why `password_wo_version` exists — the standard framework
pattern for rotating a write-only value.

`pkcs12_encoding` matters for this deployment: `modern` is AES-256-CBC +
PBKDF2, `legacy` is RC2/3DES for older iOS and Android import paths. The
existing bundles were produced by OpenSSL 3's default `-export`, so the
migration must confirm which one round-trips on the actual iPad and iPhone.

Dependencies: `software.sslmate.com/src/go-pkcs12`,
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
  `openssl` and `keytool` where available (skipped when absent)
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

### Provider functions

```hcl
provider::pki::oid("displayName")            # -> "2.16.840.1.113730.3.1.241"
provider::pki::oid_name("2.5.4.4")           # -> "surname"
```

Both error on unknown input rather than returning empty, so a typo fails at plan
time.

## 12. Release

`goreleaser` producing multi-platform binaries with GPG-signed checksums,
`tfplugindocs` for registry documentation, and GitHub Actions for test and
release — mirroring the layout already present in
`go/src/github.com/nijave/terraform-provider-mimirtool`. Whether this publishes
to the public registry or is consumed via a filesystem mirror in the cluster is
a packaging decision deferred to the migration spec.

## 13. Follow-ups

1. Migration spec: rewrite `homelab-pki` onto the provider, delete `reconcile/`,
   strip cfssl/openssl/python from the Dockerfile, collapse the two-phase apply.
2. Confirm PKCS#12 encoding compatibility on the real iPad and iPhone before
   cutover.
3. Decide provider distribution (public registry vs in-cluster mirror).
