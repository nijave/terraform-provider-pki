# terraform-provider-pki

Terraform/OpenTofu provider for managing a private certificate authority (CA) entirely through Terraform. It is a solution to fully manage private PKI in-process: generate keys, build a CA hierarchy, issue and rotate certificates, publish revocation lists, and package certificate material without an external CA service or command-line dependency.

No `openssl` binary, `cfssl` binary, CA endpoint, or provider credentials are required. Each resource performs its work in-process, while CA material can be supplied as PEM from an existing secret manager or Terraform-managed resource.

## What you can manage

- **CA hierarchy** — create self-signed roots and intermediates with path-length limits, name constraints, custom distinguished-name OIDs, and explicit extension criticality.
- **Keys and CSRs** — generate RSA, ECDSA, or Ed25519 private keys and create certificate signing requests with rich subjects and SANs.
- **Certificates** — issue leaf certificates from a CSR or inline public key, control validity and serial numbers, and rotate them with early-renewal windows.
- **Revocation** — issue CRLs with monotonic CRL numbers, validity windows, and RFC 5280 revocation reasons.
- **Distribution formats** — package certificates and keys as PEM, DER, PKCS#7, PKCS#12, or JKS bundles.
- **Inspection** — decode certificates and CSRs, inspect OIDs, and use provider functions for OID lookup.

## Example: root, intermediate, and leaf workflow

```hcl
resource "pki_private_key" "root" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "pki_certificate_authority" "root" {
  private_key_pem = pki_private_key.root.private_key_pem
  validity        = "175320h"

  subject {
    common_name = "example-root"
  }
}

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
    common_name = "example-intermediate"
  }

  basic_constraints {
    ca       = true
    path_len = 0
  }
}
```

Use `pki_certificate` to issue certificates from the intermediate, and `pki_crl` to publish revocations. See the complete [CA hierarchy example](examples/resources/pki_certificate_authority/resource.tf), [certificate example](examples/resources/pki_certificate/resource.tf), and [CRL example](examples/resources/pki_crl/resource.tf).

## Documentation

The [provider documentation](docs/index.md) lists all resources, data sources, and functions. The provider is self-contained and has no configuration block; keys and CA material are passed explicitly to the resources that use them.

## Requirements

- OpenTofu >= 1.11 (primary target, what CI tests) or Terraform >= 1.11
- Go >= 1.25 to build

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
