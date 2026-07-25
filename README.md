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