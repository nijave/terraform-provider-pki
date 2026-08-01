#!/usr/bin/env bash
# migration/homelab-pki-import/verify.sh
#
# Reproduces, against the new provider's output, the exact openssl command
# that fails against homelab-pki's current (cfssl-generated) CRL due to a
# reversed CA-issuer RDN order. Must print OK here.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=== CRL issuer vs CA subject ==="
openssl crl -in crl.pem -noout -issuer
openssl x509 -in fetched-secrets/pki-ca.crt -noout -subject

echo
echo "=== openssl verify -crl_check against a real leaf cert (expect OK) ==="
openssl verify -CAfile fetched-secrets/pki-ca.crt -crl_check -CRLfile crl.pem fetched-secrets/nick-desktop.crt

echo
echo "=== revoked cert must now fail crl_check as revoked (expect 'certificate revoked') ==="
if openssl verify -CAfile fetched-secrets/pki-ca.crt -crl_check -CRLfile crl.pem migration-test.crt; then
  echo "FAIL: expected migration-test.crt to be reported as revoked, but verify succeeded" >&2
  exit 1
fi
