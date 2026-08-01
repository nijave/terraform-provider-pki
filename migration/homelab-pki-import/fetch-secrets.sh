#!/usr/bin/env bash
# migration/homelab-pki-import/fetch-secrets.sh
#
# Read-only: pulls the real CA and device cert/key material from the live
# homelab-pki namespace so the import tasks have something real to adopt.
# Never writes to the cluster.
set -euo pipefail

NAMESPACE="homelab-pki"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="$DIR/fetched-secrets"
mkdir -p "$OUTDIR"

fetch() {
  local secret="$1" name="$2"
  kubectl get secret "$secret" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' | base64 -d > "$OUTDIR/$name.crt"
  kubectl get secret "$secret" -n "$NAMESPACE" -o jsonpath='{.data.tls\.key}' | base64 -d > "$OUTDIR/$name.key"
  echo "fetched $name ($secret)"
}

fetch pki-ca               pki-ca
fetch pki-kara-iphone-2000 kara-iphone
fetch pki-nick-desktop-2001 nick-desktop
fetch pki-nick-ipad-2002   nick-ipad
fetch pki-nick-xps-2003    nick-xps
fetch pki-pixel7-2004      pixel7

chmod 600 "$OUTDIR"/*.key
echo "Done: $(ls "$OUTDIR" | wc -l) files in $OUTDIR"
