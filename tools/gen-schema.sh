#!/usr/bin/env bash
# tfplugindocs (github.com/hashicorp/terraform-plugin-docs) resolves the
# provider schema by shelling out to a binary literally named "terraform" and
# assumes providers publish under registry.terraform.io. Neither holds for
# OpenTofu: it isn't named "terraform", so tfplugindocs falls back to
# downloading the latest real Terraform release -- silently pulling a
# BUSL-licensed binary into doc generation, which is exactly what this
# project's `license` job exists to forbid, and a source of doc drift every
# time HashiCorp cuts a release (an unrelated release crossing a schema
# feature's version threshold changes what tfplugindocs emits). OpenTofu also
# defaults unqualified provider addresses to registry.opentofu.org instead of
# registry.terraform.io, so it can't simply be renamed/wrapped as "terraform"
# either -- tfplugindocs prebuilds the provider under the Terraform hostname
# and the schema lookup only recognizes a bare name or that same hostname.
#
# Export the schema ourselves with `tofu`, using a dev_overrides CLI config
# (the standard local-provider-development mechanism) so no registry lookup
# or provider install is involved, then rewrite the registry.opentofu.org key
# to the bare provider name tfplugindocs's --providers-schema loader expects.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

command -v tofu >/dev/null || { echo "tofu not found in PATH; OpenTofu >= 1.11 is required" >&2; exit 1; }

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

(cd .. && go build -o "$workdir/terraform-provider-pki" .)

cat > "$workdir/dev.tfrc" <<EOF
provider_installation {
  dev_overrides {
    "hashicorp/pki" = "$workdir"
  }
  direct {}
}
EOF

mkdir "$workdir/work"
cat > "$workdir/work/main.tf" <<'EOF'
terraform {
  required_providers {
    pki = {
      source = "hashicorp/pki"
    }
  }
}
provider "pki" {}
EOF

TF_CLI_CONFIG_FILE="$workdir/dev.tfrc" tofu -chdir="$workdir/work" providers schema -json \
  | sed 's#"registry\.opentofu\.org/hashicorp/pki"#"pki"#' \
  > schema.json
