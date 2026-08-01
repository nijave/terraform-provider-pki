# homelab-pki import validation harness

Local-only OpenTofu root module proving `terraform-provider-pki` can import
the real homelab-pki CA and device certs with zero drift. See
`docs/superpowers/specs/2026-08-01-homelab-pki-import-validation-design.md`
for the full design.

Every `tofu`/`kubectl` command below assumes this directory as the working
directory, and `TF_CLI_CONFIG_FILE=./dev.tfrc` set for every `tofu` invocation
(re-run `go build -o bin/terraform-provider-pki ..` after any provider source
change — the dev override does not rebuild automatically).

Nothing here writes to the cluster; `fetched-secrets/`, state, and generated
certs/CRLs are all gitignored.
