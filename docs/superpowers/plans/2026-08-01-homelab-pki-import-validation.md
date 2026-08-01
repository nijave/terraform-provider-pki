# homelab-pki Import Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove, entirely locally (local `tofu` state file, no cluster writes), that `terraform-provider-pki` can import the real homelab-pki CA and all 5 real device certs with zero plan drift, issue a new cert against the imported CA, and generate a CRL that actually validates against the CA (fixing a known OU-order bug) including correctly reflecting revocation.

**Architecture:** A throwaway OpenTofu root module at `migration/homelab-pki-import/` inside this repo, wired to the provider via `dev_overrides` (no registry release exists yet) and a local backend. Real CA/device cert+key material is pulled read-only from the live `homelab-pki` k8s namespace via `kubectl` into a gitignored `fetched-secrets/` directory. Resources are explicit named blocks (no `for_each`) — 11 real resources (1 CA + 5×(private_key + certificate)) plus a throwaway `migration-test` device and a CRL resource.

**Tech Stack:** OpenTofu 1.12.1, Go 1.25.12 (building the provider binary), `kubectl`, `openssl` (verification only — never for signing).

## Global Constraints

- No cluster writes: local backend only, `kubectl get` only (read-only), never `kubectl apply`/`create`.
- No secret material committed: `fetched-secrets/`, `*.tfstate*`, `*.crt`, `*.key`, `*.p12`, `*.pem` are gitignored; only `.tf`/`.sh`/`.md` files under `migration/homelab-pki-import/` are tracked.
- Resources are explicit named blocks, never `for_each`, so a broken import stays isolated to one block.
- Every DN in this plan uses the ordered `attribute` form (never named fields), because every real cert's RDN order is non-canonical (see Task 3) and only the ordered form can reproduce it byte-for-byte.
- "Zero plan diff" after `tofu import` is the pass bar for every import task — any diff is a bug to fix (wrong attribute value/order), not a difference to accept.
- Namespace/cluster context: `homelab-pki` namespace, cluster reachable via the ambient kubeconfig already in use in this session (confirmed working: `kubectl get secrets -n homelab-pki` already succeeded during design).

---

## Reference data (gathered from the live cluster during design; do not re-derive — use these values directly)

**CA** (`pki-ca` secret):
- Subject/issuer (RDN order as encoded): `organizationalUnit=apps`, `organization=homelab`
- Serial (lowercase hex, no leading zeros): `4d71d760878eb0a8831ce2e1d6028f61f1fc7d5f`
- Key: RSA 4096
- Validity: `175320h` (20y) — issued 2025-02-26, expires 2045-02-26
- Extensions: `basicConstraints` critical `CA:TRUE` (schema default — omit block); `keyUsage` critical `keyCertSign, cRLSign` (schema default — omit block); `nameConstraints` critical, `permitted_dns_domains = ["ha.apps.somemissing.info", ".ha.apps.somemissing.info"]`

**Devices** (`pki-<name>-<serial>` secrets), all: RSA 2048 key, `key_usage { usages = ["digitalSignature", "keyEncipherment"] }`, `extended_key_usage { usages = ["clientAuth"] }`, `basic_constraints` default (`ca = false`, `critical = true` — omit block), `validity = "175320h"`, DN order `commonName, uid, displayName, givenName, surname, organization`:

| resource name | secret | serial (hex) | CN | UID | displayName | GN | SN | SAN dns_names | SAN email_addresses |
|---|---|---|---|---|---|---|---|---|---|
| `kara_iphone` | `pki-kara-iphone-2000` | `2000` | `kara-iphone.ha.apps.somemissing.info` | `kara` | `Kara G` | `Kara` | `Gilmore` | `["kara-iphone.ha.apps.somemissing.info"]` | `["karakgilmore@gmail.com"]` |
| `nick_desktop` | `pki-nick-desktop-2001` | `2001` | `nick-desktop.ha.apps.somemissing.info` | `nick` | `Nick V` | `Nick` | `Venenga` | `["nick-desktop.ha.apps.somemissing.info"]` | `["nick@venenga.com", "nijave@gmail.com"]` |
| `nick_ipad` | `pki-nick-ipad-2002` | `2002` | `nick-ipad.ha.apps.somemissing.info` | `nick` | `Nick V` | `Nick` | `Venenga` | `["nick-ipad.ha.apps.somemissing.info"]` | `["nick@venenga.com", "nijave@gmail.com"]` |
| `nick_xps` | `pki-nick-xps-2003` | `2003` | `nick-xps.ha.apps.somemissing.info` | `nick` | `Nick V` | `Nick` | `Venenga` | `["nick-xps.ha.apps.somemissing.info"]` | `["nick@venenga.com", "nijave@gmail.com"]` |
| `pixel7` | `pki-pixel7-2004` | `2004` | `pixel7.ha.apps.somemissing.info` | `nick` | `Nick V` | `Nick` | `Venenga` | `["pixel7.ha.apps.somemissing.info"]` | `["nick@venenga.com", "nijave@gmail.com"]` |

**Known bug being validated against:** the current CRL's issuer is encoded `O=homelab, OU=apps` while the CA's actual subject is `OU=apps, O=homelab` (reversed RDN order), so `openssl verify -crl_check` currently fails with `unable to get certificate CRL`. Task 8 must show this passing with the new provider.

---

### Task 1: Scaffold the harness, build the provider, wire `dev_overrides`

**Files:**
- Create: `migration/homelab-pki-import/.gitignore`
- Create: `migration/homelab-pki-import/main.tf`
- Create: `migration/homelab-pki-import/dev.tfrc` (gitignored — contains an absolute local path)
- Create: `migration/homelab-pki-import/README.md`

**Interfaces:**
- Produces: a working `tofu init`/`tofu plan` in `migration/homelab-pki-import/` using the locally built provider binary, for every later task to build on.

- [ ] **Step 1: Create the directory and `.gitignore`**

```bash
mkdir -p migration/homelab-pki-import/bin
mkdir -p migration/homelab-pki-import/fetched-secrets
```

`migration/homelab-pki-import/.gitignore`:
```
fetched-secrets/
bin/
*.tfstate
*.tfstate.backup
*.tfplan
dev.tfrc
crl.pem
migration-test.crt
.terraform/
.terraform.lock.hcl
```

- [ ] **Step 2: Build the provider binary**

```bash
cd /home/nick/Documents/workspace/go/src/github.com/nijave/terraform-provider-pki
go build -o migration/homelab-pki-import/bin/terraform-provider-pki .
```

Expected: builds with no errors, produces `migration/homelab-pki-import/bin/terraform-provider-pki`.

- [ ] **Step 3: Write the dev override CLI config**

`migration/homelab-pki-import/dev.tfrc`:
```hcl
provider_installation {
  dev_overrides {
    "registry.opentofu.org/nijave/pki" = "/home/nick/Documents/workspace/go/src/github.com/nijave/terraform-provider-pki/migration/homelab-pki-import/bin"
  }
  direct {}
}
```

- [ ] **Step 4: Write `main.tf`**

```hcl
# migration/homelab-pki-import/main.tf
terraform {
  required_providers {
    pki = {
      source = "nijave/pki"
    }
  }
}

provider "pki" {}
```

- [ ] **Step 5: Init and confirm the dev override is picked up**

```bash
cd migration/homelab-pki-import
TF_CLI_CONFIG_FILE=./dev.tfrc tofu init
TF_CLI_CONFIG_FILE=./dev.tfrc tofu plan
```

Expected: `tofu init` succeeds (no providers to download — dev override satisfies `pki`). `tofu plan` prints a warning block naming `provider registry.opentofu.org/nijave/pki` as overridden for development, then `No changes.` (no resources defined yet). A failure here (e.g. "provider not found") means the `dev_overrides` path or address string is wrong — fix before continuing; every later task depends on this working.

- [ ] **Step 6: Write `README.md` recording the invocation convention**

`migration/homelab-pki-import/README.md`:
```markdown
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
```

- [ ] **Step 7: Commit**

```bash
git add migration/homelab-pki-import/.gitignore migration/homelab-pki-import/main.tf migration/homelab-pki-import/README.md
git commit -m "chore: scaffold homelab-pki import validation harness"
```

(`dev.tfrc`, `bin/`, and `fetched-secrets/` are gitignored and stay local.)

---

### Task 2: Fetch real secret material read-only from the cluster

**Files:**
- Create: `migration/homelab-pki-import/fetch-secrets.sh`

**Interfaces:**
- Produces: `fetched-secrets/{pki-ca,kara-iphone,nick-desktop,nick-ipad,nick-xps,pixel7}.{crt,key}` — consumed by every later task's `file()` calls and `tofu import` commands.

- [ ] **Step 1: Write `fetch-secrets.sh`**

```bash
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
```

- [ ] **Step 2: Run it and verify the output**

```bash
chmod +x migration/homelab-pki-import/fetch-secrets.sh
migration/homelab-pki-import/fetch-secrets.sh
ls -la migration/homelab-pki-import/fetched-secrets/
```

Expected: 12 files (`pki-ca.crt`, `pki-ca.key`, and `.crt`/`.key` for each of the 5 devices), `.key` files mode `600`.

- [ ] **Step 3: Sanity-check one file decodes**

```bash
openssl x509 -in migration/homelab-pki-import/fetched-secrets/pki-ca.crt -noout -subject -serial
```

Expected: `subject=OU=apps, O=homelab` and `serial=4D71D760878EB0A8831CE2E1D6028F61F1FC7D5F` — matches the reference data above.

- [ ] **Step 4: Commit the script only**

```bash
git add migration/homelab-pki-import/fetch-secrets.sh
git commit -m "chore: add fetch-secrets.sh for homelab-pki import harness"
```

(`fetched-secrets/*` stays gitignored — never commit the actual key material.)

---

### Task 3: Import the CA (`pki_certificate_authority`) with zero plan diff

**Files:**
- Create: `migration/homelab-pki-import/ca.tf`

**Interfaces:**
- Consumes: `fetched-secrets/pki-ca.{crt,key}` (Task 2).
- Produces: `pki_certificate_authority.ca` — `certificate_pem` and `private_key_pem` attributes consumed by Tasks 4, 5, 6, 7.

- [ ] **Step 1: Write `ca.tf` matched to the real CA's decoded values**

```hcl
# migration/homelab-pki-import/ca.tf
resource "pki_certificate_authority" "ca" {
  private_key_pem = file("${path.module}/fetched-secrets/pki-ca.key")

  validity      = "175320h"
  serial_number = "4d71d760878eb0a8831ce2e1d6028f61f1fc7d5f"

  subject {
    attribute {
      oid   = provider::pki::oid("organizationalUnit")
      value = "apps"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  # basic_constraints and key_usage are omitted: this resource's defaults
  # (ca = true, critical = true; keyCertSign+cRLSign, critical) already match
  # the real CA's extensions.

  name_constraints {
    permitted_dns_domains = ["ha.apps.somemissing.info", ".ha.apps.somemissing.info"]
  }
}
```

- [ ] **Step 2: Plan before import — expect it to want to CREATE a new CA**

```bash
cd migration/homelab-pki-import
TF_CLI_CONFIG_FILE=./dev.tfrc tofu plan
```

Expected: plan shows `pki_certificate_authority.ca` will be created (this is expected — nothing is imported yet).

- [ ] **Step 3: Import the real CA**

```bash
TF_CLI_CONFIG_FILE=./dev.tfrc tofu import pki_certificate_authority.ca 'file://fetched-secrets/pki-ca.crt'
```

Expected: `Import successful!`

- [ ] **Step 4: Plan after import — must be zero diff**

```bash
TF_CLI_CONFIG_FILE=./dev.tfrc tofu plan
```

Expected: `No changes. Your infrastructure matches the configuration.` If it instead shows a diff, read which attribute differs (common culprits: RDN order, `string_type` on a subject attribute, `serial_number` casing, missing/extra `name_constraints` entry) and correct `ca.tf` — do not proceed to Task 4 until this is clean.

- [ ] **Step 5: Cross-check the imported cert against the source with `openssl`**

Add to `ca.tf`:
```hcl
output "ca_certificate_pem" {
  value = pki_certificate_authority.ca.certificate_pem
}
```

Then:
```bash
TF_CLI_CONFIG_FILE=./dev.tfrc tofu apply -auto-approve
diff <(TF_CLI_CONFIG_FILE=./dev.tfrc tofu output -raw ca_certificate_pem) fetched-secrets/pki-ca.crt
```

Expected: no output from `diff` (byte-identical).

- [ ] **Step 6: Commit**

```bash
git add migration/homelab-pki-import/ca.tf
git commit -m "feat: import real homelab-pki CA into pki_certificate_authority"
```

---

### Task 4: Import the first device (`kara_iphone`) — private key + certificate

**Files:**
- Create: `migration/homelab-pki-import/devices.tf`

**Interfaces:**
- Consumes: `fetched-secrets/kara-iphone.{crt,key}` (Task 2), `pki_certificate_authority.ca.{certificate_pem,private_key_pem}` (Task 3).
- Produces: `pki_private_key.kara_iphone`, `pki_certificate.kara_iphone` — establishes the per-device pattern Task 5 repeats for the other 4 devices.

- [ ] **Step 1: Write the `kara_iphone` blocks in `devices.tf`**

```hcl
# migration/homelab-pki-import/devices.tf
resource "pki_private_key" "kara_iphone" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "kara_iphone" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.kara_iphone.public_key_pem

  serial_number = "2000"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "kara-iphone.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "kara"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Kara G"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Kara"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Gilmore"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["kara-iphone.ha.apps.somemissing.info"]
    email_addresses = ["karakgilmore@gmail.com"]
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}
```

- [ ] **Step 2: Import the private key**

```bash
cd migration/homelab-pki-import
TF_CLI_CONFIG_FILE=./dev.tfrc tofu import pki_private_key.kara_iphone 'file://fetched-secrets/kara-iphone.key'
```

Expected: `Import successful!`

- [ ] **Step 3: Import the certificate**

```bash
TF_CLI_CONFIG_FILE=./dev.tfrc tofu import pki_certificate.kara_iphone 'file://fetched-secrets/kara-iphone.crt'
```

Expected: `Import successful!`

- [ ] **Step 4: Plan — must be zero diff for both resources**

```bash
TF_CLI_CONFIG_FILE=./dev.tfrc tofu plan
```

Expected: `No changes.` If `pki_private_key.kara_iphone` shows a diff, check `rsa_bits` (must be `2048`, confirmed above). If `pki_certificate.kara_iphone` shows a diff, check subject RDN order/values against the reference table and re-run `openssl x509 -in fetched-secrets/kara-iphone.crt -noout -text` to compare byte-for-byte.

- [ ] **Step 5: Commit**

```bash
git add migration/homelab-pki-import/devices.tf
git commit -m "feat: import kara-iphone device key+cert into pki_private_key/pki_certificate"
```

---

### Task 5: Import the remaining 4 devices

**Files:**
- Modify: `migration/homelab-pki-import/devices.tf`

**Interfaces:**
- Consumes: `fetched-secrets/{nick-desktop,nick-ipad,nick-xps,pixel7}.{crt,key}` (Task 2), `pki_certificate_authority.ca` (Task 3).
- Produces: `pki_private_key.{nick_desktop,nick_ipad,nick_xps,pixel7}`, `pki_certificate.{nick_desktop,nick_ipad,nick_xps,pixel7}`.

- [ ] **Step 1: Append the remaining 4 device blocks to `devices.tf`**

```hcl
resource "pki_private_key" "nick_desktop" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "nick_desktop" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.nick_desktop.public_key_pem

  serial_number = "2001"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-desktop.ha.apps.somemissing.info"
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
    dns_names       = ["nick-desktop.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

resource "pki_private_key" "nick_ipad" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "nick_ipad" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.nick_ipad.public_key_pem

  serial_number = "2002"
  validity      = "175320h"

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

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

resource "pki_private_key" "nick_xps" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "nick_xps" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.nick_xps.public_key_pem

  serial_number = "2003"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-xps.ha.apps.somemissing.info"
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
    dns_names       = ["nick-xps.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

resource "pki_private_key" "pixel7" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "pixel7" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.pixel7.public_key_pem

  serial_number = "2004"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "pixel7.ha.apps.somemissing.info"
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
    dns_names       = ["pixel7.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}
```

- [ ] **Step 2: Import all 8 remaining resources**

```bash
cd migration/homelab-pki-import
for d in nick-desktop nick-ipad nick-xps pixel7; do
  tf_name="${d//-/_}"
  TF_CLI_CONFIG_FILE=./dev.tfrc tofu import "pki_private_key.$tf_name" "file://fetched-secrets/$d.key"
  TF_CLI_CONFIG_FILE=./dev.tfrc tofu import "pki_certificate.$tf_name" "file://fetched-secrets/$d.crt"
done
```

Expected: 8× `Import successful!`.

- [ ] **Step 3: Plan — must be zero diff across all 11 resources**

```bash
TF_CLI_CONFIG_FILE=./dev.tfrc tofu plan
```

Expected: `No changes.` Debug any diff the same way as Task 4 Step 4, one resource at a time.

- [ ] **Step 4: Commit**

```bash
git add migration/homelab-pki-import/devices.tf
git commit -m "feat: import remaining 4 homelab-pki devices"
```

---

### Task 6: Issue a fresh cert against the imported CA (no import)

**Files:**
- Create: `migration/homelab-pki-import/new-cert.tf`

**Interfaces:**
- Consumes: `pki_certificate_authority.ca` (Task 3).
- Produces: `pki_private_key.migration_test`, `pki_certificate.migration_test` — the serial (`9000`) is revoked in Task 8.

- [ ] **Step 1: Write `new-cert.tf`**

```hcl
# migration/homelab-pki-import/new-cert.tf
resource "pki_private_key" "migration_test" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "migration_test" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.migration_test.public_key_pem

  serial_number = "9000"
  validity      = "175320h"

  subject {
    common_name  = "migration-test.ha.apps.somemissing.info"
    organization = "homelab"
  }

  san {
    dns_names = ["migration-test.ha.apps.somemissing.info"]
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

output "migration_test_certificate_pem" {
  value = pki_certificate.migration_test.certificate_pem
}
```

- [ ] **Step 2: Apply (this one is a normal create, not an import)**

```bash
cd migration/homelab-pki-import
TF_CLI_CONFIG_FILE=./dev.tfrc tofu apply -auto-approve
```

Expected: `pki_private_key.migration_test` and `pki_certificate.migration_test` created; everything else unchanged (`0 added` for the 11 imported resources — only these 2 are new).

- [ ] **Step 3: Write the cert out and verify its shape with `openssl`**

```bash
TF_CLI_CONFIG_FILE=./dev.tfrc tofu output -raw migration_test_certificate_pem > migration-test.crt
openssl x509 -in migration-test.crt -noout -subject -issuer -serial -ext extendedKeyUsage,keyUsage,subjectAltName
```

Expected:
```
subject=CN=migration-test.ha.apps.somemissing.info, O=homelab
issuer=OU=apps, O=homelab
serial=9000
X509v3 Extended Key Usage:
    TLS Web Client Authentication
X509v3 Key Usage: critical
    Digital Signature, Key Encipherment
X509v3 Subject Alternative Name:
    DNS:migration-test.ha.apps.somemissing.info
```

- [ ] **Step 4: Verify it chains to the real CA**

```bash
openssl verify -CAfile fetched-secrets/pki-ca.crt migration-test.crt
```

Expected: `migration-test.crt: OK`.

- [ ] **Step 5: Commit**

```bash
git add migration/homelab-pki-import/new-cert.tf
git commit -m "feat: issue a fresh test cert against the imported homelab-pki CA"
```

---

### Task 7: Generate a CRL and confirm it validates (the OU-order bug fix)

**Files:**
- Create: `migration/homelab-pki-import/crl.tf`
- Create: `migration/homelab-pki-import/verify.sh`

**Interfaces:**
- Consumes: `pki_certificate_authority.ca` (Task 3).
- Produces: `pki_crl.ca` — `revoked` block is populated in Task 8.

- [ ] **Step 1: Write `crl.tf` with no revocations yet**

```hcl
# migration/homelab-pki-import/crl.tf
resource "pki_crl" "ca" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem

  next_update = "168h"
}

output "crl_pem" {
  value = pki_crl.ca.crl_pem
}
```

- [ ] **Step 2: Apply and write the CRL out**

```bash
cd migration/homelab-pki-import
TF_CLI_CONFIG_FILE=./dev.tfrc tofu apply -auto-approve
TF_CLI_CONFIG_FILE=./dev.tfrc tofu output -raw crl_pem > crl.pem
```

- [ ] **Step 3: Confirm the issuer now matches the CA's subject exactly**

```bash
openssl crl -in crl.pem -noout -issuer
openssl x509 -in fetched-secrets/pki-ca.crt -noout -subject
```

Expected: both print `OU = apps, O = homelab` (or `OU=apps, O=homelab` depending on openssl version's formatting) — the same RDN order, unlike the current production CRL's reversed `O=homelab, OU=apps`.

- [ ] **Step 4: Write `verify.sh`, the reproduction of the exact command that fails in production today**

```bash
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
```

- [ ] **Step 5: Run it**

```bash
chmod +x verify.sh
./verify.sh
```

Expected: the final line is `fetched-secrets/nick-desktop.crt: OK` — this is the exact check that currently fails in production (`unable to get certificate CRL`). If it still fails here, this is a real provider bug (the issuer isn't being copied byte-for-byte from the CA) and must be written up in `FINDINGS.md` (Task 9) rather than worked around.

- [ ] **Step 6: Commit**

```bash
git add migration/homelab-pki-import/crl.tf migration/homelab-pki-import/verify.sh
git commit -m "feat: generate a CRL against the imported CA and verify it validates"
```

---

### Task 8: Revoke a cert and confirm the CRL reflects it

**Files:**
- Modify: `migration/homelab-pki-import/crl.tf`
- Modify: `migration/homelab-pki-import/verify.sh`

**Interfaces:**
- Consumes: `pki_certificate.migration_test` (Task 6, serial `9000`), `pki_crl.ca` (Task 7).

- [ ] **Step 1: Add a `revoked` block for the throwaway test cert**

Edit `crl.tf`:
```hcl
resource "pki_crl" "ca" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem

  next_update = "168h"

  revoked {
    serial_number = "9000"
    reason        = "cessationOfOperation"
  }
}

output "crl_pem" {
  value = pki_crl.ca.crl_pem
}
```

- [ ] **Step 2: Re-apply and regenerate the CRL file**

```bash
cd migration/homelab-pki-import
TF_CLI_CONFIG_FILE=./dev.tfrc tofu apply -auto-approve
TF_CLI_CONFIG_FILE=./dev.tfrc tofu output -raw crl_pem > crl.pem
```

Expected: `pki_crl.ca` updates in place (not replaced — same resource, new revocation entry); `number` increments to `2`.

- [ ] **Step 3: Append the revocation check to `verify.sh`**

```bash
echo
echo "=== revoked cert must now fail crl_check as revoked (expect 'certificate revoked') ==="
if openssl verify -CAfile fetched-secrets/pki-ca.crt -crl_check -CRLfile crl.pem migration-test.crt; then
  echo "FAIL: expected migration-test.crt to be reported as revoked, but verify succeeded" >&2
  exit 1
fi
```

(add this block to the end of `verify.sh`, after the existing content from Task 7)

- [ ] **Step 4: Run the full script**

```bash
./verify.sh
```

Expected: the nick-desktop check still prints `OK`, and the final block prints something like:
```
error 23 at 0 depth lookup: certificate revoked
error migration-test.crt: verification failed
```
then the script exits `0` (the `if` caught the expected non-zero `openssl verify` exit and did not hit the `FAIL:` branch). If `openssl verify` instead prints `OK` for the revoked cert, the CRL isn't reflecting revocation — a real bug, write it up in Task 9's `FINDINGS.md` rather than silently ignoring it.

- [ ] **Step 5: Confirm the untouched devices are still unaffected**

```bash
openssl verify -CAfile fetched-secrets/pki-ca.crt -crl_check -CRLfile crl.pem fetched-secrets/kara-iphone.crt
```

Expected: `fetched-secrets/kara-iphone.crt: OK` (revoking `migration-test` must not affect other certs).

- [ ] **Step 6: Commit**

```bash
git add migration/homelab-pki-import/crl.tf migration/homelab-pki-import/verify.sh
git commit -m "test: confirm CRL revocation actually takes effect"
```

---

### Task 9: Write up findings

**Files:**
- Create: `migration/homelab-pki-import/FINDINGS.md`

**Interfaces:**
- Consumes: the results of Tasks 3–8 (all `tofu plan`/`apply` and `verify.sh` output observed while executing this plan).

- [ ] **Step 1: Write `FINDINGS.md`**

```markdown
# homelab-pki import validation — findings

Ran against the real `homelab-pki` namespace's CA and 5 device certs, per
`docs/superpowers/specs/2026-08-01-homelab-pki-import-validation-design.md`.

## Results

- [ ] CA import: zero plan diff — yes/no (note any attribute that needed
      correcting to get there, e.g. RDN order, serial casing)
- [ ] All 5 device imports: zero plan diff — yes/no (note per-device issues)
- [ ] Fresh cert issuance (`migration-test`) against the imported CA — pass/fail
- [ ] CRL validates via `openssl verify -crl_check` against a real leaf cert
      (the OU-order bug fix) — pass/fail
- [ ] Revoking `migration-test`'s serial and regenerating correctly causes
      `openssl verify` to report it revoked, without affecting other certs —
      pass/fail

## Issues found

(List anything that didn't work as expected: provider bugs vs. config
mistakes on our side, with enough detail — resource, attribute, expected vs.
actual — that a follow-on task could act on it without re-running this
harness from scratch.)

## Conclusion

(State plainly whether `terraform-provider-pki` is validated as ready for
the cluster-cutover spec, or what must be fixed first.)
```

Fill in every checkbox and the two prose sections based on what actually
happened while executing Tasks 3–8 — this file is the deliverable this
whole plan exists to produce, so it must reflect real observed output, not
a restatement of the expected results above.

- [ ] **Step 2: Commit**

```bash
git add migration/homelab-pki-import/FINDINGS.md
git commit -m "docs: record homelab-pki import validation findings"
```
