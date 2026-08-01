# A self-signed root.
resource "pki_private_key" "root" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "pki_certificate_authority" "root" {
  private_key_pem = pki_private_key.root.private_key_pem

  # 20 years, the value cfssl's ca-config.json already used.
  validity      = "175320h"
  early_renewal = "8760h"

  subject {
    common_name  = "homelab-root"
    organization = "homelab"
  }

  # Omitting basic_constraints and key_usage produces ca = true with
  # keyCertSign and crlSign, both critical.
  name_constraints {
    permitted_dns_domains = [".ha.apps.somemissing.info"]
  }
}

# An intermediate under it. path_len = 0 means it may not issue further CAs;
# omitting path_len would leave the depth unconstrained.
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
    common_name  = "homelab-intermediate"
    organization = "homelab"
  }

  basic_constraints {
    ca       = true
    path_len = 0
  }
}
