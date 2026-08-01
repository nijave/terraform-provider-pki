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

  # basic_constraints and key_usage must be declared explicitly (even though
  # their values equal this resource's defaults): import always populates
  # these blocks from the certificate's actual extensions, so an omitted
  # block in config (which plans as null) is a block-shape mismatch against
  # imported state, not a no-op. Omitting them here caused a plan diff that
  # tried to null them out and would have forced a reissue on apply.
  basic_constraints {
    ca       = true
    critical = true
  }

  key_usage {
    critical = true
    usages   = ["keyCertSign", "crlSign"]
  }

  name_constraints {
    permitted_dns_domains = ["ha.apps.somemissing.info", ".ha.apps.somemissing.info"]
  }
}

output "ca_certificate_pem" {
  value = pki_certificate_authority.ca.certificate_pem
}
