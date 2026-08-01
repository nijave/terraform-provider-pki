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
