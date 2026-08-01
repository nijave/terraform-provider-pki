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
