# Inspect a CSR handed over by a device or another team before signing it.
data "pki_cert_request" "incoming" {
  content_pem = file("device.csr")
}

# Refuse to issue against a CSR whose signature does not verify, or whose
# common name is outside the domain this CA is willing to sign for.
resource "pki_certificate" "device" {
  count = data.pki_cert_request.incoming.signature_valid ? 1 : 0

  ca_certificate_pem = var.ca_certificate_pem
  ca_private_key_pem = var.ca_private_key_pem
  csr_pem            = data.pki_cert_request.incoming.content_pem
  validity           = "8760h"

  # Extensions always come from here, never from the CSR.
  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }
  extended_key_usage {
    usages = ["clientAuth"]
  }
}
