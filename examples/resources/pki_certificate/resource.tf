# The CA arrives from Bitwarden via ExternalSecret, so it is bare PEM with no CA
# resource in the graph.
data "kubernetes_secret" "ca" {
  metadata {
    name      = "pki-ca"
    namespace = "homelab-pki"
  }
}

resource "pki_private_key" "device" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_cert_request" "device" {
  private_key_pem = pki_private_key.device.private_key_pem

  subject {
    common_name          = "nick-ipad.ha.apps.somemissing.info"
    uid                  = "nick"
    given_name           = "Nick"
    surname              = "Venenga"
    organization         = "homelab"

    extra_attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }
}

resource "pki_certificate" "device" {
  ca_certificate_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.crt"])
  ca_private_key_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.key"])
  csr_pem            = pki_cert_request.device.cert_request_pem

  # An explicit serial keeps the Kubernetes Secret name stable.
  serial_number = "2001"

  # 20 years, matching the existing certificates.
  validity = "175320h"

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}
