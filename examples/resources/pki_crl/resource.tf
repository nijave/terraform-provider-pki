resource "pki_crl" "homelab" {
  ca_certificate_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.crt"])
  ca_private_key_pem = base64decode(data.kubernetes_secret.ca.binary_data["tls.key"])

  # The CRL claims freshness for a week, and reports itself ready for
  # regeneration a day before that expires. A periodic `tofu apply` is what
  # actually regenerates it — this replaces the 6-hourly refresh CronJob's
  # staleness logic, not its scheduling.
  next_update      = "168h"
  early_regenerate = "24h"

  revoked {
    serial_number = "2001"
    reason        = "keyCompromise"
  }
}

# content_base64 feeds binary_data directly, with no base64decode round trip.
resource "kubernetes_secret" "crl" {
  metadata {
    name      = "pki-crl"
    namespace = "homelab-pki"
  }
  binary_data = { "crl.pem" = pki_crl.homelab.crl_base64 }
  type        = "Opaque"
}
