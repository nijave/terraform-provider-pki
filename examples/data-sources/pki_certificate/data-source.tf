# The CA is delivered from Bitwarden into a Kubernetes Secret, so it arrives
# base64-encoded. No decoding step is needed.
data "kubernetes_secret" "ca" {
  metadata {
    name      = "pki-ca"
    namespace = "homelab-pki"
  }
}

data "pki_certificate" "ca" {
  content_base64 = data.kubernetes_secret.ca.binary_data["tls.crt"]
}

# Assert on adopted material before building anything on top of it.
check "ca_can_sign_crls" {
  assert {
    condition     = contains(data.pki_certificate.ca.key_usage.usages, "crlSign")
    error_message = "The CA cannot sign CRLs; pki_crl will fail against it."
  }
}

output "ca_expires" {
  value = data.pki_certificate.ca.not_after
}
