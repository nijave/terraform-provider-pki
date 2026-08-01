# A PKCS#12 bundle for a device, and the Secret it lands in.
resource "pki_bundle" "device_p12" {
  format          = "pkcs12"
  certificate_pem = pki_certificate.device.certificate_pem
  private_key_pem = pki_private_key.device.private_key_pem
  chain_pem       = [local.ca_certificate_pem]
  friendly_name   = "nick-ipad"

  # modern is AES-256-CBC with a SHA-256 MAC, which is what a bare
  # `openssl pkcs12 -export` produces under OpenSSL 3. Devices older than
  # iOS 18 or Android 14 need "legacy" instead — see the encoding matrix in
  # this resource's documentation.
  pkcs12_encoding = "modern"

  # Write-only: never stored in state. Bump password_wo_version to re-encrypt
  # with a new password, because a write-only value is invisible to drift
  # detection.
  password_wo         = var.p12_password
  password_wo_version = 1
}

resource "kubernetes_secret" "device" {
  metadata {
    name      = "pki-nick-ipad-2001"
    namespace = "homelab-pki"
    labels = {
      "pki/name"   = "nick-ipad"
      "pki/serial" = pki_certificate.device.serial_number
    }
  }

  # content_base64 goes straight into binary_data. This is what removes the
  # base64decode() round trip that fails on binary PKCS#12 data.
  binary_data = {
    "tls.crt"       = base64encode(pki_certificate.device.certificate_pem)
    "tls.key"       = base64encode(pki_private_key.device.private_key_pem)
    "nick-ipad.p12" = pki_bundle.device_p12.content_base64
  }
  type = "Opaque"
}

# A cert-only PKCS#12 truststore: no private_key_pem, so it is built as a
# truststore rather than a keystore, and passwordless needs no password.
resource "pki_bundle" "ca_truststore" {
  format          = "pkcs12"
  pkcs12_encoding = "passwordless"
  certificate_pem = local.ca_certificate_pem
  friendly_name   = "homelab-ca"
}
