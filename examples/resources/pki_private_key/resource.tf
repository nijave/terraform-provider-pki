resource "pki_private_key" "device" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}
