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
    organizational_units = ["infra", "clients"]

    # displayName has no named field, so supply it by OID.
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
