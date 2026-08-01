# Supply a friendly name for a DN attribute the subject block has no named
# field for.
resource "pki_cert_request" "example" {
  private_key_pem = pki_private_key.example.private_key_pem

  subject {
    common_name = "nick-ipad.ha.apps.somemissing.info"

    extra_attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
  }
}
