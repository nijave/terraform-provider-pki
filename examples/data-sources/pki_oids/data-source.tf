data "pki_oids" "std" {}

# Friendly names for OIDs the subject block has no named field for.
resource "pki_cert_request" "example" {
  private_key_pem = pki_private_key.example.private_key_pem

  subject {
    common_name = "nick-ipad.ha.apps.somemissing.info"

    extra_attribute {
      oid   = data.pki_oids.std.dn_attributes.by_name["displayName"]
      value = "Nick V"
    }
  }
}

# The maps are iterable, so they work as a for_each source.
output "extended_key_usage_names" {
  value = sort(keys(data.pki_oids.std.extended_key_usages.by_name))
}
