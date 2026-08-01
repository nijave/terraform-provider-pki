# Render an OID from a decoded certificate as a human-readable name.
data "pki_certificate" "example" {
  content_pem = file("device.crt")
}

output "first_subject_attribute" {
  value = provider::pki::oid_name(data.pki_certificate.example.subject[0].oid)
}
