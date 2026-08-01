# Adopt an existing CA. The private key cannot be recovered from a certificate,
# so supply it in configuration; the first plan will show it being set, which
# does not reissue the certificate.
terraform import pki_certificate_authority.root 'file:///tmp/pki-ca/tls.crt'
