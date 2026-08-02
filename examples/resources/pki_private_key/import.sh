# Adopt an existing key from disk. This is the only accepted form: unlike
# pki_certificate/pki_certificate_authority, this resource does not accept
# pem:// or base64:// -- OpenTofu/Terraform prints an import ID in full,
# unconditionally, before this provider ever runs, and an inline scheme would
# put the private key itself into that output.
terraform import pki_private_key.device 'file:///tmp/nick-ipad/tls.key'

# Adopting a key from somewhere other than a local file (a Kubernetes Secret,
# a secrets manager, piped from another tool) still needs to land in a file
# first -- write it to a private, short-lived temp file and import from that:
umask 077
kubectl get secret nick-ipad-tls -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/nick-ipad.key
terraform import pki_private_key.device 'file:///tmp/nick-ipad.key'
rm -f /tmp/nick-ipad.key
