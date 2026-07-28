# Adopt a device certificate extracted from the cluster. The CA certificate and
# key cannot be recovered from a leaf, so supply them in configuration; doing so
# does not reissue the certificate.
kubectl -n homelab-pki get secret pki-nick-ipad-2001 -o jsonpath='{.data.tls\.crt}' \
  | base64 -d > /tmp/nick-ipad.crt

terraform import 'pki_certificate.device["nick-ipad"]' 'file:///tmp/nick-ipad.crt'
