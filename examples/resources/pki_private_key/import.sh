# Adopt an existing key from disk.
terraform import pki_private_key.device 'file:///tmp/nick-ipad/tls.key'

# Or inline, for a key already in a variable or piped from another tool.
terraform import pki_private_key.device "base64://$(base64 -w0 < tls.key)"
