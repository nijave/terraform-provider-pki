terraform {
  required_providers {
    pki = {
      source  = "nijave/pki"
      version = "~> 0.1"
    }
  }
}

# The provider takes no configuration. There is no endpoint, no credentials, and
# no client: every resource is self-contained and CA material is passed
# per-resource as PEM strings.
provider "pki" {}
