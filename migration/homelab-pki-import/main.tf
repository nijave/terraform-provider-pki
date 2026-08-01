# migration/homelab-pki-import/main.tf
terraform {
  required_providers {
    pki = {
      source = "nijave/pki"
    }
  }
}

provider "pki" {}
