# migration/homelab-pki-import/devices.tf
resource "pki_private_key" "kara_iphone" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "kara_iphone" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.kara_iphone.public_key_pem

  serial_number = "2000"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "kara-iphone.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "kara"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Kara G"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Kara"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Gilmore"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["kara-iphone.ha.apps.somemissing.info"]
    email_addresses = ["karakgilmore@gmail.com"]
  }

  # basic_constraints must be declared explicitly (even though its values equal
  # this resource's leaf default), for the same reason as pki_certificate_authority.ca
  # in ca.tf: ImportState always populates this block from the certificate's
  # actual basicConstraints extension, so an omitted block in config (which
  # plans as null) is a block-shape mismatch against imported state, not a
  # no-op -- ModifyPlan's copyComputed guard (resource_certificate.go) bails out
  # on any BasicConstraints difference and Update reissues the cert with a
  # fresh not_before.
  basic_constraints {
    ca       = false
    critical = true
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

resource "pki_private_key" "nick_desktop" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "nick_desktop" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.nick_desktop.public_key_pem

  serial_number = "2001"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-desktop.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Nick"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Venenga"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["nick-desktop.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  # basic_constraints must be declared explicitly -- see the comment on
  # pki_certificate.kara_iphone above for why (ImportState always populates
  # this block from the certificate's actual extension, so an omitted block
  # is a block-shape mismatch, not a no-op).
  basic_constraints {
    ca       = false
    critical = true
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

resource "pki_private_key" "nick_ipad" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "nick_ipad" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.nick_ipad.public_key_pem

  serial_number = "2002"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-ipad.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Nick"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Venenga"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  # basic_constraints must be declared explicitly -- see the comment on
  # pki_certificate.kara_iphone above for why.
  basic_constraints {
    ca       = false
    critical = true
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

resource "pki_private_key" "nick_xps" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "nick_xps" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.nick_xps.public_key_pem

  serial_number = "2003"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "nick-xps.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Nick"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Venenga"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["nick-xps.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  # basic_constraints must be declared explicitly -- see the comment on
  # pki_certificate.kara_iphone above for why.
  basic_constraints {
    ca       = false
    critical = true
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}

resource "pki_private_key" "pixel7" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "pixel7" {
  ca_certificate_pem = pki_certificate_authority.ca.certificate_pem
  ca_private_key_pem = pki_certificate_authority.ca.private_key_pem
  public_key_pem      = pki_private_key.pixel7.public_key_pem

  serial_number = "2004"
  validity      = "175320h"

  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "pixel7.ha.apps.somemissing.info"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
    attribute {
      oid   = provider::pki::oid("givenName")
      value = "Nick"
    }
    attribute {
      oid   = provider::pki::oid("surname")
      value = "Venenga"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }

  san {
    dns_names       = ["pixel7.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  # basic_constraints must be declared explicitly -- see the comment on
  # pki_certificate.kara_iphone above for why.
  basic_constraints {
    ca       = false
    critical = true
  }

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}
