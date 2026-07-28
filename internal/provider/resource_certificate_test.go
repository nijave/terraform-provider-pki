// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// testAccLeafFromCSR is the shape the homelab reconciler uses: a key, a CSR,
// and a certificate signed by a CA supplied as bare PEM.
const testAccLeafFromCSR = `
resource "pki_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_cert_request" "leaf" {
  private_key_pem = pki_private_key.leaf.private_key_pem

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
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.leaf.cert_request_pem
  serial_number      = "2001"
  validity           = "175320h"

  key_usage {
    usages = ["digitalSignature", "keyEncipherment"]
  }

  extended_key_usage {
    usages = ["clientAuth"]
  }
}
`

func TestAccCertificateFromCSR(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + testAccLeafFromCSR + `
data "pki_certificate" "leaf" {
  content_pem = pki_certificate.leaf.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_certificate.leaf", tfjsonpath.New("serial_number"),
					knownvalue.StringExact("2001")),
				// The CSR's subject is used when no subject block overrides it,
				// including the ordered form with displayName in the middle.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("subject").AtSliceIndex(2).AtMapKey("oid"),
					knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				// And the CSR's SAN, including both rfc822Name entries -- the
				// capability hashicorp/tls lacks entirely.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("san").AtMapKey("email_addresses"),
					knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("nick@venenga.com"),
						knownvalue.StringExact("nijave@gmail.com"),
					})),
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("is_ca"), knownvalue.Bool(false)),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateInlineMode covers the public_key_pem path: no CSR, with the
// subject and SAN supplied directly.
func TestAccCertificateInlineMode(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + testAccKeyConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"

  subject {
    common_name  = "inline.example"
    organization = "homelab"
  }

  san {
    dns_names = ["inline.example"]
  }
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_certificate.leaf", tfjsonpath.New("certificate_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN CERTIFICATE-----`))),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateSubjectOverridesCSR pins the precedence rule from spec
// section 6.4: an explicitly-set subject replaces the CSR's wholesale, with no
// field-level merging.
func TestAccCertificateSubjectOverridesCSR(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_cert_request" "leaf" {
  private_key_pem = pki_private_key.leaf.private_key_pem
  subject {
    common_name  = "requested.example"
    organization = "requested-org"
  }
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.leaf.cert_request_pem
  validity           = "8760h"

  subject {
    common_name = "issued.example"
  }
}

data "pki_certificate" "leaf" {
  content_pem = pki_certificate.leaf.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("issued.example")),
				// Wholesale replacement: the CSR's organization is NOT merged in.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("subject"),
					knownvalue.ListSizeExact(1)),
			},
		}},
	})
}

// TestAccCertificateNeverCopiesCSRExtensions is the security property spec
// section 6.4 calls out. cfssl's copy_extensions = true let a requester dictate
// its own extensions, which is a well-known escalation hazard: a CSR asking for
// basicConstraints CA:TRUE must not get it.
func TestAccCertificateNeverCopiesCSRExtensions(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_cert_request" "escalating" {
  private_key_pem = pki_private_key.leaf.private_key_pem
  subject { common_name = "wants-to-be-a-ca.example" }

  # The CSR asks for CA:TRUE and keyCertSign. DER for
  # BasicConstraints{cA: TRUE} is 30 03 01 01 FF.
  extra_extension {
    oid          = provider::pki::oid("basicConstraints")
    value_base64 = "MAMBAf8="
    critical     = true
  }
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.escalating.cert_request_pem
  validity           = "8760h"

  key_usage {
    usages = ["digitalSignature"]
  }
}

data "pki_certificate" "leaf" {
  content_pem = pki_certificate.leaf.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// The issued certificate is not a CA, regardless of what the
				// CSR requested.
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("is_ca"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("basic_constraints").AtMapKey("ca"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("data.pki_certificate.leaf",
					tfjsonpath.New("key_usage").AtMapKey("usages"),
					knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("digitalSignature")})),
			},
		}},
	})
}

func TestAccCertificateRejectsBadConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"csr and public key together": {
			config: testAccCAConfig + testAccKeyConfig + `
resource "pki_cert_request" "r" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  csr_pem            = pki_cert_request.r.cert_request_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"
}`,
			expect: regexp.MustCompile(`(?s)cannot be configured together|Invalid Attribute Combination`),
		},
		"neither csr nor public key": {
			config: testAccCAConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  validity           = "8760h"
  subject { common_name = "cn" }
}`,
			expect: regexp.MustCompile(`(?s)csr_pem|public_key_pem`),
		},
		"inline mode without subject or san": {
			config: testAccCAConfig + testAccKeyConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"
}`,
			expect: regexp.MustCompile(`(?s)subject|san`),
		},
		"ca key does not match ca cert": {
			config: testAccCAConfig + testAccKeyConfig + `
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.test.private_key_pem
  public_key_pem     = pki_private_key.test.public_key_pem
  validity           = "8760h"
  subject { common_name = "cn" }
}`,
			// The distinctive fragment of the real cross-reference error: the
			// provider emits "CA key does not match CA certificate" and a detail
			// whose "public key does not match the certificate's" phrase cannot
			// appear in the config the test sends (which has the attribute names
			// ca_private_key_pem and ca_certificate_pem but never the phrase
			// "does not match"). Mutation evidence: removing the PublicKeysEqual
			// cross-check in Create makes this case pass (cert issues with the
			// wrong key), so the pattern is load-bearing.
			expect: regexp.MustCompile(`(?s)does not match`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps:                    []resource.TestStep{{Config: tc.config, ExpectError: tc.expect}},
			})
		})
	}
}

// TestAccCertificateChainVerifies is spec section 10's first acceptance
// criterion, end to end through Terraform: root -> intermediate -> leaf
// verifies with x509.Certificate.Verify.
func TestAccCertificateChainVerifies(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "intermediate" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "intermediate" {
  private_key_pem        = pki_private_key.intermediate.private_key_pem
  parent_certificate_pem = pki_certificate_authority.root.certificate_pem
  parent_private_key_pem = pki_private_key.ca.private_key_pem
  validity               = "87600h"
  subject { common_name = "homelab-intermediate" }
  key_usage { usages = ["keyCertSign", "crlSign"] }
}

resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.intermediate.certificate_pem
  ca_private_key_pem = pki_private_key.intermediate.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  validity           = "8760h"
  subject { common_name = "device.ha.apps.somemissing.info" }
  san { dns_names = ["device.ha.apps.somemissing.info"] }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
  extended_key_usage { usages = ["clientAuth"] }
}

output "root_pem" { value = pki_certificate_authority.root.certificate_pem }
output "intermediate_pem" { value = pki_certificate_authority.intermediate.certificate_pem }
output "leaf_pem" { value = pki_certificate.leaf.certificate_pem }
`,
			Check: resource.ComposeAggregateTestCheckFunc(
				func(s *terraform.State) error {
					rootPEM := s.RootModule().Outputs["root_pem"].Value.(string)
					interPEM := s.RootModule().Outputs["intermediate_pem"].Value.(string)
					leafPEM := s.RootModule().Outputs["leaf_pem"].Value.(string)

					parse := func(p string) (*x509.Certificate, error) {
						block, _ := pem.Decode([]byte(p))
						if block == nil {
							return nil, fmt.Errorf("not PEM")
						}
						return x509.ParseCertificate(block.Bytes)
					}
					root, err := parse(rootPEM)
					if err != nil {
						return fmt.Errorf("parsing the root: %w", err)
					}
					inter, err := parse(interPEM)
					if err != nil {
						return fmt.Errorf("parsing the intermediate: %w", err)
					}
					leaf, err := parse(leafPEM)
					if err != nil {
						return fmt.Errorf("parsing the leaf: %w", err)
					}

					roots := x509.NewCertPool()
					roots.AddCert(root)
					intermediates := x509.NewCertPool()
					intermediates.AddCert(inter)
					if _, err := leaf.Verify(x509.VerifyOptions{
						Roots:         roots,
						Intermediates: intermediates,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					}); err != nil {
						return fmt.Errorf("chain verification failed: %w", err)
					}
					return nil
				},
			),
		}},
	})
}
