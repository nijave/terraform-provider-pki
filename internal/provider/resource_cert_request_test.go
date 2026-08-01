// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// testAccKeyConfig is the fragment every certificate-related test starts from.
const testAccKeyConfig = `
resource "pki_private_key" "test" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
`

func TestAccCertRequestNamedSubject(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem

  subject {
    common_name          = "nick-ipad.ha.apps.somemissing.info"
    uid                  = "nick"
    given_name           = "Nick"
    surname              = "Venenga"
    organization         = "homelab"
    organizational_units = ["infra", "clients"]

    extra_attribute {
      oid   = provider::pki::oid("displayName")
      value = "Nick V"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_cert_request.test", tfjsonpath.New("cert_request_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN CERTIFICATE REQUEST-----`))),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertRequestOrderedSubject exercises the form that reproduces
// engine.py's DN, where displayName sits between UID and GN — an order the
// canonical named-field expansion cannot produce (spec section 5.1).
func TestAccCertRequestOrderedSubject(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem

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
  }
}

data "pki_cert_request" "decoded" {
  content_pem = pki_cert_request.test.cert_request_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// The decoded subject must come back in the same order it was
				// declared, with displayName third.
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(2).AtMapKey("oid"),
					knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(2).AtMapKey("value"),
					knownvalue.StringExact("Nick V")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("signature_valid"), knownvalue.Bool(true)),
			},
		}},
	})
}

// TestAccCertRequestRejectsMixedSubjectForms covers the mutually-exclusive-forms
// rule on the real pki_cert_request schema. The ExpectError matches a distinctive
// fragment of the diagnostic subjectFormsValidator emits ("Conflicting subject
// forms"), not the config text — the prior `(?s)mutually exclusive|attribute`
// pattern matched the config's own `attribute {` block, so it passed whether or
// not the provider ever ran.
func TestAccCertRequestRejectsMixedSubjectForms(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem

  subject {
    common_name = "cn"
    attribute {
      oid   = "2.5.4.3"
      value = "cn"
    }
  }
}
`,
			ExpectError: regexp.MustCompile(`Conflicting subject forms`),
		}},
	})
}

// TestAccCertRequestRotatingKeyReplaces confirms a new key means a new CSR:
// a CSR is a signature over a specific public key and cannot outlive it.
func TestAccCertRequestRotatingKeyReplaces(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}
`,
			},
			{
				Config: `
resource "pki_private_key" "test" {
  algorithm = "RSA"
}
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_cert_request.test", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}

// TestAccCertRequestDefaultSignatureAlgorithm pins the computed
// signature_algorithm for an ECDSA P-256 key. The default is ECDSA-SHA256, and
// writing the resolved name back to state is what makes the Optional+Computed
// attribute concrete after apply rather than unknown.
func TestAccCertRequestDefaultSignatureAlgorithm(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject { common_name = "cn" }
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_cert_request.test",
					tfjsonpath.New("signature_algorithm"), knownvalue.StringExact("ECDSA-SHA256")),
			},
		}},
	})
}
