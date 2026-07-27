// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccDataSourceCertRequest(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccKeyConfig + `
resource "pki_cert_request" "test" {
  private_key_pem = pki_private_key.test.private_key_pem
  subject {
    common_name  = "nick-ipad.ha.apps.somemissing.info"
    organization = "homelab"
  }
  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com"]
  }
}

data "pki_cert_request" "decoded" {
  content_pem = pki_cert_request.test.cert_request_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("nick-ipad.ha.apps.somemissing.info")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("san").AtMapKey("dns_names").AtSliceIndex(0),
					knownvalue.StringExact("nick-ipad.ha.apps.somemissing.info")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("san").AtMapKey("email_addresses").AtSliceIndex(0),
					knownvalue.StringExact("nick@venenga.com")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("public_key_algorithm"), knownvalue.StringExact("ECDSA")),
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("signature_valid"), knownvalue.Bool(true)),
			},
		}},
	})
}

// TestAccDataSourceCertRequestAcceptsBase64 covers the ergonomic spec section
// 11 asks for on the certificate data source and which applies equally here:
// material read straight out of a Kubernetes Secret needs no decoding step.
func TestAccDataSourceCertRequestAcceptsBase64(t *testing.T) {
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

data "pki_cert_request" "decoded" {
  content_base64 = base64encode(pki_cert_request.test.cert_request_pem)
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("cn")),
			},
		}},
	})
}

// TestAccDataSourceCertRequestStringTypeAlwaysPopulated verifies overlay C's
// requirement: the data source's computed subject always carries string_type,
// even for the utf8 default — unlike the resource's input form which omits it.
// A null string_type here would mean the provider failed to populate a field
// the schema marks Required.
func TestAccDataSourceCertRequestStringTypeAlwaysPopulated(t *testing.T) {
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

data "pki_cert_request" "decoded" {
  content_pem = pki_cert_request.test.cert_request_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_cert_request.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("string_type"),
					knownvalue.StringExact("utf8")),
			},
		}},
	})
}

func TestAccDataSourceCertRequestRejectsBadInput(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"neither input": {
			config: `data "pki_cert_request" "d" {}`,
			expect: regexp.MustCompile(`(?s)content_pem|content_base64`),
		},
		"both inputs": {
			config: `data "pki_cert_request" "d" {
  content_pem    = "x"
  content_base64 = "eA=="
}`,
			expect: regexp.MustCompile(`(?s)cannot be configured together|Invalid Attribute Combination`),
		},
		"not a csr": {
			config: `data "pki_cert_request" "d" { content_pem = "hello" }`,
			expect: regexp.MustCompile(`(?s)certificate request|PEM`),
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
