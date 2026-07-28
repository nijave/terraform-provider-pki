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

// TestAccDataSourceCertificateRejectsBadInput is the one test this task lands:
// it exercises only the data source's own input validation, with no dependency
// on the certificate resources that arrive in Tasks 8 and 9. The plan's other
// three acceptance tests move to those tasks, along with testAccCAConfig.
//
// Two of the four cases carry ExpectError patterns that have to be load-bearing
// rather than vacuous. "not a certificate" must match a fragment of the real
// parse error the provider emits, not the word "certificate" (which appears in
// the config as the resource type `pki_certificate`). "bad base64" must match a
// fragment of the real base64-decode error, not the word "base64" (which
// appears in the config as the attribute name `content_base64`). The other two
// cases are sound as written.
func TestAccDataSourceCertificateRejectsBadInput(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"neither input": {
			config: `data "pki_certificate" "d" {}`,
			expect: regexp.MustCompile(`(?s)content_pem|content_base64`),
		},
		"both inputs": {
			config: `data "pki_certificate" "d" {
  content_pem    = "x"
  content_base64 = "eA=="
}`,
			expect: regexp.MustCompile(`(?s)cannot be configured together|Invalid Attribute Combination`),
		},
		// The distinctive fragment of the real error: ParseCertificatePEM wraps
		// decodeSinglePEMBlock's "no PEM block found" message, which does not
		// appear in the config text the way "certificate" or "PEM" alone would.
		"not a certificate": {
			config: `data "pki_certificate" "d" { content_pem = "hello" }`,
			expect: regexp.MustCompile(`(?s)no PEM block found`),
		},
		// The distinctive fragment of the real base64 error: the provider's
		// diagnostic detail says "standard base64 encoding", a phrase that does
		// not appear in the config (which has only `content_base64`).
		"bad base64": {
			config: `data "pki_certificate" "d" { content_base64 = "!!!!" }`,
			expect: regexp.MustCompile(`(?s)standard base64 encoding`),
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

// TestAccDataSourceCertificate and TestAccDataSourceCertificateAcceptsBase64
// were deferred from Task 7, which built the data source but had no certificate
// resource to decode. They land here, against testAccCAConfig (defined in
// resource_certificate_authority_test.go, the same package), which Task 8
// introduces. Their bodies are taken verbatim from Task 7's Step 1.
//
// TestAccDataSourceCertificateExtensionsAndSAN still moves to Task 9, which
// introduces pki_certificate (the leaf resource it decodes).

func TestAccDataSourceCertificate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
data "pki_certificate" "decoded" {
  content_pem = pki_certificate_authority.root.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("oid"),
					knownvalue.StringExact("2.5.4.3")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("homelab-root")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("is_ca"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("public_key_algorithm"), knownvalue.StringExact("ECDSA")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("signature_algorithm"), knownvalue.StringExact("ECDSA-SHA384")),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("serial_number"), knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]+$`))),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("not_after"), knownvalue.StringRegexp(regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`))),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject_key_id"), knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]{40}$`))),
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("fingerprint_sha256"), knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]{64}$`))),
			},
		}},
	})
}

func TestAccDataSourceCertificateAcceptsBase64(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// This is the shape that matters operationally: the CA arrives as
			// base64 in a Kubernetes Secret's data map, and spec section 11
			// requires no decoding step.
			Config: testAccCAConfig + `
data "pki_certificate" "decoded" {
  content_base64 = base64encode(pki_certificate_authority.root.certificate_pem)
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.decoded",
					tfjsonpath.New("subject").AtSliceIndex(0).AtMapKey("value"),
					knownvalue.StringExact("homelab-root")),
			},
		}},
	})
}
