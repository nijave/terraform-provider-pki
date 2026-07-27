// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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
