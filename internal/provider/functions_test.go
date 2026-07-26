// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
)

func TestAccFunctionOID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "display_name" {
  value = provider::pki::oid("displayName")
}
output "surname" {
  value = provider::pki::oid("surname")
}
output "client_auth" {
  value = provider::pki::oid("clientAuth")
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("display_name", knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				statecheck.ExpectKnownOutputValue("surname", knownvalue.StringExact("2.5.4.4")),
				statecheck.ExpectKnownOutputValue("client_auth", knownvalue.StringExact("1.3.6.1.5.5.7.3.2")),
			},
		}},
	})
}

func TestAccFunctionOIDName(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "surname" {
  value = provider::pki::oid_name("2.5.4.4")
}
output "san" {
  value = provider::pki::oid_name("2.5.29.17")
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("surname", knownvalue.StringExact("surname")),
				statecheck.ExpectKnownOutputValue("san", knownvalue.StringExact("subjectAltName")),
			},
		}},
	})
}

// TestAccFunctionOIDUnknownNameFails is the behavior spec section 11 requires
// explicitly: a typo must fail at plan time, not resolve to an empty string
// that silently produces a certificate with a missing DN attribute.
//
// The regexp deliberately matches the message pki.OIDByName itself produces
// (`unknown OID name "commonNam"`) rather than just the bare argument
// "commonNam". A looser regexp matching only "commonNam" would pass even
// before the function is implemented at all: OpenTofu's "Function not found
// in provider" diagnostic echoes the offending source line verbatim, which
// contains that same literal. Matching the library's own error text is what
// ties this assertion to the function actually running and rejecting the
// input, rather than to config parsing failing before the function is ever
// invoked.
func TestAccFunctionOIDUnknownNameFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "typo" {
  value = provider::pki::oid("commonNam")
}
`,
			ExpectError: regexp.MustCompile(`(?s)unknown OID name "commonNam"`),
		}},
	})
}

// The regexp matches pki.NameByOID's own message (`unknown OID
// "1.2.3.4.5.6.7.8.9"`) for the same reason as
// TestAccFunctionOIDUnknownNameFails above: the bare dotted OID alone would
// also appear in a plain "function not registered" parse error, since that
// diagnostic echoes the source line containing the literal argument.
func TestAccFunctionOIDNameUnknownOIDFails(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "unknown" {
  value = provider::pki::oid_name("1.2.3.4.5.6.7.8.9")
}
`,
			ExpectError: regexp.MustCompile(`(?s)unknown OID "1\.2\.3\.4\.5\.6\.7\.8\.9"`),
		}},
	})
}

// TestAccFunctionsComposeInASubjectBlock is the actual use case from spec
// section 5.1: the function supplies a friendly name for an OID the subject
// block has no named field for.
func TestAccFunctionsComposeInASubjectBlock(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
output "round_trip" {
  value = provider::pki::oid_name(provider::pki::oid("displayName"))
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("round_trip", knownvalue.StringExact("displayName")),
			},
		}},
	})
}
