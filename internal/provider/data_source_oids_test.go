// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccDataSourceOIDs(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `data "pki_oids" "std" {}`,
			ConfigStateChecks: []statecheck.StateCheck{
				// Spec section 11's exact examples.
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("dn_attributes").AtMapKey("by_name").AtMapKey("displayName"),
					knownvalue.StringExact("2.16.840.1.113730.3.1.241")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("dn_attributes").AtMapKey("by_oid").AtMapKey("2.5.4.4"),
					knownvalue.StringExact("surname")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("extended_key_usages").AtMapKey("by_name").AtMapKey("clientAuth"),
					knownvalue.StringExact("1.3.6.1.5.5.7.3.2")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("extensions").AtMapKey("by_name").AtMapKey("subjectAltName"),
					knownvalue.StringExact("2.5.29.17")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("signature_algorithms").AtMapKey("by_name").AtMapKey("SHA256-RSA"),
					knownvalue.StringExact("1.2.840.113549.1.1.11")),
				// key_usages carries the RFC 5280 bit position rather than an
				// OID, because key usages are bits in a BIT STRING and have no
				// OIDs. Documented on the attribute.
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("key_usages").AtMapKey("by_name").AtMapKey("digitalSignature"),
					knownvalue.StringExact("0")),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("key_usages").AtMapKey("by_name").AtMapKey("crlSign"),
					knownvalue.StringExact("6")),
			},
		}},
	})
}

// TestAccDataSourceOIDsSupportsForEach is the capability spec section 11 calls
// out: the maps must be real maps, iterable and usable as a for_each source,
// not opaque strings.
func TestAccDataSourceOIDsSupportsForEach(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pki_oids" "std" {}

output "dn_attribute_count" {
  value = length(data.pki_oids.std.dn_attributes.by_name)
}

output "sorted_eku_names" {
  value = sort(keys(data.pki_oids.std.extended_key_usages.by_name))
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownOutputValue("dn_attribute_count", knownvalue.Int64Func(func(v int64) error {
					if v < 20 {
						return fmt.Errorf("dn_attributes.by_name has %d entries, want at least 20", v)
					}
					return nil
				})),
			},
		}},
	})
}
