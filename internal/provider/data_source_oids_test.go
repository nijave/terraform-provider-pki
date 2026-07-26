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

// TestAccDataSourceOIDsSignatureAlgorithmAsymmetry asserts the one group that is
// not a bijection, through the data source rather than through internal/pki.
//
// RFC 8017 registers a single OID for RSASSA-PSS, 1.2.840.113549.1.1.10, across
// all hash sizes, because the hash is a PSS parameter rather than part of the
// OID. So `by_name` maps all three of SHA256-RSAPSS, SHA384-RSAPSS and
// SHA512-RSAPSS to that one value, and `by_oid` omits it rather than picking one
// name to answer for it or inventing sub-arcs no implementation would recognise.
//
// internal/pki's TestSignatureAlgorithmTableIsNotBijective pins the table. It
// cannot see this conversion path, which builds both maps out of pki.Table with
// types.MapValueFrom: a change there that filled in the missing key, or that
// dropped the duplicate names from `by_name`, would leave that test passing and
// silently change what a `for_each` over this data source produces.
func TestAccDataSourceOIDsSignatureAlgorithmAsymmetry(t *testing.T) {
	const pssOID = "1.2.840.113549.1.1.10"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
data "pki_oids" "std" {}

output "pss_oid_answers_in_by_oid" {
  value = contains(keys(data.pki_oids.std.signature_algorithms.by_oid), "` + pssOID + `")
}

output "names_without_an_oid_of_their_own" {
  value = length(data.pki_oids.std.signature_algorithms.by_name) - length(data.pki_oids.std.signature_algorithms.by_oid)
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// All three PSS names resolve, and to the same real OID.
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("signature_algorithms").AtMapKey("by_name").AtMapKey("SHA256-RSAPSS"),
					knownvalue.StringExact(pssOID)),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("signature_algorithms").AtMapKey("by_name").AtMapKey("SHA384-RSAPSS"),
					knownvalue.StringExact(pssOID)),
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("signature_algorithms").AtMapKey("by_name").AtMapKey("SHA512-RSAPSS"),
					knownvalue.StringExact(pssOID)),
				// by_oid is populated and answers for the algorithms that do own
				// their OID, so the absence assertion below is about the one
				// shared OID and not about an empty map.
				statecheck.ExpectKnownValue("data.pki_oids.std",
					tfjsonpath.New("signature_algorithms").AtMapKey("by_oid").AtMapKey("1.2.840.113549.1.1.11"),
					knownvalue.StringExact("SHA256-RSA")),
				// The shared OID is absent from by_oid. Asserted through
				// `contains(keys(...))` because a state check can only assert what
				// a key holds, never that the map does not have it.
				statecheck.ExpectKnownOutputValue("pss_oid_answers_in_by_oid", knownvalue.Bool(false)),
				// And exactly three names are missing from the reverse map, which
				// is the same statement counted the other way: it fails both if
				// by_oid gains the shared OID and if by_name loses a PSS name.
				statecheck.ExpectKnownOutputValue("names_without_an_oid_of_their_own", knownvalue.Int64Exact(3)),
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
