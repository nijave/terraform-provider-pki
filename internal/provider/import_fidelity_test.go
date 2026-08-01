// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// testdataPath returns an absolute path to a file in testdata, since the
// Terraform working directory the harness creates is not the package directory.
func testdataPath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("resolving testdata/%s: %v", name, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("testdata/%s is missing: %v", name, err)
	}
	return abs
}

// mustReadFile reads a file or fails the test. Used to feed the imported
// certificate's exact bytes into a known-value check, so the test can assert
// the settling apply did not reissue the cert.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return b
}

// TestAccImportFidelity is the gate on the migration follow-up (spec sections 8
// and 10).
//
// It imports a certificate that was produced by openssl the way
// reconcile/engine.py produces one — ordered DN with displayName between UID
// and GN, UTF8String values, two rfc822Name SANs, an explicit serial — and
// asserts the subsequent plan is empty. An empty plan means every input
// attribute was reconstructed from the DER exactly: the DN byte-for-byte
// including ASN.1 string types, the SAN, the serial, the validity window, and
// every extension.
//
// If this test fails, the homelab migration cannot proceed: applying would
// reissue 20-year certificates that are installed on phones and tablets, and
// each reissue means a manual re-enrollment. Do NOT weaken the empty-plan
// assertion — a failure is real signal: a bug in ImportState reconstruction or
// ModifyPlan drift detection that must be fixed at the source.
func TestAccImportFidelity(t *testing.T) {
	caCert := testdataPath(t, "ca.crt")
	caKey := testdataPath(t, "ca.key")
	leafCert := testdataPath(t, "leaf.crt")
	leafKey := testdataPath(t, "leaf.key")

	// The configuration supplies only what cannot be recovered from a
	// certificate: the CA material and the device's own key. Everything else
	// must come from the import.
	//
	// The key is adopted as a pki_private_key in the first step, which is the
	// realistic shape — a device's key and certificate are adopted together —
	// and it gives public_key_pem something to reference. The adopted key's
	// public key MUST match the public key inside the imported certificate or
	// the comparison in certdrift.go reports public-key drift.
	//
	// Everything below `public_key_pem` (subject, san, serial, validity, every
	// extension) is what import reconstructs. It is spelled out here because a
	// Terraform resource must have a configuration — and the point of the test
	// is that this configuration matches what import produced, so the
	// subsequent plan is empty.
	//
	// The subject uses raw dotted-decimal OIDs rather than the
	// `provider::pki::oid("...")` shortcut used elsewhere in this package's
	// acceptance tests. The shortcut would resolve identically here, but
	// `tofu import` (the ImportCommandWithID path this test exercises, which
	// mirrors what the migration actually runs) parses the whole config
	// outside a plan context and OpenTofu cannot resolve provider functions
	// there — it errors with `Unknown function provider` before the provider
	// is reached. ImportBlockWithID would route through plan and resolve the
	// function, but the terraform-plugin-testing harness disallows combining
	// plannable import blocks with ImportStatePersist, and ImportStatePersist
	// is what carries the adopted key from Step 1 into Step 2 and the adopted
	// certificate from Step 2 into Step 3. Raw OIDs are byte-equivalent and
	// avoid the harness limitation without weakening anything the test asserts.
	keyConfig := `
resource "pki_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
`

	fullConfig := fmt.Sprintf(`
resource "pki_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "adopted" {
  ca_certificate_pem = file(%q)
  ca_private_key_pem = file(%q)

  # public_key_pem is required by the schema in inline mode. It comes from the
  # adopted key, and must match the public key inside the imported certificate
  # or the comparison in certdrift.go reports public_key drift.
  public_key_pem = pki_private_key.leaf.public_key_pem

  # Everything below is what import reconstructs. It is spelled out here
  # because a Terraform resource must have a configuration — and the point of
  # the test is that this configuration matches what import produced.
  validity = "175320h"

  subject {
    attribute {
      oid   = "2.5.4.3"   # commonName
      value = "nick-ipad.ha.apps.somemissing.info"
    }
    attribute {
      oid   = "0.9.2342.19200300.100.1.1" # uid
      value = "nick"
    }
    attribute {
      oid   = "2.16.840.1.113730.3.1.241" # displayName — between UID and GN
      value = "Nick V"
    }
    attribute {
      oid   = "2.5.4.42"  # givenName
      value = "Nick"
    }
    attribute {
      oid   = "2.5.4.4"   # surname
      value = "Venenga"
    }
    attribute {
      oid   = "2.5.4.10"  # organization
      value = "homelab"
    }
  }

  san {
    dns_names       = ["nick-ipad.ha.apps.somemissing.info"]
    email_addresses = ["nick@venenga.com", "nijave@gmail.com"]
  }

  serial_number = "2001"

  basic_constraints {
    ca       = false
    critical = true
  }

  key_usage {
    usages   = ["digitalSignature", "keyEncipherment"]
    critical = true
  }

  extended_key_usage {
    usages   = ["clientAuth"]
    critical = false
  }
}
`, caCert, caKey)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Adopt the device's key first, and persist it so the next step
				// can reference its public key. ImportStatePersist is what
				// carries imported state into the following step.
				//
				// keyConfig (not fullConfig) because the certificate block is
				// unnecessary for the key import and keeping the config small
				// avoids surfacing resource types the import is not operating
				// on.
				Config:             keyConfig,
				ResourceName:       "pki_private_key.leaf",
				ImportState:        true,
				ImportStateId:      "file://" + leafKey,
				ImportStatePersist: true,
				ImportStateVerify:  false,
			},
			{
				// Adopt the certificate. ImportStatePersist carries it into
				// Step 3 so the settling apply runs against fully-adopted
				// state. ImportStateVerify is false because there is no prior
				// config-set state to compare against.
				Config:             fullConfig,
				ResourceName:       "pki_certificate.adopted",
				ImportState:        true,
				ImportStateId:      "file://" + leafCert,
				ImportStatePersist: true,
				ImportStateVerify:  false,
			},
			{
				// The settling apply. After ImportState, the cryptographic
				// inputs that cannot be recovered from a leaf (the CA cert and
				// key) are null in state while configuration supplies them, so
				// a plan diff exists and Update fires. Two things must be true
				// about that Update:
				//
				//   1. It must NOT reissue the certificate. Update's no-drift
				//      short-circuit (triggered by copyComputed having already
				//      populated certificate_pem from state) writes the plan
				//      back to state verbatim, preserving the imported cert's
				//      notBefore and bytes. The PreApply plan check verifies
				//      this by pinning the planned certificate_pem to the
				//      exact bytes of the imported leaf.crt — if Update were
				//      going to reissue, certificate_pem would be Unknown in
				//      the plan and the known-value check would fail.
				//
				//   2. The plan AFTER the settling apply must be empty. That
				//      is the migration gate: once the inputs have been
				//      recorded into state, `tofu plan` proposes nothing. A
				//      non-empty plan here means a real reconstruction bug
				//      (ImportState mis-decoded the DER) or a real drift bug
				//      (ModifyPlan compared incorrectly). Do NOT weaken the
				//      ExpectEmptyPlan assertion.
				Config: fullConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						// certificate_pem must arrive in the plan as the
						// imported bytes, not Unknown. Unknown would mean
						// Update is about to reissue.
						plancheck.ExpectKnownValue("pki_certificate.adopted",
							tfjsonpath.New("certificate_pem"),
							knownvalue.StringExact(string(mustReadFile(t, leafCert)))),
					},
					PostApplyPostRefresh: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				// And state's certificate_pem after the settling apply must
				// equal the imported leaf.crt byte-for-byte, which is the
				// direct assertion that no reissue happened: a reissued cert
				// would carry a fresh notBefore and different bytes.
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_certificate.adopted",
						tfjsonpath.New("certificate_pem"),
						knownvalue.StringExact(string(mustReadFile(t, leafCert)))),
				},
			},
		},
	})
}

// TestAccImportFidelityDiagnosesTheDifference runs the same import and, when
// the plan is not empty, reports which attribute drifted.
//
// It exists because ExpectEmptyPlan's failure output says only that the plan
// was non-empty, and the interesting question is always *which* field failed to
// round-trip — almost always the DN's ASN.1 string types or the SAN's
// GeneralName ordering.
func TestAccImportFidelityDiagnosesTheDifference(t *testing.T) {
	leafCert := testdataPath(t, "leaf.crt")
	caCert := testdataPath(t, "ca.crt")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// Decode the reference certificate through the data source and
			// assert on what came back, so a mismatch names the field.
			Config: fmt.Sprintf(`
data "pki_certificate" "reference" {
  content_pem = file(%q)
}

data "pki_certificate" "ca" {
  content_pem = file(%q)
}

output "subject_oids" {
  value = [for a in data.pki_certificate.reference.subject : a.oid]
}
output "subject_string_types" {
  value = [for a in data.pki_certificate.reference.subject : a.string_type]
}
output "san_emails" {
  value = data.pki_certificate.reference.san.email_addresses
}
output "serial" {
  value = data.pki_certificate.reference.serial_number
}
`, leafCert, caCert),
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				out := s.RootModule().Outputs

				oids, ok := out["subject_oids"].Value.([]any)
				if !ok {
					return fmt.Errorf("subject_oids is %T, want a list", out["subject_oids"].Value)
				}
				want := []string{
					"2.5.4.3",                   // CN
					"0.9.2342.19200300.100.1.1", // UID
					"2.16.840.1.113730.3.1.241", // displayName — between UID and GN
					"2.5.4.42",                  // GN
					"2.5.4.4",                   // SN
					"2.5.4.10",                  // O
				}
				if len(oids) != len(want) {
					return fmt.Errorf("subject has %d attributes, want %d: %v", len(oids), len(want), oids)
				}
				for i, w := range want {
					if oids[i].(string) != w {
						return fmt.Errorf("subject attribute %d is %s, want %s; DN order is significant in DER", i, oids[i], w)
					}
				}

				// engine.py runs openssl with string_mask = utf8only, so every
				// value must decode as UTF8String. If this reports "printable",
				// the DN will not re-encode byte-exact.
				types, _ := out["subject_string_types"].Value.([]any)
				for i, st := range types {
					if st.(string) != "utf8" {
						return fmt.Errorf("subject attribute %d has string type %q, want \"utf8\"", i, st)
					}
				}

				emails, _ := out["san_emails"].Value.([]any)
				if len(emails) != 2 || emails[0].(string) != "nick@venenga.com" || emails[1].(string) != "nijave@gmail.com" {
					return fmt.Errorf("SAN emails = %v, want [nick@venenga.com nijave@gmail.com] in that order", emails)
				}

				if got := out["serial"].Value.(string); got != "2001" {
					return fmt.Errorf("serial = %q, want \"2001\"", got)
				}
				return nil
			}),
		}},
	})
}
