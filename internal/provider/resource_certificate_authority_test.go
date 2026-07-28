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

// testAccCAConfig is a self-signed CA every later test builds on. crlSign is
// included because Go refuses to sign a CRL with a CA that lacks it.
const testAccCAConfig = `
resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "pki_certificate_authority" "root" {
  private_key_pem = pki_private_key.ca.private_key_pem
  validity        = "175320h"

  subject {
    common_name  = "homelab-root"
    organization = "homelab"
  }

  basic_constraints {
    ca = true
  }

  key_usage {
    usages = ["keyCertSign", "crlSign"]
  }
}
`

func TestAccCertificateAuthorityRoot(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("certificate_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN CERTIFICATE-----`))),
				// No parent means no chain.
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("certificate_chain_pem"),
					knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("ready_for_renewal"),
					knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("serial_number"),
					knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]+$`))),
				statecheck.ExpectKnownValue("pki_certificate_authority.root", tfjsonpath.New("subject_key_id"),
					knownvalue.StringRegexp(regexp.MustCompile(`^[0-9a-f]{40}$`))),
				// Self-signed: crypto/x509 omits authorityKeyIdentifier entirely
				// when the issuer DN equals the subject DN (internal/pki/sign.go
				// documents this and sign_test.go asserts it), so authority_key_id
				// is null rather than echoing the subject_key_id.
				statecheck.ExpectKnownValue("pki_certificate_authority.root",
					tfjsonpath.New("authority_key_id"), knownvalue.Null()),
				// basic_constraints is a SingleNestedBlock, which serializes to
				// state as a single object (BlockNestingModeSingle), not a list.
				statecheck.ExpectKnownValue("pki_certificate_authority.root",
					tfjsonpath.New("basic_constraints").AtMapKey("ca"), knownvalue.Bool(true)),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccCertificateAuthorityIntermediate(t *testing.T) {
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

  subject {
    common_name  = "homelab-intermediate"
    organization = "homelab"
  }

  basic_constraints {
    ca       = true
    path_len = 0
  }

  key_usage {
    usages = ["keyCertSign", "crlSign"]
  }
}

data "pki_certificate" "intermediate" {
  content_pem = pki_certificate_authority.intermediate.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// A parent means a chain, leaf-adjacent first.
				statecheck.ExpectKnownValue("pki_certificate_authority.intermediate", tfjsonpath.New("certificate_chain_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`(?s)^-----BEGIN CERTIFICATE-----.*-----BEGIN CERTIFICATE-----`))),
				// path_len = 0 must survive as a real constraint, distinct from
				// unset (spec section 5.3).
				statecheck.ExpectKnownValue("data.pki_certificate.intermediate",
					tfjsonpath.New("basic_constraints").AtMapKey("path_len"), knownvalue.Int64Exact(0)),
				statecheck.ExpectKnownValue("data.pki_certificate.intermediate",
					tfjsonpath.New("is_ca"), knownvalue.Bool(true)),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateAuthorityPathLenUnsetVersusZero is the pair of cases spec
// section 5.3 exists for. Unset must produce no pathLenConstraint at all.
func TestAccCertificateAuthorityPathLenUnsetVersusZero(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "unset" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  subject { common_name = "unset" }
  basic_constraints { ca = true }
}

resource "pki_certificate_authority" "zero" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  subject { common_name = "zero" }
  basic_constraints {
    ca       = true
    path_len = 0
  }
}

data "pki_certificate" "unset" {
  content_pem = pki_certificate_authority.unset.certificate_pem
}

data "pki_certificate" "zero" {
  content_pem = pki_certificate_authority.zero.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.pki_certificate.unset",
					tfjsonpath.New("basic_constraints").AtMapKey("path_len"), knownvalue.Null()),
				statecheck.ExpectKnownValue("data.pki_certificate.zero",
					tfjsonpath.New("basic_constraints").AtMapKey("path_len"), knownvalue.Int64Exact(0)),
			},
		}},
	})
}

// TestAccCertificateAuthorityExplicitSerial covers spec section 7: an explicit
// hex serial is honored, and the issued certificate carries the canonical form.
//
// The resource serial_number preserves the configured spelling verbatim because
// Terraform Core requires the planned value of a config-set Optional+Computed
// attribute to equal the configured value — normalizing it in state surfaces as
// an inconsistent result after apply (verified: both a resource.ModifyPlan and
// a per-attribute string plan modifier were rejected with "planned value ...
// does not match config value"). The data source, which reads the certificate's
// actual serial, reports the canonical parsed value, which is where the
// normalization this test cares about is observable.
func TestAccCertificateAuthorityExplicitSerial(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  serial_number   = "0x0002ABC"
  subject { common_name = "ca" }
}

data "pki_certificate" "ca" {
  content_pem = pki_certificate_authority.ca.certificate_pem
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// The configured spelling is preserved in resource state.
				statecheck.ExpectKnownValue("pki_certificate_authority.ca", tfjsonpath.New("serial_number"),
					knownvalue.StringExact("0x0002ABC")),
				// The issued certificate carries the canonical parsed serial:
				// lowercased, 0x stripped, leading zeros stripped.
				statecheck.ExpectKnownValue("data.pki_certificate.ca", tfjsonpath.New("serial_number"),
					knownvalue.StringExact("2abc")),
				// This config omits basic_constraints and key_usage, so the
				// issuance defaults must have been applied: a CA certificate
				// (ca = true) with keyCertSign and crlSign (DefaultCAKeyUsage).
				// An omitted SingleNestedBlock cannot be materialized into state,
				// so the defaults are observable only on the issued certificate,
				// which is why these checks read through the data source. A
				// regression in basicConstraintsValue(nil) or keyUsageValue(nil)
				// would fail here.
				statecheck.ExpectKnownValue("data.pki_certificate.ca",
					tfjsonpath.New("is_ca"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue("data.pki_certificate.ca",
					tfjsonpath.New("key_usage").AtMapKey("usages"),
					knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact("keyCertSign"),
						knownvalue.StringExact("crlSign"),
					})),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateAuthoritySerialIsStableAcrossPlans is the guarantee that
// keeps a 20-year CA from being replaced. A random serial is drawn once and then
// held in state forever.
func TestAccCertificateAuthoritySerialIsStableAcrossPlans(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: testAccCAConfig},
			{
				// Same config, applied again. Nothing may change.
				Config: testAccCAConfig,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply:             []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
			},
		},
	})
}

// TestAccCertificateAuthorityRejectsBadConfig is the plan-time validation
// surface. The "bad validity" and "bad serial" cases carry ExpectError patterns
// that have to be load-bearing rather than vacuous: the original patterns
// `(?s)validity|duration` and `(?s)serial|hex` both matched the test's own config
// text and would have passed whether or not the provider emitted any error at
// all. Each is replaced with a distinctive fragment of the real
// pki.ParseDuration / pki.ParseSerial error message -- a phrase that cannot
// appear in the config the test sends.
func TestAccCertificateAuthorityRejectsBadConfig(t *testing.T) {
	const keyConfig = `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
`
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"parent cert without parent key": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem        = pki_private_key.k.private_key_pem
  parent_certificate_pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
  validity               = "8760h"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)parent_private_key_pem`),
		},
		"parent key without parent cert": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem        = pki_private_key.k.private_key_pem
  parent_private_key_pem = pki_private_key.k.private_key_pem
  validity               = "8760h"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)parent_certificate_pem`),
		},
		// The distinctive fragment of the real ParseDuration error -- "want a
		// Go duration such as" is part of pki.ParseDuration's "invalid
		// duration" message and cannot be confused with the config text the
		// test sends (which contains "validity" and "forever" but never "Go
		// duration").
		"bad validity": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "forever"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)Go duration such as`),
		},
		// The distinctive fragment of the real ParseSerial error --
		// "hexadecimal string" is part of pki.ParseSerial's rejection of a
		// non-hex value and cannot be confused with the config text the test
		// sends (which has the attribute "serial_number" and the value
		// "not-hex" but never the phrase "hexadecimal string").
		"bad serial": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  serial_number   = "not-hex"
  subject { common_name = "ca" }
}`,
			expect: regexp.MustCompile(`(?s)hexadecimal string`),
		},
		"no subject and no san": {
			config: keyConfig + `
resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
}`,
			expect: regexp.MustCompile(`(?s)subject|san`),
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

// TestAccCertificateAuthorityRejectsEmptyKeyUsage closes the acceptance-level
// gap Task 6 deferred: nonEmptyBlockValidator (schema_common.go) refuses a
// present-but-empty `key_usage {}` or `extended_key_usage {}` block during a
// real plan, with a diagnostic carrying an attribute path. The unit tests cover
// the validator's Go method directly; this is the "does it fire during a real
// plan" check, and it lands here because pki_certificate_authority is the first
// resource carrying these blocks.
func TestAccCertificateAuthorityRejectsEmptyKeyUsage(t *testing.T) {
	const config = `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  subject { common_name = "ca" }

  key_usage {}
}
`
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      config,
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`(?s)Missing key usages`),
		}},
	})
}

// TestAccCertificateAuthorityRejectsEmptyExtendedKeyUsage is the same rule for
// the extended_key_usage block, mutation-proved alongside the key_usage case.
func TestAccCertificateAuthorityRejectsEmptyExtendedKeyUsage(t *testing.T) {
	const config = `
resource "pki_private_key" "k" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "ca" {
  private_key_pem = pki_private_key.k.private_key_pem
  validity        = "8760h"
  subject { common_name = "ca" }

  extended_key_usage {}
}
`
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      config,
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`(?s)Missing extended key usages`),
		}},
	})
}
