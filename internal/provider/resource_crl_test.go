// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const testAccCRLConfig = testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
  early_regenerate   = "24h"

  revoked {
    serial_number = "2001"
    reason        = "keyCompromise"
    revoked_at    = "2026-06-01T00:00:00Z"
  }

  revoked {
    serial_number = "0x2002"
  }
}

output "crl_pem" { value = pki_crl.test.crl_pem }
output "ca_pem"  { value = pki_certificate_authority.root.certificate_pem }
`

// TestAccCRLSignatureVerifiesAndSerialIsPresent is spec section 10's CRL
// acceptance criterion.
func TestAccCRLSignatureVerifiesAndSerialIsPresent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCRLConfig,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("crl_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN X509 CRL-----`))),
				statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"),
					knownvalue.Int64Exact(1)),
				statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("ready_for_regeneration"),
					knownvalue.Bool(false)),
				// The configured spelling is preserved verbatim in state: the
				// framework's "planned value must match config" rule forbids
				// the provider from rewriting a configured value, the same
				// constraint the certificate resources document. The canonical
				// form lives on the CRL itself (observable through crl_pem).
				statecheck.ExpectKnownValue("pki_crl.test",
					tfjsonpath.New("revoked").AtSliceIndex(1).AtMapKey("serial_number"),
					knownvalue.StringExact("0x2002")),
				// revoked_at defaults to the time the entry first appeared and
				// is then held stable, so the CRL does not churn its timestamps.
				statecheck.ExpectKnownValue("pki_crl.test",
					tfjsonpath.New("revoked").AtSliceIndex(1).AtMapKey("revoked_at"),
					knownvalue.NotNull()),
			},
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				crlPEM := s.RootModule().Outputs["crl_pem"].Value.(string)
				caPEM := s.RootModule().Outputs["ca_pem"].Value.(string)

				crlBlock, _ := pem.Decode([]byte(crlPEM))
				if crlBlock == nil {
					return fmt.Errorf("crl_pem is not PEM")
				}
				crl, err := x509.ParseRevocationList(crlBlock.Bytes)
				if err != nil {
					return fmt.Errorf("parsing the CRL: %w", err)
				}
				caBlock, _ := pem.Decode([]byte(caPEM))
				ca, err := x509.ParseCertificate(caBlock.Bytes)
				if err != nil {
					return fmt.Errorf("parsing the CA: %w", err)
				}
				if err := crl.CheckSignatureFrom(ca); err != nil {
					return fmt.Errorf("the CRL signature does not verify against the CA: %w", err)
				}
				if len(crl.RevokedCertificateEntries) != 2 {
					return fmt.Errorf("the CRL has %d entries, want 2", len(crl.RevokedCertificateEntries))
				}
				want := big.NewInt(0x2001)
				if crl.RevokedCertificateEntries[0].SerialNumber.Cmp(want) != 0 {
					return fmt.Errorf("entry 0 serial = %s, want %s", crl.RevokedCertificateEntries[0].SerialNumber, want)
				}
				if crl.RevokedCertificateEntries[0].ReasonCode != 1 {
					return fmt.Errorf("entry 0 reason = %d, want 1 (keyCompromise)", crl.RevokedCertificateEntries[0].ReasonCode)
				}
				return nil
			}),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccCRLEmptyIsValid(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			// config.hcl ships revoked_serials = [] and the cluster still needs
			// a fresh, valid CRL for Envoy to load.
			Config: testAccCAConfig + `
resource "pki_crl" "empty" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_crl.empty", tfjsonpath.New("crl_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN X509 CRL-----`))),
				statecheck.ExpectKnownValue("pki_crl.empty", tfjsonpath.New("crl_base64"),
					knownvalue.NotNull()),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccCRLNumberIncrementsOnRegeneration covers the RFC 5280 requirement that
// each CRL carry a higher cRLNumber than the last.
func TestAccCRLNumberIncrementsOnRegeneration(t *testing.T) {
	base := func(extra string) string {
		return testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
` + extra + `
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: base(``),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"), knownvalue.Int64Exact(1)),
				},
			},
			{
				Config: base(`  revoked { serial_number = "2001" }`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"), knownvalue.Int64Exact(2)),
				},
			},
			{
				Config: base(`  revoked { serial_number = "2001" }
  revoked { serial_number = "2002" }`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("pki_crl.test", tfjsonpath.New("number"), knownvalue.Int64Exact(3)),
				},
			},
		},
	})
}

// TestAccCRLRevokedAtIsStable is the anti-churn property from spec section 6.5:
// an unchanged CRL must not rewrite its revocation timestamps on every
// regeneration, or the Kubernetes Secret changes on every apply.
func TestAccCRLRevokedAtIsStable(t *testing.T) {
	config := testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
  revoked { serial_number = "2001" }
}
`
	withSecond := testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
  revoked { serial_number = "2001" }
  revoked { serial_number = "2002" }
}
`
	var firstRevokedAt string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources["pki_crl.test"]
					if !ok {
						return fmt.Errorf("pki_crl.test not in state")
					}
					firstRevokedAt = rs.Primary.Attributes["revoked.0.revoked_at"]
					if firstRevokedAt == "" {
						return fmt.Errorf("revoked.0.revoked_at is empty")
					}
					return nil
				},
			},
			{
				// Adding a second entry regenerates the CRL. The first entry's
				// timestamp must be unchanged.
				Config: withSecond,
				Check: func(s *terraform.State) error {
					rs := s.RootModule().Resources["pki_crl.test"]
					if got := rs.Primary.Attributes["revoked.0.revoked_at"]; got != firstRevokedAt {
						return fmt.Errorf("revoked.0.revoked_at changed from %q to %q on regeneration", firstRevokedAt, got)
					}
					if rs.Primary.Attributes["revoked.1.revoked_at"] == "" {
						return fmt.Errorf("the new entry has no revoked_at")
					}
					return nil
				},
			},
		},
	})
}

// TestAccCRLReadyForRegeneration covers the staleness logic that replaces the
// pki-crl-refresh CronJob's role.
func TestAccCRLReadyForRegeneration(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "1h"
  early_regenerate   = "2h"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_crl.test",
					tfjsonpath.New("ready_for_regeneration"), knownvalue.Bool(true)),
			},
			// Inside the regeneration window, every plan proposes regeneration —
			// both the immediate post-apply plan and the post-apply-post-refresh
			// plan — mirroring TestAccCertificateReadyForRenewal. ExpectNonEmptyPlan
			// disables the implicit empty-plan idempotency check on the immediate
			// post-apply plan; PostApplyPostRefresh asserts the same for the
			// refresh-then-plan path that Read drives. The plan section's test
			// body omitted ExpectNonEmptyPlan, but the behavior the section
			// describes (drift visible to the operator) requires both plans to
			// surface the regeneration.
			ExpectNonEmptyPlan: true,
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectNonEmptyPlan()},
			},
		}},
	})
}

// TestAccCRLRejectsACAWithoutCRLSign is the migration hazard made visible.
// cfssl signed CRLs with any CA key; Go requires crlSign and a
// subjectKeyIdentifier on the issuer. The externally-owned Bitwarden CA cannot
// be inspected ahead of an apply, so the message must be actionable.
func TestAccCRLRejectsACAWithoutCRLSign(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate_authority" "no_crlsign" {
  private_key_pem = pki_private_key.ca.private_key_pem
  validity        = "8760h"
  subject { common_name = "no-crlsign" }
  key_usage { usages = ["keyCertSign"] }
}

resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.no_crlsign.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "168h"
}
`,
			// crlSign is the deliberately-absent key usage bit the provider's
			// CheckCRLSigner diagnostic names; the CA above omits it on purpose.
			ExpectError: regexp.MustCompile(`(?s)crlSign`),
		}},
	})
}

// TestAccCRLRejectsBadConfig is the plan-time and apply-time validation surface.
// Each ExpectError pattern is a distinctive fragment of the real error the
// provider (or a validator it wires up) emits, NOT a fragment of the test's
// own config text. The original plan had five vacuous patterns that matched
// their own config bodies and would have passed whether or not the provider
// ran; each is replaced with a phrase the config does not contain.
func TestAccCRLRejectsBadConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		body   string
		expect *regexp.Regexp
	}{
		// "value must be one of" is the distinctive fragment of the
		// stringvalidator.OneOf diagnostic the schema wires onto revoked.reason.
		// The config below contains "reason" and "becauseISaidSo" but never
		// that phrase, so matching it requires the validator to have fired.
		"unknown reason": {
			body: `next_update = "168h"
  revoked {
    serial_number = "2001"
    reason        = "becauseISaidSo"
  }`,
			expect: regexp.MustCompile(`(?s)value must be one of`),
		},
		// "hexadecimal string" is the distinctive fragment of pki.ParseSerial's
		// rejection of a non-hex value. Task 8 used the same fragment for the
		// same case. The config has the attribute name "serial_number" and the
		// value "not-hex" but never that phrase.
		"bad serial": {
			body:   `next_update = "168h"` + "\n" + `  revoked { serial_number = "not-hex" }`,
			expect: regexp.MustCompile(`(?s)hexadecimal string`),
		},
		// "Go duration such as" is the distinctive fragment of pki.ParseDuration's
		// rejection of an unparseable duration. Task 8 used the same fragment.
		// The config has the attribute name "next_update" and the value "soon"
		// but never that phrase.
		"bad next_update": {
			body:   `next_update = "soon"`,
			expect: regexp.MustCompile(`(?s)Go duration such as`),
		},
		// "cannot parse" is the distinctive fragment Go's time.Parse emits when
		// it rejects a non-RFC3339 string. The config has the attribute name
		// "revoked_at" and the value "yesterday" but never that phrase.
		"bad revoked_at": {
			body: `next_update = "168h"
  revoked {
    serial_number = "2001"
    revoked_at    = "yesterday"
  }`,
			expect: regexp.MustCompile(`(?s)cannot parse`),
		},
		// "already present in this CRL" is the distinctive fragment of the
		// duplicate-serial diagnostic the provider emits after normalizing
		// serials (so "2001" and "0x2001" collide). The config has the bare
		// digits "2001" but never that phrase.
		"duplicate serial": {
			body:   `next_update = "168h"` + "\n" + `  revoked { serial_number = "2001" }` + "\n" + `  revoked { serial_number = "0x2001" }`,
			expect: regexp.MustCompile(`(?s)already present in this CRL`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config: testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  ` + tc.body + `
}
`,
					ExpectError: tc.expect,
				}},
			})
		})
	}
}
