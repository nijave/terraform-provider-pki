// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// TestAccCertificateRotatingCAKeyDoesNotReplace is spec section 10's
// acceptance criterion and the single most valuable test in this plan.
//
// The homelab CA key is delivered from a Bitwarden ExternalSecret. If a
// re-read of that Secret -- with identical key material presented as a
// different expression, or simply re-read at a different time -- caused a
// replacement, every 20-year certificate under it would be reissued and every
// phone and tablet would need a manual re-enrollment. ModifyPlan compares the
// desired cert to state and suppresses the plan when the content is unchanged.
func TestAccCertificateRotatingCAKeyDoesNotReplace(t *testing.T) {
	// The two configs differ only in how ca_private_key_pem is expressed:
	// once directly, once through a round trip that produces the identical
	// bytes by a different expression. Terraform sees a changed configuration
	// expression; the provider must see no content drift.
	const direct = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "175320h"
  subject { common_name = "stable.example" }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
}
`
	const indirect = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

locals {
  ca_key = join("", [pki_private_key.ca.private_key_pem])
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = local.ca_key
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "175320h"
  subject { common_name = "stable.example" }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
}
`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: direct},
			{
				Config: indirect,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateValidityStringRewriteDoesNotReplace covers the same
// principle for a duration: "175320h" and "7305d" are different strings, but
// 7305 * 24 == 175320 is the same window. Rewriting the expression must not
// reissue, because the desired NotAfter (stateNotBefore + validity) lands on
// the same instant.
func TestAccCertificateValidityStringRewriteDoesNotReplace(t *testing.T) {
	base := func(validity string) string {
		return testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "` + validity + `"
  subject { common_name = "stable.example" }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("175320h")},
			{
				Config: base("7305d"), // 7305 * 24 == 175320
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateSubjectFormRewriteDoesNotReplace is spec section 5.1's
// requirement, narrowed to what Terraform Core's plan-vs-config consistency
// check permits at the framework level. CompareCertificate compares encoded DN
// bytes (overlay A: trust the library; the provider adds no block-shape diff),
// so the cert's *content* is byte-identical across the two forms. But switching
// the configuration between the named-field form and the equivalent ordered
// `attribute` form changes the *shape* of the subject block, and Terraform Core
// rejects any provider rewrite of a non-Computed attribute or of a block list
// count to differ from config — so a literal Noop is unimplementable for a form
// switch without marking every named subject field Optional+Computed, which
// would in turn weaken the validator that enforces "named and ordered forms are
// mutually exclusive".
//
// What this test pins instead is the guarantee the comparison *does* provide:
// the resource is updated in place (reissued with the same encoded DN) rather
// than replaced. A replacement would re-draw the random serial and force a full
// re-enrollment; an in-place Update preserves the serial (see resolveSerial) so
// only the cert bytes that depend on NotBefore change. That is the meaningful
// distinction for a 20-year certificate on a phone.
func TestAccCertificateSubjectFormRewriteDoesNotReplace(t *testing.T) {
	const named = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "8760h"
  subject {
    common_name  = "cn.example"
    uid          = "nick"
    organization = "homelab"
  }
}
`
	const ordered = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "8760h"
  subject {
    attribute {
      oid   = provider::pki::oid("commonName")
      value = "cn.example"
    }
    attribute {
      oid   = provider::pki::oid("uid")
      value = "nick"
    }
    attribute {
      oid   = provider::pki::oid("organization")
      value = "homelab"
    }
  }
}
`
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: named},
			{
				Config: ordered,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						// Update (in-place reissue), NOT Replace. The encoded
						// DN is identical, so the cert content is preserved;
						// only NotBefore changes (and with it the cert bytes
						// that depend on NotBefore).
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

// TestAccCertificateGenuineDriftReissues is the other half: real content
// changes must produce a real update, and the certificate must actually change.
// On drift ModifyPlan leaves the plan in place and emits a warning (overlay E);
// the configured Update path then reissues the certificate in place.
func TestAccCertificateGenuineDriftReissues(t *testing.T) {
	base := func(cn string) string {
		return testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "8760h"
  subject { common_name = "` + cn + `" }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("before.example")},
			{
				Config: base("after.example"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate.leaf", plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

// TestAccCertificateAuthorityRotatingParentKeyDoesNotReplace extends the
// rotating-CA-key guarantee to an intermediate authority: re-reading the
// parent's key under a different expression must not reissue the intermediate,
// because reissuing an intermediate forces a re-enrollment of every leaf
// beneath it.
func TestAccCertificateAuthorityRotatingParentKeyDoesNotReplace(t *testing.T) {
	base := func(indirect bool) string {
		parentKey := "pki_private_key.ca.private_key_pem"
		locals := ""
		if indirect {
			locals = "\nlocals { parent_key = join(\"\", [pki_private_key.ca.private_key_pem]) }\n"
			parentKey = "local.parent_key"
		}
		return testAccCAConfig + locals + `
resource "pki_private_key" "intermediate" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate_authority" "intermediate" {
  private_key_pem        = pki_private_key.intermediate.private_key_pem
  parent_certificate_pem = pki_certificate_authority.root.certificate_pem
  parent_private_key_pem = ` + parentKey + `
  serial_number          = "3001"
  validity               = "87600h"
  subject { common_name = "homelab-intermediate" }
  key_usage { usages = ["keyCertSign", "crlSign"] }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base(false)},
			{
				Config: base(true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate_authority.intermediate", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateReadyForRenewal covers spec section 5.4 and overlay C:
// ready_for_renewal flips true once inside the early-renewal window, and
// ModifyPlan then leaves the plan in place so the certificate is reissued on
// apply -- the one case where a content-identical certificate still reissues,
// on purpose. early_renewal longer than validity puts the resource inside the
// window immediately, which is the only way to test this without waiting.
func TestAccCertificateReadyForRenewal(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  validity           = "1h"
  early_renewal      = "2h"
  subject { common_name = "renewing.example" }
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_certificate.leaf",
					tfjsonpath.New("ready_for_renewal"), knownvalue.Bool(true)),
			},
			// Inside the renewal window, every plan proposes reissuance — both
			// the immediate post-apply plan and the post-apply-post-refresh
			// plan — matching hashicorp/tls behavior. ExpectNonEmptyPlan: true
			// disables the implicit empty-plan idempotency check on the
			// immediate post-apply plan; PostApplyPostRefresh asserts the same
			// for the refresh-then-plan path that Read drives.
			ExpectNonEmptyPlan: true,
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectNonEmptyPlan()},
			},
		}},
	})
}

// TestAccCertificateAuthorityValidityRewriteDoesNotReplace is the CA analogue of
// TestAccCertificateValidityStringRewriteDoesNotReplace, and unlike
// TestAccCertificateAuthorityRotatingParentKeyDoesNotReplace it genuinely
// exercises the CA resource's ModifyPlan: the configured *value* of validity
// changes (175320h -> 7305d), so without the drift comparison Core would plan an
// Update and the CA would reissue (advancing NotBefore). The comparison must find
// no drift -- the window is identical -- and copyComputed must turn the plan into
// a Noop. This is the verification that the CA's buildDesired (state-sourced
// NotBefore, parent/self-signed handling) and copyComputed work end to end.
func TestAccCertificateAuthorityValidityRewriteDoesNotReplace(t *testing.T) {
	base := func(validity string) string {
		return `
resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "pki_certificate_authority" "root" {
  private_key_pem = pki_private_key.ca.private_key_pem
  validity        = "` + validity + `"
  serial_number   = "1001"
  subject { common_name = "homelab-root" }
  key_usage { usages = ["keyCertSign", "crlSign"] }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("175320h")},
			{
				Config: base("7305d"), // 7305 * 24 == 175320
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate_authority.root", plancheck.ResourceActionNoop),
					},
				},
			},
		},
	})
}

// TestAccCertificateAuthorityGenuineDriftReissues is the CA analogue of
// TestAccCertificateGenuineDriftReissues: a real content change (the subject CN)
// must plan an in-place Update, not a Noop and not a replace. It exercises the
// CA resource's full drift path -- buildDesired with a self-signed root
// (caCert nil), CompareCertificate detecting the subject change, the warning
// diagnostic, and Update reissuing -- which the no-drift CA tests do not reach.
func TestAccCertificateAuthorityGenuineDriftReissues(t *testing.T) {
	base := func(cn string) string {
		return `
resource "pki_private_key" "ca" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "pki_certificate_authority" "root" {
  private_key_pem = pki_private_key.ca.private_key_pem
  validity        = "87600h"
  serial_number   = "1001"
  subject { common_name = "` + cn + `" }
  key_usage { usages = ["keyCertSign", "crlSign"] }
}
`
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("before-root")},
			{
				Config: base("after-root"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_certificate_authority.root", plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

// TestAccCertificateAuthorityIntermediateReadyForRenewalApplies is the
// whole-branch-review regression for the shared forceReissuePlan omitting
// certificate_chain_pem. An intermediate CA (non-null chain) inside its
// early_renewal window must not just PLAN a reissue but APPLY it without an
// "inconsistent result after apply" error: on the config-unchanged early-renewal
// path Core carries every Computed attr forward from state, forceReissuePlan
// flips the cert-derived ones Unknown, and Update rebuilds the chain with a
// fresh notBefore -- so certificate_chain_pem MUST be marked Unknown too, or the
// applied chain differs from the (carried-forward) planned one. The existing
// TestAccCertificateReadyForRenewal masks this: it uses a leaf (null chain) and a
// single step that never applies the reissue.
func TestAccCertificateAuthorityIntermediateReadyForRenewalApplies(t *testing.T) {
	config := testAccCAConfig + `
resource "pki_private_key" "intermediate" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}
resource "pki_certificate_authority" "intermediate" {
  private_key_pem        = pki_private_key.intermediate.private_key_pem
  parent_certificate_pem = pki_certificate_authority.root.certificate_pem
  parent_private_key_pem = pki_private_key.ca.private_key_pem
  validity               = "1h"
  early_renewal          = "2h"
  serial_number          = "4001"
  subject { common_name = "homelab-intermediate" }
  key_usage { usages = ["keyCertSign", "crlSign"] }
}
`
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: config, ExpectNonEmptyPlan: true},
			// The second apply of the same config is what applies the reissue the
			// window forces. Without certificate_chain_pem marked Unknown, this
			// step fails with "Provider produced inconsistent result after apply".
			{Config: config, ExpectNonEmptyPlan: true},
		},
	})
}

// TestAccCRLIntermediateReadyForRegenerationApplies is the CRL analogue: a CRL in
// its regeneration window must apply the regeneration (not just plan it) without
// an inconsistent-result error. The window force block must mark
// ready_for_regeneration Unknown -- Read set it true on the entering refresh, but
// issue() recomputes it false from the new far-future next_update_time (the normal
// early_regenerate < next_update case), so a carried-forward true would mismatch
// the applied false. TestAccCRLReadyForRegeneration masks this with an inverted
// window (next_update < early_regenerate, so ready stays true) and a single step.
func TestAccCRLIntermediateReadyForRegenerationApplies(t *testing.T) {
	config := testAccCAConfig + `
resource "pki_crl" "test" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  next_update        = "1h"
  early_regenerate   = "2h"
  revoked { serial_number = "2001" }
}
`
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: config, ExpectNonEmptyPlan: true},
			{Config: config, ExpectNonEmptyPlan: true},
		},
	})
}
