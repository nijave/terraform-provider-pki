// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"fmt"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

func TestAccPrivateKeyRSA(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "test" {
  algorithm = "RSA"
  rsa_bits  = 2048
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("algorithm"), knownvalue.StringExact("RSA")),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("rsa_bits"), knownvalue.Int64Exact(2048)),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("private_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN RSA PRIVATE KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("private_key_pem_pkcs8"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN PRIVATE KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("public_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN PUBLIC KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("public_key_openssh"),
					knownvalue.StringRegexp(regexp.MustCompile(`^ssh-rsa `))),
				statecheck.ExpectKnownValue("pki_private_key.test", tfjsonpath.New("public_key_fingerprint_sha256"),
					knownvalue.StringRegexp(regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`))),
				// private_key_pem must be marked sensitive or it lands in plan
				// output and CI logs.
				statecheck.ExpectSensitiveValue("pki_private_key.test", tfjsonpath.New("private_key_pem")),
				statecheck.ExpectSensitiveValue("pki_private_key.test", tfjsonpath.New("private_key_pem_pkcs8")),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				// A second plan after apply must be empty. Anything else means a
				// computed attribute is being recomputed, which for a key means
				// a replacement and a new key on every apply.
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccPrivateKeyDefaults(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
resource "pki_private_key" "rsa" {
  algorithm = "RSA"
}
resource "pki_private_key" "ecdsa" {
  algorithm = "ECDSA"
}
resource "pki_private_key" "ed25519" {
  algorithm = "ED25519"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("pki_private_key.rsa", tfjsonpath.New("rsa_bits"), knownvalue.Int64Exact(2048)),
				statecheck.ExpectKnownValue("pki_private_key.ecdsa", tfjsonpath.New("ecdsa_curve"), knownvalue.StringExact("P256")),
				statecheck.ExpectKnownValue("pki_private_key.ecdsa", tfjsonpath.New("private_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN EC PRIVATE KEY-----`))),
				// Ed25519 has no legacy encoding, so its native form is PKCS#8.
				statecheck.ExpectKnownValue("pki_private_key.ed25519", tfjsonpath.New("private_key_pem"),
					knownvalue.StringRegexp(regexp.MustCompile(`^-----BEGIN PRIVATE KEY-----`))),
				statecheck.ExpectKnownValue("pki_private_key.ed25519", tfjsonpath.New("public_key_openssh"),
					knownvalue.StringRegexp(regexp.MustCompile(`^ssh-ed25519 `))),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccPrivateKeyChangingAlgorithmReplaces confirms the RequiresReplace
// modifiers are wired: a key's algorithm cannot be changed in place.
func TestAccPrivateKeyChangingAlgorithmReplaces(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: `resource "pki_private_key" "test" { algorithm = "ECDSA" }`},
			{
				Config: `resource "pki_private_key" "test" { algorithm = "RSA" }`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_private_key.test", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}

func TestAccPrivateKeyRejectsInvalidConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		config string
		expect *regexp.Regexp
	}{
		"unknown algorithm": {
			config: `resource "pki_private_key" "test" { algorithm = "DSA" }`,
			// Framework OneOf validator text; "DSA" alone would also match the
			// config's own source line, so this pins the surrounding phrase the
			// validator actually emits.
			expect: regexp.MustCompile(`(?s)Attribute algorithm value must be one of`),
		},
		"rsa too small": {
			config: `resource "pki_private_key" "test" {
  algorithm = "RSA"
  rsa_bits  = 1024
}`,
			expect: regexp.MustCompile(`(?s)2048`),
		},
		"curve on rsa": {
			config: `resource "pki_private_key" "test" {
  algorithm   = "RSA"
  ecdsa_curve = "P256"
}`,
			// pki.GenerateKey's own rejection message, surfaced as an attribute
			// error on ecdsa_curve; the config text alone ("ecdsa_curve" or
			// "P256") would pass regardless of whether this code ran.
			//
			// The echoed source line between the summary and the detail is the
			// line the diagnostic's *path* selects, so requiring it in that
			// position asserts the path too: an error attached to `algorithm`
			// would echo `algorithm   = "RSA"` there instead.
			expect: regexp.MustCompile(`(?s)Unable to generate private key.*` +
				`ecdsa_curve = "P256".*ecdsa_curve is not valid for algorithm RSA`),
		},
		"bits on ed25519": {
			config: `resource "pki_private_key" "test" {
  algorithm = "ED25519"
  rsa_bits  = 2048
}`,
			// Likewise pki.GenerateKey's message, not the config's own tokens,
			// with the path asserted the same way.
			expect: regexp.MustCompile(`(?s)Unable to generate private key.*` +
				`rsa_bits  = 2048.*rsa_bits is not valid for algorithm ED25519`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      tc.config,
					ExpectError: tc.expect,
				}},
			})
		})
	}
}

// TestAccPrivateKeyImport is spec section 8's requirement at its simplest: every
// input attribute is reconstructed from the parsed key, so the plan after import
// is empty.
//
// hashicorp/local is used here only as a test-time external provider to write
// the generated key to disk so the import source is a real file. It is
// MPL-2.0, never linked into the provider binary, and so does not affect the
// licensing audit (spec section 13).
func TestAccPrivateKeyImport(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tls.key")

	// ProtoV6ProviderFactories is set per-step, not on the TestCase, because
	// terraform-plugin-testing rejects a TestCase that sets providers at both
	// levels: the first step also needs ExternalProviders for hashicorp/local.
	resource.Test(t, resource.TestCase{
		PreCheck:               func() { testAccPreCheck(t) },
		TerraformVersionChecks: testAccVersionChecks,
		Steps: []resource.TestStep{
			{
				// Generate a key and write it out, so the import source is a
				// real file rather than a fixture checked into the repository.
				Config: fmt.Sprintf(`
resource "pki_private_key" "origin" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}

resource "local_sensitive_file" "key" {
  filename        = %q
  content         = pki_private_key.origin.private_key_pem
  file_permission = "0600"
}
`, keyPath),
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ExternalProviders: map[string]resource.ExternalProvider{
					"local": {Source: "hashicorp/local"},
				},
			},
			{
				// Now import that file into a second resource address.
				Config: `resource "pki_private_key" "imported" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384"
}`,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				ResourceName:             "pki_private_key.imported",
				ImportState:              true,
				ImportStateId:            "file://" + keyPath,
				ImportStateVerify:        false, // there is no prior state to compare against
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected 1 imported instance, got %d", len(states))
					}
					attrs := states[0].Attributes
					if attrs["algorithm"] != "ECDSA" {
						return fmt.Errorf("algorithm = %q, want ECDSA", attrs["algorithm"])
					}
					if attrs["ecdsa_curve"] != "P384" {
						return fmt.Errorf("ecdsa_curve = %q, want P384; input attributes must be reconstructed from the key", attrs["ecdsa_curve"])
					}
					if attrs["private_key_pem"] == "" {
						return fmt.Errorf("private_key_pem is empty after import")
					}
					if attrs["public_key_fingerprint_sha256"] == "" {
						return fmt.Errorf("public_key_fingerprint_sha256 is empty after import")
					}
					return nil
				},
			},
		},
	})
}

func TestAccPrivateKeyImportRejectsBadID(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:        `resource "pki_private_key" "test" { algorithm = "ECDSA" }`,
			ResourceName:  "pki_private_key.test",
			ImportState:   true,
			ImportStateId: "/tmp/no-scheme.key",
			ExpectError:   regexp.MustCompile(`(?s)file://`),
		}},
	})
}
