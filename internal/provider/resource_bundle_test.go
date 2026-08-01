// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// testAccBundleBase issues a leaf under a root, which every bundle test needs.
const testAccBundleBase = testAccCAConfig + `
resource "pki_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "pki_certificate" "leaf" {
  ca_certificate_pem = pki_certificate_authority.root.certificate_pem
  ca_private_key_pem = pki_private_key.ca.private_key_pem
  public_key_pem     = pki_private_key.leaf.public_key_pem
  serial_number      = "2001"
  validity           = "175320h"
  subject { common_name = "nick-ipad.ha.apps.somemissing.info" }
  san { dns_names = ["nick-ipad.ha.apps.somemissing.info"] }
  key_usage { usages = ["digitalSignature", "keyEncipherment"] }
  extended_key_usage { usages = ["clientAuth"] }
}
`

func TestAccBundlePEM(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "full" {
  format          = "pem"
  certificate_pem = pki_certificate.leaf.certificate_pem
  private_key_pem = pki_private_key.leaf.private_key_pem
  chain_pem       = [pki_certificate_authority.root.certificate_pem]
}

# Spec section 6.6: the optional fields are the switches. No private_key_pem
# yields a cert-only bundle; no chain_pem yields no chain.
resource "pki_bundle" "cert_only" {
  format          = "pem"
  certificate_pem = pki_certificate.leaf.certificate_pem
}

output "full_content" {
  value     = pki_bundle.full.content
  sensitive = true
}
output "cert_only_content" {
  value     = pki_bundle.cert_only.content
  sensitive = true
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// content is set for text formats.
				statecheck.ExpectKnownValue("pki_bundle.full", tfjsonpath.New("content"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue("pki_bundle.full", tfjsonpath.New("content_base64"), knownvalue.NotNull()),
				// A bundle carrying a private key must be sensitive in both
				// representations, or it lands in plan output and CI logs.
				statecheck.ExpectSensitiveValue("pki_bundle.full", tfjsonpath.New("content")),
				statecheck.ExpectSensitiveValue("pki_bundle.full", tfjsonpath.New("content_base64")),
			},
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				full := s.RootModule().Outputs["full_content"].Value.(string)
				certOnly := s.RootModule().Outputs["cert_only_content"].Value.(string)

				if n := strings.Count(full, "BEGIN CERTIFICATE"); n != 2 {
					return fmt.Errorf("the full bundle has %d certificates, want 2", n)
				}
				if !strings.Contains(full, "BEGIN RSA PRIVATE KEY") {
					return fmt.Errorf("the full bundle has no private key")
				}
				// Order: certificate, chain, then the key last.
				if strings.Index(full, "BEGIN RSA PRIVATE KEY") < strings.LastIndex(full, "BEGIN CERTIFICATE") {
					return fmt.Errorf("the private key appears before the last certificate; order must be certificate, chain, key")
				}
				if strings.Contains(certOnly, "PRIVATE KEY") {
					return fmt.Errorf("the cert-only bundle contains a private key")
				}
				if n := strings.Count(certOnly, "BEGIN CERTIFICATE"); n != 1 {
					return fmt.Errorf("the cert-only bundle has %d certificates, want 1", n)
				}
				return nil
			}),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

func TestAccBundleBinaryFormatsHaveNullContent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "der" {
  format          = "der"
  certificate_pem = pki_certificate.leaf.certificate_pem
}

resource "pki_bundle" "pkcs7" {
  format          = "pkcs7"
  certificate_pem = pki_certificate.leaf.certificate_pem
  chain_pem       = [pki_certificate_authority.root.certificate_pem]
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// Spec section 6.6: content is null for binary formats,
				// content_base64 is always set.
				statecheck.ExpectKnownValue("pki_bundle.der", tfjsonpath.New("content"), knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_bundle.der", tfjsonpath.New("content_base64"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue("pki_bundle.pkcs7", tfjsonpath.New("content"), knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_bundle.pkcs7", tfjsonpath.New("content_base64"), knownvalue.NotNull()),
			},
			ConfigPlanChecks: resource.ConfigPlanChecks{
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccBundlePKCS12WriteOnlyPassword is the write-only attribute in action:
// password_wo is always null in state, which is why password_wo_version exists.
func TestAccBundlePKCS12WriteOnlyPassword(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "p12" {
  format              = "pkcs12"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  chain_pem           = [pki_certificate_authority.root.certificate_pem]
  friendly_name       = "nick-ipad"
  password_wo         = "password"
  password_wo_version = 1
}

output "p12_base64" {
  value     = pki_bundle.p12.content_base64
  sensitive = true
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				// A write-only attribute is never persisted.
				statecheck.ExpectKnownValue("pki_bundle.p12", tfjsonpath.New("password_wo"), knownvalue.Null()),
				statecheck.ExpectKnownValue("pki_bundle.p12", tfjsonpath.New("content"), knownvalue.Null()),
				statecheck.ExpectSensitiveValue("pki_bundle.p12", tfjsonpath.New("content_base64")),
				// modern is the default (spec section 6.6).
				statecheck.ExpectKnownValue("pki_bundle.p12", tfjsonpath.New("pkcs12_encoding"),
					knownvalue.StringExact("modern")),
			},
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				encoded := s.RootModule().Outputs["p12_base64"].Value.(string)
				pfx, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return fmt.Errorf("content_base64 is not base64: %w", err)
				}
				key, cert, chain, err := pkcs12.DecodeChain(pfx, "password")
				if err != nil {
					return fmt.Errorf("the PKCS#12 bundle does not decode with the configured password: %w", err)
				}
				if key == nil || cert == nil {
					return fmt.Errorf("the bundle is missing its key or certificate")
				}
				if len(chain) != 1 {
					return fmt.Errorf("the bundle has %d CA certificates, want 1", len(chain))
				}
				return nil
			}),
			ConfigPlanChecks: resource.ConfigPlanChecks{
				// A write-only value is invisible to drift detection, so a
				// second plan must be empty even though the password is not in
				// state.
				PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
			},
		}},
	})
}

// TestAccBundlePasswordVersionForcesReEncryption is why password_wo_version
// exists: with the password absent from state, nothing else can signal that it
// changed.
func TestAccBundlePasswordVersionForcesReEncryption(t *testing.T) {
	base := func(password string, version int) string {
		return testAccBundleBase + fmt.Sprintf(`
resource "pki_bundle" "p12" {
  format              = "pkcs12"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  password_wo         = %q
  password_wo_version = %d
}
`, password, version)
	}
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: base("first-password", 1)},
			{
				// Changing only the password, with the version unchanged, is
				// invisible: this is the documented limitation, not a bug.
				Config: base("second-password", 1),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_bundle.p12", plancheck.ResourceActionNoop),
					},
				},
			},
			{
				// Bumping the version is what re-encrypts.
				Config: base("second-password", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("pki_bundle.p12", plancheck.ResourceActionUpdate),
					},
				},
			},
		},
	})
}

// TestAccBundlePKCS12Encodings covers the matrix from spec section 6.6. The
// algorithm-level assertions live in Plan 1's unit tests; here the concern is
// that the attribute is plumbed through and that all three values work.
func TestAccBundlePKCS12Encodings(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "modern" {
  format              = "pkcs12"
  pkcs12_encoding     = "modern"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  password_wo         = "password"
  password_wo_version = 1
}

# legacy is 3DES with a SHA-1 MAC: the only combination universally importable
# on iOS < 18 and Android < 14.
resource "pki_bundle" "legacy" {
  format              = "pkcs12"
  pkcs12_encoding     = "legacy"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  password_wo         = "password"
  password_wo_version = 1
}

# passwordless has no encryption and no MAC, and requires no password.
resource "pki_bundle" "truststore" {
  format          = "pkcs12"
  pkcs12_encoding = "passwordless"
  certificate_pem = pki_certificate_authority.root.certificate_pem
}

output "legacy_base64" {
  value     = pki_bundle.legacy.content_base64
  sensitive = true
}
output "truststore_base64" {
  value     = pki_bundle.truststore.content_base64
  sensitive = true
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				legacy, err := base64.StdEncoding.DecodeString(s.RootModule().Outputs["legacy_base64"].Value.(string))
				if err != nil {
					return err
				}
				if _, _, _, err := pkcs12.DecodeChain(legacy, "password"); err != nil {
					return fmt.Errorf("the legacy bundle does not decode: %w", err)
				}
				trust, err := base64.StdEncoding.DecodeString(s.RootModule().Outputs["truststore_base64"].Value.(string))
				if err != nil {
					return err
				}
				certs, err := pkcs12.DecodeTrustStore(trust, "")
				if err != nil {
					return fmt.Errorf("the passwordless truststore does not decode: %w", err)
				}
				if len(certs) != 1 {
					return fmt.Errorf("the truststore holds %d certificates, want 1", len(certs))
				}
				return nil
			}),
		}},
	})
}

func TestAccBundleJKS(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		TerraformVersionChecks:   testAccVersionChecks,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: testAccBundleBase + `
resource "pki_bundle" "jks" {
  format              = "jks"
  certificate_pem     = pki_certificate.leaf.certificate_pem
  private_key_pem     = pki_private_key.leaf.private_key_pem
  chain_pem           = [pki_certificate_authority.root.certificate_pem]
  friendly_name       = "nick-ipad"
  password_wo         = "changeit"
  password_wo_version = 1
}

output "jks_base64" {
  value     = pki_bundle.jks.content_base64
  sensitive = true
}
`,
			Check: resource.ComposeAggregateTestCheckFunc(func(s *terraform.State) error {
				raw, err := base64.StdEncoding.DecodeString(s.RootModule().Outputs["jks_base64"].Value.(string))
				if err != nil {
					return err
				}
				// The JKS magic bytes.
				if len(raw) < 4 || raw[0] != 0xfe || raw[1] != 0xed || raw[2] != 0xfe || raw[3] != 0xed {
					return fmt.Errorf("the output does not start with the JKS magic 0xfeedfeed")
				}
				return nil
			}),
		}},
	})
}

// TestAccBundleRejectsBadConfig covers the eight rejection cases from spec
// section 6.6. Five of the ExpectError patterns (overlay A) were replaced from
// the original plan because each matched its own config text: the patterns now
// anchor on a distinctive fragment of the real provider or framework error that
// cannot appear in the configuration. The remaining three are sound and match
// provider error text that the config does not contain.
//
// Each replacement is load-bearing: removing the provider-side check that
// produces the error causes the test to FAIL, either because no error is
// produced or because a different error (from internal/pki's fallback) does not
// match the regex. Mutation evidence is documented in task-12-report.md.
func TestAccBundleRejectsBadConfig(t *testing.T) {
	for label, tc := range map[string]struct {
		body   string
		expect *regexp.Regexp
	}{
		// Overlay A replacement #1: the original (?s)pkcs11|Invalid Attribute
		// Value matched the config text ("pkcs11") OR the framework summary.
		// "must be one of" is the OneOf validator's detail text, which does not
		// appear in the config. Mutation: remove the OneOf validator on format
		// → EncodeBundle fires with "set format to one of" (different phrase)
		// → the regex fails to match → test fails.
		"unknown format": {
			body:   `format = "pkcs11"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem`,
			expect: regexp.MustCompile(`must be one of`),
		},
		// Sound: all three content attributes are omitted from the body, so the
		// regex matches the AtLeastOneOf error (which names them), not the
		// config.
		"nothing to encode": {
			body:   `format = "pem"`,
			expect: regexp.MustCompile(`certificate_pem|private_key_pem|chain_pem`),
		},
		// Overlay A replacement #2: the original (?s)der|private key matched
		// the config. "is not supported by format" is the provider's
		// ValidateConfig text. Mutation: remove the der+key check → EncodeBundle
		// fires with "cannot carry a private key" (different phrase) → regex
		// fails → test fails.
		"der with a key": {
			body: `format = "der"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.leaf.private_key_pem`,
			expect: regexp.MustCompile(`is not supported by format`),
		},
		// Overlay A replacement #3: same as der, for pkcs7.
		"pkcs7 with a key": {
			body: `format = "pkcs7"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.leaf.private_key_pem`,
			expect: regexp.MustCompile(`is not supported by format`),
		},
		// Sound: password_wo is omitted, so the regex matches the provider's
		// "requires password_wo" error (the attribute name does not appear in
		// the config body).
		"pkcs12 without a password": {
			body: `format = "pkcs12"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.leaf.private_key_pem`,
			expect: regexp.MustCompile(`password_wo`),
		},
		// Overlay A replacement #4: the original (?s)passwordless matched the
		// config text ("passwordless"). "is not supported by pkcs12_encoding"
		// is the provider's ValidateConfig text. Mutation: remove the
		// passwordless+password check → EncodeBundle fires with "cannot carry a
		// password" (different phrase) → regex fails → test fails.
		"passwordless with a password": {
			body: `format = "pkcs12"` + "\n" + `  pkcs12_encoding = "passwordless"` + "\n" +
				`  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  password_wo = "password"` + "\n" + `  password_wo_version = 1`,
			expect: regexp.MustCompile(`is not supported by pkcs12_encoding`),
		},
		// Sound: "does not match" is the provider's mismatched-key error text,
		// which does not appear in the config.
		"mismatched key and certificate": {
			body: `format = "pkcs12"` + "\n" + `  certificate_pem = pki_certificate.leaf.certificate_pem` + "\n" +
				`  private_key_pem = pki_private_key.ca.private_key_pem` + "\n" +
				`  password_wo = "password"` + "\n" + `  password_wo_version = 1`,
			expect: regexp.MustCompile(`does not match`),
		},
		// Overlay A replacement #5: the original (?s)pkcs12_encoding|pkcs12
		// matched the config text. "only applies to" is the provider's
		// ValidateConfig text. Mutation: remove the pkcs12_encoding-on-non-pkcs12
		// check → the bundle encodes successfully as pem and NO error is
		// produced → ExpectError fails → test fails.
		"pkcs12_encoding on a non-pkcs12 format": {
			body: `format = "pem"` + "\n" + `  pkcs12_encoding = "legacy"` + "\n" +
				`  certificate_pem = pki_certificate.leaf.certificate_pem`,
			expect: regexp.MustCompile(`only applies to`),
		},
	} {
		t.Run(label, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				PreCheck:                 func() { testAccPreCheck(t) },
				TerraformVersionChecks:   testAccVersionChecks,
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      testAccBundleBase + "\nresource \"pki_bundle\" \"b\" {\n  " + tc.body + "\n}\n",
					ExpectError: tc.expect,
				}},
			})
		})
	}
}
