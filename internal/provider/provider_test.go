// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/nijave/terraform-provider-pki/internal/provider"
)

// testAccProtoV6ProviderFactories serves the provider in-process over protocol
// 6. Every acceptance test uses this; there is no external provider to install
// and no registry lookup.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pki": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// testAccVersionChecks pins the floor for every acceptance test.
//
// 1.11 is required because pki_bundle's password_wo is a write-only attribute,
// and older versions error when one is set. OpenTofu 1.11 supports them; the
// check is expressed against the CLI version the harness drives, whichever
// binary TF_ACC_TERRAFORM_PATH points at.
var testAccVersionChecks = []tfversion.TerraformVersionCheck{
	tfversion.SkipBelow(tfversion.Version1_11_0),
}

// testAccPreCheck fails fast with an actionable message when the harness is
// misconfigured, rather than letting terraform-plugin-testing download a
// Terraform binary. There are no credentials to check: every resource in this
// provider is self-contained, which is also why Dependabot PRs get the full
// test matrix (spec section 12).
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC is not set; skipping the acceptance test")
	}
	path := os.Getenv("TF_ACC_TERRAFORM_PATH")
	if path == "" {
		t.Fatal("TF_ACC_TERRAFORM_PATH is not set. Run `make testacc`, which points it at the tofu binary. " +
			"Without it the harness falls back to downloading Terraform, which is not the tested platform.")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("TF_ACC_TERRAFORM_PATH=%q is not usable: %v", path, err)
	}
}

// TestProviderSchema is a unit test -- no TF_ACC required -- that catches a
// malformed schema at `go test` time instead of at `tofu plan` time. Every
// resource and data source added in a later task is validated by it
// automatically, because it walks whatever the provider registers.
//
// The config below is deliberately just the empty provider block. The design
// this test was drafted against also references `data "pki_oids" "check" {}`,
// but that data source does not exist until Task 3 adds it; Task 3's brief
// restores the reference. Until then, the bare provider block is already a
// valid plan-only step and exercises the same schema-validation path.
func TestProviderSchema(t *testing.T) {
	t.Parallel()
	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:   `provider "pki" {}`,
			PlanOnly: true,
		}},
	})
}
