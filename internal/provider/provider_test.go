// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	// Without this, terraform-plugin-testing pairs its default host
	// registry.terraform.io with the legacy "-" namespace it registers for
	// reattach, and OpenTofu refuses the combination with a message about
	// provider address parsing that says nothing about the real cause. Fail
	// here instead, where the message can name the fix.
	if os.Getenv("TF_ACC_PROVIDER_HOST") == "" {
		t.Fatal("TF_ACC_PROVIDER_HOST is not set. Run `make testacc`, which sets it to " +
			"registry.opentofu.org. Without it terraform-plugin-testing pairs its default " +
			"registry.terraform.io host with the legacy \"-\" namespace, and OpenTofu rejects " +
			"that pairing before the provider is ever reached.")
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

// TestEveryGoFileHasTheSPDXHeader guards the whole module, not just this
// package. internal/pki enforces the header for its own files (see that
// package's boundary_test.go), but every later task in this plan adds files
// under main.go, internal/provider, and tools/ -- directories that package's
// same-directory os.ReadDir check never sees. Without a repo-wide walk, the
// header requirement is a convention everywhere outside internal/pki, and
// conventions are exactly what slip.
func TestEveryGoFileHasTheSPDXHeader(t *testing.T) {
	t.Parallel()

	const root = "../.."
	const want = "// SPDX-License-Identifier: GPL-3.0-or-later"
	skipDirs := map[string]bool{
		".git":         true,
		".claude":      true,
		".superpowers": true,
	}

	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("reading %s: %v", path, err)
			return nil
		}
		checked++
		if !strings.HasPrefix(string(content), want) {
			t.Errorf("%s does not start with %q", path, want)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if checked == 0 {
		t.Fatal("no Go files were checked; the test is not doing what it claims")
	}
}
