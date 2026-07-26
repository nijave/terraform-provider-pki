// SPDX-License-Identifier: GPL-3.0-or-later

package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
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
// The `data "pki_oids" "check" {}` line exercises the pki_oids schema Task 3
// adds; Task 1 deferred it because that data source did not exist yet.
func TestProviderSchema(t *testing.T) {
	t.Parallel()
	resource.Test(t, resource.TestCase{
		IsUnitTest:               true,
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: `
provider "pki" {}

data "pki_oids" "check" {}
`,
			PlanOnly: true,
		}},
	})
}

// TestUserFacingStringsUseEmDashes pins the house style split that a cosmetic
// review finding turned up: Go comments in this repository write a parenthetical
// break as `--`, but user-facing text renders it, so it has to be a real em dash
// there. `--` inside a MarkdownDescription reaches the registry documentation as
// two literal hyphens.
//
// Scanning string literals rather than the raw file text is what separates the
// two cases cleanly: a comment is not a literal, so the convention that applies
// to comments cannot trip this test. And every user-facing string this package
// produces -- MarkdownDescription, diagnostic summary, diagnostic detail -- is a
// literal in one of these files, so the one rule covers all of them.
//
// Scoped to internal/provider. internal/pki has two error-message literals with
// `--` in them and belongs to a different set of files.
func TestUserFacingStringsUseEmDashes(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing the package source: %v", err)
	}

	checked := 0
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					// A raw string literal that will not unquote is not
					// something this test can read; skip it rather than fail.
					return true
				}
				checked++
				if strings.Contains(value, " -- ") {
					t.Errorf("%s: string literal contains \" -- \"; user-facing text renders it "+
						"literally, so use an em dash (—) instead", fset.Position(lit.Pos()))
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no string literals were checked; the test is not doing what it claims")
	}
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
