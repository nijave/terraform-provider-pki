// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPackageImportsNoTerraform enforces the boundary spec section 3 draws:
// internal/pki is pure Go and imports zero Terraform packages, so every
// cryptographic decision is testable without a plugin harness and the framework
// layer stays a mechanical translation.
//
// This is a test rather than a convention because the pressure to violate it is
// real and arrives gradually -- one diag.Diagnostics here, one types.String
// there -- and each individual step looks harmless.
func TestPackageImportsNoTerraform(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	fset := token.NewFileSet()
	forbidden := []string{
		// The dash matters: it distinguishes the modern, split-out
		// terraform-plugin-* / terraform-* module families from the bare
		// github.com/hashicorp/terraform/... path, which is the legacy
		// pre-split in-tree SDK (e.g. github.com/hashicorp/terraform/helper/schema).
		// Both prefixes are required; do not collapse this to one entry.
		"github.com/hashicorp/terraform-",
		"github.com/hashicorp/terraform/",
		"github.com/opentofu/",
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parsing %s: %v", e.Name(), err)
			continue
		}
		checked++
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.HasPrefix(path, bad) {
					t.Errorf("%s imports %q; internal/pki must not depend on Terraform packages", e.Name(), path)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no Go files were checked; the test is not doing what it claims")
	}
}

// TestEveryFileHasTheSPDXHeader keeps the GPLv3 licensing consistent, which
// matters because a file without the header is ambiguously licensed.
func TestEveryFileHasTheSPDXHeader(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	const want = "// SPDX-License-Identifier: GPL-3.0-or-later"
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		content, err := os.ReadFile(e.Name())
		if err != nil {
			t.Errorf("reading %s: %v", e.Name(), err)
			continue
		}
		if !strings.HasPrefix(string(content), want) {
			t.Errorf("%s does not start with %q", e.Name(), want)
		}
	}
}
