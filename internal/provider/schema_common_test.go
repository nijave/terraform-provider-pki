// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

// The test-only probe resource pkiprobe_shared_blocks (and its
// sharedBlockProbeProvider) that previously lived here was deleted in Task 6:
// pki_cert_request is the first real resource to embed the shared subject, san,
// and extra_extension blocks, so the probe's reason for existing is gone for
// those. The acceptance tests that used the probe for key_usage,
// extended_key_usage, and name_constraints empty-block rejection are deferred to
// Tasks 8 and 9 — the certificate resources that embed those blocks — because
// pki_cert_request carries only CSR-relevant blocks (subject, san,
// extra_extension), and the nonEmptyBlockValidator lives on the certificate-
// extension blocks it does not have. The unit tests below continue to cover
// nonEmptyBlockValidator's Go-level behavior directly, without a probe.

// TestNameConstraintsListNamesMatchTheBlock pins the derivation the emptiness
// rule and its diagnostic both depend on. A ninth subtree list added to the model
// and the schema but somehow missing from the derived list would be exempt from
// the "at least one entry" rule, so a block constraining only that list would be
// rejected as empty; a name in the list that the schema does not have would make
// the rule consult an attribute that can never be set.
func TestNameConstraintsListNamesMatchTheBlock(t *testing.T) {
	t.Parallel()
	block := nameConstraintsBlock().(schema.SingleNestedBlock)

	inSchema := make(map[string]bool, len(block.Attributes))
	for name := range block.Attributes {
		if name == nameConstraintsCriticalFieldName {
			continue
		}
		inSchema[name] = true
	}

	derived := make(map[string]bool, len(nameConstraintsListNames))
	for _, name := range nameConstraintsListNames {
		if derived[name] {
			t.Errorf("%q appears twice in nameConstraintsListNames", name)
		}
		derived[name] = true
	}

	for name := range inSchema {
		if !derived[name] {
			t.Errorf("the name_constraints block has %q but nameConstraintsListNames does not, so a "+
				"block constraining only that list would be rejected as empty", name)
		}
	}
	for name := range derived {
		if !inSchema[name] {
			t.Errorf("nameConstraintsListNames has %q but the name_constraints block does not", name)
		}
	}
	if len(nameConstraintsListNames) != 8 {
		t.Errorf("nameConstraintsListNames has %d entries, want the eight RFC 5280 subtree lists: %v",
			len(nameConstraintsListNames), nameConstraintsListNames)
	}
	// The critical flag is not a subtree, so a block that sets nothing but
	// critical must still count as empty.
	if derived[nameConstraintsCriticalFieldName] {
		t.Errorf("nameConstraintsListNames includes %q, which would make `name_constraints { critical = true }` "+
			"count as a constrained block", nameConstraintsCriticalFieldName)
	}
}

// TestNonEmptyBlockValidatorAttachesAPath is the half of the emptiness rule that
// an acceptance test cannot see. Terraform renders a diagnostic's source range,
// never the attribute path itself, so the only place to assert the path is here,
// against the same entry point the framework calls.
func TestNonEmptyBlockValidatorAttachesAPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := map[string]struct {
		block     schema.Block
		value     any
		blockPath path.Path
		wantPath  path.Path
	}{
		"key_usage with no usages": {
			block:     keyUsageBlock(),
			value:     &keyUsageModel{Usages: types.ListNull(types.StringType), Critical: types.BoolValue(true)},
			blockPath: path.Root("key_usage"),
			wantPath:  path.Root("key_usage").AtName("usages"),
		},
		"key_usage with an empty usages list": {
			block:     keyUsageBlock(),
			value:     &keyUsageModel{Usages: types.ListValueMust(types.StringType, nil), Critical: types.BoolValue(true)},
			blockPath: path.Root("key_usage"),
			wantPath:  path.Root("key_usage").AtName("usages"),
		},
		"extended_key_usage with no usages": {
			block:     extendedKeyUsageBlock(),
			value:     &extKeyUsageModel{Usages: types.ListNull(types.StringType), Critical: types.BoolValue(false)},
			blockPath: path.Root("extended_key_usage"),
			wantPath:  path.Root("extended_key_usage").AtName("usages"),
		},
		"name_constraints with nothing in any list": {
			block:     nameConstraintsBlock(),
			value:     nullNameConstraintsModel(),
			blockPath: path.Root("name_constraints"),
			// The rule spans eight attributes and no single one of them is at
			// fault, so the block itself is the honest path.
			wantPath: path.Root("name_constraints"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			diags := validateBlockObject(ctx, t, tt.block, tt.value, tt.blockPath)
			if !diags.HasError() {
				t.Fatalf("the validator accepted a block with nothing set: %v", diags)
			}
			withPath, ok := diags.Errors()[0].(diag.DiagnosticWithPath)
			if !ok {
				t.Fatalf("the diagnostic is a %T, which carries no attribute path; the operator gets "+
					"a resource-level error with no line to look at", diags.Errors()[0])
			}
			if got := withPath.Path(); !got.Equal(tt.wantPath) {
				t.Errorf("the diagnostic is attached to %s, want %s", got, tt.wantPath)
			}
		})
	}
}

// TestNonEmptyBlockValidatorStaysQuiet covers the three ways the rule must not
// fire. The absent-block case is the important one: the framework descends into
// an absent single-nested block's nested attributes, so a rule expressed with
// listvalidator.IsRequired() would reject every configuration that simply leaves
// the optional block out.
func TestNonEmptyBlockValidatorStaysQuiet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := map[string]struct {
		block schema.Block
		value any
	}{
		"a usage is named": {
			block: keyUsageBlock(),
			value: &keyUsageModel{Usages: mustList(t, []string{"keyCertSign"}), Critical: types.BoolValue(true)},
		},
		"one subtree list has an entry": {
			block: nameConstraintsBlock(),
			value: nameConstraintsFromPKI(pki.NameConstraints{
				ExcludedIPRanges: []string{"10.0.0.0/8"},
				Critical:         true,
			}),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if diags := validateBlockObject(ctx, t, tt.block, tt.value, path.Root("probe")); diags.HasError() {
				t.Errorf("the validator reported %v", diags.Errors())
			}
		})
	}

	// An absent block arrives as a null object, and an unknown one as an unknown
	// object. Neither is the mistake this rule looks for, and the framework calls
	// the validator for both.
	for _, block := range []schema.Block{keyUsageBlock(), extendedKeyUsageBlock(), nameConstraintsBlock()} {
		attrTypes := block.Type().(types.ObjectType).AttrTypes
		for _, absent := range []types.Object{types.ObjectNull(attrTypes), types.ObjectUnknown(attrTypes)} {
			resp := &validator.ObjectResponse{}
			for _, v := range block.(schema.SingleNestedBlock).ObjectValidators() {
				v.ValidateObject(ctx, validator.ObjectRequest{Path: path.Root("probe"), ConfigValue: absent}, resp)
			}
			if resp.Diagnostics.HasError() {
				t.Errorf("validating %v reported %v", absent, resp.Diagnostics.Errors())
			}
		}
	}

	// An unknown list defers: it may resolve to a non-empty one, and rejecting it
	// now would fail a configuration that applies cleanly.
	unknownUsages := &keyUsageModel{Usages: types.ListUnknown(types.StringType), Critical: types.BoolValue(true)}
	if diags := validateBlockObject(ctx, t, keyUsageBlock(), unknownUsages, path.Root("key_usage")); diags.HasError() {
		t.Errorf("an unknown usages list was rejected at plan time: %v", diags.Errors())
	}
}

// nullNameConstraintsModel is a name_constraints block that sets nothing but its
// criticality flag: eight null lists, which is what `name_constraints {}` and
// `name_constraints { critical = true }` both arrive as.
func nullNameConstraintsModel() *nameConstraintsModel {
	null := types.ListNull(types.StringType)
	return &nameConstraintsModel{
		PermittedDNSDomains:   null,
		ExcludedDNSDomains:    null,
		PermittedEmailDomains: null,
		ExcludedEmailDomains:  null,
		PermittedIPRanges:     null,
		ExcludedIPRanges:      null,
		PermittedURIDomains:   null,
		ExcludedURIDomains:    null,
		Critical:              types.BoolValue(true),
	}
}

// validateBlockObject runs every object validator a block carries over a value
// of that block's type, the way the framework does.
func validateBlockObject(ctx context.Context, t *testing.T, block schema.Block, value any, at path.Path) diag.Diagnostics {
	t.Helper()
	single, ok := block.(schema.SingleNestedBlock)
	if !ok {
		t.Fatalf("block is a %T, not a SingleNestedBlock", block)
	}
	var obj types.Object
	if diags := tfsdk.ValueFrom(ctx, value, single.Type(), &obj); diags.HasError() {
		t.Fatalf("ValueFrom: %v", diags.Errors())
	}
	validators := single.ObjectValidators()
	if len(validators) == 0 {
		t.Fatal("the block carries no object validators, so the emptiness rule is not wired at all")
	}
	resp := &validator.ObjectResponse{}
	for _, v := range validators {
		v.ValidateObject(ctx, validator.ObjectRequest{Path: at, ConfigValue: obj}, resp)
	}
	return resp.Diagnostics
}
