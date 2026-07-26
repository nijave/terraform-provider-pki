// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"encoding/asn1"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

func TestSubjectModelNamedFieldsToPKI(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		CommonName:          types.StringValue("nick-ipad.ha.apps.somemissing.info"),
		UID:                 types.StringValue("nick"),
		GivenName:           types.StringValue("Nick"),
		Surname:             types.StringValue("Venenga"),
		Organization:        types.StringValue("homelab"),
		OrganizationalUnits: mustList(t, []string{"infra", "clients"}),
	}
	got, diags := m.toPKI(context.Background(), path.Root("subject"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	want := pki.NamedSubject{
		CommonName:          "nick-ipad.ha.apps.somemissing.info",
		UID:                 "nick",
		GivenName:           "Nick",
		Surname:             "Venenga",
		Organization:        "homelab",
		OrganizationalUnits: []string{"infra", "clients"},
	}.Expand()
	if !got.Equal(want) {
		t.Fatalf("toPKI produced %s, want %s", got.String(), want.String())
	}
}

// TestSubjectModelOrderedFormToPKI covers the form import always emits and the
// only form that can reproduce engine.py's DN (spec section 5.1).
func TestSubjectModelOrderedFormToPKI(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		Attributes: []attributeModel{
			{OID: types.StringValue("2.5.4.3"), Value: types.StringValue("cn")},
			{OID: types.StringValue("0.9.2342.19200300.100.1.1"), Value: types.StringValue("nick")},
			{OID: types.StringValue("2.16.840.1.113730.3.1.241"), Value: types.StringValue("Nick V")},
		},
	}
	got, diags := m.toPKI(context.Background(), path.Root("subject"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if len(got.Attributes) != 3 {
		t.Fatalf("produced %d attributes, want 3", len(got.Attributes))
	}
	if pki.FormatOID(got.Attributes[2].OID) != "2.16.840.1.113730.3.1.241" || got.Attributes[2].Value != "Nick V" {
		t.Fatalf("attribute 2 = %s/%q, want displayName/\"Nick V\"",
			pki.FormatOID(got.Attributes[2].OID), got.Attributes[2].Value)
	}
	// The ordered form must survive in declaration order, unsorted.
	if pki.FormatOID(got.Attributes[0].OID) != "2.5.4.3" {
		t.Errorf("attribute 0 = %s, want 2.5.4.3; declaration order must be preserved", pki.FormatOID(got.Attributes[0].OID))
	}
}

// TestSubjectModelRejectsMixingForms enforces the mutual exclusivity spec
// section 5.1 requires. The schema-level validator catches this at plan time
// too, but the converter must not silently pick one.
func TestSubjectModelRejectsMixingForms(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		CommonName: types.StringValue("cn"),
		Attributes: []attributeModel{
			{OID: types.StringValue("2.5.4.3"), Value: types.StringValue("cn")},
		},
	}
	_, diags := m.toPKI(context.Background(), path.Root("subject"))
	if !diags.HasError() {
		t.Fatal("toPKI accepted both named fields and the ordered form")
	}
}

func TestSubjectModelRejectsBadOID(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		Attributes: []attributeModel{{OID: types.StringValue("not-an-oid"), Value: types.StringValue("v")}},
	}
	_, diags := m.toPKI(context.Background(), path.Root("subject"))
	if !diags.HasError() {
		t.Fatal("toPKI accepted an unparseable OID")
	}
	// The diagnostic must point at the offending attribute, not at the block.
	if got := diags.Errors()[0].Summary(); got == "" {
		t.Error("the diagnostic has an empty summary")
	}
}

// TestSubjectFromPKIRoundTrip is what import fidelity rests on: state written
// from a parsed certificate must convert back to the identical DN.
func TestSubjectFromPKIRoundTrip(t *testing.T) {
	t.Parallel()
	original := pki.NamedSubject{
		CommonName:          "cn",
		UID:                 "uid",
		Organization:        "o",
		OrganizationalUnits: []string{"a", "b"},
	}.Expand()

	m := subjectFromPKI(original)
	if len(m.Attributes) != len(original.Attributes) {
		t.Fatalf("subjectFromPKI produced %d attributes, want %d", len(m.Attributes), len(original.Attributes))
	}
	// Import always emits the ordered form; the named fields must be null.
	if !m.CommonName.IsNull() {
		t.Error("subjectFromPKI populated common_name; import must emit only the ordered form")
	}
	back, diags := m.toPKI(context.Background(), path.Root("subject"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if !back.Equal(original) {
		t.Fatalf("round trip produced %s, want %s", back.String(), original.String())
	}
}

func TestSANModelToPKI(t *testing.T) {
	t.Parallel()
	m := &sanModel{
		DNSNames:       mustList(t, []string{"a.example"}),
		EmailAddresses: mustList(t, []string{"nick@venenga.com"}),
		IPAddresses:    mustList(t, []string{"10.0.0.5", "fd00::5"}),
		URIs:           mustList(t, []string{"spiffe://homelab/nick-ipad"}),
		Critical:       types.BoolValue(true),
	}
	got, diags := m.toPKI(context.Background(), path.Root("san"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if len(got.DNSNames) != 1 || len(got.EmailAddresses) != 1 || len(got.IPAddresses) != 2 || len(got.URIs) != 1 {
		t.Fatalf("toPKI produced %+v, want one of each type and two IPs", got)
	}
	if !got.Critical {
		t.Error("Critical was not carried through")
	}

	bad := &sanModel{IPAddresses: mustList(t, []string{"10.0.0.256"})}
	if _, diags := bad.toPKI(context.Background(), path.Root("san")); !diags.HasError() {
		t.Error("toPKI accepted an invalid IP address")
	}
}

func TestBasicConstraintsModelPathLenNullHandling(t *testing.T) {
	t.Parallel()
	// The pointer distinction from spec section 5.3 has to survive the
	// framework boundary: a null path_len is "no constraint", and 0 is a real
	// constraint. types.Int64 is the only type that can express both.
	unset := &basicConstraintsModel{CA: types.BoolValue(true), PathLen: types.Int64Null(), Critical: types.BoolValue(true)}
	got, diags := unset.toPKI(path.Root("basic_constraints"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if got.PathLen != nil {
		t.Errorf("a null path_len produced PathLen = %d, want nil", *got.PathLen)
	}

	zero := &basicConstraintsModel{CA: types.BoolValue(true), PathLen: types.Int64Value(0), Critical: types.BoolValue(true)}
	got, diags = zero.toPKI(path.Root("basic_constraints"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	if got.PathLen == nil || *got.PathLen != 0 {
		t.Errorf("path_len = 0 produced %v, want a pointer to 0", got.PathLen)
	}
}

// TestBasicConstraintsFromPKIPathLenNullHandling is the import half of the same
// distinction, and it is the half that matters most for adoption: a nil PathLen
// rendered as path_len = 0 would write "this CA may not issue further CA
// certificates" into the state of every imported CA that had no
// pathLenConstraint at all, and the next apply would reissue it that way.
func TestBasicConstraintsFromPKIPathLenNullHandling(t *testing.T) {
	t.Parallel()
	intPtr := func(n int) *int { return &n }

	unset := basicConstraintsFromPKI(pki.BasicConstraints{CA: true, Critical: true})
	if !unset.PathLen.IsNull() {
		t.Errorf("a nil PathLen produced path_len = %v, want null", unset.PathLen)
	}
	if !unset.CA.ValueBool() || !unset.Critical.ValueBool() {
		t.Errorf("ca/critical came back %v/%v, want true/true", unset.CA, unset.Critical)
	}

	for _, want := range []int64{0, 3} {
		got := basicConstraintsFromPKI(pki.BasicConstraints{CA: true, PathLen: intPtr(int(want)), Critical: true})
		if got.PathLen.IsNull() {
			t.Errorf("PathLen %d produced a null path_len, want %d", want, want)
			continue
		}
		if got.PathLen.ValueInt64() != want {
			t.Errorf("PathLen %d produced path_len = %d", want, got.PathLen.ValueInt64())
		}
	}

	// Round trip both directions, because each alone can be wrong in a way the
	// other hides: absent, the boundary value 0, and an ordinary value.
	for _, original := range []pki.BasicConstraints{
		{CA: true, Critical: true},
		{CA: true, PathLen: intPtr(0), Critical: true},
		{CA: true, PathLen: intPtr(3), Critical: true},
	} {
		back, diags := basicConstraintsFromPKI(original).toPKI(path.Root("basic_constraints"))
		if diags.HasError() {
			t.Fatalf("toPKI: %v", diags.Errors())
		}
		switch {
		case original.PathLen == nil && back.PathLen != nil:
			t.Errorf("round trip turned an absent PathLen into %d", *back.PathLen)
		case original.PathLen != nil && back.PathLen == nil:
			t.Errorf("round trip turned PathLen %d into absent", *original.PathLen)
		case original.PathLen != nil && *original.PathLen != *back.PathLen:
			t.Errorf("round trip turned PathLen %d into %d", *original.PathLen, *back.PathLen)
		}
		if back.CA != original.CA || back.Critical != original.Critical {
			t.Errorf("round trip produced ca=%t critical=%t, want ca=%t critical=%t",
				back.CA, back.Critical, original.CA, original.Critical)
		}
	}
}

// TestSubjectFieldListsCoverTheWholeModel pins the claim the derivation makes:
// that no subject field can be present in the model and the schema yet missing
// from the named-form list. Adding a field to subjectModel and subjectBlock but
// not to namedSubjectFieldNames would make it accepted alongside an `attribute`
// block and then silently dropped, since the ordered branch is what runs.
func TestSubjectFieldListsCoverTheWholeModel(t *testing.T) {
	t.Parallel()
	block := subjectBlock().(schema.SingleNestedBlock)

	inSchema := make(map[string]bool, len(block.Attributes)+len(block.Blocks))
	for name := range block.Attributes {
		inSchema[name] = true
	}
	for name := range block.Blocks {
		inSchema[name] = true
	}

	covered := map[string]bool{orderedSubjectFieldName: true}
	for _, name := range namedSubjectFieldNames {
		if covered[name] {
			t.Errorf("%q appears twice in namedSubjectFieldNames", name)
		}
		covered[name] = true
	}

	for name := range inSchema {
		if !covered[name] {
			t.Errorf("subject schema has %q but namedSubjectFieldNames does not, so a config "+
				"setting it alongside an `attribute` block would be accepted and then dropped", name)
		}
	}
	for name := range covered {
		if !inSchema[name] {
			t.Errorf("namedSubjectFieldNames has %q but the subject schema does not", name)
		}
	}
	if _, ok := subjectFieldIndex[orderedSubjectFieldName]; !ok {
		t.Errorf("subjectFieldIndex is missing %q", orderedSubjectFieldName)
	}
}

// TestSubjectModelFieldsAreAllRecognizedKinds closes fieldIsSet's default
// branch. A field of some third kind would report "not set" forever, which is
// the same silent drop the derivation exists to prevent.
func TestSubjectModelFieldsAreAllRecognizedKinds(t *testing.T) {
	t.Parallel()
	attrValue := reflect.TypeOf((*attr.Value)(nil)).Elem()
	blockSlice := reflect.TypeOf([]attributeModel(nil))

	st := reflect.TypeOf(subjectModel{})
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		if f.Tag.Get("tfsdk") == "" {
			t.Errorf("field %s has no tfsdk tag, so the derivation cannot see it", f.Name)
			continue
		}
		if f.Type.Implements(attrValue) || f.Type == blockSlice {
			continue
		}
		t.Errorf("field %s is a %s, which fieldIsSet does not recognize; it would always "+
			"report unset", f.Name, f.Type)
	}
}

func TestParseDurationAttr(t *testing.T) {
	t.Parallel()
	got, diags := parseDurationAttr(types.StringValue("175320h"), path.Root("validity"))
	if diags.HasError() {
		t.Fatalf("parseDurationAttr: %v", diags.Errors())
	}
	if got.Hours() != 175320 {
		t.Errorf("parsed %v, want 175320h", got)
	}
	if _, diags := parseDurationAttr(types.StringValue("forever"), path.Root("validity")); !diags.HasError() {
		t.Error("parseDurationAttr accepted garbage")
	}
	// A null duration is not an error here; the caller decides whether the
	// attribute is required.
	if _, diags := parseDurationAttr(types.StringNull(), path.Root("early_renewal")); diags.HasError() {
		t.Errorf("parseDurationAttr rejected a null value: %v", diags.Errors())
	}
}

// TestSubjectFromPKIPreservesStringType covers the half of import fidelity the
// round-trip case above cannot reach: its DN is entirely UTF8String, so a
// subjectFromPKI that dropped string_type outright would still pass it. The
// certificates being adopted were produced by openssl with
// string_mask = utf8only, but a DN from any other producer may carry a
// PrintableString, and Go's asn1.Marshal would re-encode the same value as
// PrintableString or UTF8String depending only on its content.
func TestSubjectFromPKIPreservesStringType(t *testing.T) {
	t.Parallel()
	original := pki.Subject{Attributes: []pki.Attribute{
		{OID: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "cn", StringType: pki.StringTypePrintable},
		{OID: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "o", StringType: pki.StringTypeUTF8},
	}}

	m := subjectFromPKI(original)
	if got := m.Attributes[0].StringType.ValueString(); got != "printable" {
		t.Errorf("attribute 0 string_type = %q, want \"printable\"", got)
	}
	// utf8 is the default, so it must not be written out: emitting it would
	// make a hand-written config and imported state differ cosmetically.
	if !m.Attributes[1].StringType.IsNull() {
		t.Errorf("attribute 1 string_type = %v, want null for the utf8 default", m.Attributes[1].StringType)
	}

	back, diags := m.toPKI(context.Background(), path.Root("subject"))
	if diags.HasError() {
		t.Fatalf("toPKI: %v", diags.Errors())
	}
	// Equal compares encoded DER, so a lost string type changes the ASN.1 tag
	// and fails here.
	if !back.Equal(original) {
		t.Fatalf("round trip produced %s, want %s", back.String(), original.String())
	}
}

// TestSubjectModelRejectsUnknownStringType pins the error path of the
// string_type mapping, which is the only place an unrecognized encoding can be
// caught before EncodeDER.
func TestSubjectModelRejectsUnknownStringType(t *testing.T) {
	t.Parallel()
	m := &subjectModel{
		Attributes: []attributeModel{{
			OID:        types.StringValue("2.5.4.3"),
			Value:      types.StringValue("cn"),
			StringType: types.StringValue("utf16"),
		}},
	}
	_, diags := m.toPKI(context.Background(), path.Root("subject"))
	if !diags.HasError() {
		t.Fatal("toPKI accepted an unknown string_type")
	}
}

// TestExtraExtensionOIDStructuralRules pins the behavioural claim
// extra_extension.oid's MarkdownDescription makes. The rules themselves live in
// internal/pki -- first arc 0, 1 or 2; second arc under 40 when the first is 0
// or 1; no ceiling at all under arc 2, so the example arc 2.999.x stays legal --
// and nothing in this package would notice them loosening, leaving a description
// that promises validation the provider no longer performs.
//
// The two stages are asserted separately because they fail in different places:
// toPKI's ParseOID accepts anything with two or more numeric arcs, and the
// structural refusal happens when the extension is encoded.
func TestExtraExtensionOIDStructuralRules(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		oid            string
		wantConvertErr bool
		wantEncodeErr  bool
	}{
		{oid: "1.3.6.1.5.5.7.1.24"},
		// The arc reserved for examples, which an operator testing an
		// extra_extension block is likely to reach for.
		{oid: "2.999.1"},
		{oid: "0.39"},
		{oid: "5.99", wantEncodeErr: true},
		{oid: "1.40", wantEncodeErr: true},
		{oid: "0.40", wantEncodeErr: true},
		// A single arc never gets as far as the structural rules.
		{oid: "2", wantConvertErr: true},
	} {
		t.Run(tt.oid, func(t *testing.T) {
			t.Parallel()
			m := &extraExtensionModel{
				OID:         types.StringValue(tt.oid),
				ValueBase64: types.StringValue("MAMCAQU="),
				Critical:    types.BoolValue(false),
			}
			ext, diags := m.toPKI(path.Root("extra_extension").AtListIndex(0))
			if got := diags.HasError(); got != tt.wantConvertErr {
				t.Fatalf("toPKI HasError = %t, want %t (diagnostics: %v)", got, tt.wantConvertErr, diags)
			}
			if tt.wantConvertErr {
				return
			}
			if _, err := ext.Extension(); (err != nil) != tt.wantEncodeErr {
				t.Fatalf("Extension() error = %v, want an error: %t", err, tt.wantEncodeErr)
			}
		})
	}
}

// TestSubjectFormsInUse pins the predicate the schema-level validator and the
// converter share. It is a table rather than a validator test because building
// the whole subject types.Object would prove only that the test and the schema
// agree on attribute types.
func TestSubjectFormsInUse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		attrs       map[string]attr.Value
		wantNamed   bool
		wantOrdered bool
	}{
		{
			name: "named only",
			attrs: map[string]attr.Value{
				"common_name":     types.StringValue("cn"),
				"attribute":       types.ListValueMust(subjectAttributeObjectType(), nil),
				"extra_attribute": types.ListValueMust(subjectAttributeObjectType(), nil),
			},
			wantNamed: true,
		},
		{
			// An absent block collection arrives as null, so this case uses an
			// empty list only as the stricter input: isSet must report "not in
			// use" for either shape.
			name: "ordered only",
			attrs: map[string]attr.Value{
				"common_name": types.StringNull(),
				"attribute": types.ListValueMust(subjectAttributeObjectType(), []attr.Value{
					types.ObjectValueMust(subjectAttributeObjectType().AttrTypes, map[string]attr.Value{
						"oid":         types.StringValue("2.5.4.3"),
						"value":       types.StringValue("cn"),
						"string_type": types.StringNull(),
					}),
				}),
				"extra_attribute": types.ListValueMust(subjectAttributeObjectType(), nil),
			},
			wantOrdered: true,
		},
		{
			name: "extra_attribute counts as the named form",
			attrs: map[string]attr.Value{
				"common_name": types.StringNull(),
				"attribute":   types.ListValueMust(subjectAttributeObjectType(), nil),
				"extra_attribute": types.ListValueMust(subjectAttributeObjectType(), []attr.Value{
					types.ObjectValueMust(subjectAttributeObjectType().AttrTypes, map[string]attr.Value{
						"oid":         types.StringValue("2.16.840.1.113730.3.1.241"),
						"value":       types.StringValue("Nick V"),
						"string_type": types.StringNull(),
					}),
				}),
			},
			wantNamed: true,
		},
		{
			name: "a list-valued named field counts",
			attrs: map[string]attr.Value{
				"organizational_units": types.ListValueMust(types.StringType, []attr.Value{types.StringValue("infra")}),
				"attribute":            types.ListValueMust(subjectAttributeObjectType(), nil),
				"extra_attribute":      types.ListValueMust(subjectAttributeObjectType(), nil),
			},
			wantNamed: true,
		},
		{
			// `organizational_units = []` written explicitly: a known,
			// zero-element list. Measured against OpenTofu 1.12, this is the
			// only way a zero-element collection reaches the provider.
			name: "an empty named list does not count",
			attrs: map[string]attr.Value{
				"organizational_units": types.ListValueMust(types.StringType, nil),
				"attribute":            types.ListValueMust(subjectAttributeObjectType(), nil),
				"extra_attribute":      types.ListValueMust(subjectAttributeObjectType(), nil),
			},
		},
		{
			name: "an unknown named field counts, because config declared it",
			attrs: map[string]attr.Value{
				"common_name":     types.StringUnknown(),
				"attribute":       types.ListValueMust(subjectAttributeObjectType(), nil),
				"extra_attribute": types.ListValueMust(subjectAttributeObjectType(), nil),
			},
			wantNamed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			named, ordered := subjectFormsInUse(tt.attrs)
			if named != tt.wantNamed || ordered != tt.wantOrdered {
				t.Errorf("subjectFormsInUse = (named %t, ordered %t), want (named %t, ordered %t)",
					named, ordered, tt.wantNamed, tt.wantOrdered)
			}
		})
	}
}

// allCommonBlocks names every shared block against its constructor, so a block
// added to schema_common.go without being added here is the only way to escape
// the two schema tests below.
func allCommonBlocks() map[string]schema.Block {
	return map[string]schema.Block{
		"subject":                subjectBlock(),
		"san":                    sanBlock(),
		"basic_constraints_ca":   basicConstraintsBlock(true),
		"basic_constraints_leaf": basicConstraintsBlock(false),
		"key_usage":              keyUsageBlock(),
		"extended_key_usage":     extendedKeyUsageBlock(),
		"name_constraints":       nameConstraintsBlock(),
		"extra_extension":        extraExtensionBlock(),
	}
}

// TestSubjectSANAndExtensionSchemaBlocksValidate runs the framework's own
// schema implementation checks over every shared block. Without it the blocks
// have no test at all until a resource embeds one, and the failure mode is a
// provider that will not start: booldefault.StaticBool on an attribute that is
// Optional but not Computed, for instance, is rejected here and nowhere else.
func TestSubjectSANAndExtensionSchemaBlocksValidate(t *testing.T) {
	t.Parallel()
	s := schema.Schema{Blocks: allCommonBlocks()}
	if diags := s.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("ValidateImplementation: %v", diags.Errors())
	}
}

// TestSubjectAndExtensionModelsMatchTheirSchemaBlocks converts each model
// through its block's attr.Type using the same reflection resp.State.Set uses.
// A tfsdk tag that does not name a real schema attribute, or a schema attribute
// no model field names, fails here -- which is the one mistake in this task
// that would break all eleven resource and data source tasks at once rather
// than showing up in a converter test.
func TestSubjectAndExtensionModelsMatchTheirSchemaBlocks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	blocks := allCommonBlocks()
	models := map[string]any{
		"subject":                subjectFromPKI(pki.NamedSubject{CommonName: "cn"}.Expand()),
		"san":                    sanFromPKI(pki.SAN{DNSNames: []string{"a.example"}, Critical: true}),
		"basic_constraints_ca":   basicConstraintsFromPKI(pki.BasicConstraints{CA: true, Critical: true}),
		"basic_constraints_leaf": basicConstraintsFromPKI(pki.BasicConstraints{CA: false, Critical: true}),
		"key_usage":              keyUsageFromPKI(pki.KeyUsage{Usages: []string{"keyCertSign"}, Critical: true}),
		"extended_key_usage":     extKeyUsageFromPKI(pki.ExtKeyUsage{Usages: []string{"clientAuth"}}),
		"name_constraints":       nameConstraintsFromPKI(pki.NameConstraints{PermittedDNSDomains: []string{".example"}, Critical: true}),
		"extra_extension": []extraExtensionModel{extraExtensionFromPKI(pki.ExtraExtension{
			OID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05},
		})},
	}

	if len(models) != len(blocks) {
		t.Fatalf("%d models for %d blocks; every block needs one", len(models), len(blocks))
	}

	for name, block := range blocks {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			model, ok := models[name]
			if !ok {
				t.Fatalf("no model for block %q", name)
			}
			var got attr.Value
			switch block.Type().(type) {
			case types.ListType:
				got = types.List{}
			default:
				got = types.Object{}
			}
			target := reflect.New(reflect.TypeOf(got))
			if diags := tfsdk.ValueFrom(ctx, model, block.Type(), target.Interface()); diags.HasError() {
				t.Fatalf("ValueFrom(%T -> %s): %v", model, block.Type(), diags.Errors())
			}
			if v := target.Elem().Interface().(attr.Value); v.IsNull() || v.IsUnknown() {
				t.Errorf("converted to %v, want a known value", v)
			}
		})
	}
}

// TestSubjectFormsValidatorRejectsAMixedBlock exercises the schema-level
// validator through the same entry point the framework calls, over an object
// built from the real subject block's type. Without it the validator's glue --
// the null and unknown early returns and the diagnostic itself -- has no test
// until a resource embeds the block in Task 5.
func TestSubjectFormsValidatorRejectsAMixedBlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	block := subjectBlock().(schema.SingleNestedBlock)
	objType := block.Type()

	// The block must actually carry the validator. Everything below would pass
	// just as happily with the Validators field deleted from subjectBlock,
	// leaving mixed configuration to be caught only at apply time.
	validators := block.ObjectValidators()
	if len(validators) != 1 {
		t.Fatalf("subject block has %d object validators, want exactly the mutual-exclusivity one", len(validators))
	}
	if _, ok := validators[0].(subjectFormsValidator); !ok {
		t.Fatalf("subject block's validator is %T, want subjectFormsValidator", validators[0])
	}

	// Start from subjectFromPKI so every list field carries its element type,
	// which a zero-valued subjectModel would not.
	mixed := subjectFromPKI(pki.Subject{Attributes: []pki.Attribute{
		{OID: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "cn"},
	}})
	mixed.CommonName = types.StringValue("cn")

	orderedOnly := subjectFromPKI(pki.Subject{Attributes: []pki.Attribute{
		{OID: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "cn"},
	}})

	tests := []struct {
		name      string
		value     any
		wantError bool
	}{
		{name: "both forms", value: mixed, wantError: true},
		{name: "ordered form alone", value: orderedOnly},
		{name: "empty subject", value: subjectFromPKI(pki.Subject{})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var obj types.Object
			if diags := tfsdk.ValueFrom(ctx, tt.value, objType, &obj); diags.HasError() {
				t.Fatalf("ValueFrom: %v", diags.Errors())
			}
			resp := &validator.ObjectResponse{}
			subjectFormsValidator{}.ValidateObject(ctx,
				validator.ObjectRequest{Path: path.Root("subject"), ConfigValue: obj}, resp)
			if got := resp.Diagnostics.HasError(); got != tt.wantError {
				t.Fatalf("HasError = %t, want %t (diagnostics: %v)", got, tt.wantError, resp.Diagnostics)
			}
		})
	}

	// A block the configuration omits arrives as a null object, and validating
	// it must not report the absence as a conflict. This holds by two
	// independent routes -- the explicit early return, and types.Object
	// returning a nil attribute map when null or unknown -- so it documents the
	// contract rather than guarding a single line.
	for _, absent := range []types.Object{types.ObjectNull(objType.(types.ObjectType).AttrTypes), types.ObjectUnknown(objType.(types.ObjectType).AttrTypes)} {
		resp := &validator.ObjectResponse{}
		subjectFormsValidator{}.ValidateObject(ctx,
			validator.ObjectRequest{Path: path.Root("subject"), ConfigValue: absent}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("validating %v reported %v", absent, resp.Diagnostics.Errors())
		}
	}
}

// mustList builds a types.List of strings or fails the test.
func mustList(t *testing.T, values []string) types.List {
	t.Helper()
	elems := make([]attr.Value, 0, len(values))
	for _, v := range values {
		elems = append(elems, types.StringValue(v))
	}
	list, diags := types.ListValue(types.StringType, elems)
	if diags.HasError() {
		t.Fatalf("types.ListValue: %v", diags.Errors())
	}
	return list
}
