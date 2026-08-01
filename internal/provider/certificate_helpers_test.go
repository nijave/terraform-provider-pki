// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

// TestSubjectListValueAndExtensionListValue cover the two helpers the
// pki_certificate data source and Tasks 8/9 ImportState both depend on. The
// certificate data source's acceptance coverage of subject/issuer/extensions
// values is deferred to Tasks 8 and 9 (the resources it asserts through do not
// exist yet), so these helpers would otherwise go untested between this task
// and then -- including the empty case, which must serialize as null (not [])
// to match the resource import path. That drift is what the refactor that
// introduced these tests closed.
func TestSubjectListValueAndExtensionListValue(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// A non-empty subject: two attributes, the first with an explicit string
	// type and the second relying on the UTF8 default a zero StringType means.
	subject := pki.Subject{Attributes: []pki.Attribute{
		{OID: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "homelab-root", StringType: pki.StringTypeUTF8},
		{OID: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "homelab"}, // zero StringType -> utf8
	}}

	t.Run("non-empty subject yields the ordered attributes", func(t *testing.T) {
		t.Parallel()
		list, diags := subjectListValue(ctx, subject)
		if diags.HasError() {
			t.Fatalf("subjectListValue returned diagnostics: %v", diags)
		}
		if list.IsNull() {
			t.Fatal("subjectListValue returned a null list for a non-empty subject")
		}
		elems := list.Elements()
		if len(elems) != 2 {
			t.Fatalf("subject list has %d elements, want 2", len(elems))
		}
		first := elems[0].(types.Object).Attributes()
		if got := first["oid"].(types.String).ValueString(); got != "2.5.4.3" {
			t.Errorf("first subject oid = %q, want 2.5.4.3 (commonName)", got)
		}
		if got := first["value"].(types.String).ValueString(); got != "homelab-root" {
			t.Errorf("first subject value = %q, want homelab-root", got)
		}
		if got := first["string_type"].(types.String).ValueString(); got != "utf8" {
			t.Errorf("first subject string_type = %q, want utf8", got)
		}
		// The second attribute had a zero StringType, which the helper must
		// default to utf8 -- the whole point of populating string_type at all.
		second := elems[1].(types.Object).Attributes()
		if got := second["string_type"].(types.String).ValueString(); got != "utf8" {
			t.Errorf("second subject string_type = %q, want utf8 (the zero-Type default)", got)
		}
	})

	t.Run("empty subject yields null, not an empty list", func(t *testing.T) {
		t.Parallel()
		list, diags := subjectListValue(ctx, pki.Subject{})
		if diags.HasError() {
			t.Fatalf("subjectListValue(empty) returned diagnostics: %v", diags)
		}
		// null, not []: a certificate whose subject decodes to nothing must
		// produce the same state shape from this helper that the resource
		// import path will. An empty list here would drift from null.
		if !list.IsNull() {
			t.Errorf("subjectListValue(empty) = %v, want a null list", list)
		}
	})

	// A non-empty extension list and the empty case, symmetric to the subject.
	wantValue := []byte{0x01, 0x02, 0x03}
	exts := []pkix.Extension{{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: true,
		Value:    wantValue,
	}}

	t.Run("non-empty extensions carry oid, critical, value_base64", func(t *testing.T) {
		t.Parallel()
		list, diags := extensionListValue(ctx, exts)
		if diags.HasError() {
			t.Fatalf("extensionListValue returned diagnostics: %v", diags)
		}
		if list.IsNull() {
			t.Fatal("extensionListValue returned a null list for a non-empty extension set")
		}
		elems := list.Elements()
		if len(elems) != 1 {
			t.Fatalf("extension list has %d elements, want 1", len(elems))
		}
		attrs := elems[0].(types.Object).Attributes()
		if got := attrs["oid"].(types.String).ValueString(); got != "2.5.29.19" {
			t.Errorf("extension oid = %q, want 2.5.29.19", got)
		}
		if got := attrs["critical"].(types.Bool).ValueBool(); !got {
			t.Errorf("extension critical = false, want true")
		}
		if got, want := attrs["value_base64"].(types.String).ValueString(), base64.StdEncoding.EncodeToString(wantValue); got != want {
			t.Errorf("extension value_base64 = %q, want %q", got, want)
		}
	})

	t.Run("empty extensions yield null, not an empty list", func(t *testing.T) {
		t.Parallel()
		// A v1 certificate carries no extensions; this is the case that would
		// have serialized as [] before the refactor and null after.
		list, diags := extensionListValue(ctx, nil)
		if diags.HasError() {
			t.Fatalf("extensionListValue(nil) returned diagnostics: %v", diags)
		}
		if !list.IsNull() {
			t.Errorf("extensionListValue(nil) = %v, want a null list", list)
		}
	})
}
