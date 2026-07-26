// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var _ datasource.DataSource = (*oidsDataSource)(nil)

// oidsDataSource exposes the whole internal/pki OID table as five groups of
// bidirectional maps, for callers who need to iterate or use for_each rather
// than look up one value with the oid/oid_name provider functions.
type oidsDataSource struct{}

// NewOIDsDataSource returns the pki_oids data source.
func NewOIDsDataSource() datasource.DataSource {
	return &oidsDataSource{}
}

func (d *oidsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oids"
}

// oidGroupAttribute is the schema for one group of the OID table: two maps
// pointing at each other.
func oidGroupAttribute(description string) schema.SingleNestedAttribute {
	return schema.SingleNestedAttribute{
		Computed:            true,
		MarkdownDescription: description,
		Attributes: map[string]schema.Attribute{
			"by_name": schema.MapAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Keyed by friendly name.",
			},
			"by_oid": schema.MapAttribute{
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Keyed by dotted OID, the reverse of `by_name`.",
			},
		},
	}
}

func (d *oidsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The full internal/pki OID table as five groups of bidirectional maps, " +
			"for callers who need to iterate or use `for_each` rather than look up one value with the " +
			"`oid` and `oid_name` provider functions.",
		Attributes: map[string]schema.Attribute{
			"dn_attributes": oidGroupAttribute(
				"Distinguished name attribute types, such as `commonName` and `displayName`."),
			"extensions": oidGroupAttribute(
				"Certificate extension types, such as `subjectAltName` and `basicConstraints`."),
			"extended_key_usages": oidGroupAttribute(
				"Extended key usage purposes, such as `clientAuth`."),
			"key_usages": oidGroupAttribute(
				"Key usage names mapped to their **RFC 5280 bit position**, not to an OID: key usages " +
					"are bits in a `BIT STRING` and have no object identifiers. `by_oid` is therefore " +
					"keyed by that same decimal bit position."),
			"signature_algorithms": oidGroupAttribute(
				"Signature algorithm names, spelled as Go's `crypto/x509` spells them, mapped to their " +
					"algorithm OIDs. **`by_oid` is smaller than `by_name`:** RFC 8017 registers a single " +
					"OID for RSASSA-PSS (`1.2.840.113549.1.1.10`) across all hash sizes, because the hash " +
					"is a PSS parameter rather than part of the OID. All three of `SHA256-RSAPSS`, " +
					"`SHA384-RSAPSS`, and `SHA512-RSAPSS` therefore share that value in `by_name`, and " +
					"`by_oid` omits it, because that OID alone cannot say which hash is in use."),
		},
	}
}

// oidsDataSourceModel is the top-level state model: one field per group,
// nested to match the schema above.
type oidsDataSourceModel struct {
	DNAttributes        oidGroupModel `tfsdk:"dn_attributes"`
	Extensions          oidGroupModel `tfsdk:"extensions"`
	ExtendedKeyUsages   oidGroupModel `tfsdk:"extended_key_usages"`
	KeyUsages           oidGroupModel `tfsdk:"key_usages"`
	SignatureAlgorithms oidGroupModel `tfsdk:"signature_algorithms"`
}

// oidGroupModel is one group's pair of bidirectional maps.
type oidGroupModel struct {
	ByName types.Map `tfsdk:"by_name"`
	ByOID  types.Map `tfsdk:"by_oid"`
}

// groupModelFromTable converts one pki.Table into the group's state model.
// The table is static data, so there is no error path worth its own
// diagnostic -- but a conversion failure is still threaded through diags
// rather than ignored, both because that is the framework's normal idiom and
// because it catches a future table entry with a value that cannot convert.
func groupModelFromTable(ctx context.Context, tbl pki.Table, diags *diag.Diagnostics) oidGroupModel {
	byName, d := types.MapValueFrom(ctx, types.StringType, tbl.ByName)
	diags.Append(d...)

	byOID, d := types.MapValueFrom(ctx, types.StringType, tbl.ByOID)
	diags.Append(d...)

	return oidGroupModel{ByName: byName, ByOID: byOID}
}

// Read walks pki.Tables() and converts each group into the matching model
// field, keyed by tbl.Name rather than position: Tables() documents a stable
// order, but matching by name is one line more code and does not depend on
// that order holding.
func (d *oidsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model oidsDataSourceModel
	dests := map[string]*oidGroupModel{
		"dn_attributes":        &model.DNAttributes,
		"extensions":           &model.Extensions,
		"extended_key_usages":  &model.ExtendedKeyUsages,
		"key_usages":           &model.KeyUsages,
		"signature_algorithms": &model.SignatureAlgorithms,
	}

	seen := make(map[string]bool, len(dests))
	for _, tbl := range pki.Tables() {
		dst, ok := dests[tbl.Name]
		if !ok {
			resp.Diagnostics.AddError(
				"Unexpected OID table shape",
				"internal/pki.Tables() returned an unrecognized group named \""+tbl.Name+"\".",
			)
			return
		}
		*dst = groupModelFromTable(ctx, tbl, &resp.Diagnostics)
		seen[tbl.Name] = true
	}
	if len(seen) != len(dests) {
		resp.Diagnostics.AddError(
			"Unexpected OID table shape",
			"internal/pki.Tables() did not return all five expected groups.",
		)
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
