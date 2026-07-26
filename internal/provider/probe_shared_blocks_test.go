// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// This file exists to answer questions about the shared blocks that no mock can
// answer, before the resources that embed them exist.
//
// The shared subject, san and extension blocks in schema_common.go are used by
// eleven later tasks and by none of the three resources built so far, so until
// Task 6 there is no way to put a real `tofu plan` through them. Two of the
// review findings this file closes are specifically about what Terraform does
// with them, not about what the Go code says:
//
//   - whether an empty non-nil block collection in state drifts against a
//     configuration that declares no such block (subjectFromPKI's
//     ExtraAttributes), which only an apply plus a follow-up plan can settle;
//   - whether the emptiness rules on key_usage, extended_key_usage and
//     name_constraints fire at plan time, and whether they stay quiet when the
//     optional block is left out entirely, which depends on the framework
//     descending into an absent single-nested block's nested attributes.
//
// So this is a real resource, served over protocol 6 to a real OpenTofu, whose
// only job is to carry those blocks. It is defined in a _test.go file and
// registered only by sharedBlockProbeProvider, so it is not part of the provider
// binary and cannot appear in the generated documentation. Once a real resource
// embeds these blocks and asserts the same two properties, this probe is
// redundant and should be deleted.

// sharedBlockProbeModel holds every shared block, using the same models the real
// resources will.
type sharedBlockProbeModel struct {
	ID              types.String          `tfsdk:"id"`
	Subject         *subjectModel         `tfsdk:"subject"`
	SAN             *sanModel             `tfsdk:"san"`
	KeyUsage        *keyUsageModel        `tfsdk:"key_usage"`
	ExtKeyUsage     *extKeyUsageModel     `tfsdk:"extended_key_usage"`
	NameConstraints *nameConstraintsModel `tfsdk:"name_constraints"`
	ExtraExtensions []extraExtensionModel `tfsdk:"extra_extension"`
}

type sharedBlockProbeResource struct{}

var _ resource.Resource = (*sharedBlockProbeResource)(nil)

func (r *sharedBlockProbeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_shared_blocks"
}

func (r *sharedBlockProbeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Test-only probe carrying the shared blocks.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "Always `probe`.",
			},
		},
		Blocks: map[string]schema.Block{
			"subject":            subjectBlock(),
			"san":                sanBlock(),
			"key_usage":          keyUsageBlock(),
			"extended_key_usage": extendedKeyUsageBlock(),
			"name_constraints":   nameConstraintsBlock(),
			"extra_extension":    extraExtensionBlock(),
		},
	}
}

// Create writes the plan straight back to state, except for a subject in the
// ordered form: that one is round-tripped through internal/pki and back through
// subjectFromPKI, which is what every certificate resource's Read and
// ImportState will do. The round trip is what puts subjectFromPKI's empty
// non-nil ExtraAttributes into state against a configuration that declared no
// `extra_attribute` block, so Terraform's own after-apply consistency check and
// the following plan get to rule on whether the two forms of absence are the
// same.
func (r *sharedBlockProbeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var model sharedBlockProbeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if model.Subject != nil && len(model.Subject.Attributes) > 0 {
		subject, diags := model.Subject.toPKI(ctx, path.Root("subject"))
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		roundTripped := subjectFromPKI(subject)
		model.Subject = &roundTripped
	}

	model.ID = types.StringValue("probe")
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *sharedBlockProbeResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

func (r *sharedBlockProbeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model sharedBlockProbeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	model.ID = types.StringValue("probe")
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (r *sharedBlockProbeResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// sharedBlockProbeProvider serves nothing but the probe resource, under its own
// type name so it can never be confused with the real `pki` provider in a test
// configuration.
type sharedBlockProbeProvider struct{}

var _ fwprovider.Provider = (*sharedBlockProbeProvider)(nil)

func (p *sharedBlockProbeProvider) Metadata(_ context.Context, _ fwprovider.MetadataRequest, resp *fwprovider.MetadataResponse) {
	resp.TypeName = "pkiprobe"
}

func (p *sharedBlockProbeProvider) Schema(_ context.Context, _ fwprovider.SchemaRequest, resp *fwprovider.SchemaResponse) {
	resp.Schema = providerschema.Schema{
		MarkdownDescription: "Test-only provider for the shared block probe.",
	}
}

func (p *sharedBlockProbeProvider) Configure(_ context.Context, _ fwprovider.ConfigureRequest, _ *fwprovider.ConfigureResponse) {
}

func (p *sharedBlockProbeProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource { return &sharedBlockProbeResource{} },
	}
}

func (p *sharedBlockProbeProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

func (p *sharedBlockProbeProvider) Functions(_ context.Context) []func() function.Function {
	return nil
}
