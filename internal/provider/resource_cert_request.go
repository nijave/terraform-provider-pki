// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var _ resource.Resource = (*certRequestResource)(nil)

// certRequestResource builds a certificate signing request entirely in-process
// and holds it in state. There is no external system to talk to, exactly like
// pki_private_key: a CSR is a signed object, and once it is created nothing
// about it can change.
type certRequestResource struct{}

// NewCertRequestResource returns the pki_cert_request resource.
func NewCertRequestResource() resource.Resource {
	return &certRequestResource{}
}

// certRequestResourceModel is pki_cert_request's state model.
type certRequestResourceModel struct {
	PrivateKeyPEM      types.String          `tfsdk:"private_key_pem"`
	Subject            *subjectModel         `tfsdk:"subject"`
	SAN                *sanModel             `tfsdk:"san"`
	ExtraExtensions    []extraExtensionModel `tfsdk:"extra_extension"`
	SignatureAlgorithm types.String          `tfsdk:"signature_algorithm"`
	CertRequestPEM     types.String          `tfsdk:"cert_request_pem"`
	ID                 types.String          `tfsdk:"id"`
}

func (r *certRequestResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_request"
}

func (r *certRequestResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Builds a certificate signing request (CSR) in-process and holds it in " +
			"state. A CSR is an immutable signed object — every input attribute carries " +
			"`RequiresReplace`, so any change produces a new CSR rather than an in-place edit.\n\n" +
			"This resource is **not importable**. A CSR is a transient artifact whose only " +
			"purpose is to be signed into a certificate; adopting one that arrived from elsewhere " +
			"has no value, because the certificate it produced is what matters and that is " +
			"importable on its own. To inspect a CSR handed over by a device or another team, use " +
			"the `pki_cert_request` **data source**, which decodes one without creating it.",
		Attributes: map[string]schema.Attribute{
			"private_key_pem": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				MarkdownDescription: "The private key to sign the request with, in any PEM encoding " +
					"`pki_private_key` produces (PKCS#1, SEC1, or PKCS#8). The request's public key " +
					"is derived from this key, and the signature proves the requester holds it. " +
					"Changing this value replaces the request.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"signature_algorithm": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(pki.SignatureAlgorithmNames()...),
				},
				MarkdownDescription: "The signature algorithm, one of " +
					quotedList(pki.SignatureAlgorithmNames()) + ". When omitted, the conventional " +
					"algorithm for the key is chosen: SHA-256 with RSA, Ed25519's pure algorithm, " +
					"and for ECDSA the hash matched to the curve's field size (P-256 to SHA-256, " +
					"P-384 to SHA-384, P-521 to SHA-512). The resolved name is written back to " +
					"state. Changing this value replaces the request.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"cert_request_pem": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The certificate signing request as a PEM `CERTIFICATE REQUEST` " +
					"block.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The hex-encoded SHA-256 of the request's DER — a stable " +
					"identifier for the exact bytes of the request, which changes if and only if " +
					"any signed content or the signature itself does.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			// Every block carries RequiresReplace because a CSR is an immutable
			// signed object: changing the subject, san, or any extension produces
			// a different DER, whose signature is by construction different. The
			// objectplanmodifier/listplanmodifier variants are the block-level
			// analogues of stringplanmodifier.RequiresReplace — there is no
			// ForceNew field on a block, the plan modifier is where it lives.
			"subject":         requiresReplaceSubjectBlock(),
			"san":             requiresReplaceSANBlock(),
			"extra_extension": requiresReplaceExtraExtensionBlock(),
		},
	}
}

// requiresReplaceSubjectBlock returns the shared subject block with a
// RequiresReplace plan modifier appended, so a change to any field inside it
// triggers replacement rather than reaching the unreachable Update path.
func requiresReplaceSubjectBlock() schema.Block {
	b := subjectBlock().(schema.SingleNestedBlock)
	b.PlanModifiers = []planmodifier.Object{
		objectplanmodifier.RequiresReplace(),
	}
	return b
}

// requiresReplaceSANBlock returns the shared san block with RequiresReplace.
func requiresReplaceSANBlock() schema.Block {
	b := sanBlock().(schema.SingleNestedBlock)
	b.PlanModifiers = []planmodifier.Object{
		objectplanmodifier.RequiresReplace(),
	}
	return b
}

// requiresReplaceExtraExtensionBlock returns the shared extra_extension block
// with RequiresReplace.
func requiresReplaceExtraExtensionBlock() schema.Block {
	b := extraExtensionBlock().(schema.ListNestedBlock)
	b.PlanModifiers = []planmodifier.List{
		listplanmodifier.RequiresReplace(),
	}
	return b
}

func (r *certRequestResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan certRequestResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse the private key. ParsePrivateKeyPEM's errors are structural (tag,
	// length, and offset descriptions) and never echo key bytes — the invariant
	// assertNoEcho in internal/pki guards — so err.Error() is safe to surface.
	// The diagnostic lands on private_key_pem because that is the one attribute
	// the operator has to fix; nothing else in this resource can influence a
	// key parse failure, and a resource-level diagnostic would leave them
	// guessing which input was wrong.
	key, err := pki.ParsePrivateKeyPEM([]byte(plan.PrivateKeyPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("private_key_pem"),
			"Unable to parse private key",
			"The private key could not be parsed as PKCS#8, PKCS#1, or SEC1: "+err.Error())
		return
	}

	// Convert the subject, san, and extra_extension blocks through their toPKI
	// methods. Each attaches its own diagnostics at the offending attribute.
	var subject pki.Subject
	if plan.Subject != nil {
		s, d := plan.Subject.toPKI(ctx, path.Root("subject"))
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		subject = s
	}

	var san pki.SAN
	if plan.SAN != nil {
		s, d := plan.SAN.toPKI(ctx, path.Root("san"))
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		san = s
	}

	extras := make([]pki.ExtraExtension, 0, len(plan.ExtraExtensions))
	for i, em := range plan.ExtraExtensions {
		e, d := em.toPKI(path.Root("extra_extension").AtListIndex(i))
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		extras = append(extras, e)
	}

	tpl := pki.CertRequestTemplate{
		Subject:         subject,
		SAN:             san,
		ExtraExtensions: extras,
	}

	// Resolve signature_algorithm. The x509.SignatureAlgorithm type arrives
	// through pki's function returns, so crypto/x509 never needs to be imported
	// in this file: both branches use := and assign into tpl.SignatureAlgorithm,
	// whose type is whatever pki.CertRequestTemplate declares.
	if !plan.SignatureAlgorithm.IsNull() && !plan.SignatureAlgorithm.IsUnknown() {
		sigAlg, err := pki.SignatureAlgorithmByName(plan.SignatureAlgorithm.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("signature_algorithm"),
				"Unknown signature algorithm", err.Error())
			return
		}
		tpl.SignatureAlgorithm = sigAlg
	} else {
		// Pick the key's conventional default and write the resolved name back
		// to state so the computed attribute is concrete rather than unknown.
		sigAlg, err := pki.DefaultSignatureAlgorithm(key)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("signature_algorithm"),
				"Unable to resolve default signature algorithm", err.Error())
			return
		}
		tpl.SignatureAlgorithm = sigAlg
		resolved, err := pki.SignatureAlgorithmName(sigAlg)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("signature_algorithm"),
				"Unable to resolve default signature algorithm", err.Error())
			return
		}
		plan.SignatureAlgorithm = types.StringValue(resolved)
	}

	csrPEM, err := pki.CreateCertRequest(key, tpl)
	if err != nil {
		// CreateCertRequest's failures are about the subject, SAN, or extensions
		// (encoding errors, duplicate OIDs), and its messages already name which
		// extension failed and why. addPKIError's attribute-name matching is not
		// useful here because none of those messages name a provider attribute,
		// so the diagnostic lands on the resource root with the verbatim error.
		resp.Diagnostics.AddError("Unable to create certificate request", err.Error())
		return
	}

	plan.CertRequestPEM = types.StringValue(string(csrPEM))

	id, err := certRequestIDFromPEM(csrPEM)
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute certificate request id", err.Error())
		return
	}
	plan.ID = types.StringValue(id)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is a genuine no-op that re-reads state unchanged, for the same reason
// pki_private_key's Read is: the CSR exists only in Terraform state, signed once
// by Create. A Read that recomputed cert_request_pem would re-sign and produce a
// different request on every refresh, which is exactly the rotation-on-every-
// plan bug UseStateForUnknown exists to prevent. This emptiness is deliberate.
func (r *certRequestResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

// Update is unreachable: every input attribute (private_key_pem, signature_algorithm,
// and the subject, san, and extra_extension blocks) carries RequiresReplace, so
// the framework always plans a destroy/create instead of calling Update. It is
// implemented as a loud diagnostic, rather than left empty, so that a future
// schema change making it reachable fails immediately instead of silently
// keeping stale state.
func (r *certRequestResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"pki_cert_request does not support in-place update",
		"Every input attribute requires replacement, so Update should never be called. "+
			"If you are seeing this, a schema change has made an attribute updatable in place "+
			"without also implementing Update for it.",
	)
}

// Delete is a no-op; the framework removes the resource from state and there is
// nothing external to tear down.
func (r *certRequestResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// certRequestIDFromPEM decodes a single CERTIFICATE REQUEST PEM block and
// returns the hex-encoded SHA-256 of its DER bytes. The PEM is decoded here
// rather than tracking the DER separately because CreateCertRequest returns PEM,
// and a single source of truth for the request's bytes is simpler than threading
// both forms through the model. encoding/pem is a base64-wrapper decoder, not
// crypto/x509 parsing, so it stays on the provider side of the boundary.
func certRequestIDFromPEM(csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", fmt.Errorf("the certificate request is not a valid PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
