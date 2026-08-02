// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var (
	_ resource.Resource                     = (*privateKeyResource)(nil)
	_ resource.ResourceWithImportState      = (*privateKeyResource)(nil)
	_ resource.ResourceWithConfigValidators = (*privateKeyResource)(nil)
)

// privateKeyResource generates (or, on import, adopts) a private key and
// holds it entirely in state. There is no external system to talk to.
type privateKeyResource struct{}

// NewPrivateKeyResource returns the pki_private_key resource.
func NewPrivateKeyResource() resource.Resource {
	return &privateKeyResource{}
}

// privateKeyErrorAttributes are the attributes pki.GenerateKey names when it
// rejects an algorithm or a parameter mismatch (e.g. ecdsa_curve alongside
// algorithm = "RSA"), all of them root attributes here. The fallback at the
// GenerateKey call site is algorithm, which is what "unknown key algorithm" is
// about and the attribute every other value depends on.
//
// pki.DescribeKey's "unsupported ecdsa curve %q" names the same ecdsa_curve
// candidate, so it localizes through addPKIError too when DescribeKey runs in a
// config context (Create, below). The import path's DescribeKey failure is a
// different matter: see ImportState for why it stays a resource-level error.
var privateKeyErrorAttributes = rootPKIErrorAttributes("algorithm", "rsa_bits", "ecdsa_curve")

// privateKeyResourceModel is pki_private_key's state model.
type privateKeyResourceModel struct {
	Algorithm                  types.String `tfsdk:"algorithm"`
	RSABits                    types.Int64  `tfsdk:"rsa_bits"`
	ECDSACurve                 types.String `tfsdk:"ecdsa_curve"`
	PrivateKeyPEM              types.String `tfsdk:"private_key_pem"`
	PrivateKeyPEMPKCS8         types.String `tfsdk:"private_key_pem_pkcs8"`
	PublicKeyPEM               types.String `tfsdk:"public_key_pem"`
	PublicKeyOpenSSH           types.String `tfsdk:"public_key_openssh"`
	PublicKeyFingerprintSHA256 types.String `tfsdk:"public_key_fingerprint_sha256"`
	ID                         types.String `tfsdk:"id"`
}

func (r *privateKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_private_key"
}

func (r *privateKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Generates a private key entirely in-process, or adopts an existing one on " +
			"import. The key exists only in Terraform state: there is nothing external to refresh, so " +
			"`terraform apply` never rotates it and `terraform plan` after apply is always empty.",
		Attributes: map[string]schema.Attribute{
			"algorithm": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf("RSA", "ECDSA", "ED25519"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				MarkdownDescription: "The key algorithm: one of `RSA`, `ECDSA`, or `ED25519`. Changing " +
					"this value replaces the key.",
			},
			"rsa_bits": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Validators: []validator.Int64{
					int64validator.AtLeast(2048),
				},
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
					int64planmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "RSA modulus size in bits. Only valid when `algorithm = \"RSA\"`. " +
					"Defaults to `2048`, the CA/Browser Forum minimum. Changing this value replaces " +
					"the key.",
			},
			"ecdsa_curve": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf("P224", "P256", "P384", "P521"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "ECDSA curve, one of `P224`, `P256`, `P384`, or `P521`. Only valid " +
					"when `algorithm = \"ECDSA\"`. Defaults to `P256`. Changing this value replaces the " +
					"key.",
			},
			"private_key_pem": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "The private key in its algorithm's conventional legacy PEM " +
					"encoding: PKCS#1 (`RSA PRIVATE KEY`) for RSA, SEC1 (`EC PRIVATE KEY`) for ECDSA, " +
					"or PKCS#8 (`PRIVATE KEY`) for Ed25519, which has no legacy encoding of its own.",
			},
			"private_key_pem_pkcs8": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "The private key encoded as PKCS#8 (`PRIVATE KEY`), regardless of " +
					"algorithm.",
			},
			"public_key_pem": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "The public key, PKIX-encoded (`PUBLIC KEY`).",
			},
			"public_key_openssh": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "The public key in OpenSSH `authorized_keys` form.",
			},
			"public_key_fingerprint_sha256": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "The public key's OpenSSH SHA256 fingerprint, `SHA256:` followed " +
					"by the unpadded standard base64 of the SHA-256 hash of the SSH wire-format key. " +
					"Matches `hashicorp/tls` exactly.",
			},
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				MarkdownDescription: "Set to `public_key_fingerprint_sha256`.",
			},
		},
	}
}

// ConfigValidators catches the "both rsa_bits and ecdsa_curve set" case at
// plan time with one diagnostic. The algorithm-specific cases -- rsa_bits on
// an ECDSA key, ecdsa_curve on an RSA key, either on an ED25519 key -- cannot
// be expressed as a static attribute conflict because "conflicting" here
// depends on algorithm's value, so those are left to pki.GenerateKey's own
// validation, surfaced as an attribute error in Create.
func (r *privateKeyResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.Conflicting(
			path.MatchRoot("rsa_bits"),
			path.MatchRoot("ecdsa_curve"),
		),
	}
}

// setKeyAttributes populates every computed attribute of pki_private_key from
// a key. Create and ImportState both use it, which is what guarantees an
// imported key's state is indistinguishable from a generated one -- the
// property spec section 8 needs for the plan after import to be empty.
func setKeyAttributes(m *privateKeyResourceModel, key crypto.Signer) error {
	params, err := pki.DescribeKey(key)
	if err != nil {
		return err
	}

	privPEM, err := pki.EncodePrivateKeyPEM(key)
	if err != nil {
		return err
	}
	privPKCS8PEM, err := pki.EncodePrivateKeyPKCS8PEM(key)
	if err != nil {
		return err
	}
	pub := pki.PublicKeyOf(key)
	pubPEM, err := pki.EncodePublicKeyPEM(pub)
	if err != nil {
		return err
	}
	pubOpenSSH, err := pki.EncodePublicKeyOpenSSH(pub)
	if err != nil {
		return err
	}
	fingerprint, err := pki.PublicKeyFingerprintSHA256(pub)
	if err != nil {
		return err
	}

	m.Algorithm = types.StringValue(string(params.Algorithm))
	if params.RSABits != 0 {
		m.RSABits = types.Int64Value(int64(params.RSABits))
	} else {
		m.RSABits = types.Int64Null()
	}
	if params.ECDSACurve != "" {
		m.ECDSACurve = types.StringValue(params.ECDSACurve)
	} else {
		m.ECDSACurve = types.StringNull()
	}
	m.PrivateKeyPEM = types.StringValue(string(privPEM))
	m.PrivateKeyPEMPKCS8 = types.StringValue(string(privPKCS8PEM))
	m.PublicKeyPEM = types.StringValue(string(pubPEM))
	m.PublicKeyOpenSSH = types.StringValue(string(pubOpenSSH))
	m.PublicKeyFingerprintSHA256 = types.StringValue(fingerprint)
	m.ID = types.StringValue(fingerprint)

	return nil
}

func (r *privateKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan privateKeyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	params := pki.KeyParams{Algorithm: pki.Algorithm(plan.Algorithm.ValueString())}
	if !plan.RSABits.IsNull() && !plan.RSABits.IsUnknown() {
		params.RSABits = int(plan.RSABits.ValueInt64())
	}
	if !plan.ECDSACurve.IsNull() && !plan.ECDSACurve.IsUnknown() {
		params.ECDSACurve = plan.ECDSACurve.ValueString()
	}

	key, err := pki.GenerateKey(params)
	if err != nil {
		// pki.GenerateKey rejects an algorithm/parameter mismatch (e.g.
		// ecdsa_curve set alongside algorithm = "RSA") with a message naming the
		// offending field, so the message decides where the diagnostic lands.
		// Re-deriving that here from the KeyParams just sent would be a second
		// copy of internal/pki's validation rules, in different words; see
		// diagnostics.go.
		addPKIError(&resp.Diagnostics, err, "Unable to generate private key",
			path.Root("algorithm"), privateKeyErrorAttributes)
		return
	}

	if err := setKeyAttributes(&plan, key); err != nil {
		// DescribeKey runs here on a key GenerateKey just produced, so the only
		// way it fails is an internal disagreement between the two -- but it
		// routes through addPKIError like GenerateKey above, so a failure that
		// does name a field (an "unsupported ecdsa curve" message) lands on
		// ecdsa_curve rather than the whole resource block.
		addPKIError(&resp.Diagnostics, err, "Unable to describe generated private key",
			path.Root("algorithm"), privateKeyErrorAttributes)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read is a genuine no-op that re-reads state unchanged.
//
// There is nothing external to refresh: the key exists only in Terraform
// state, generated once by Create. A Read that recomputed private_key_pem --
// or anything derived from it -- would generate a *new* key on every refresh,
// which is exactly the rotation-on-every-plan bug UseStateForUnknown exists
// to prevent. This emptiness is deliberate, not an oversight.
func (r *privateKeyResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

// Update is unreachable: every input attribute (algorithm, rsa_bits,
// ecdsa_curve) carries RequiresReplace, so the framework always plans a
// destroy/create instead of calling Update. It is implemented as a loud
// diagnostic, rather than left empty, so that a future schema change making
// it reachable fails immediately instead of silently keeping stale state.
func (r *privateKeyResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"pki_private_key does not support in-place update",
		"Every input attribute requires replacement, so Update should never be called. "+
			"If you are seeing this, a schema change has made an attribute updatable in place "+
			"without also implementing Update for it.",
	)
}

// Delete is a no-op; the framework removes the resource from state and there
// is nothing external to tear down.
func (r *privateKeyResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState resolves the import ID through resolveImportID, parses the PEM
// it returns, and reconstructs the whole model with setKeyAttributes -- the
// same helper Create uses, so an imported key's state cannot drift from a
// generated key's state in shape.
//
// This is not ImportStatePassthroughID: the ID is a locator (file:// only for
// this resource -- see resolveImportID) that describes where to find the key,
// not the resource's identity. The resource's identity, once imported, is its
// fingerprint.
//
// resolveImportID is called with allowInline=false: pem:// and base64:// both
// carry the key itself inline, and OpenTofu/Terraform prints an import ID in
// full, unconditionally, in its own progress output before this provider ever
// runs -- unlike this resource's private_key_pem attribute, which the
// framework correctly redacts in a plan diff, that progress line is not a
// resource attribute and is never redacted. A private key resource is the one
// place in this provider where that distinction is not academic.
func (r *privateKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// These three errors are deliberately resource-level (AddError, no path),
	// not attribute-level. Import runs against `terraform import <addr> <id>`
	// while no configuration block exists -- state is being built from the ID --
	// so there is no schema attribute to localize a diagnostic against. The
	// addPKIError routing Create uses is for config-time failures, where a value
	// the operator wrote is wrong; here the failure is the import ID itself, and
	// the framework renders a resource-level diagnostic against the resource
	// address, which is the right place for it.
	pemBytes, err := resolveImportID(req.ID, false)
	if err != nil {
		resp.Diagnostics.AddError("Unable to resolve import ID", err.Error())
		return
	}

	key, err := pki.ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse private key", err.Error())
		return
	}

	var model privateKeyResourceModel
	if err := setKeyAttributes(&model, key); err != nil {
		resp.Diagnostics.AddError("Unable to describe imported private key", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
