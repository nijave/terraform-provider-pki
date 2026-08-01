// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var (
	_ resource.Resource                     = (*bundleResource)(nil)
	_ resource.ResourceWithConfigValidators = (*bundleResource)(nil)
	_ resource.ResourceWithValidateConfig   = (*bundleResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*bundleResource)(nil)
)

// bundleResource composes certificate bundles in pem, der, pkcs7, pkcs12, and
// jks formats. It is a pure function of its inputs: the output is derived once
// at create or update time and held in state. Read does not re-derive it,
// because re-deriving a pkcs12 or jks bundle would require the password, which
// is write-only and therefore absent from state — the same reason
// password_wo_version exists as the rotation trigger.
type bundleResource struct{}

// NewBundleResource returns the pki_bundle resource.
func NewBundleResource() resource.Resource {
	return &bundleResource{}
}

// bundleResourceModel is pki_bundle's state model.
//
// PasswordWO carries the write-only password in config/plan transitions. It is
// never persisted to state: the framework strips write-only values before state
// is written, so it appears as null in every state snapshot. PasswordWOVersion
// is the persisted signal that forces re-encryption when the operator rotates
// the password — bumping it changes a state-visible value, which plans an
// update, which re-encrypts with the new PasswordWO read from config.
type bundleResourceModel struct {
	Format            types.String `tfsdk:"format"`
	CertificatePEM    types.String `tfsdk:"certificate_pem"`
	PrivateKeyPEM     types.String `tfsdk:"private_key_pem"`
	ChainPEM          types.List   `tfsdk:"chain_pem"`
	FriendlyName      types.String `tfsdk:"friendly_name"`
	PKCS12Encoding    types.String `tfsdk:"pkcs12_encoding"`
	PasswordWO        types.String `tfsdk:"password_wo"`
	PasswordWOVersion types.Int64  `tfsdk:"password_wo_version"`

	Content       types.String `tfsdk:"content"`
	ContentBase64 types.String `tfsdk:"content_base64"`
	ID            types.String `tfsdk:"id"`
}

func (r *bundleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_bundle"
}

func (r *bundleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Composes certificate bundles in `pem`, `der`, `pkcs7`, `pkcs12`, and `jks` " +
			"formats from a certificate, an optional private key, and an optional chain. The output is " +
			"derived once at create or update time and held in state — `terraform plan` after apply is " +
			"empty until the inputs change.\n\n" +
			"The bundle is a pure function of its inputs, so `Read` re-reads state unchanged rather than " +
			"re-deriving the output. Re-deriving a `pkcs12` or `jks` bundle would require the password, " +
			"which is write-only and therefore absent from state. `password_wo_version` is the rotation " +
			"trigger that bridges that gap: bumping it changes a state-visible value, which plans an " +
			"update, which re-encrypts with the new `password_wo`.\n\n" +
			"This resource is NOT importable. A bundle is derived output, so there is nothing to adopt.",
		Attributes: map[string]schema.Attribute{
			"format": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(formatStrings()...),
				},
				MarkdownDescription: "The output format, one of " + quotedList(formatStrings()) + ". " +
					"Changing this value replaces the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"certificate_pem": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The end-entity certificate, as a PEM `CERTIFICATE` block. At least " +
					"one of `certificate_pem`, `private_key_pem`, and `chain_pem` must be set — an empty " +
					"bundle is meaningless.",
			},
			"private_key_pem": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "The private key paired with `certificate_pem`, in any PEM encoding " +
					"`pki_private_key` produces (PKCS#1, SEC1, or PKCS#8). Omitting it yields a " +
					"certificate-only bundle (a truststore for `pkcs12` and `jks`). Only `pem`, `pkcs12`, " +
					"and `jks` formats can carry a private key; `der` and `pkcs7` reject it. Errors name " +
					"this attribute rather than echoing key material.",
			},
			"chain_pem": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "The certificate chain (CA and intermediaries), leaf-adjacent first, " +
					"as a list of PEM `CERTIFICATE` blocks. Omitting it yields a bundle with no chain.",
			},
			"friendly_name": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "An alias for the certificate entry. Honored for `jks` (as the " +
					"keystore alias) and for keyless `pkcs12` truststores (as the trust-anchor alias). " +
					"**Has no effect on a keyed `pkcs12` bundle** — `go-pkcs12` v0.7.3 sets only the " +
					"`localKeyId` attribute on a keyed entry and exposes no way to add a `friendlyName`, " +
					"so Java synthesizes the alias instead. This is an accepted limitation of the " +
					"underlying library, not a bug in this provider.",
			},
			"pkcs12_encoding": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(pkcs12EncodingStrings()...),
				},
				MarkdownDescription: "The algorithm suite for a `pkcs12` bundle, one of " +
					quotedList(pkcs12EncodingStrings()) + `. Defaults to "modern" (AES-256-CBC with ` +
					"PBKDF2 and an HMAC-SHA256 MAC — what `openssl pkcs12 -export` produces under " +
					"OpenSSL 3). `legacy` is 3DES with a SHA-1 MAC, the only combination universally " +
					"importable on iOS < 18 and Android < 14. `passwordless` has no encryption and no " +
					"MAC, requires no `password_wo`, and is rejected with a private key because Java " +
					"reads such a bundle as empty. Setting `pkcs12_encoding` on a format other than " +
					"`pkcs12` is an error rather than being silently ignored.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"password_wo": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				WriteOnly: true,
				MarkdownDescription: "The password encrypting a `pkcs12` or `jks` bundle. **Write-only**: " +
					"never persisted to state, never compared for drift. Required for `pkcs12` (unless " +
					"`pkcs12_encoding` is `passwordless`) and for `jks`. Because the value is invisible to " +
					"drift detection, bump `password_wo_version` to force re-encryption with a new " +
					"password — changing `password_wo` alone is not visible to the plan. Requires " +
					"OpenTofu ≥ 1.11 or Terraform ≥ 1.11. Errors name this attribute rather than echoing " +
					"the password.",
			},
			"password_wo_version": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "An integer the operator bumps to force re-encryption when " +
					"`password_wo` changes. Because `password_wo` is write-only and absent from state, " +
					"its value cannot trigger a plan on its own; bumping this attribute changes a " +
					"state-visible value, which plans an update, which re-encrypts with the new " +
					"`password_wo`. Required when `password_wo` is set.",
			},
			"content": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				MarkdownDescription: "The bundle output for text formats (`pem`), as the raw text. Null " +
					"for binary formats (`der`, `pkcs7`, `pkcs12`, `jks`); use `content_base64` for " +
					"those. Marked sensitive unconditionally — a bundle carrying a private key is the " +
					"common case, and sensitivity is a static schema property that cannot vary per " +
					"apply. A cert-only bundle is therefore also marked sensitive as a consequence; " +
					"`nonsensitive()` is the escape hatch when a caller genuinely needs to expose one.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"content_base64": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				MarkdownDescription: "The bundle output for all formats, as standard-alphabet base64. " +
					"This is the attribute to feed `kubernetes_secret.binary_data` (or equivalent), " +
					"whose consumers expect raw bytes; `base64decode()` on binary PKCS#12 data fails. " +
					"Marked sensitive unconditionally — see `content`.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The hex-encoded SHA-256 of the bundle output — a stable identifier " +
					"for the exact bytes produced, which changes if and only if the output does.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// ConfigValidators catches the two cross-attribute rules the framework's stock
// validators can express: at least one content-bearing attribute must be set,
// and a password must arrive with a version (a password with no version can
// never be rotated, which is a trap worth failing on).
func (r *bundleResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.AtLeastOneOf(
			path.MatchRoot("certificate_pem"),
			path.MatchRoot("private_key_pem"),
			path.MatchRoot("chain_pem"),
		),
		resourcevalidator.RequiredTogether(
			path.MatchRoot("password_wo"),
			path.MatchRoot("password_wo_version"),
		),
	}
}

// ValidateConfig enforces the format-specific rules the stock validators cannot
// express. Each diagnostic names the attribute to change and uses a distinctive
// phrase that cannot appear in the configuration text, so the acceptance test's
// ExpectError patterns are load-bearing rather than vacuously matching the
// echoed config.
//
// The rules:
//   - der and pkcs7 reject private_key_pem (neither format can carry one).
//   - pkcs12 with any encoding other than passwordless requires password_wo.
//   - passwordless rejects password_wo (the two are contradictory).
//   - jks requires password_wo (JKS has no passwordless mode).
//   - pkcs12_encoding on a format other than pkcs12 is an error, not a silent
//     ignore.
//
// These duplicate internal/pki's own checks intentionally: catching them at
// plan time gives the operator an immediate diagnostic, while the apply-time
// checks remain as a fallback for any path ValidateConfig does not cover.
func (r *bundleResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config bundleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Defer when format is unknown or null — every rule below branches on it,
	// and an unresolved format makes none of them answerable yet.
	if config.Format.IsNull() || config.Format.IsUnknown() {
		return
	}
	format := pki.Format(config.Format.ValueString())

	hasPrivateKey := !config.PrivateKeyPEM.IsNull() && !config.PrivateKeyPEM.IsUnknown()
	hasPassword := !config.PasswordWO.IsNull() && !config.PasswordWO.IsUnknown()

	// Resolve the effective encoding. An omitted or unknown pkcs12_encoding
	// defaults to modern, matching EncodeBundle's own resolution.
	encoding := pki.PKCS12Modern
	if !config.PKCS12Encoding.IsNull() && !config.PKCS12Encoding.IsUnknown() {
		encoding = pki.PKCS12Encoding(config.PKCS12Encoding.ValueString())
	}

	pkcs12EncodingSet := !config.PKCS12Encoding.IsNull() && !config.PKCS12Encoding.IsUnknown()

	// der and pkcs7 cannot carry a private key.
	if (format == pki.FormatDER || format == pki.FormatPKCS7) && hasPrivateKey {
		resp.Diagnostics.AddAttributeError(path.Root("private_key_pem"),
			"Private key not supported by format",
			fmt.Sprintf("private_key_pem is not supported by format %q: clear private_key_pem, "+
				"or use format %q, %q, or %q to include a key in the bundle.",
				format, pki.FormatPEM, pki.FormatPKCS12, pki.FormatJKS))
	}

	// pkcs12_encoding on a format other than pkcs12 is an error.
	if pkcs12EncodingSet && format != pki.FormatPKCS12 {
		resp.Diagnostics.AddAttributeError(path.Root("pkcs12_encoding"),
			"pkcs12_encoding not applicable",
			fmt.Sprintf("pkcs12_encoding only applies to format %q: clear pkcs12_encoding, "+
				"or set format to %q.",
				pki.FormatPKCS12, pki.FormatPKCS12))
	}

	if format == pki.FormatPKCS12 {
		if encoding == pki.PKCS12Passwordless {
			// passwordless rejects a password.
			if hasPassword {
				resp.Diagnostics.AddAttributeError(path.Root("password_wo"),
					"Password not supported by encoding",
					fmt.Sprintf("password_wo is not supported by pkcs12_encoding %q: clear password_wo, "+
						"or choose pkcs12_encoding %q or %q.",
						pki.PKCS12Passwordless, pki.PKCS12Modern, pki.PKCS12Legacy))
			}
		} else {
			// modern and legacy require a password.
			if !hasPassword {
				resp.Diagnostics.AddAttributeError(path.Root("password_wo"),
					"Password required",
					fmt.Sprintf("format %q with pkcs12_encoding %q requires password_wo: set password_wo, "+
						"or use pkcs12_encoding %q for an unencrypted bundle.",
						format, encoding, pki.PKCS12Passwordless))
			}
		}
	}

	// jks requires a password (JKS has no passwordless mode).
	if format == pki.FormatJKS && !hasPassword {
		resp.Diagnostics.AddAttributeError(path.Root("password_wo"),
			"Password required",
			fmt.Sprintf("format %q requires password_wo: set password_wo to a password of at least "+
				"six characters.", format))
	}
}

func (r *bundleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan bundleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// password_wo is write-only: present in req.Config, stripped from req.Plan.
	var config bundleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.PasswordWO = config.PasswordWO

	r.encode(ctx, &plan, &resp.Diagnostics, &resp.State)
}

// Read re-reads state unchanged. The bundle is a pure function of its inputs,
// and re-deriving it here would require password_wo for pkcs12 and jks formats
// — which is write-only and absent from state. password_wo_version exists
// precisely because this Read cannot detect a password change: the version is
// the state-visible signal that bridges the gap.
func (r *bundleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state bundleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *bundleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan bundleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var config bundleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.PasswordWO = config.PasswordWO

	r.encode(ctx, &plan, &resp.Diagnostics, &resp.State)
}

// Delete is a no-op; the framework removes the resource from state and there is
// nothing external to tear down.
func (r *bundleResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ModifyPlan resolves the tension between UseStateForUnknown (which carries
// state's content/content_base64/id forward for a stable refresh plan) and the
// non-determinism of pkcs12 and jks keyed encodings (which draw a fresh random
// salt on every call). Without this hook, an input change — most commonly a
// password_wo_version bump — plans an Update whose computed attrs are carried
// forward from state by UseStateForUnknown, but Update then produces new bytes
// (new salt), and the framework rejects the mismatch as "inconsistent result
// after apply".
//
// The fix is the same pattern pki_crl and pki_certificate use: when the
// state-visible inputs have changed, clear the computed attrs to Unknown so
// Update is free to compose fresh values; when they have not, leave the plan
// alone so UseStateForUnknown produces the empty refresh plan the tests require.
// password_wo is write-only and absent from state, so a password-only change is
// invisible here — that is the documented limitation password_wo_version
// exists to bridge, and the version bump IS state-visible and triggers this
// clearing.
func (r *bundleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Create: no state to compare against.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroy: nothing to carry.
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan, state bundleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if bundleInputsChanged(plan, state) {
		// Inputs changed: clear the computed attrs so Update can produce fresh
		// values without tripping "inconsistent result after apply".
		plan.Content = types.StringUnknown()
		plan.ContentBase64 = types.StringUnknown()
		plan.ID = types.StringUnknown()
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}
	// Inputs unchanged: UseStateForUnknown on content/content_base64/id already
	// carries state forward, producing the empty refresh plan. Nothing to do.
}

// bundleInputsChanged reports whether any state-visible input in plan differs
// from state. password_wo is write-only and absent from state, so it is not
// compared here — its invisibility is the reason password_wo_version exists.
func bundleInputsChanged(plan, state bundleResourceModel) bool {
	if !plan.Format.Equal(state.Format) {
		return true
	}
	if !plan.CertificatePEM.Equal(state.CertificatePEM) {
		return true
	}
	if !plan.PrivateKeyPEM.Equal(state.PrivateKeyPEM) {
		return true
	}
	if !plan.ChainPEM.Equal(state.ChainPEM) {
		return true
	}
	if !plan.FriendlyName.Equal(state.FriendlyName) {
		return true
	}
	if !plan.PKCS12Encoding.Equal(state.PKCS12Encoding) {
		return true
	}
	if !plan.PasswordWOVersion.Equal(state.PasswordWOVersion) {
		return true
	}
	return false
}

// encode parses the model's PEM inputs, calls pki.EncodeBundle, and writes the
// output plus the derived fields (content, content_base64, id) to state. It is
// shared by Create and Update — the two are identical for a pure-function
// resource.
func (r *bundleResource) encode(
	ctx context.Context,
	model *bundleResourceModel,
	diags *diag.Diagnostics,
	stateOut interface {
		Set(ctx context.Context, v interface{}) diag.Diagnostics
	},
) {
	format := pki.Format(model.Format.ValueString())

	// 1. Parse the certificate.
	var cert *x509.Certificate
	if !model.CertificatePEM.IsNull() && !model.CertificatePEM.IsUnknown() {
		c, err := pki.ParseCertificatePEM([]byte(model.CertificatePEM.ValueString()))
		if err != nil {
			diags.AddAttributeError(path.Root("certificate_pem"),
				"Unable to parse certificate",
				"The certificate could not be parsed as a PEM CERTIFICATE block: "+err.Error())
			return
		}
		cert = c
	}

	// 2. Parse the private key. ParsePrivateKeyPEM's errors are structural and
	// never echo key bytes, so err.Error() is safe to surface.
	var key crypto.Signer
	if !model.PrivateKeyPEM.IsNull() && !model.PrivateKeyPEM.IsUnknown() {
		k, err := pki.ParsePrivateKeyPEM([]byte(model.PrivateKeyPEM.ValueString()))
		if err != nil {
			diags.AddAttributeError(path.Root("private_key_pem"),
				"Unable to parse private key",
				"The private key could not be parsed as PKCS#8, PKCS#1, or SEC1: "+err.Error())
			return
		}
		key = k
	}

	// 3. Parse the chain. Each list element is one PEM CERTIFICATE block.
	var chain []*x509.Certificate
	if !model.ChainPEM.IsNull() && !model.ChainPEM.IsUnknown() {
		chainStrs, d := stringsFromList(ctx, model.ChainPEM, path.Root("chain_pem"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		for i, pemStr := range chainStrs {
			c, err := pki.ParseCertificatePEM([]byte(pemStr))
			if err != nil {
				diags.AddAttributeError(path.Root("chain_pem").AtListIndex(i),
					"Unable to parse chain certificate",
					"The chain entry could not be parsed as a PEM CERTIFICATE block: "+err.Error())
				return
			}
			chain = append(chain, c)
		}
	}

	// 4. Resolve the encoding. An omitted or unknown pkcs12_encoding defaults
	// to modern, matching EncodeBundle's own resolution. The resolved value is
	// written back to state only for a pkcs12 bundle, where it names the suite
	// that was used; every other format has no encoding, so the attribute stays
	// null rather than persisting a meaningless "modern" (ValidateConfig already
	// rejects setting pkcs12_encoding on a non-pkcs12 format).
	encoding := pki.PKCS12Modern
	if !model.PKCS12Encoding.IsNull() && !model.PKCS12Encoding.IsUnknown() {
		encoding = pki.PKCS12Encoding(model.PKCS12Encoding.ValueString())
	}
	if format == pki.FormatPKCS12 {
		model.PKCS12Encoding = types.StringValue(string(encoding))
	} else {
		model.PKCS12Encoding = types.StringNull()
	}

	// 5. Read the write-only password from the model (which Create/Update
	// populated from req.Config).
	password := ""
	if !model.PasswordWO.IsNull() && !model.PasswordWO.IsUnknown() {
		password = model.PasswordWO.ValueString()
	}

	// 6. Build the input and encode.
	input := pki.BundleInput{
		Format:         format,
		Certificate:    cert,
		PrivateKey:     key,
		Chain:          chain,
		FriendlyName:   model.FriendlyName.ValueString(),
		PKCS12Encoding: encoding,
		Password:       password,
	}

	output, err := pki.EncodeBundle(input)
	if err != nil {
		// EncodeBundle's errors name the attribute to edit. Route them through
		// addPKIError so the diagnostic lands on the right attribute rather than
		// the resource root.
		addPKIError(diags, err, "Unable to encode bundle", path.Root("format"),
			rootPKIErrorAttributes("certificate_pem", "private_key_pem", "chain_pem",
				"format", "pkcs12_encoding", "password_wo", "friendly_name"))
		return
	}

	// 7. Write the output. content is set only for text formats (pem);
	// content_base64 is always set. Both are sensitive unconditionally.
	model.ContentBase64 = types.StringValue(base64.StdEncoding.EncodeToString(output))
	if format.IsText() {
		model.Content = types.StringValue(string(output))
	} else {
		model.Content = types.StringNull()
	}

	sum := sha256.Sum256(output)
	model.ID = types.StringValue(hex.EncodeToString(sum[:]))

	diags.Append(stateOut.Set(ctx, model)...)
}

// formatStrings returns pki.Formats() as a []string for stringvalidator.OneOf.
// It exists because pki.Formats returns []Format (a named string type), which
// OneOf does not accept directly.
func formatStrings() []string {
	formats := pki.Formats()
	out := make([]string, len(formats))
	for i, f := range formats {
		out[i] = string(f)
	}
	return out
}

// pkcs12EncodingStrings returns pki.PKCS12Encodings() as a []string for
// stringvalidator.OneOf, mirroring formatStrings.
func pkcs12EncodingStrings() []string {
	encodings := pki.PKCS12Encodings()
	out := make([]string, len(encodings))
	for i, e := range encodings {
		out[i] = string(e)
	}
	return out
}
