// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"time"

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
	_ resource.Resource                     = (*certificateAuthorityResource)(nil)
	_ resource.ResourceWithConfigValidators = (*certificateAuthorityResource)(nil)
	_ resource.ResourceWithImportState      = (*certificateAuthorityResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*certificateAuthorityResource)(nil)
)

// certificateAuthorityResource issues (and, on import, adopts) a certificate
// authority certificate. With no parent it self-signs a root; with a parent
// certificate and key it signs an intermediate. The issued certificate is held
// entirely in state — there is no external CA to refresh against.
type certificateAuthorityResource struct{}

// NewCertificateAuthorityResource returns the pki_certificate_authority resource.
func NewCertificateAuthorityResource() resource.Resource {
	return &certificateAuthorityResource{}
}

// certificateAuthorityResourceModel is pki_certificate_authority's state model.
//
// The extension blocks are pointers so that "not configured" is distinguishable
// from "configured empty": a nil BasicConstraints means the block was omitted
// (and Create applies the CA default), while a non-nil one holds the configured
// values. The typed extension blocks (basic_constraints, key_usage,
// extended_key_usage, name_constraints) are SingleNestedBlocks, which serialize
// to state as a one-element list; extra_extension is a ListNestedBlock.
type certificateAuthorityResourceModel struct {
	PrivateKeyPEM        types.String `tfsdk:"private_key_pem"`
	ParentCertificatePEM types.String `tfsdk:"parent_certificate_pem"`
	ParentPrivateKeyPEM  types.String `tfsdk:"parent_private_key_pem"`

	Subject *subjectModel `tfsdk:"subject"`
	SAN     *sanModel     `tfsdk:"san"`

	Validity     types.String `tfsdk:"validity"`
	EarlyRenewal types.String `tfsdk:"early_renewal"`
	SerialNumber types.String `tfsdk:"serial_number"`

	BasicConstraints *basicConstraintsModel `tfsdk:"basic_constraints"`
	KeyUsage         *keyUsageModel         `tfsdk:"key_usage"`
	ExtKeyUsage      *extKeyUsageModel      `tfsdk:"extended_key_usage"`
	NameConstraints  *nameConstraintsModel  `tfsdk:"name_constraints"`
	ExtraExtensions  []extraExtensionModel  `tfsdk:"extra_extension"`

	SignatureAlgorithm types.String `tfsdk:"signature_algorithm"`

	CertificatePEM      types.String `tfsdk:"certificate_pem"`
	CertificateChainPEM types.String `tfsdk:"certificate_chain_pem"`
	NotBefore           types.String `tfsdk:"not_before"`
	NotAfter            types.String `tfsdk:"not_after"`
	ReadyForRenewal     types.Bool   `tfsdk:"ready_for_renewal"`
	SubjectKeyID        types.String `tfsdk:"subject_key_id"`
	AuthorityKeyID      types.String `tfsdk:"authority_key_id"`
	ID                  types.String `tfsdk:"id"`
}

func (r *certificateAuthorityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate_authority"
}

func (r *certificateAuthorityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Issues a certificate authority certificate in-process. With no parent " +
			"it self-signs a root; with a parent certificate and key it signs an intermediate under " +
			"that parent. The issued certificate is held in Terraform state — there is no external " +
			"CA service to refresh against, so `terraform plan` after apply is empty until the " +
			"inputs change.\n\n" +
			"Reissue is gated by a plan-time comparison against the certificate in state. A change " +
			"only reissues when it changes the certificate's *content* — the encoded subject, the " +
			"public key, the serial, the validity window, the extensions, or the issuer. Two " +
			"consequences are surprising in a good way: changing `validity` to a different spelling " +
			"of the **same window** (`175320h` vs `7305d`) does not reissue, and changing " +
			"`parent_private_key_pem` (or `private_key_pem`) never reissues at all, because neither " +
			"can be read back from a certificate. A CA key arriving from a rotating Bitwarden " +
			"Secret therefore never forces a re-enrollment of the certificates it signed.\n\n" +
			"Changing any of the cryptographic inputs (`private_key_pem`, `parent_certificate_pem`, " +
			"`parent_private_key_pem`) replaces the certificate. Changing the content inputs " +
			"(`subject`, `san`, `validity`, `serial_number`, the extension blocks) reissues the " +
			"certificate in place via `Update`. The `serial_number` is drawn once at create time " +
			"and then held in state, so reissuing for any other reason keeps the serial stable.\n\n" +
			"This resource is importable. The private key cannot be recovered from a certificate, " +
			"so after import the configuration must supply `private_key_pem`; the first plan will " +
			"show it being set, which does not reissue the certificate. For a byte-exact adoption — " +
			"an empty plan after import — write the `subject` in its **ordered `attribute` form** " +
			"(`subject { attribute { oid = ... } }`); the named-field form reissues on the settling " +
			"apply because Terraform cannot reconcile the block-shape change to a no-op.",
		Attributes: map[string]schema.Attribute{
			"private_key_pem": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				MarkdownDescription: "The private key the certificate is signed with, in any PEM " +
					"encoding `pki_private_key` produces (PKCS#1, SEC1, or PKCS#8). For a " +
					"self-signed root this is the certificate's own key; for an intermediate it is " +
					"the key whose certificate matches `parent_certificate_pem`. Changing this " +
					"value replaces the certificate.",
				PlanModifiers: []planmodifier.String{
					requiresReplaceUnlessStateIsNull(),
				},
			},
			"parent_certificate_pem": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The issuing CA's certificate, as a PEM `CERTIFICATE` block or " +
					"a chain (leaf-adjacent first). Absent means self-signed root. When set, " +
					"`parent_private_key_pem` must also be set, and the two must correspond: the " +
					"key's public key must match the certificate's. Changing this value replaces " +
					"the certificate.",
				PlanModifiers: []planmodifier.String{
					requiresReplaceUnlessStateIsNull(),
				},
			},
			"parent_private_key_pem": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				MarkdownDescription: "The issuing CA's private key, used to sign this certificate. " +
					"Required iff `parent_certificate_pem` is set, and must correspond to it. " +
					"Changing this value replaces the certificate.",
				PlanModifiers: []planmodifier.String{
					requiresReplaceUnlessStateIsNull(),
				},
			},
			"validity": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "How long the certificate is valid for, as a Go duration " +
					"(`175320h`) or an integer count with a `d` (day) or `y` (365-day year) " +
					"suffix (`20y`). The certificate's `notBefore` is the moment of issue, " +
					"truncated to a second, and `notAfter` is `notBefore` plus this duration.",
			},
			"early_renewal": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "How long before `notAfter` the certificate reports " +
					"`ready_for_renewal = true`, in the same duration syntax as `validity`. " +
					"Defaults to zero, which reduces the readiness check to \"has the certificate " +
					"expired\". This is a clock-only signal: it does not by itself reissue anything.",
			},
			"serial_number": schema.StringAttribute{
				Optional: true,
				Computed: true,
				MarkdownDescription: "The certificate's serial number as lowercase hex with no " +
					"`0x` prefix and no leading zeros. A configured value is accepted in any " +
					"spelling pki.ParseSerial understands (`0x` prefix, leading zeros, any case) " +
					"and preserved in state as written; the certificate itself carries the " +
					"canonical parsed value. When omitted, a random 128-bit serial is drawn once " +
					"at create time and then held in state forever — reissuing the certificate " +
					"for any other reason keeps the serial stable.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
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
					"algorithm for the **signing key** is chosen: for a self-signed root that is " +
					"the certificate's own key, for an intermediate it is the parent's key. The " +
					"resolved name is written back to state.",
				// UseStateForUnknown is intentionally absent on the cert-derived Computed
				// attributes below (signature_algorithm, certificate_pem, certificate_chain_pem,
				// not_before, not_after, subject_key_id, authority_key_id, id): ModifyPlan (Task
				// 10) owns the no-drift plan, copying state into plan when the comparison finds no
				// content change. On genuine drift the cert is reissued and these take new values,
				// so the framework must not carry the prior value forward. ready_for_renewal never
				// carried it either. serial_number keeps UseStateForUnknown (it is Optional+
				// Computed; resolveSerial preserves it across plans).
			},
			"certificate_pem": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The issued certificate as a PEM `CERTIFICATE` block.",
			},
			"certificate_chain_pem": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The certificate plus its ancestry, leaf-adjacent first, as " +
					"concatenated PEM `CERTIFICATE` blocks. Null when the certificate is " +
					"self-signed (no parent).",
			},
			"not_before": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate's `notBefore`, RFC 3339 timestamp.",
			},
			"not_after": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate's `notAfter`, RFC 3339 timestamp.",
			},
			"ready_for_renewal": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether the certificate is within the `early_renewal` window " +
					"of `not_after` (or past it). Recomputed on every read, so it flips as " +
					"wall-clock time passes without any change to the configuration — which is " +
					"why this is the one computed attribute that intentionally does not carry " +
					"`UseStateForUnknown`. A clock-only signal; it does not by itself reissue " +
					"anything. ModifyPlan (Task 10) copies state's value into the plan when the " +
					"drift comparison finds no content change, so the absence of UseStateForUnknown " +
					"does not surface as a spurious update.",
			},
			"subject_key_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The `subjectKeyIdentifier` extension's key identifier, " +
					"lowercase hex (the SHA-1 of the public key, per RFC 5280 method 1).",
			},
			"authority_key_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The `authorityKeyIdentifier` extension's key identifier, " +
					"lowercase hex. Null for a self-signed root whose issuer DN equals its subject " +
					"DN, because crypto/x509 omits the extension in that case.",
			},
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The hex-encoded SHA-256 of the certificate's DER — a stable " +
					"identifier for the exact bytes of the certificate, which changes if and only " +
					"if any signed content or the signature itself does.",
			},
		},
		Blocks: map[string]schema.Block{
			"subject":            subjectBlock(),
			"san":                sanBlock(),
			"basic_constraints":  basicConstraintsBlock(true),
			"key_usage":          keyUsageBlock(),
			"extended_key_usage": extendedKeyUsageBlock(),
			"name_constraints":   nameConstraintsBlock(),
			"extra_extension":    extraExtensionBlock(),
		},
	}
}

// caBasicConstraintsBlock and caKeyUsageBlock previously wrapped the shared
// blocks with object plan modifiers to materialize CA defaults when the blocks
// were omitted. Terraform Core rejects that — "planned for existence but config
// wants absence" — because a SingleNestedBlock is config-driven and cannot be
// added to a plan or state that the configuration did not declare. The defaults
// are instead applied during issuance (basicConstraintsValue / keyUsageValue)
// and surfaced in the issued certificate's extensions; the state block reflects
// what the configuration declared, which is null when the block is omitted.
// Task 9's leaf resource applies the same pattern with different defaults.
//
// Serial normalization (rewriting a configured serial_number to canonical hex)
// was attempted both here as a resource.ModifyPlan and as a per-attribute string
// plan modifier. Terraform Core rejects both — "planned value ... does not match
// config value" — because for an Optional+Computed attribute that the
// configuration set, the planned value must equal the configured value. The
// provider therefore preserves the configured spelling verbatim in state and
// parses it for issuance; the issued certificate carries the canonical value.

// ConfigValidators catches the two cross-attribute rules the framework's stock
// validators can express: the parent cert and key must arrive together, and a
// certificate must identify at least one subject (a DN or a subjectAltName).
//
// The subject/san blocks are SingleNestedBlocks, which arrive as null when the
// configuration omits them (measured against OpenTofu 1.12 and framework
// v1.19), so the stock AtLeastOneOf and RequiredTogether validators behave
// correctly on them. This is the sound shape subjectFormsValidator's comment
// points at for later cross-attribute rules.
func (r *certificateAuthorityResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.RequiredTogether(
			path.MatchRoot("parent_certificate_pem"),
			path.MatchRoot("parent_private_key_pem"),
		),
		resourcevalidator.AtLeastOneOf(
			path.MatchRoot("subject"),
			path.MatchRoot("san"),
		),
	}
}

// ModifyPlan is intentionally absent here. Serial normalization (rewriting a
// configured serial_number to canonical hex) is unimplementable for the reason
// above: Terraform Core rejects any provider rewrite of a value the
// configuration set, whether via resource.ModifyPlan or a per-attribute plan
// modifier, so the configured spelling is preserved verbatim and the canonical
// value lives only on the issued certificate (observable through the data
// source). Block defaults cannot be materialized into state for an omitted
// SingleNestedBlock either, so they are applied at issuance, not in a plan
// modifier. Task 10 adds a resource-level ModifyPlan for the drift-detection
// gating that decides whether an in-place Update happens at all; that concern
// is orthogonal to normalization and lands then.

func (r *certificateAuthorityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan certificateAuthorityResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.issue(ctx, &plan, types.StringNull(), time.Now(), &resp.Diagnostics, &resp.State)
}

// Read re-parses certificate_pem from state and recomputes only ready_for_renewal.
// Everything else stays as stored: the certificate cannot change underneath us
// (there is no external CA to refresh against), and re-deriving derived fields
// would risk a spurious diff. ready_for_renewal is the one exception because it
// is a function of the clock — its whole purpose is to flip as wall-clock time
// passes, so it carries no UseStateForUnknown and is recalculated here from
// not_after and early_renewal through pki.CompareValidity.
func (r *certificateAuthorityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state certificateAuthorityResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cert, err := pki.ParseCertificatePEM([]byte(state.CertificatePEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse stored certificate",
			"The certificate in state could not be parsed: "+err.Error())
		return
	}

	var earlyDur time.Duration
	if !state.EarlyRenewal.IsNull() && !state.EarlyRenewal.IsUnknown() {
		ed, d := parseDurationAttr(state.EarlyRenewal, path.Root("early_renewal"))
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		earlyDur = ed
	}

	// CompareValidity now returns (bool, error): a nil actual is a precondition
	// error rather than a panic. actual is non-nil here (parsed above), but the
	// error is still threaded so a future caller cannot drop it silently.
	ready, err := pki.CompareValidity(cert, earlyDur, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute readiness for renewal", err.Error())
		return
	}
	state.ReadyForRenewal = types.BoolValue(ready)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update reissues the certificate in place. It shares issue with Create; the
// only difference is that the serial comes from state unless the configuration
// changed it, which resolveSerial expresses by preferring a configured value
// and falling back to the prior state. This reachability is deliberate and is
// what distinguishes this resource from pki_private_key and pki_cert_request,
// whose Update paths are unreachable because every input requires replacement.
// Task 10 adds the ModifyPlan gating that decides whether an update happens at
// all (by comparing desired content against the issued certificate).
//
// The same no-drift short-circuit as pki_certificate.Update applies here: when
// ModifyPlan's copyComputed has already populated certificate_pem from state,
// the post-import settling apply has reached Update solely to record the
// previously-null private_key_pem (and parent material) from configuration, and
// reissuing would burn a fresh notBefore onto an adopted CA. Writing the plan
// straight back to state preserves the imported cert.
func (r *certificateAuthorityResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan certificateAuthorityResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior certificateAuthorityResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// No-drift signal from ModifyPlan: copyComputed already populated the
	// cert-derived attrs from state. Skip issue() so the imported cert's
	// notBefore (and bytes) survive the settling apply.
	if !plan.CertificatePEM.IsNull() && !plan.CertificatePEM.IsUnknown() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	r.issue(ctx, &plan, prior.SerialNumber, time.Now(), &resp.Diagnostics, &resp.State)
}

// Delete is a no-op; the framework removes the resource from state and there is
// nothing external to tear down.
func (r *certificateAuthorityResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState resolves the import ID, parses the certificate it locates, and
// reconstructs the model from the parsed certificate using the same *FromPKI
// converters the certificate data source uses. The subject is written in the
// ordered `attribute` form (subjectFromPKI), which is the only form that
// reproduces an adopted DN byte-for-byte; Task 10's drift comparison is on
// encoded DN bytes rather than block shape, so a hand-written named-field
// configuration still plans clean against imported ordered-form state.
//
// private_key_pem cannot be recovered from a certificate and is left null; the
// resource description documents that the configuration must supply it and that
// the first plan after import shows it being set, which does not reissue the
// certificate (Task 10's comparison excludes it). early_renewal is also left
// null: it is not a property of the certificate, and the readiness check
// reduces to "has the certificate expired" until configuration sets a window.
func (r *certificateAuthorityResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	pemBytes, err := resolveImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to resolve import ID", err.Error())
		return
	}

	cert, err := pki.ParseCertificatePEM(pemBytes)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate", err.Error())
		return
	}

	var model certificateAuthorityResourceModel

	subject, err := pki.ParseSubjectDER(cert.RawSubject)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate subject", err.Error())
		return
	}
	s := subjectFromPKI(subject)
	model.Subject = &s

	model.SerialNumber = types.StringValue(pki.FormatSerial(cert.SerialNumber))
	model.Validity = types.StringValue(fmt.Sprintf("%dh", int(cert.NotAfter.Sub(cert.NotBefore).Hours())))
	model.NotBefore = types.StringValue(cert.NotBefore.Format(time.RFC3339))
	model.NotAfter = types.StringValue(cert.NotAfter.Format(time.RFC3339))

	// signature_algorithm: read back from the parsed certificate so the
	// imported state reflects what was signed. An unsupported algorithm is
	// still reported as data rather than failing the import.
	if name, err := pki.SignatureAlgorithmName(cert.SignatureAlgorithm); err == nil {
		model.SignatureAlgorithm = types.StringValue(name)
	} else {
		model.SignatureAlgorithm = types.StringValue(fmt.Sprintf("%v", cert.SignatureAlgorithm))
	}

	model.CertificatePEM = types.StringValue(string(pki.EncodeCertificatePEM(cert.Raw)))
	// The chain is null on import: only the single certificate was located, and
	// the parentage cannot be reconstructed from a certificate alone. Operators
	// importing a full chain do so one certificate at a time.
	model.CertificateChainPEM = types.StringNull()
	model.PrivateKeyPEM = types.StringNull()
	model.ParentCertificatePEM = types.StringNull()
	model.ParentPrivateKeyPEM = types.StringNull()

	if len(cert.SubjectKeyId) > 0 {
		model.SubjectKeyID = types.StringValue(hex.EncodeToString(cert.SubjectKeyId))
	} else {
		model.SubjectKeyID = types.StringNull()
	}
	if len(cert.AuthorityKeyId) > 0 {
		model.AuthorityKeyID = types.StringValue(hex.EncodeToString(cert.AuthorityKeyId))
	} else {
		model.AuthorityKeyID = types.StringNull()
	}

	// ready_for_renewal: with no configured early_renewal the check reduces to
	// "has the certificate expired".
	ready, err := pki.CompareValidity(cert, 0, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute readiness for renewal", err.Error())
		return
	}
	model.ReadyForRenewal = types.BoolValue(ready)

	// Walk the extensions once, dispatching by OID to the typed converters and
	// collecting anything left over into extra_extension blocks. The typed OIDs
	// and subjectKeyIdentifier/authorityKeyIdentifier are excluded from the
	// leftovers because the typed blocks and computed attributes already cover
	// them.
	sanOID, _ := pki.ParseOID("2.5.29.17")
	bcOID, _ := pki.ParseOID("2.5.29.19")
	kuOID, _ := pki.ParseOID("2.5.29.15")
	ekuOID, _ := pki.ParseOID("2.5.29.37")
	ncOID, _ := pki.ParseOID("2.5.29.30")
	skiOID, _ := pki.ParseOID("2.5.29.14")
	akiOID, _ := pki.ParseOID("2.5.29.35")

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(sanOID):
			s, parseErr := pki.ParseSANExtension(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse subjectAltName extension", parseErr.Error())
				return
			}
			model.SAN = sanFromPKI(s)
		case ext.Id.Equal(bcOID):
			bc, parseErr := pki.ParseBasicConstraints(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse basicConstraints extension", parseErr.Error())
				return
			}
			model.BasicConstraints = basicConstraintsFromPKI(bc)
		case ext.Id.Equal(kuOID):
			ku, parseErr := pki.ParseKeyUsage(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse keyUsage extension", parseErr.Error())
				return
			}
			model.KeyUsage = keyUsageFromPKI(ku)
		case ext.Id.Equal(ekuOID):
			eku, parseErr := pki.ParseExtKeyUsage(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse extendedKeyUsage extension", parseErr.Error())
				return
			}
			model.ExtKeyUsage = extKeyUsageFromPKI(eku)
		case ext.Id.Equal(ncOID):
			nc, parseErr := pki.ParseNameConstraints(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse nameConstraints extension", parseErr.Error())
				return
			}
			model.NameConstraints = nameConstraintsFromPKI(nc)
		case ext.Id.Equal(skiOID), ext.Id.Equal(akiOID):
			// Surfaced via subject_key_id / authority_key_id; not an extra.
		default:
			model.ExtraExtensions = append(model.ExtraExtensions, extraExtensionFromPKI(pki.ExtraExtension{
				OID:      ext.Id,
				Value:    ext.Value,
				Critical: ext.Critical,
			}))
		}
	}

	der := cert.Raw
	sum := sha256.Sum256(der)
	model.ID = types.StringValue(hex.EncodeToString(sum[:]))

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

// issue holds the shared create-and-reissue logic. now is passed in (rather than
// read inside) so the few unit tests that need to exercise this path could
// inject a fixed clock; in practice both callers pass time.Now(). priorSerial
// is the serial held in state (null for Create), used by resolveSerial when the
// configuration does not name one.
//
// The plan is mutated in place: block defaults that the configuration omits
// (basic_constraints → {ca:true, critical:true}, key_usage → the CA default) are
// resolved here rather than at the schema level, because a block has no Default,
// and the resolved values are written back so state shows the block populated
// rather than null.
func (r *certificateAuthorityResource) issue(
	ctx context.Context,
	plan *certificateAuthorityResourceModel,
	priorSerial types.String,
	now time.Time,
	diags *diag.Diagnostics,
	stateOut interface {
		Set(ctx context.Context, v interface{}) diag.Diagnostics
	},
) {
	// 1. Parse the subject key. ParsePrivateKeyPEM's errors are structural and
	// never echo key bytes, so err.Error() is safe to surface at the attribute.
	subjectKey, err := pki.ParsePrivateKeyPEM([]byte(plan.PrivateKeyPEM.ValueString()))
	if err != nil {
		diags.AddAttributeError(path.Root("private_key_pem"),
			"Unable to parse private key",
			"The private key could not be parsed as PKCS#8, PKCS#1, or SEC1: "+err.Error())
		return
	}

	// 2. Resolve the parent. Absent means self-signed root. When present, parse
	// the chain (single or multi) and verify the parent key matches the parent
	// certificate — a crossed reference here produces a chain that verifies
	// nowhere, and catching it at apply time with a clear message is far
	// cheaper than debugging it later.
	var parent *x509.Certificate
	var parentChain []*x509.Certificate
	// signerKey is the key that signs the certificate: the subject key for a
	// self-signed root, the parent key for an intermediate. It starts as the
	// subject key and is reassigned only when a parent is configured.
	signerKey := subjectKey
	hasParent := !plan.ParentCertificatePEM.IsNull() && !plan.ParentCertificatePEM.IsUnknown()
	if hasParent {
		parentChain, err = pki.ParseCertificateChainPEM([]byte(plan.ParentCertificatePEM.ValueString()))
		if err != nil {
			diags.AddAttributeError(path.Root("parent_certificate_pem"),
				"Unable to parse parent certificate", err.Error())
			return
		}
		parent = parentChain[0]

		parentKey, parseErr := pki.ParsePrivateKeyPEM([]byte(plan.ParentPrivateKeyPEM.ValueString()))
		if parseErr != nil {
			diags.AddAttributeError(path.Root("parent_private_key_pem"),
				"Unable to parse parent private key",
				"The parent private key could not be parsed as PKCS#8, PKCS#1, or SEC1: "+parseErr.Error())
			return
		}
		if !pki.PublicKeysEqual(parent.PublicKey, parentKey.Public()) {
			// Naming the value would echo key material; name the two attributes.
			diags.AddAttributeError(path.Root("parent_private_key_pem"),
				"Parent key does not match parent certificate",
				"The parent_private_key_pem does not correspond to parent_certificate_pem: its "+
					"public key does not match the certificate's. A chain signed with this key "+
					"combination would verify nowhere.")
			return
		}
		signerKey = parentKey
	}

	// 3. Resolve validity. Truncating notBefore to a second matters: DER encodes
	// UTCTime at second granularity, so an untruncated notBefore would not
	// survive parse-and-compare and the drift check would fire on every plan.
	notBefore, notAfter, ready, d := issuanceValidity(plan.Validity, plan.EarlyRenewal, now, path.Root("validity"))
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	// 4. Resolve the serial. Configured wins; otherwise the prior state's serial
	// is reused; otherwise a fresh random one is drawn. A configured value is
	// preserved in state verbatim — Terraform Core requires the planned value
	// of a config-set Optional+Computed attribute to equal the configured
	// value, so normalizing it in state would surface as an inconsistent result
	// after apply. A drawn or reused serial is written in the canonical form.
	serial, d := resolveSerial(plan.SerialNumber, priorSerial, path.Root("serial_number"))
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	if plan.SerialNumber.IsNull() || plan.SerialNumber.IsUnknown() {
		plan.SerialNumber = types.StringValue(pki.FormatSerial(serial))
	}

	// 5. Convert the blocks. Each attaches its own diagnostics at the offending
	// attribute. basic_constraints and key_usage apply the CA defaults when
	// their blocks are absent.
	var subject pki.Subject
	if plan.Subject != nil {
		s, d := plan.Subject.toPKI(ctx, path.Root("subject"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		subject = s
	}

	var san pki.SAN
	if plan.SAN != nil {
		s, d := plan.SAN.toPKI(ctx, path.Root("san"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		san = s
	}

	// basic_constraints and key_usage apply the CA defaults when their blocks
	// are omitted, so the issued certificate always carries them. The state
	// block reflects what the configuration declared: a configured block is
	// written back with the resolved inner values (a self-check against the
	// issued certificate), and an omitted block stays null. Terraform Core
	// forbids materializing an omitted block into plan or state.
	bcConfigured := plan.BasicConstraints != nil
	bc, d := basicConstraintsValue(plan.BasicConstraints)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	if bcConfigured {
		plan.BasicConstraints = basicConstraintsFromPKI(bc)
	}

	kuConfigured := plan.KeyUsage != nil
	ku, d := keyUsageValue(ctx, plan.KeyUsage)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	if kuConfigured {
		plan.KeyUsage = keyUsageFromPKI(ku)
	}

	var eku *pki.ExtKeyUsage
	if plan.ExtKeyUsage != nil {
		e, d := plan.ExtKeyUsage.toPKI(ctx, path.Root("extended_key_usage"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		eku = &e
	}

	var nc *pki.NameConstraints
	if plan.NameConstraints != nil {
		n, d := plan.NameConstraints.toPKI(ctx, path.Root("name_constraints"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		nc = &n
	}

	extras := make([]pki.ExtraExtension, 0, len(plan.ExtraExtensions))
	for i, em := range plan.ExtraExtensions {
		e, d := em.toPKI(path.Root("extra_extension").AtListIndex(i))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		extras = append(extras, e)
	}

	// 6. Resolve signature_algorithm. A zero value means "pick the conventional
	// one for the signing key" (the subject's key for a root, the parent's key
	// for an intermediate); the resolved name is read back from the issued
	// certificate below.
	var sigAlg x509.SignatureAlgorithm
	if !plan.SignatureAlgorithm.IsNull() && !plan.SignatureAlgorithm.IsUnknown() {
		a, err := pki.SignatureAlgorithmByName(plan.SignatureAlgorithm.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("signature_algorithm"), "Unknown signature algorithm", err.Error())
			return
		}
		sigAlg = a
	}

	tpl := pki.CertTemplate{
		Subject:            subject,
		SAN:                san,
		Serial:             serial,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		BasicConstraints:   &bc,
		KeyUsage:           &ku,
		ExtKeyUsage:        eku,
		NameConstraints:    nc,
		ExtraExtensions:    extras,
		SignatureAlgorithm: sigAlg,
	}

	// pub is always the SUBJECT key's public key — the key the certificate is
	// for — regardless of whether the signer is that key (self-signed root) or
	// the parent key (intermediate). signerKey was resolved above.
	certPEM, err := pki.CreateCertificate(tpl, pki.PublicKeyOf(subjectKey), parent, signerKey)
	if err != nil {
		diags.AddError("Unable to create certificate", err.Error())
		return
	}

	plan.CertificatePEM = types.StringValue(string(certPEM))

	// certificate_chain_pem: this certificate plus the parent chain (which is
	// nil for a self-signed root), leaf-adjacent first. Null when self-signed.
	if hasParent {
		chainPEM := certPEM
		for _, c := range parentChain {
			chainPEM = append(chainPEM, pki.EncodeCertificatePEM(c.Raw)...)
		}
		plan.CertificateChainPEM = types.StringValue(string(chainPEM))
	} else {
		plan.CertificateChainPEM = types.StringNull()
	}

	// 7. Parse the result back and set the derived fields from the parsed
	// certificate rather than from the template. Reading them back is a
	// self-check that costs one parse and catches any divergence between what
	// was requested and what was signed.
	parsed, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		diags.AddError("Unable to parse issued certificate", err.Error())
		return
	}
	plan.NotBefore = types.StringValue(parsed.NotBefore.Format(time.RFC3339))
	plan.NotAfter = types.StringValue(parsed.NotAfter.Format(time.RFC3339))
	if len(parsed.SubjectKeyId) > 0 {
		plan.SubjectKeyID = types.StringValue(hex.EncodeToString(parsed.SubjectKeyId))
	} else {
		plan.SubjectKeyID = types.StringNull()
	}
	if len(parsed.AuthorityKeyId) > 0 {
		plan.AuthorityKeyID = types.StringValue(hex.EncodeToString(parsed.AuthorityKeyId))
	} else {
		plan.AuthorityKeyID = types.StringNull()
	}
	if name, err := pki.SignatureAlgorithmName(parsed.SignatureAlgorithm); err == nil {
		plan.SignatureAlgorithm = types.StringValue(name)
	} else {
		plan.SignatureAlgorithm = types.StringValue(fmt.Sprintf("%v", parsed.SignatureAlgorithm))
	}
	sum := sha256.Sum256(parsed.Raw)
	plan.ID = types.StringValue(hex.EncodeToString(sum[:]))
	plan.ReadyForRenewal = types.BoolValue(ready)

	diags.Append(stateOut.Set(ctx, plan)...)
}

// buildDesired assembles the certificate template the plan is asking for, plus
// the public key it is for and the CA certificate that signs it (the parent, or
// nil for a self-signed root). It mirrors issue()'s template construction
// exactly, with two differences that matter for the drift comparison: it does
// not issue (no CreateCertificate, no state write), and the desired NotBefore
// comes from STATE (desiredNotBefore) rather than time.Now, with NotAfter =
// desiredNotBefore.Add(validity). That is what makes a rewritten-but-equivalent
// validity ("175320h" vs "7305d") compare equal: both produce the same NotAfter
// against the same NotBefore. caCert is the parent so pki.CompareCertificate
// verifies the stored certificate's signature against the right issuer; nil for
// a root means the comparison treats it as self-signed.
func (r *certificateAuthorityResource) buildDesired(
	ctx context.Context,
	plan *certificateAuthorityResourceModel,
	desiredNotBefore time.Time,
	priorSerial types.String,
) (tpl pki.CertTemplate, pub crypto.PublicKey, caCert *x509.Certificate, diags diag.Diagnostics) {
	subjectKey, err := pki.ParsePrivateKeyPEM([]byte(plan.PrivateKeyPEM.ValueString()))
	if err != nil {
		diags.AddAttributeError(path.Root("private_key_pem"),
			"Unable to parse private key",
			"The private key could not be parsed as PKCS#8, PKCS#1, or SEC1: "+err.Error())
		return tpl, nil, nil, diags
	}
	pub = pki.PublicKeyOf(subjectKey)

	if !plan.ParentCertificatePEM.IsNull() && !plan.ParentCertificatePEM.IsUnknown() {
		parentChain, parseErr := pki.ParseCertificateChainPEM([]byte(plan.ParentCertificatePEM.ValueString()))
		if parseErr != nil {
			diags.AddAttributeError(path.Root("parent_certificate_pem"),
				"Unable to parse parent certificate", parseErr.Error())
			return tpl, nil, nil, diags
		}
		caCert = parentChain[0]
		// The parent private key is not needed for the comparison (CompareCertificate
		// verifies against caCert.PublicKey), so it is not parsed here. A mismatched
		// parent key is an issuance concern that Update will surface, not a drift one.
	}

	var subject pki.Subject
	if plan.Subject != nil {
		s, d := plan.Subject.toPKI(ctx, path.Root("subject"))
		diags.Append(d...)
		if diags.HasError() {
			return tpl, nil, nil, diags
		}
		subject = s
	}

	var san pki.SAN
	if plan.SAN != nil {
		s, d := plan.SAN.toPKI(ctx, path.Root("san"))
		diags.Append(d...)
		if diags.HasError() {
			return tpl, nil, nil, diags
		}
		san = s
	}

	bc, d := basicConstraintsValue(plan.BasicConstraints)
	diags.Append(d...)
	if diags.HasError() {
		return tpl, nil, nil, diags
	}

	ku, d := keyUsageValue(ctx, plan.KeyUsage)
	diags.Append(d...)
	if diags.HasError() {
		return tpl, nil, nil, diags
	}

	var eku *pki.ExtKeyUsage
	if plan.ExtKeyUsage != nil {
		e, d := plan.ExtKeyUsage.toPKI(ctx, path.Root("extended_key_usage"))
		diags.Append(d...)
		if diags.HasError() {
			return tpl, nil, nil, diags
		}
		eku = &e
	}

	var nc *pki.NameConstraints
	if plan.NameConstraints != nil {
		n, d := plan.NameConstraints.toPKI(ctx, path.Root("name_constraints"))
		diags.Append(d...)
		if diags.HasError() {
			return tpl, nil, nil, diags
		}
		nc = &n
	}

	extras := make([]pki.ExtraExtension, 0, len(plan.ExtraExtensions))
	for i, em := range plan.ExtraExtensions {
		e, d := em.toPKI(path.Root("extra_extension").AtListIndex(i))
		diags.Append(d...)
		if diags.HasError() {
			return tpl, nil, nil, diags
		}
		extras = append(extras, e)
	}

	validDur, d := parseDurationAttr(plan.Validity, path.Root("validity"))
	diags.Append(d...)
	if diags.HasError() {
		return tpl, nil, nil, diags
	}
	notAfter := desiredNotBefore.Add(validDur)

	serial, d := resolveSerial(plan.SerialNumber, priorSerial, path.Root("serial_number"))
	diags.Append(d...)
	if diags.HasError() {
		return tpl, nil, nil, diags
	}

	var sigAlg x509.SignatureAlgorithm
	if !plan.SignatureAlgorithm.IsNull() && !plan.SignatureAlgorithm.IsUnknown() {
		a, err := pki.SignatureAlgorithmByName(plan.SignatureAlgorithm.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("signature_algorithm"), "Unknown signature algorithm", err.Error())
			return tpl, nil, nil, diags
		}
		sigAlg = a
	}

	tpl = pki.CertTemplate{
		Subject:            subject,
		SAN:                san,
		Serial:             serial,
		NotBefore:          desiredNotBefore,
		NotAfter:           notAfter,
		BasicConstraints:   &bc,
		KeyUsage:           &ku,
		ExtKeyUsage:        eku,
		NameConstraints:    nc,
		ExtraExtensions:    extras,
		SignatureAlgorithm: sigAlg,
	}
	return tpl, pub, caCert, diags
}

// ModifyPlan is the gate that decides whether Update reissues at all. See
// modifyCertificatePlan (certdrift.go) and the resource description for the
// consequences. The build closure mirrors issue()'s template construction via
// buildDesired, and copyComputed turns a no-drift plan into a genuine Noop by
// carrying state's cert-derived Computed values forward (guarded against Core
// rejecting a Noop when a block's shape changed, exactly as the leaf resource
// does).
func (r *certificateAuthorityResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	stateNotBefore, ok := stateNotBefore(ctx, req, resp)
	if !ok {
		return
	}

	build := func() (pki.CertTemplate, crypto.PublicKey, *x509.Certificate, diag.Diagnostics) {
		var plan certificateAuthorityResourceModel
		var diags diag.Diagnostics
		diags.Append(req.Plan.Get(ctx, &plan)...)
		if diags.HasError() {
			return pki.CertTemplate{}, nil, nil, diags
		}
		var prior certificateAuthorityResourceModel
		diags.Append(req.State.Get(ctx, &prior)...)
		if diags.HasError() {
			return pki.CertTemplate{}, nil, nil, diags
		}
		tpl, pub, caCert, buildDiags := r.buildDesired(ctx, &plan, stateNotBefore, prior.SerialNumber)
		diags.Append(buildDiags...)
		if diags.HasError() {
			return pki.CertTemplate{}, nil, nil, diags
		}
		return tpl, pub, caCert, diags
	}

	copyComputed := func() {
		var plan, state certificateAuthorityResourceModel
		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		// Guard: copyComputed can only suppress the plan when the framework-level
		// diff on the uncopiable blocks is absent. A subject block that switched
		// between the named-field form and the ordered `attribute` form (or any
		// other block-shape change) cannot be reconciled to a Noop — Update fires,
		// the cert is reissued, and the cert-derived Computed attrs take new
		// values. Copying state's cert values into plan in that case would lie to
		// Core and trigger an "inconsistent result after apply". Mirrors the leaf.
		if !reflect.DeepEqual(plan.Subject, state.Subject) ||
			!reflect.DeepEqual(plan.SAN, state.SAN) ||
			!reflect.DeepEqual(plan.BasicConstraints, state.BasicConstraints) ||
			!reflect.DeepEqual(plan.KeyUsage, state.KeyUsage) ||
			!reflect.DeepEqual(plan.ExtKeyUsage, state.ExtKeyUsage) ||
			!reflect.DeepEqual(plan.NameConstraints, state.NameConstraints) ||
			!reflect.DeepEqual(plan.ExtraExtensions, state.ExtraExtensions) {
			return
		}
		plan.CertificatePEM = state.CertificatePEM
		plan.CertificateChainPEM = state.CertificateChainPEM
		plan.NotBefore = state.NotBefore
		plan.NotAfter = state.NotAfter
		plan.SubjectKeyID = state.SubjectKeyID
		plan.AuthorityKeyID = state.AuthorityKeyID
		plan.SignatureAlgorithm = state.SignatureAlgorithm
		plan.ID = state.ID
		plan.ReadyForRenewal = state.ReadyForRenewal
		if plan.SerialNumber.IsNull() || plan.SerialNumber.IsUnknown() {
			plan.SerialNumber = state.SerialNumber
		}
		// Carry validity and early_renewal from state so a rewritten-but-
		// equivalent expression does not surface as a plan diff.
		plan.Validity = state.Validity
		plan.EarlyRenewal = state.EarlyRenewal
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
	}

	modifyCertificatePlan(ctx, req, resp, build, copyComputed)
}

// issuanceValidity resolves the validity window and the renewal-readiness flag
// from the validity and early_renewal attributes. It is shared by Tasks 8 and 9
// (the certificate authority and leaf certificate resources).
//
// notBefore is now truncated to a second because DER UTCTime is second-granular:
// an untruncated value would not survive parse-and-compare and the drift check
// would fire on every plan.
//
// readiness is computed through pki.CompareValidity so this code and the Read
// path share a single source of truth for the formula. The synthesized
// certificate carries only the NotAfter the formula reads — at create time no
// certificate exists yet, and the issued certificate's NotAfter is the
// notBefore-plus-validity computed here.
// issuanceValidity parses validity and early_renewal, computes the issuance
// window, and reports ready_for_renewal. p is the path of the validity
// attribute (the caller passes path.Root("validity")); early_renewal is a
// separate top-level attribute, so its diagnostics carry path.Root("early_renewal")
// directly. Using p.AtName("...") here produced validity.validity and
// validity.early_renewal -- paths to attributes that do not exist, inherited
// by Task 9 when it reuses this helper.
func issuanceValidity(validity, earlyRenewal types.String, now time.Time, p path.Path) (notBefore, notAfter time.Time, ready bool, diags diag.Diagnostics) {
	validDur, d := parseDurationAttr(validity, p)
	diags.Append(d...)
	if diags.HasError() {
		return time.Time{}, time.Time{}, false, diags
	}

	var earlyDur time.Duration
	if !earlyRenewal.IsNull() && !earlyRenewal.IsUnknown() {
		earlyDur, d = parseDurationAttr(earlyRenewal, path.Root("early_renewal"))
		diags.Append(d...)
		if diags.HasError() {
			return time.Time{}, time.Time{}, false, diags
		}
	}

	notBefore = now.UTC().Truncate(time.Second)
	notAfter = notBefore.Add(validDur)

	readyForRenewal, err := pki.CompareValidity(&x509.Certificate{NotAfter: notAfter}, earlyDur, now)
	if err != nil {
		diags.AddAttributeError(p, "Unable to compute readiness for renewal", err.Error())
		return time.Time{}, time.Time{}, false, diags
	}
	return notBefore, notAfter, readyForRenewal, diags
}

// resolveSerial picks the serial number: a configured value wins, then the
// prior state's value, then a fresh random draw. Configured and state values
// are both normalized through ParseSerial so the canonical spelling is what
// reaches the template. It is shared by Tasks 8 and 9.
func resolveSerial(configured, state types.String, p path.Path) (*big.Int, diag.Diagnostics) {
	var diags diag.Diagnostics
	if !configured.IsNull() && !configured.IsUnknown() {
		n, err := pki.ParseSerial(configured.ValueString())
		if err != nil {
			diags.AddAttributeError(p, "Invalid serial number", err.Error())
			return nil, diags
		}
		return n, diags
	}
	if !state.IsNull() && !state.IsUnknown() {
		n, err := pki.ParseSerial(state.ValueString())
		if err != nil {
			diags.AddAttributeError(p, "Invalid serial number in state", err.Error())
			return nil, diags
		}
		return n, diags
	}
	n, err := pki.RandomSerial()
	if err != nil {
		diags.AddAttributeError(p, "Unable to generate serial number", err.Error())
		return nil, diags
	}
	return n, diags
}

// basicConstraintsValue converts the configured block, applying the CA default
// (ca = true, critical = true) when the block is omitted. The default cannot be
// a schema-level Default because a block has no Default — it is resolved here.
func basicConstraintsValue(m *basicConstraintsModel) (pki.BasicConstraints, diag.Diagnostics) {
	if m == nil {
		return pki.BasicConstraints{CA: true, Critical: true}, nil
	}
	return m.toPKI(path.Root("basic_constraints"))
}

// keyUsageValue converts the configured block, applying the CA default
// (keyCertSign, crlSign, critical) when the block is omitted.
func keyUsageValue(ctx context.Context, m *keyUsageModel) (pki.KeyUsage, diag.Diagnostics) {
	if m == nil {
		return pki.DefaultCAKeyUsage(), nil
	}
	return m.toPKI(ctx, path.Root("key_usage"))
}
