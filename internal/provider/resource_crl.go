// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var (
	_ resource.Resource               = (*crlResource)(nil)
	_ resource.ResourceWithModifyPlan = (*crlResource)(nil)
)

// crlResource issues a Certificate Revocation List signed by a CA supplied as
// bare PEM. The CRL is regenerated wholesale whenever any input changes; there
// is no in-place update vs. replace distinction the way there is for the
// certificate resources, because a CRL carries no long-lived identity a
// replace would disrupt.
type crlResource struct{}

// NewCRLResource returns the pki_crl resource.
func NewCRLResource() resource.Resource {
	return &crlResource{}
}

// crlResourceModel is pki_crl's state model.
//
// Number is the cRLNumber extension RFC 5280 requires to monotonically
// increase across regenerations of the same CRL. The provider reads it from
// state in Update, adds one, and writes the new value back; it is therefore
// Computed with no UseStateForUnknown, since carrying the prior value forward
// would suppress the increment.
type crlResourceModel struct {
	CACertificatePEM types.String `tfsdk:"ca_certificate_pem"`
	CAPrivateKeyPEM  types.String `tfsdk:"ca_private_key_pem"`

	NextUpdate      types.String `tfsdk:"next_update"`
	EarlyRegenerate types.String `tfsdk:"early_regenerate"`

	Revoked []revokedEntryModel `tfsdk:"revoked"`

	SignatureAlgorithm types.String `tfsdk:"signature_algorithm"`

	Number               types.Int64  `tfsdk:"number"`
	CRLPEM               types.String `tfsdk:"crl_pem"`
	CRLBase64            types.String `tfsdk:"crl_base64"`
	ThisUpdate           types.String `tfsdk:"this_update"`
	NextUpdateTime       types.String `tfsdk:"next_update_time"`
	ReadyForRegeneration types.Bool   `tfsdk:"ready_for_regeneration"`
	ID                   types.String `tfsdk:"id"`
}

// revokedEntryModel is one entry in the revoked block.
//
// revoked_at is Optional + Computed with UseNonNullStateForUnknown so an
// omitted timestamp is filled in on first apply and then preserved from state
// across later plans — that is the mechanism behind TestAccCRLRevokedAtIsStable.
// UseNonNullStateForUnknown (not UseStateForUnknown) is the variant that
// copies state's value ONLY when state is non-null: when a brand-new revoked
// entry is appended, state has nothing at that list position, and the
// modifier correctly leaves the plan Unknown for the provider to compose.
// Because revoked is a ListNestedBlock, the state-preservation is POSITIONAL:
// reordering the blocks, or inserting one near the top, reshuffles which
// configured entry inherits the prior defaulted timestamp. Supply revoked_at
// explicitly when positional stability matters.
type revokedEntryModel struct {
	SerialNumber types.String `tfsdk:"serial_number"`
	Reason       types.String `tfsdk:"reason"`
	RevokedAt    types.String `tfsdk:"revoked_at"`
}

func (r *crlResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_crl"
}

func (r *crlResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Issues a Certificate Revocation List (CRL) signed by a CA supplied as bare PEM, " +
			"listing the serial numbers its certificates have been revoked under. The CRL is regenerated " +
			"wholesale whenever any input changes, and `number` (the cRLNumber extension RFC 5280 requires " +
			"to monotonically increase) increments on each regeneration.\n\n" +
			"The staleness signal that the 6-hourly `pki-crl-refresh` CronJob used to own now lives in " +
			"`ready_for_regeneration`: a periodic `tofu apply` is still what actually regenerates the CRL, " +
			"but the operator sees the resource drift when the CRL is within `early_regenerate` of " +
			"`next_update_time` (or past it). A CRL past `next_update_time` is stale; regenerating on every " +
			"read would be the rotation-on-every-plan bug, so `next_update_time` is held stable from the " +
			"moment of issue and only `ready_for_regeneration` recomputes with the clock.\n\n" +
			"This resource is NOT importable. A CRL is regenerable from the CA key plus the revocation " +
			"list, so adopting one has no value, and a CRL of unknown provenance is a security risk — " +
			"the very thing this provider exists to eliminate. Reissue by configuring the resource instead.",
		Attributes: map[string]schema.Attribute{
			"ca_certificate_pem": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The issuing CA's certificate, as a PEM `CERTIFICATE` block or a chain " +
					"(leaf-adjacent first). The CA must carry `crlSign` in its keyUsage extension and a " +
					"subjectKeyIdentifier (both of which this provider always emits on a CA it issues); " +
					"Go's `x509.CreateRevocationList` enforces both, where cfssl enforced neither, and the " +
					"externally-owned Bitwarden CA cannot be inspected before apply. The diagnostic names " +
					"`crlSign` so a migration off cfssl fails with an actionable message rather than a " +
					"generic standard-library error.",
			},
			"ca_private_key_pem": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				MarkdownDescription: "The CA's private key, in any PEM encoding `pki_private_key` produces " +
					"(PKCS#1, SEC1, or PKCS#8). Its public key must match `ca_certificate_pem`. Errors name " +
					"this attribute rather than echoing key material.",
			},
			"next_update": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "How long the CRL claims freshness for, as a Go duration (`168h`) or " +
					"an integer count with a `d` (day) or `y` (365-day year) suffix (`90d`). " +
					"`next_update_time` is the absolute timestamp this resolves to at issue time, held " +
					"stable thereafter.",
			},
			"early_regenerate": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "How long before `next_update_time` the resource reports " +
					"`ready_for_regeneration = true`, in the same duration syntax as `next_update`. " +
					"Defaults to zero, which reduces the readiness check to \"has the CRL expired\". " +
					"A clock-only signal: it does not by itself regenerate anything.",
			},
			"signature_algorithm": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(pki.SignatureAlgorithmNames()...),
				},
				MarkdownDescription: "The signature algorithm, one of " +
					quotedList(pki.SignatureAlgorithmNames()) + ". When omitted, the conventional " +
					"algorithm for the **signing key** is chosen. The resolved name is written back to " +
					"state.",
				// No UseStateForUnknown: ModifyPlan (crlDrifts) owns the no-drift
				// plan, copying state's resolved value in when inputs are unchanged.
				// On drift, this attribute stays Unknown so Update can compose a
				// fresh value without tripping "inconsistent result after apply".
			},
			"number": schema.Int64Attribute{
				Computed: true,
				MarkdownDescription: "The cRLNumber extension RFC 5280 requires to monotonically increase " +
					"across regenerations of the same CRL. Starts at 1 on first issue and increments by " +
					"one on every regeneration. Carries no `UseStateForUnknown` on purpose: copying the " +
					"prior value into the plan would suppress the increment that is this attribute's " +
					"entire job.",
			},
			"crl_pem": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The issued CRL as a PEM `X509 CRL` block.",
				// No UseStateForUnknown: see signature_algorithm. ModifyPlan owns
				// the no-drift carry-forward so that Update is free to compose a
				// fresh CRL on actual input change.
			},
			"crl_base64": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Base64 (standard alphabet) of the **PEM** bytes in `crl_pem` — not " +
					"of the DER. The attribute exists to feed `kubernetes_secret.binary_data` directly " +
					"(via `content_base64`), whose consumers expect a PEM file; base64-of-DER would be a " +
					"reasonable alternative reading and getting it wrong silently produces a file Envoy " +
					"cannot load.",
			},
			"this_update": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The CRL's `thisUpdate`, RFC 3339 timestamp. Set at issue time and " +
					"held stable thereafter.",
			},
			"next_update_time": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The CRL's `nextUpdate`, RFC 3339 timestamp. Set at issue time from " +
					"`this_update + next_update` and held stable thereafter; advancing wall-clock does NOT " +
					"recompute it. `ready_for_regeneration` is the clock-driven signal; this attribute is " +
					"the fixed horizon the signal measures against.",
			},
			"ready_for_regeneration": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether the CRL is within `early_regenerate` of `next_update_time` " +
					"(or past it). Recomputed on every read, so it flips as wall-clock time passes " +
					"without any change to the configuration — which is why this is the one computed " +
					"attribute that intentionally does not carry `UseStateForUnknown`. A clock-only " +
					"signal; it does not by itself regenerate anything.",
			},
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The hex-encoded SHA-256 of the CRL's DER — a stable identifier for " +
					"the exact bytes of the CRL, which changes if and only if any signed content or the " +
					"signature itself does.",
			},
		},
		Blocks: map[string]schema.Block{
			"revoked": schema.ListNestedBlock{
				MarkdownDescription: "One revoked certificate, identified by serial number. Repeatable; " +
					"order is significant for `revoked_at` stability (see that attribute). A duplicate " +
					"serial — including the same value in a different surface form, so `\"2001\"` and " +
					"`\"0x2001\"` collide — is rejected at apply.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"serial_number": schema.StringAttribute{
							Required: true,
							MarkdownDescription: "The revoked certificate's serial number, accepted in " +
								"any spelling `pki.ParseSerial` understands (`0x` prefix, leading zeros, " +
								"any case). Configured spelling is preserved in state verbatim — the " +
								"framework's \"planned value must match config\" rule forbids the provider " +
								"from rewriting it (the same constraint the certificate resources note), " +
								"and the canonical form lives on the CRL itself, observable through " +
								"`crl_pem`. A `0x` prefix is therefore NOT normalized away in state the " +
								"way the plan's comment suggested; it round-trips as written.",
						},
						"reason": schema.StringAttribute{
							Optional: true,
							Validators: []validator.String{
								stringvalidator.OneOf(pki.ReasonNames()...),
							},
							MarkdownDescription: "The RFC 5280 5.3.1 reason code, one of " +
								quotedList(pki.ReasonNames()) + ". Listed in numeric-code order rather " +
								"than alphabetically so generated documentation reads the way the RFC " +
								"does. Omitting it leaves the extension absent, which is the RFC-correct " +
								"encoding for \"no reason given\" and is what cfssl emitted too.",
						},
						"revoked_at": schema.StringAttribute{
							Optional: true,
							Computed: true,
							MarkdownDescription: "When the certificate was revoked, as an RFC 3339 " +
								"timestamp. Omitting it defaults to the moment the entry first appeared " +
								"in configuration, and the defaulted value is then held stable across " +
								"later regenerations so the CRL does not churn its timestamps (and the " +
								"Kubernetes Secret that carries it does not churn its hash). " +
								"Positional in a `revoked` list: reordering blocks reshuffles which " +
								"entry inherits the prior defaulted timestamp.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseNonNullStateForUnknown(),
							},
						},
					},
				},
				// listplanmodifier.UseStateForUnknown on the block itself is what lets the
				// nested revoked_at's UseNonNullStateForUnknown do its job across plans:
				// without it, the framework would mark every nested attribute Unknown
				// whenever the list as a whole looked different, and the prior defaulted
				// timestamps would be lost even on no-op refresh plans. (The list still
				// regenerates the CRL on any real change; ModifyPlan's drift detection
				// is what gates the carry-forward of the cert-derived Computed attrs.)
				PlanModifiers: []planmodifier.List{
					listplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create issues the CRL with number = 1. signature_algorithm, revoked_at, and
// the parsed-back fields are resolved and written to state in r.issue, which
// Create and Update share.
func (r *crlResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan crlResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.issue(ctx, &plan, 1, time.Now(), &resp.Diagnostics, &resp.State)
}

// Read recomputes ready_for_regeneration from next_update_time and
// early_regenerate; everything else stays as stored. The CRL exists only in
// state (signed once by Create, regenerated on Update), and re-deriving
// crl_pem here would regenerate it — the rotation-on-every-plan bug. Plan 1
// Task 10 established that CRL signing is deterministic, so the bytes are
// stable until the inputs change; only the readiness flag is clock-driven.
//
// next_update and next_update_time are NOT recomputed in Read. The plan
// (Task 11) calls for stable timestamps: a CRL past its next_update is stale,
// but the operator drives regeneration through a periodic apply (where
// ready_for_regeneration surfaces as drift), not by having the provider
// silently rewrite the issued CRL on refresh. Advancing next_update_time
// here would surface a diff on every refresh and re-issue the CRL on every
// apply, which is exactly the churn this resource replaces.
func (r *crlResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state crlResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Parse next_update_time once; an unparseable stored value is a state
	// corruption bug rather than a config one, so it surfaces as a generic
	// error rather than at an attribute path.
	nextUpdate, err := time.Parse(time.RFC3339, state.NextUpdateTime.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse stored next_update_time",
			"The next_update_time in state could not be parsed as an RFC 3339 timestamp: "+err.Error())
		return
	}

	var earlyDur time.Duration
	if !state.EarlyRegenerate.IsNull() && !state.EarlyRegenerate.IsUnknown() {
		ed, d := parseDurationAttr(state.EarlyRegenerate, path.Root("early_regenerate"))
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		earlyDur = ed
	}

	state.ReadyForRegeneration = types.BoolValue(crlReadyForRegeneration(nextUpdate, earlyDur, time.Now()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update regenerates the CRL with number = prior.Number + 1, the RFC 5280
// requirement that each successive CRL carry a higher cRLNumber than the last.
// All other behavior is shared with Create through r.issue.
func (r *crlResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan crlResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior crlResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// prior.Number is the cRLNumber last written to state. The schema's lack
	// of UseStateForUnknown on number means the framework cannot carry it
	// forward into the plan, so reading it from state here is the only path.
	next := prior.Number.ValueInt64() + 1
	r.issue(ctx, &plan, next, time.Now(), &resp.Diagnostics, &resp.State)
}

// Delete is a no-op; the framework removes the resource from state and there
// is nothing external to tear down.
func (r *crlResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ModifyPlan carries state's cert-derived Computed values (crl_pem,
// crl_base64, this_update, next_update_time, signature_algorithm, id, number)
// into the plan when the inputs have NOT changed, so a refresh plan against an
// unchanged config is empty. On drift it leaves those attributes Unknown so
// Update is free to compose fresh values without tripping "inconsistent
// result after apply" — exactly the pattern pki_certificate and
// pki_certificate_authority use ModifyPlan for.
//
// This deviates from the plan section's "No ModifyPlan: unlike a certificate,
// regenerating a CRL is cheap..." line. The deviation is forced by the test
// requirements the same section writes: TestAccCRLSignatureVerifiesAndSerialIsPresent
// and TestAccCRLEmptyIsValid assert `PostApplyPostRefresh: ExpectEmptyPlan`,
// and TestAccCRLNumberIncrementsOnRegeneration exercises real Updates that
// produce new crl_pem values. Both together are inconsistent: the framework's
// default refresh plan carries state's Computed values forward, so a no-op
// refresh is empty by default — but Update (on drift) needs those values
// marked Unknown so the apply response can compose fresh ones. ModifyPlan's
// drift check is the mechanism that does the right one in each case, which is
// why the cert resources use it. The plan author's "no ModifyPlan" line was
// an aspiration that did not survive contact with the framework.
//
// "Cheap to regenerate" is still true: unlike the cert resources, whose
// ModifyPlan also gates whether Update fires at all, this one does NOT
// suppress Updates. Any input change still reaches Update and regenerates.
//
// The one override on top of drift is the regeneration window: when
// ready_for_regeneration is true (state.next_update_time within plan's
// early_regenerate, or past it), force the cert-derived attrs Unknown so the
// plan shows a diff and the operator sees — and an apply drives — the
// regeneration. Mirrors forceReissuePlan in certdrift.go.
func (r *crlResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Create path: no state to carry forward.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroy path: nothing to carry.
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan, state crlResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Regeneration window: recompute readiness against state's next_update_time
	// (held stable; only ready_for_regeneration tracks the clock) and plan's
	// early_regenerate. If ready, force a diff so the apply regenerates.
	var earlyDur time.Duration
	if !plan.EarlyRegenerate.IsNull() && !plan.EarlyRegenerate.IsUnknown() {
		ed, d := parseDurationAttr(plan.EarlyRegenerate, path.Root("early_regenerate"))
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		earlyDur = ed
	}
	nextUpdate, err := time.Parse(time.RFC3339, state.NextUpdateTime.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse stored next_update_time",
			"The next_update_time in state could not be parsed as an RFC 3339 timestamp: "+err.Error())
		return
	}
	if crlReadyForRegeneration(nextUpdate, earlyDur, time.Now()) {
		// Inside the regeneration window: leave cert-derived Computed values
		// Unknown so Core sees a diff and proposes an Update — even though the
		// inputs are otherwise unchanged. This is the one case where a
		// content-identical CRL still regenerates, on purpose, mirroring the
		// certificate resources' early-renewal override.
		plan.Number = types.Int64Null()
		plan.CRLPEM = types.StringUnknown()
		plan.CRLBase64 = types.StringUnknown()
		plan.ThisUpdate = types.StringUnknown()
		plan.NextUpdateTime = types.StringUnknown()
		plan.SignatureAlgorithm = types.StringUnknown()
		plan.ID = types.StringUnknown()
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}

	if crlDrifts(plan, state) {
		// Inputs changed: leave cert-derived Computed values Unknown so
		// Update can compose fresh ones without "inconsistent result after
		// apply".
		return
	}

	// No drift and not stale: carry state's cert-derived Computed values
	// forward so the refresh plan is empty. ready_for_regeneration is set
	// by Read and carried by the framework's default refresh-plan behavior;
	// it is not copied here because (a) it would be a no-op given that
	// default behavior, and (b) leaving it alone keeps the only clock-driven
	// attribute out of the cert-derived copy block.
	plan.CRLPEM = state.CRLPEM
	plan.CRLBase64 = state.CRLBase64
	plan.ThisUpdate = state.ThisUpdate
	plan.NextUpdateTime = state.NextUpdateTime
	plan.SignatureAlgorithm = state.SignatureAlgorithm
	plan.Number = state.Number
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// crlDrifts reports whether the operator-visible inputs in plan differ from
// those in state. revoked_at is deliberately excluded: a config that omits
// it (preserving the prior defaulted timestamp) is NOT drift, and including
// null-vs-value comparisons there would force a regeneration on every plan.
// Explicitly changing revoked_at IS drift, handled via the "config-set value
// differs from state" branch of crlRevokedDrifts.
func crlDrifts(plan, state crlResourceModel) bool {
	if plan.CACertificatePEM.ValueString() != state.CACertificatePEM.ValueString() {
		return true
	}
	if plan.CAPrivateKeyPEM.ValueString() != state.CAPrivateKeyPEM.ValueString() {
		return true
	}
	if plan.NextUpdate.ValueString() != state.NextUpdate.ValueString() {
		return true
	}
	// early_regenerate: null-config matches any state value (treat omitted as
	// "leave whatever state has"); a configured value must equal state's.
	if !plan.EarlyRegenerate.IsNull() && !plan.EarlyRegenerate.IsUnknown() {
		if plan.EarlyRegenerate.ValueString() != state.EarlyRegenerate.ValueString() {
			return true
		}
	}
	// signature_algorithm: same null-matches-anything rule as early_regenerate.
	if !plan.SignatureAlgorithm.IsNull() && !plan.SignatureAlgorithm.IsUnknown() {
		if plan.SignatureAlgorithm.ValueString() != state.SignatureAlgorithm.ValueString() {
			return true
		}
	}
	return crlRevokedDrifts(plan.Revoked, state.Revoked)
}

// crlRevokedDrifts compares two revoked lists positionally, treating an
// omitted (null/Unknown) revoked_at in plan as "preserve state's value" so
// the anti-churn property from spec section 6.5 holds. serial_number and
// reason are compared as exact strings.
func crlRevokedDrifts(plan, state []revokedEntryModel) bool {
	if len(plan) != len(state) {
		return true
	}
	for i := range plan {
		if plan[i].SerialNumber.ValueString() != state[i].SerialNumber.ValueString() {
			return true
		}
		if plan[i].Reason.ValueString() != state[i].Reason.ValueString() {
			return true
		}
		// revoked_at: drift only if plan explicitly sets a value that differs
		// from state. An omitted (null/Unknown) plan value means "preserve
		// state" — not drift.
		if !plan[i].RevokedAt.IsNull() && !plan[i].RevokedAt.IsUnknown() {
			if plan[i].RevokedAt.ValueString() != state[i].RevokedAt.ValueString() {
				return true
			}
		}
	}
	return false
}

// issue holds the shared create-and-regenerate logic. now is passed in (rather
// than read inside) so a unit test could inject a fixed clock; in practice
// both callers pass time.Now(). nextNumber is the cRLNumber to embed: 1 for
// Create, prior.Number+1 for Update.
func (r *crlResource) issue(
	ctx context.Context,
	plan *crlResourceModel,
	nextNumber int64,
	now time.Time,
	diags *diag.Diagnostics,
	stateOut interface {
		Set(ctx context.Context, v interface{}) diag.Diagnostics
	},
) {
	// 1. Parse the CA certificate and key, verify they match, and call
	// pki.CheckCRLSigner BEFORE attempting to sign. The CA's key arrives as
	// PEM (possibly from Bitwarden) and cannot be inspected ahead of apply,
	// so the failure must surface at apply with an actionable message. The
	// diagnostic attaches to ca_certificate_pem because crlSign and
	// subjectKeyIdentifier are properties of the certificate, not the key.
	caChain, err := pki.ParseCertificateChainPEM([]byte(plan.CACertificatePEM.ValueString()))
	if err != nil {
		diags.AddAttributeError(path.Root("ca_certificate_pem"),
			"Unable to parse CA certificate", err.Error())
		return
	}
	caCert := caChain[0]

	caKey, err := pki.ParsePrivateKeyPEM([]byte(plan.CAPrivateKeyPEM.ValueString()))
	if err != nil {
		diags.AddAttributeError(path.Root("ca_private_key_pem"),
			"Unable to parse CA private key",
			"The CA private key could not be parsed as PKCS#8, PKCS#1, or SEC1: "+err.Error())
		return
	}
	if !pki.PublicKeysEqual(caCert.PublicKey, caKey.Public()) {
		// Naming the value would echo key material; name the two attributes.
		diags.AddAttributeError(path.Root("ca_private_key_pem"),
			"CA key does not match CA certificate",
			"The ca_private_key_pem does not correspond to ca_certificate_pem: its "+
				"public key does not match the certificate's. A CRL signed with this key "+
				"combination would verify nowhere.")
		return
	}
	if err := pki.CheckCRLSigner(caCert); err != nil {
		// CheckCRLSigner's message names crlSign (or subjectKeyIdentifier)
		// and the fix; surface it verbatim at the certificate attribute.
		diags.AddAttributeError(path.Root("ca_certificate_pem"),
			"CA cannot sign CRLs", err.Error())
		return
	}

	// 2. Parse next_update and early_regenerate.
	nextUpdateDur, d := parseDurationAttr(plan.NextUpdate, path.Root("next_update"))
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	var earlyDur time.Duration
	if !plan.EarlyRegenerate.IsNull() && !plan.EarlyRegenerate.IsUnknown() {
		earlyDur, d = parseDurationAttr(plan.EarlyRegenerate, path.Root("early_regenerate"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
	}

	// 3. Resolve signature_algorithm. A zero value means "pick the
	// conventional one for the signing key" (resolved inside CreateCRL); the
	// resolved name is read back from the parsed CRL below.
	var sigAlg x509.SignatureAlgorithm
	if !plan.SignatureAlgorithm.IsNull() && !plan.SignatureAlgorithm.IsUnknown() {
		a, err := pki.SignatureAlgorithmByName(plan.SignatureAlgorithm.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("signature_algorithm"),
				"Unknown signature algorithm", err.Error())
			return
		}
		sigAlg = a
	}

	// 4. Build the revoked list, parsing each serial and rejecting duplicates
	// after normalization — which is what makes "2001" and "0x2001" collide
	// (they both normalize to "2001"). UseNonNullStateForUnknown on the
	// nested revoked_at means an omitted timestamp arrives here as Unknown
	// (Create, or a brand-new entry in Update) or as state's prior value (an
	// existing entry in Update); in the Unknown case, fill it from thisUpdate
	// so it is held stable from this apply forward.
	thisUpdate := now.UTC().Truncate(time.Second)

	revoked := make([]pki.RevokedCert, 0, len(plan.Revoked))
	seen := make(map[string]bool, len(plan.Revoked))
	for i, entry := range plan.Revoked {
		p := path.Root("revoked").AtListIndex(i)
		serial, dd := parseSerialEntry(entry.SerialNumber, p.AtName("serial_number"))
		diags.Append(dd...)
		if diags.HasError() {
			return
		}

		key := pki.FormatSerial(serial)
		if seen[key] {
			// This is the diagnostic TestAccCRLRejectsBadConfig "duplicate
			// serial" anchors to. The phrase "already present in this CRL"
			// cannot appear in the configuration text, so the ExpectError
			// pattern is load-bearing rather than vacuous.
			diags.AddAttributeError(p.AtName("serial_number"),
				"Duplicate serial number",
				fmt.Sprintf("Serial %s is already present in this CRL; the same value in a different "+
					"surface form (0x prefix, leading zeros) collides after normalization.", key))
			return
		}
		seen[key] = true

		var revokedAt time.Time
		if entry.RevokedAt.IsNull() || entry.RevokedAt.IsUnknown() {
			// Omitted timestamp: default to thisUpdate and write it back so
			// the next plan sees a concrete value (and
			// UseNonNullStateForUnknown then preserves it).
			revokedAt = thisUpdate
			plan.Revoked[i].RevokedAt = types.StringValue(revokedAt.Format(time.RFC3339))
		} else {
			parsed, parseErr := time.Parse(time.RFC3339, entry.RevokedAt.ValueString())
			if parseErr != nil {
				// time.Parse's error contains "cannot parse", the distinctive
				// fragment TestAccCRLRejectsBadConfig "bad revoked_at"
				// anchors to. The configuration value (e.g. "yesterday")
				// cannot produce that phrase, so the pattern is
				// load-bearing.
				diags.AddAttributeError(p.AtName("revoked_at"),
					"Unable to parse revoked_at",
					fmt.Sprintf("revoked_at must be an RFC 3339 timestamp: %v", parseErr))
				return
			}
			revokedAt = parsed.UTC()
		}

		// entry.Reason's OneOf validator already rejected unknown names at
		// plan time, so an empty string ("not configured") is the only other
		// value reaching here. pki.RevokedCert's zero Reason has the same
		// effect as "unspecified" — Go omits the reasonCode extension.
		revoked = append(revoked, pki.RevokedCert{
			Serial:    serial,
			Reason:    entry.Reason.ValueString(),
			RevokedAt: revokedAt,
		})
	}

	// 5. Build the template and sign.
	nextUpdateTime := thisUpdate.Add(nextUpdateDur)
	tpl := pki.CRLTemplate{
		Number:             big.NewInt(nextNumber),
		ThisUpdate:         thisUpdate,
		NextUpdate:         nextUpdateTime,
		Revoked:            revoked,
		SignatureAlgorithm: sigAlg,
	}

	crlPEM, err := pki.CreateCRL(tpl, caCert, caKey)
	if err != nil {
		diags.AddError("Unable to create CRL", err.Error())
		return
	}

	// 6. Parse the result back and set the derived fields from the parsed CRL
	// rather than from the template. Reading them back is a self-check that
	// costs one parse and catches any divergence between what was requested
	// and what was signed.
	parsed, err := pki.ParseCRLPEM(crlPEM)
	if err != nil {
		diags.AddError("Unable to parse issued CRL", err.Error())
		return
	}
	plan.CRLPEM = types.StringValue(string(crlPEM))
	plan.CRLBase64 = types.StringValue(base64.StdEncoding.EncodeToString(crlPEM))
	plan.ThisUpdate = types.StringValue(parsed.ThisUpdate.Format(time.RFC3339))
	plan.NextUpdateTime = types.StringValue(parsed.NextUpdate.Format(time.RFC3339))
	plan.Number = types.Int64Value(parsed.Number.Int64())
	if name, err := pki.SignatureAlgorithmName(parsed.SignatureAlgorithm); err == nil {
		plan.SignatureAlgorithm = types.StringValue(name)
	} else {
		plan.SignatureAlgorithm = types.StringValue(fmt.Sprintf("%v", parsed.SignatureAlgorithm))
	}
	der := parsed.Raw
	sum := sha256.Sum256(der)
	plan.ID = types.StringValue(hex.EncodeToString(sum[:]))

	plan.ReadyForRegeneration = types.BoolValue(crlReadyForRegeneration(parsed.NextUpdate, earlyDur, now))

	diags.Append(stateOut.Set(ctx, plan)...)
}

// parseSerialEntry adapts pki.ParseSerial to a nested-attribute diagnostic at
// the serial_number path. The error's "hexadecimal string" fragment is what
// TestAccCRLRejectsBadConfig "bad serial" anchors to.
func parseSerialEntry(value types.String, p path.Path) (*big.Int, diag.Diagnostics) {
	var diags diag.Diagnostics
	n, err := pki.ParseSerial(value.ValueString())
	if err != nil {
		diags.AddAttributeError(p, "Invalid serial number", err.Error())
		return nil, diags
	}
	return n, diags
}

// crlReadyForRegeneration reports whether the CRL should be regenerated:
// within the early window of nextUpdate, or past it. early may be zero, in
// which case the check reduces to "has the CRL expired".
func crlReadyForRegeneration(nextUpdate time.Time, early time.Duration, now time.Time) bool {
	return now.Add(early).After(nextUpdate) || !nextUpdate.After(now)
}
