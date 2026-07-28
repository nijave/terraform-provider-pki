// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	_ resource.Resource                     = (*certificateResource)(nil)
	_ resource.ResourceWithConfigValidators = (*certificateResource)(nil)
	_ resource.ResourceWithImportState      = (*certificateResource)(nil)
)

// certificateResource issues (and, on import, adopts) an end-entity (leaf)
// certificate signed by a CA. The CA is supplied as bare PEM, so the
// Bitwarden-delivered pki-ca Secret works with no CA resource in the graph.
// The leaf's public key comes from either a CSR (csr_pem) or an inline public
// key (public_key_pem).
type certificateResource struct{}

// NewCertificateResource returns the pki_certificate resource.
func NewCertificateResource() resource.Resource {
	return &certificateResource{}
}

// certificateResourceModel is pki_certificate's state model.
//
// The extension blocks are pointers so that "not configured" is distinguishable
// from "configured empty": a nil KeyUsage means the block was omitted (and the
// issued certificate carries no keyUsage extension), while a non-nil one holds
// the configured values.
type certificateResourceModel struct {
	CACertificatePEM types.String `tfsdk:"ca_certificate_pem"`
	CAPrivateKeyPEM  types.String `tfsdk:"ca_private_key_pem"`
	CSRPEM           types.String `tfsdk:"csr_pem"`
	PublicKeyPEM     types.String `tfsdk:"public_key_pem"`

	Subject *subjectModel `tfsdk:"subject"`
	SAN     *sanModel     `tfsdk:"san"`

	Validity     types.String `tfsdk:"validity"`
	EarlyRenewal types.String `tfsdk:"early_renewal"`
	SerialNumber types.String `tfsdk:"serial_number"`

	BasicConstraints *basicConstraintsModel `tfsdk:"basic_constraints"`
	KeyUsage         *keyUsageModel         `tfsdk:"key_usage"`
	ExtKeyUsage      *extKeyUsageModel      `tfsdk:"extended_key_usage"`
	ExtraExtensions  []extraExtensionModel  `tfsdk:"extra_extension"`

	SignatureAlgorithm types.String `tfsdk:"signature_algorithm"`

	CertificatePEM  types.String `tfsdk:"certificate_pem"`
	NotBefore       types.String `tfsdk:"not_before"`
	NotAfter        types.String `tfsdk:"not_after"`
	ReadyForRenewal types.Bool   `tfsdk:"ready_for_renewal"`
	SubjectKeyID    types.String `tfsdk:"subject_key_id"`
	AuthorityKeyID  types.String `tfsdk:"authority_key_id"`
	ID              types.String `tfsdk:"id"`
}

func (r *certificateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (r *certificateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Issues an end-entity (leaf) certificate in-process, signed by a CA supplied " +
			"as bare PEM. The leaf's public key comes from either a CSR (`csr_pem`) or an inline public " +
			"key (`public_key_pem`) — exactly one of the two. The issued certificate is held in Terraform " +
			"state; there is no external CA service to refresh against, so `terraform plan` after apply " +
			"is empty until the inputs change.\n\n" +
			"Changing the cryptographic inputs (`ca_certificate_pem`, `ca_private_key_pem`, `csr_pem`, " +
			"`public_key_pem`) replaces the certificate. Changing the content inputs (`subject`, `san`, " +
			"`validity`, `serial_number`, the extension blocks) reissues the certificate in place via " +
			"`Update`. The `serial_number` is drawn once at create time and then held in state, so " +
			"reissuing for any other reason keeps the serial stable.\n\n" +
			"With `csr_pem`, the CSR's subject and SAN become the defaults, and an explicit `subject` or " +
			"`san` block overrides them wholesale (no field-level merging). Extensions are **never** " +
			"copied from the CSR — see the `basic_constraints` and `key_usage` descriptions for why.\n\n" +
			"This resource is importable. The CA certificate and key cannot be recovered from a leaf, " +
			"so after import the configuration must supply them; the first plan will show them being " +
			"set, which does not reissue the certificate.",
		Attributes: map[string]schema.Attribute{
			"ca_certificate_pem": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The issuing CA's certificate, as a PEM `CERTIFICATE` block or a " +
					"chain (leaf-adjacent first). The certificate is signed with the key whose public " +
					"key matches this certificate, supplied as `ca_private_key_pem`. Changing this " +
					"value replaces the certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ca_private_key_pem": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				MarkdownDescription: "The issuing CA's private key, used to sign this certificate, in " +
					"any PEM encoding `pki_private_key` produces (PKCS#1, SEC1, or PKCS#8). Must " +
					"correspond to `ca_certificate_pem`: the key's public key must match the " +
					"certificate's. Changing this value replaces the certificate.\n\n" +
					"This attribute is sensitive and is never drift-compared: a different encoding of " +
					"the same key produces the same signature, so comparing the bytes would manufacture " +
					"spurious drift.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"csr_pem": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "A certificate signing request whose public key and (by default) " +
					"subject and SAN the issued certificate carries. Exactly one of `csr_pem` and " +
					"`public_key_pem` must be set. The CSR's signature is verified at apply time — a " +
					"tampered CSR is refused, because it proves nothing about the requester's hold on " +
					"the key.\n\n" +
					"An explicit `subject` or `san` block overrides the CSR's values wholesale; " +
					"extensions are never copied from the CSR (see `basic_constraints` and " +
					"`key_usage`). Changing this value replaces the certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"public_key_pem": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "An inline public key, PKIX-encoded (`PUBLIC KEY`), for the " +
					"certificate to certify. Exactly one of `csr_pem` and `public_key_pem` must be " +
					"set. Inline mode requires a `subject` or `san` block, since there is no CSR to " +
					"derive them from. Changing this value replaces the certificate.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"validity": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "How long the certificate is valid for, as a Go duration " +
					"(`8760h`) or an integer count with a `d` (day) or `y` (365-day year) suffix " +
					"(`1y`). The certificate's `notBefore` is the moment of issue, truncated to a " +
					"second, and `notAfter` is `notBefore` plus this duration.",
			},
			"early_renewal": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "How long before `not_after` the certificate reports " +
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
					"algorithm for the **signing key** (the CA's key) is chosen. The resolved name " +
					"is written back to state.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"certificate_pem": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The issued certificate as a PEM `CERTIFICATE` block.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"not_before": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate's `notBefore`, RFC 3339 timestamp.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"not_after": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate's `notAfter`, RFC 3339 timestamp.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"ready_for_renewal": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether the certificate is within the `early_renewal` window " +
					"of `not_after` (or past it). Recomputed on every read, so it flips as " +
					"wall-clock time passes without any change to the configuration — which is " +
					"why this is the one computed attribute that intentionally does not carry " +
					"`UseStateForUnknown`. A clock-only signal; it does not by itself reissue " +
					"anything.",
			},
			"subject_key_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The `subjectKeyIdentifier` extension's key identifier, " +
					"lowercase hex (the SHA-1 of the public key, per RFC 5280 method 1).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"authority_key_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The `authorityKeyIdentifier` extension's key identifier, " +
					"lowercase hex. Carried for every leaf issued under a CA, because the " +
					"issuer DN always differs from the subject DN for a leaf.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The hex-encoded SHA-256 of the certificate's DER — a stable " +
					"identifier for the exact bytes of the certificate, which changes if and only " +
					"if any signed content or the signature itself does.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"subject":            subjectBlock(),
			"san":                sanBlock(),
			"basic_constraints":  basicConstraintsBlock(false),
			"key_usage":          keyUsageBlock(),
			"extended_key_usage": extendedKeyUsageBlock(),
			"extra_extension":    extraExtensionBlock(),
		},
	}
}

// ConfigValidators enforces the one cross-attribute rule the framework's stock
// validators can express for this resource: exactly one of csr_pem and
// public_key_pem must be set. The "inline mode needs subject or san" rule is
// left to pki.CreateCertificate's own validation, which reports "a certificate
// must have a subject, a subject alternative name, or both" — a message that
// does not depend on which mode produced the empty subject, so the same
// diagnostic covers a CSR with no identity just as well.
func (r *certificateResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("csr_pem"),
			path.MatchRoot("public_key_pem"),
		),
	}
}

func (r *certificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.issue(ctx, &plan, types.StringNull(), time.Now(), &resp.Diagnostics, &resp.State)
}

// Read re-parses certificate_pem from state and recomputes only ready_for_renewal,
// mirroring the CA resource: the certificate cannot change underneath us (there
// is no external CA to refresh against), and re-deriving derived fields would
// risk a spurious diff. ready_for_renewal is the one exception because it is a
// function of the clock.
func (r *certificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state certificateResourceModel
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

	ready, err := pki.CompareValidity(cert, earlyDur, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute readiness for renewal", err.Error())
		return
	}
	state.ReadyForRenewal = types.BoolValue(ready)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update reissues the certificate in place, sharing issue with Create. The
// serial comes from state unless the configuration changed it, which
// resolveSerial expresses by preferring a configured value and falling back to
// the prior state.
func (r *certificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var prior certificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.issue(ctx, &plan, prior.SerialNumber, time.Now(), &resp.Diagnostics, &resp.State)
}

// Delete is a no-op; the framework removes the resource from state and there is
// nothing external to tear down.
func (r *certificateResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState resolves the import ID, parses the certificate it locates, and
// reconstructs the model from the parsed certificate using the same *FromPKI
// converters the certificate data source uses. The subject and SAN are written
// in the ordered block form (subjectFromPKI / sanFromPKI), which is the only
// form that reproduces an adopted DN byte-for-byte.
//
// ca_certificate_pem and ca_private_key_pem cannot be recovered from a leaf and
// are left null; the resource description documents that the configuration must
// supply them and that the first plan after import shows them being set, which
// does not reissue the certificate — Task 10's comparison excludes
// ca_private_key_pem entirely and matches ca_certificate_pem against the
// certificate's issuer rather than treating it as an input diff. early_renewal
// is also left null: it is not a property of the certificate, and the readiness
// check reduces to "has the certificate expired" until configuration sets a
// window. csr_pem and public_key_pem are likewise left null: the certificate's
// public key is the only recoverable identity, and supplying either in
// configuration post-import selects the mode without forcing reissue.
func (r *certificateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

	var model certificateResourceModel

	subject, err := pki.ParseSubjectDER(cert.RawSubject)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate subject", err.Error())
		return
	}
	if len(subject.Attributes) > 0 {
		s := subjectFromPKI(subject)
		model.Subject = &s
	}

	model.SerialNumber = types.StringValue(pki.FormatSerial(cert.SerialNumber))
	model.Validity = types.StringValue(fmt.Sprintf("%dh", int(cert.NotAfter.Sub(cert.NotBefore).Hours())))
	model.NotBefore = types.StringValue(cert.NotBefore.Format(time.RFC3339))
	model.NotAfter = types.StringValue(cert.NotAfter.Format(time.RFC3339))

	if name, err := pki.SignatureAlgorithmName(cert.SignatureAlgorithm); err == nil {
		model.SignatureAlgorithm = types.StringValue(name)
	} else {
		model.SignatureAlgorithm = types.StringValue(fmt.Sprintf("%v", cert.SignatureAlgorithm))
	}

	model.CertificatePEM = types.StringValue(string(pki.EncodeCertificatePEM(cert.Raw)))
	model.CACertificatePEM = types.StringNull()
	model.CAPrivateKeyPEM = types.StringNull()
	model.CSRPEM = types.StringNull()
	model.PublicKeyPEM = types.StringNull()

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

	ready, err := pki.CompareValidity(cert, 0, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute readiness for renewal", err.Error())
		return
	}
	model.ReadyForRenewal = types.BoolValue(ready)

	sanOID, _ := pki.ParseOID("2.5.29.17")
	bcOID, _ := pki.ParseOID("2.5.29.19")
	kuOID, _ := pki.ParseOID("2.5.29.15")
	ekuOID, _ := pki.ParseOID("2.5.29.37")
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
// (basic_constraints → {ca:false, critical:true}) are resolved here rather than
// at the schema level. Unlike the CA resource, key_usage has NO default: a
// leaf's usages depend on what the certificate is for, and silently issuing
// digitalSignature + keyEncipherment because that is what the homelab happens
// to need would be wrong for a server certificate. Omitting key_usage produces
// a certificate with no keyUsage extension, which is legal and occasionally
// intended.
func (r *certificateResource) issue(
	ctx context.Context,
	plan *certificateResourceModel,
	priorSerial types.String,
	now time.Time,
	diags *diag.Diagnostics,
	stateOut interface {
		Set(ctx context.Context, v interface{}) diag.Diagnostics
	},
) {
	// 1. Parse the CA certificate and key, and verify the key matches the
	// certificate — a crossed reference here (two HCL attributes pointing at
	// different keys) produces a certificate no client trusts, and catching it
	// at apply time with a clear message is the TestAccCertificateRejectsBadConfig
	// "ca key does not match ca cert" case.
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
		// The summary "CA key does not match CA certificate" and the detail's
		// "public key does not match the certificate's" are the distinctive
		// fragments TestAccCertificateRejectsBadConfig matches against — they
		// cannot appear in the configuration text, so the ExpectError pattern
		// is load-bearing rather than vacuous. Mutation evidence: disabling
		// this check lets x509.CreateCertificate catch the mismatch instead,
		// but its message is "provided PrivateKey doesn't match parent's
		// PublicKey" — "doesn't" rather than "does not" — so the test's
		// `(?s)does not match` pattern fails to match and the test fails,
		// proving the cross-check (not Go's underlying check) is what the
		// pattern anchors to.
		diags.AddAttributeError(path.Root("ca_private_key_pem"),
			"CA key does not match CA certificate",
			"The ca_private_key_pem does not correspond to ca_certificate_pem: its "+
				"public key does not match the certificate's. A certificate signed with this key "+
				"combination would verify nowhere.")
		return
	}

	// 2. Resolve the subject public key and the default subject/SAN. With
	// csr_pem: pki.ParseCertRequestPEM verifies the CSR signature and refuses a
	// tampered one — the right default when issuing, because you are about to
	// sign against this public key and an unverifiable CSR proves nothing about
	// the requester's hold on it. The CSR's subject and SAN become the defaults.
	// With public_key_pem: parse the key; there is no default subject or SAN, so
	// inline mode requires a subject or san block (enforced by the cert template
	// validation downstream).
	var pub crypto.PublicKey
	var defaultSubject pki.Subject
	var defaultSAN pki.SAN

	if !plan.CSRPEM.IsNull() && !plan.CSRPEM.IsUnknown() {
		csr, parseErr := pki.ParseCertRequestPEM([]byte(plan.CSRPEM.ValueString()))
		if parseErr != nil {
			diags.AddAttributeError(path.Root("csr_pem"),
				"Unable to parse certificate signing request", parseErr.Error())
			return
		}
		pub = csr.PublicKey
		defaultSubject, parseErr = pki.ParseSubjectDER(csr.RawSubject)
		if parseErr != nil {
			diags.AddAttributeError(path.Root("csr_pem"),
				"Unable to parse CSR subject", parseErr.Error())
			return
		}
		// Derive the default SAN from the CSR's SAN extension, if it carries
		// one. Any GeneralName type this provider cannot represent is silently
		// skipped by ParseSANExtension rather than rejected, matching import.
		sanOID, oidErr := pki.ParseOID("2.5.29.17")
		if oidErr != nil {
			diags.AddError("Internal error resolving subjectAltName OID", oidErr.Error())
			return
		}
		for _, ext := range csr.Extensions {
			if ext.Id.Equal(sanOID) {
				s, extErr := pki.ParseSANExtension(ext)
				if extErr != nil {
					diags.AddAttributeError(path.Root("csr_pem"),
						"Unable to parse CSR subjectAltName extension", extErr.Error())
					return
				}
				defaultSAN = s
				break
			}
		}
	} else {
		pub, err = pki.ParsePublicKeyPEM([]byte(plan.PublicKeyPEM.ValueString()))
		if err != nil {
			diags.AddAttributeError(path.Root("public_key_pem"),
				"Unable to parse public key", err.Error())
			return
		}
	}

	// 3. Apply precedence: an explicitly-set subject block replaces the CSR's
	// subject wholesale, and likewise for san. No field-level merging — a merge
	// would be both surprising and untestable, and spec section 6.4 pins the
	// wholesale-replacement rule.
	var subject pki.Subject
	if plan.Subject != nil {
		s, d := plan.Subject.toPKI(ctx, path.Root("subject"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		subject = s
	} else {
		subject = defaultSubject
	}

	var san pki.SAN
	if plan.SAN != nil {
		s, d := plan.SAN.toPKI(ctx, path.Root("san"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		san = s
	} else {
		san = defaultSAN
	}

	// 4. NEVER read extensions from the CSR. Build them only from the resource's
	// own blocks. cfssl's ca-config.json copy_extensions: true was a well-known
	// escalation hazard: a CSR asking for basicConstraints CA:TRUE got it, and a
	// requester could dictate their own keyUsage or EKU. To a future reader "we
	// already have the CSR's extensions parsed, why not use them" looks like an
	// easy improvement — it is not, and TestAccCertificateNeverCopiesCSRExtensions
	// pins that.

	// 5. Convert the extension blocks. basic_constraints applies the leaf
	// default ({ca:false, critical:true}) when the block is omitted; key_usage
	// has NO default, so a nil block means the issued certificate carries no
	// keyUsage extension. The state block reflects what the configuration
	// declared: a configured block is written back with the resolved inner
	// values, and an omitted block stays null (Terraform Core forbids
	// materializing an omitted block into plan or state).
	bcConfigured := plan.BasicConstraints != nil
	bc, d := leafBasicConstraintsValue(plan.BasicConstraints)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	if bcConfigured {
		plan.BasicConstraints = basicConstraintsFromPKI(bc)
	}

	var ku *pki.KeyUsage
	if plan.KeyUsage != nil {
		k, d := plan.KeyUsage.toPKI(ctx, path.Root("key_usage"))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		ku = &k
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

	extras := make([]pki.ExtraExtension, 0, len(plan.ExtraExtensions))
	for i, em := range plan.ExtraExtensions {
		e, d := em.toPKI(path.Root("extra_extension").AtListIndex(i))
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		extras = append(extras, e)
	}

	// 6. Resolve validity and serial via the shared helpers from Task 8 (the
	// CA resource). issuanceValidity truncates notBefore to a second because DER
	// UTCTime is second-granular: an untruncated value would not survive
	// parse-and-compare and the drift check would fire on every plan.
	notBefore, notAfter, ready, d := issuanceValidity(plan.Validity, plan.EarlyRenewal, now, path.Root("validity"))
	diags.Append(d...)
	if diags.HasError() {
		return
	}

	serial, d := resolveSerial(plan.SerialNumber, priorSerial, path.Root("serial_number"))
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	if plan.SerialNumber.IsNull() || plan.SerialNumber.IsUnknown() {
		plan.SerialNumber = types.StringValue(pki.FormatSerial(serial))
	}

	// 7. Resolve signature_algorithm. A zero value means "pick the conventional
	// one for the CA's signing key"; the resolved name is read back from the
	// issued certificate below. Assigning directly to tpl.SignatureAlgorithm
	// avoids importing crypto/x509 here — both branches use := and the type
	// is whatever pki.CertTemplate declares.
	tpl := pki.CertTemplate{
		Subject:          subject,
		SAN:              san,
		Serial:           serial,
		NotBefore:        notBefore,
		NotAfter:         notAfter,
		BasicConstraints: &bc,
		KeyUsage:         ku,
		ExtKeyUsage:      eku,
		ExtraExtensions:  extras,
	}
	if !plan.SignatureAlgorithm.IsNull() && !plan.SignatureAlgorithm.IsUnknown() {
		a, err := pki.SignatureAlgorithmByName(plan.SignatureAlgorithm.ValueString())
		if err != nil {
			diags.AddAttributeError(path.Root("signature_algorithm"),
				"Unknown signature algorithm", err.Error())
			return
		}
		tpl.SignatureAlgorithm = a
	}

	certPEM, err := pki.CreateCertificate(tpl, pub, caCert, caKey)
	if err != nil {
		diags.AddError("Unable to create certificate", err.Error())
		return
	}

	plan.CertificatePEM = types.StringValue(string(certPEM))

	// 8. Parse the result back and set the derived fields from the parsed
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

// leafBasicConstraintsValue converts the configured block, applying the leaf
// default (ca = false, critical = true) when the block is omitted. The default
// cannot be a schema-level Default because a block has no Default — it is
// resolved here. This is the leaf-specific analogue of the CA resource's
// basicConstraintsValue; the difference is the ca default (false vs true).
func leafBasicConstraintsValue(m *basicConstraintsModel) (pki.BasicConstraints, diag.Diagnostics) {
	if m == nil {
		return pki.BasicConstraints{CA: false, Critical: true}, nil
	}
	return m.toPKI(path.Root("basic_constraints"))
}
