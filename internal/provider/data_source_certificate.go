// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var _ datasource.DataSource = (*certificateDataSource)(nil)

// certificateDataSource decodes a certificate PEM that arrived from elsewhere —
// a device, another team, a Kubernetes Secret — and reports its parts for
// inspection or assertion. It is the read-side counterpart to the certificate
// resources in Tasks 8 and 9, and exists separately so configuration can assert
// on adopted material (the Bitwarden-delivered CA, an issued leaf) through the
// provider's own surface instead of reaching into Go.
type certificateDataSource struct{}

// NewCertificateDataSource returns the pki_certificate data source.
func NewCertificateDataSource() datasource.DataSource {
	return &certificateDataSource{}
}

func (d *certificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_certificate"
}

func (d *certificateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Decodes a certificate — a root CA delivered from Bitwarden, an issued leaf, " +
			"material adopted from another issuer — and reports its parts for inspection or assertion " +
			"before building anything on top of it.\n\n" +
			"Unlike the resources of the same family, this data source does not create anything: it " +
			"reads an existing certificate. The typed extension attributes (`basic_constraints`, " +
			"`key_usage`, `extended_key_usage`, `name_constraints`, `san`) are parsed for convenience, " +
			"and the complete `extensions` list carries every extension verbatim — including the ones " +
			"the typed attributes surface — so a caller asserting on an extension the provider has no " +
			"typed attribute for still has somewhere to look.",
		Attributes: map[string]schema.Attribute{
			"content_pem": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The certificate as a PEM `CERTIFICATE` block. Exactly one of " +
					"`content_pem` and `content_base64` must be set.",
			},
			"content_base64": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The certificate's DER, standard base64-encoded, so material read " +
					"straight out of a Kubernetes Secret needs no decoding step. Exactly one of " +
					"`content_pem` and `content_base64` must be set.",
			},
			"subject": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The certificate's subject DN as a list of `{oid, value, " +
					"string_type}` objects in declaration order — the only order a parser can " +
					"report, because the DN's attribute order is part of its bytes. `string_type` " +
					"is always populated, including for the `utf8` default.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: subjectDNComputedAttributes(),
				},
			},
			"issuer": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The certificate's issuer DN as a list of `{oid, value, " +
					"string_type}` objects in declaration order, in the same shape as `subject`.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: subjectDNComputedAttributes(),
				},
			},
			"serial_number": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The certificate's serial number as lowercase hex with no `0x` " +
					"prefix and no leading zeros. This is the certificate's serial, not the DN " +
					"attribute of the same OID-prefixed name.",
			},
			"not_before": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate's `notBefore`, RFC 3339 timestamp.",
			},
			"not_after": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate's `notAfter`, RFC 3339 timestamp.",
			},
			"san": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "The `subjectAltName` extension, decoded into its four " +
					"GeneralName types. Null when the certificate carries no subjectAltName.",
				Attributes: sanComputedAttributes(),
			},
			"basic_constraints": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "The `basicConstraints` extension (RFC 5280 4.2.1.9), decoded. " +
					"`path_len` is null when the certificate carries no `pathLenConstraint`. Null " +
					"when the extension is absent.",
				Attributes: basicConstraintsComputedAttributes(),
			},
			"key_usage": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "The `keyUsage` extension (RFC 5280 4.2.1.3), decoded into its " +
					"RFC 5280 bit-order name list. Null when the extension is absent.",
				Attributes: keyUsageComputedAttributes(),
			},
			"extended_key_usage": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "The `extendedKeyUsage` extension (RFC 5280 4.2.1.12), decoded. " +
					"Null when the extension is absent.",
				Attributes: extKeyUsageComputedAttributes(),
			},
			"name_constraints": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "The `nameConstraints` extension (RFC 5280 4.2.1.10), decoded. " +
					"Null when the extension is absent.",
				Attributes: nameConstraintsComputedAttributes(),
			},
			"extensions": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "Every extension the certificate carries, in declaration order, " +
					"each reported unparsed as `{oid, critical, value_base64}`. This is the **complete** " +
					"list, including extensions the typed attributes above also surface (`basic_constraints`, " +
					"`key_usage`, `extended_key_usage`, `name_constraints`, `san`, `subject_key_id`, " +
					"`authority_key_id`): the typed attributes are for reading convenience, and this list " +
					"is the source of truth, so a caller asserting on an extension the provider has no " +
					"typed attribute for has somewhere to look without losing anything the typed path " +
					"already parsed.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: extensionComputedAttributes(),
				},
			},
			"is_ca": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether the certificate asserts `cA: TRUE` in its " +
					"`basicConstraints`. Convenience derived from `basic_constraints.ca`; null only " +
					"when the certificate carries no basicConstraints at all, which is rare in " +
					"practice — RFC 5280 recommends but does not require it.",
			},
			"public_key_algorithm": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The public key's algorithm: `RSA`, `ECDSA`, or `ED25519`.",
			},
			"public_key_pem": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate's public key, PKIX-encoded (`PUBLIC KEY`).",
			},
			"public_key_fingerprint_sha256": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The SHA-256 fingerprint of the certificate's **public key** in " +
					"OpenSSH form (`SHA256:base64`, matching `pki_private_key`'s " +
					"`fingerprint_sha256`). This is **not** the certificate fingerprint: it identifies " +
					"the key, not the certificate that carries it. See `fingerprint_sha256` for the " +
					"certificate's own identity.",
			},
			"signature_algorithm": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The signature algorithm the certificate carries, one of " +
					quotedList(pki.SignatureAlgorithmNames()) + ".",
			},
			"fingerprint_sha256": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The SHA-256 hash of the certificate's **DER**, lowercase hex — " +
					"the certificate's identity. Distinct from `public_key_fingerprint_sha256`, which " +
					"is the OpenSSH fingerprint of the public key the certificate carries: two " +
					"certificates for the same key have the same `public_key_fingerprint_sha256` but " +
					"different `fingerprint_sha256`.",
			},
			"subject_key_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The `subjectKeyIdentifier` extension's key identifier, lowercase " +
					"hex. Null when the certificate carries no subjectKeyIdentifier.",
			},
			"authority_key_id": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The `authorityKeyIdentifier` extension's key identifier, " +
					"lowercase hex. Null when the certificate carries no authorityKeyIdentifier — " +
					"which includes every self-signed root whose issuer DN equals its subject DN, " +
					"because crypto/x509 omits the extension in that case.",
			},
			"version": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "The certificate's X.509 version: `1`, `2`, or `3`.",
			},
		},
	}
}

// ConfigValidators requires exactly one of content_pem and content_base64, using
// the datasourcevalidator package (not resourcevalidator). The framework's
// diagnostic for a violation includes "Invalid Attribute Combination", which is
// distinct from any configuration text and is what the acceptance test matches.
func (d *certificateDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("content_pem"),
			path.MatchRoot("content_base64"),
		),
	}
}

// certificateDataSourceModel is the data source's state model. The subject and
// issuer lists reuse attributeModel, and extensions reuses extraExtensionModel,
// because their shapes — `{oid, value, string_type}` and `{oid, value_base64,
// critical}` — are the same shapes the resource's blocks use, and the tfsdk
// tags already match.
type certificateDataSourceModel struct {
	ContentPEM                 types.String           `tfsdk:"content_pem"`
	ContentBase64              types.String           `tfsdk:"content_base64"`
	Subject                    []attributeModel       `tfsdk:"subject"`
	Issuer                     []attributeModel       `tfsdk:"issuer"`
	SerialNumber               types.String           `tfsdk:"serial_number"`
	NotBefore                  types.String           `tfsdk:"not_before"`
	NotAfter                   types.String           `tfsdk:"not_after"`
	SAN                        *sanModel              `tfsdk:"san"`
	BasicConstraints           *basicConstraintsModel `tfsdk:"basic_constraints"`
	KeyUsage                   *keyUsageModel         `tfsdk:"key_usage"`
	ExtKeyUsage                *extKeyUsageModel      `tfsdk:"extended_key_usage"`
	NameConstraints            *nameConstraintsModel  `tfsdk:"name_constraints"`
	Extensions                 []extraExtensionModel  `tfsdk:"extensions"`
	IsCA                       types.Bool             `tfsdk:"is_ca"`
	PublicKeyAlgorithm         types.String           `tfsdk:"public_key_algorithm"`
	PublicKeyPEM               types.String           `tfsdk:"public_key_pem"`
	PublicKeyFingerprintSHA256 types.String           `tfsdk:"public_key_fingerprint_sha256"`
	SignatureAlgorithm         types.String           `tfsdk:"signature_algorithm"`
	FingerprintSHA256          types.String           `tfsdk:"fingerprint_sha256"`
	SubjectKeyID               types.String           `tfsdk:"subject_key_id"`
	AuthorityKeyID             types.String           `tfsdk:"authority_key_id"`
	Version                    types.Int64            `tfsdk:"version"`
}

func (d *certificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config certificateDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve the input to PEM bytes. content_pem is used verbatim;
	// content_base64 is decoded first, so a Kubernetes Secret's base64 needs no
	// manual decoding step. The detail-message phrases ("standard base64
	// encoding", "no PEM block found") are load-bearing: the acceptance test
	// matches them rather than the words "base64" or "certificate", both of
	// which appear in the test's own config and would match whether or not the
	// provider ran.
	var pemBytes []byte
	if !config.ContentBase64.IsNull() {
		decoded, err := base64.StdEncoding.DecodeString(config.ContentBase64.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("content_base64"),
				"Invalid base64 in content_base64",
				"content_base64 must be the standard base64 encoding of the certificate's DER: "+err.Error())
			return
		}
		pemBytes = decoded
	} else {
		pemBytes = []byte(config.ContentPEM.ValueString())
	}

	// Parse the certificate. The certificate's type (*x509.Certificate) arrives
	// through pki's return and is never named here, so crypto/x509 stays out of
	// this file's import block. Field access and method calls on the inferred
	// type do not require the caller to import the type's defining package.
	cert, err := pki.ParseCertificatePEM(pemBytes)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate", err.Error())
		return
	}

	// Subject and issuer: ordered form, with string_type always populated.
	subject, err := pki.ParseSubjectDER(cert.RawSubject)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate subject", err.Error())
		return
	}
	config.Subject = certificateSubjectFromPKI(subject)

	issuer, err := pki.ParseSubjectDER(cert.RawIssuer)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate issuer", err.Error())
		return
	}
	config.Issuer = certificateSubjectFromPKI(issuer)

	config.SerialNumber = types.StringValue(pki.FormatSerial(cert.SerialNumber))
	config.NotBefore = types.StringValue(cert.NotBefore.Format("2006-01-02T15:04:05Z07:00"))
	config.NotAfter = types.StringValue(cert.NotAfter.Format("2006-01-02T15:04:05Z07:00"))
	config.Version = types.Int64Value(int64(cert.Version))

	// Walk the extensions once, dispatching by OID to the typed parsers and
	// capturing every extension into the unparsed list. The typed OIDs are
	// resolved once up front; ranging over cert.Extensions with := avoids naming
	// pkix.Extension here.
	sanOID, err := pki.ParseOID("2.5.29.17")
	if err != nil {
		resp.Diagnostics.AddError("Internal error resolving subjectAltName OID", err.Error())
		return
	}
	bcOID, err := pki.ParseOID("2.5.29.19")
	if err != nil {
		resp.Diagnostics.AddError("Internal error resolving basicConstraints OID", err.Error())
		return
	}
	kuOID, err := pki.ParseOID("2.5.29.15")
	if err != nil {
		resp.Diagnostics.AddError("Internal error resolving keyUsage OID", err.Error())
		return
	}
	ekuOID, err := pki.ParseOID("2.5.29.37")
	if err != nil {
		resp.Diagnostics.AddError("Internal error resolving extendedKeyUsage OID", err.Error())
		return
	}
	ncOID, err := pki.ParseOID("2.5.29.30")
	if err != nil {
		resp.Diagnostics.AddError("Internal error resolving nameConstraints OID", err.Error())
		return
	}

	extensions := make([]extraExtensionModel, 0, len(cert.Extensions))
	for _, ext := range cert.Extensions {
		// Always capture the raw extension first so a parse failure on a typed
		// one is still reported in the complete list.
		extensions = append(extensions, extraExtensionModel{
			OID:         types.StringValue(pki.FormatOID(ext.Id)),
			Critical:    types.BoolValue(ext.Critical),
			ValueBase64: types.StringValue(base64.StdEncoding.EncodeToString(ext.Value)),
		})

		switch {
		case ext.Id.Equal(sanOID):
			s, parseErr := pki.ParseSANExtension(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse subjectAltName extension", parseErr.Error())
				return
			}
			config.SAN = sanFromPKI(s)
		case ext.Id.Equal(bcOID):
			bc, parseErr := pki.ParseBasicConstraints(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse basicConstraints extension", parseErr.Error())
				return
			}
			config.BasicConstraints = basicConstraintsFromPKI(bc)
			config.IsCA = types.BoolValue(bc.CA)
		case ext.Id.Equal(kuOID):
			ku, parseErr := pki.ParseKeyUsage(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse keyUsage extension", parseErr.Error())
				return
			}
			config.KeyUsage = keyUsageFromPKI(ku)
		case ext.Id.Equal(ekuOID):
			eku, parseErr := pki.ParseExtKeyUsage(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse extendedKeyUsage extension", parseErr.Error())
				return
			}
			config.ExtKeyUsage = extKeyUsageFromPKI(eku)
		case ext.Id.Equal(ncOID):
			nc, parseErr := pki.ParseNameConstraints(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse nameConstraints extension", parseErr.Error())
				return
			}
			config.NameConstraints = nameConstraintsFromPKI(nc)
		}
	}

	// is_ca is null when basicConstraints is absent rather than defaulting to
	// false: a certificate that does not assert the extension has not made the
	// claim either way, and a typed false here would hide that distinction.
	// (When basicConstraints is present with cA: FALSE — the common leaf shape —
	// IsCA is a real false, set above.)
	if config.BasicConstraints == nil {
		config.IsCA = types.BoolNull()
	}

	config.Extensions = extensions

	// Public key algorithm in the provider's canonical spelling (ED25519, not
	// Go's "Ed25519"). The mapping lives in pki.PublicKeyAlgorithm so the
	// cert_request data source and the certificate resources share it rather
	// than each rewriting "Ed25519".
	alg, err := pki.PublicKeyAlgorithm(cert.PublicKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read certificate public key algorithm", err.Error())
		return
	}
	config.PublicKeyAlgorithm = types.StringValue(string(alg))

	pubPEM, err := pki.EncodePublicKeyPEM(cert.PublicKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to encode public key", err.Error())
		return
	}
	config.PublicKeyPEM = types.StringValue(string(pubPEM))

	pubFP, err := pki.PublicKeyFingerprintSHA256(cert.PublicKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute public key fingerprint", err.Error())
		return
	}
	config.PublicKeyFingerprintSHA256 = types.StringValue(pubFP)

	// An unsupported algorithm in a parsed certificate is still data the caller
	// may want to see; report the raw value rather than failing the read.
	if sigAlgName, err := pki.SignatureAlgorithmName(cert.SignatureAlgorithm); err != nil {
		config.SignatureAlgorithm = types.StringValue(fmt.Sprintf("%v", cert.SignatureAlgorithm))
	} else {
		config.SignatureAlgorithm = types.StringValue(sigAlgName)
	}

	// fingerprint_sha256: SHA-256 of the certificate's DER, the certificate's
	// identity (as distinct from the public key's).
	certFP := sha256.Sum256(cert.Raw)
	config.FingerprintSHA256 = types.StringValue(hex.EncodeToString(certFP[:]))

	// subject_key_id and authority_key_id: lowercase hex, null when absent.
	// crypto/x509 names both fields "KeyId" but the field types are []byte, not
	// the *AuthorityKeyIdentifier the extension's own ASN.1 carries, so the nil
	// check is a length check.
	if len(cert.SubjectKeyId) > 0 {
		config.SubjectKeyID = types.StringValue(hex.EncodeToString(cert.SubjectKeyId))
	} else {
		config.SubjectKeyID = types.StringNull()
	}
	if len(cert.AuthorityKeyId) > 0 {
		config.AuthorityKeyID = types.StringValue(hex.EncodeToString(cert.AuthorityKeyId))
	} else {
		config.AuthorityKeyID = types.StringNull()
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// certificateSubjectFromPKI converts a parsed subject to the data source's
// always-populated form. string_type is always written, because the data
// source's computed subject documents the encoding every attribute carries — a
// caller comparing two certificates needs to see it.
//
// Mirrors certRequestSubjectFromPKI; the two are kept identical rather than
// shared through subjectListValue because the data source populates a slice
// of attributeModel structs and lets the framework serialize them, while the
// ImportState path in Tasks 8/9 needs a types.List directly.
func certificateSubjectFromPKI(s pki.Subject) []attributeModel {
	out := make([]attributeModel, 0, len(s.Attributes))
	for _, a := range s.Attributes {
		st := a.StringType
		if st == "" {
			st = pki.StringTypeUTF8
		}
		out = append(out, attributeModel{
			OID:        types.StringValue(pki.FormatOID(a.OID)),
			Value:      types.StringValue(a.Value),
			StringType: types.StringValue(string(st)),
		})
	}
	return out
}

// subjectListValue converts a parsed Subject to a types.List of `{oid, value,
// string_type}` objects, matching the shape the data source's `subject` and
// `issuer` attributes and the resources' `attribute`/`extra_attribute` blocks
// all use. Tasks 8 and 9 call this during ImportState to reconstruct subject
// state from a parsed certificate, so the conversion lives here (next to the
// data source that first produces it) rather than duplicated in two more
// places — the project's recurring derive-don't-duplicate lesson.
//
// An empty Subject produces a null list rather than an empty one, matching
// stringsToList and the import convention that an absent collection is null.
func subjectListValue(ctx context.Context, s pki.Subject) (types.List, diag.Diagnostics) {
	_ = ctx // reserved for signature stability; the value builders do not consult it
	attrs := s.Attributes
	if len(attrs) == 0 {
		return types.ListNull(subjectAttributeObjectType()), diag.Diagnostics{}
	}
	elems := make([]attr.Value, 0, len(attrs))
	var diags diag.Diagnostics
	for _, a := range attrs {
		st := a.StringType
		if st == "" {
			st = pki.StringTypeUTF8
		}
		obj, d := types.ObjectValue(subjectAttributeObjectType().AttrTypes, map[string]attr.Value{
			"oid":         types.StringValue(pki.FormatOID(a.OID)),
			"value":       types.StringValue(a.Value),
			"string_type": types.StringValue(string(st)),
		})
		elems = append(elems, obj)
		diags.Append(d...)
	}
	if diags.HasError() {
		return types.ListNull(subjectAttributeObjectType()), diags
	}
	list, d := types.ListValue(subjectAttributeObjectType(), elems)
	diags.Append(d...)
	return list, diags
}

// extensionListValue converts a parsed extension list to a types.List of `{oid,
// critical, value_base64}` objects, matching the shape the data source's
// `extensions` attribute and the resource's `extra_extension` block both use.
// Tasks 8 and 9 call this during ImportState.
//
// crypto/x509/pkix is the type of x509.Certificate.Extensions, which is the
// slice Tasks 8 and 9 already have in hand; accepting pkix.Extension directly
// avoids an extra conversion at every caller.
func extensionListValue(ctx context.Context, exts []pkix.Extension) (types.List, diag.Diagnostics) {
	_ = ctx
	if len(exts) == 0 {
		return types.ListNull(extensionAttributeObjectType()), diag.Diagnostics{}
	}
	elems := make([]attr.Value, 0, len(exts))
	var diags diag.Diagnostics
	for _, ext := range exts {
		obj, d := types.ObjectValue(extensionAttributeObjectType().AttrTypes, map[string]attr.Value{
			"oid":          types.StringValue(pki.FormatOID(ext.Id)),
			"critical":     types.BoolValue(ext.Critical),
			"value_base64": types.StringValue(base64.StdEncoding.EncodeToString(ext.Value)),
		})
		elems = append(elems, obj)
		diags.Append(d...)
	}
	if diags.HasError() {
		return types.ListNull(extensionAttributeObjectType()), diags
	}
	list, d := types.ListValue(extensionAttributeObjectType(), elems)
	diags.Append(d...)
	return list, diags
}

// extensionAttributeObjectType is the attr.Type of one element of the
// `extensions` list, mirroring subjectAttributeObjectType's role for the
// subject list. The three attribute names match extraExtensionModel's tfsdk
// tags so the framework serializes the two interchangeably.
func extensionAttributeObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"oid":          types.StringType,
		"critical":     types.BoolType,
		"value_base64": types.StringType,
	}}
}

// subjectDNComputedAttributes returns the nested attribute map shared by the
// `subject` and `issuer` lists: `{oid, value, string_type}`, each Required
// because the data source always populates them — a null sub-attribute would
// mean the provider failed to populate a field it already parsed.
func subjectDNComputedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"oid": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Dotted-decimal OID of the DN attribute type.",
		},
		"value": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "The attribute's value.",
		},
		"string_type": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "The ASN.1 string encoding of `value`: one of " +
				quotedList(subjectStringTypeNames()) + ". Always populated, " +
				"including for the `utf8` default.",
		},
	}
}

// extensionComputedAttributes returns the nested attribute map for the
// `extensions` list: `{oid, critical, value_base64}`, each Required for the
// same reason as the subject's sub-attributes.
func extensionComputedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"oid": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Dotted-decimal OID of the extension.",
		},
		"critical": schema.BoolAttribute{
			Required:            true,
			MarkdownDescription: "Whether the extension is marked critical.",
		},
		"value_base64": schema.StringAttribute{
			Required: true,
			MarkdownDescription: "Standard base64 of the extension's raw DER " +
				"`extnValue` (the OCTET STRING content, not the whole `Extension` " +
				"SEQUENCE).",
		},
	}
}

// sanComputedAttributes returns the nested attribute map for the computed `san`
// object. Computed-only because a data source reads, never configures.
func sanComputedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"dns_names": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "`dNSName` entries, in declaration order.",
		},
		"email_addresses": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "`rfc822Name` entries, in declaration order.",
		},
		"ip_addresses": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			MarkdownDescription: "`iPAddress` entries as plain addresses (`10.0.0.5`, " +
				"`fd00::5`), in declaration order.",
		},
		"uris": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "`uniformResourceIdentifier` entries, in declaration order.",
		},
		"critical": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the extension is marked critical.",
		},
	}
}

// basicConstraintsComputedAttributes returns the nested attribute map for the
// computed `basic_constraints` object.
func basicConstraintsComputedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"ca": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the certificate may act as a certificate authority.",
		},
		"path_len": schema.Int64Attribute{
			Computed: true,
			MarkdownDescription: "Maximum number of intermediate CA certificates that may " +
				"follow this one in a valid chain (`pathLenConstraint`). Null when " +
				"the certificate carries no `pathLenConstraint`.",
		},
		"critical": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the extension is marked critical.",
		},
	}
}

// keyUsageComputedAttributes returns the nested attribute map for the computed
// `key_usage` object.
func keyUsageComputedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"usages": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			MarkdownDescription: "Key usage names in RFC 5280 bit order, such as " +
				"`digitalSignature`, `keyEncipherment`, `keyCertSign`, and `crlSign`. " +
				"The `pki_oids` data source's `key_usages` group lists every accepted " +
				"name against its bit position.",
		},
		"critical": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the extension is marked critical.",
		},
	}
}

// extKeyUsageComputedAttributes returns the nested attribute map for the
// computed `extended_key_usage` object.
func extKeyUsageComputedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"usages": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			MarkdownDescription: "Extended key usage purposes, each either a friendly name " +
				"such as `clientAuth` or a dotted OID. Order is preserved, because " +
				"`extendedKeyUsage` is a `SEQUENCE OF`.",
		},
		"critical": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the extension is marked critical.",
		},
	}
}

// nameConstraintsComputedAttributes returns the nested attribute map for the
// computed `name_constraints` object: the eight subtree lists plus `critical`.
func nameConstraintsComputedAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"permitted_dns_domains": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Permitted DNS name subtrees.",
		},
		"excluded_dns_domains": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Excluded DNS name subtrees.",
		},
		"permitted_email_domains": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Permitted `rfc822Name` subtrees.",
		},
		"excluded_email_domains": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Excluded `rfc822Name` subtrees.",
		},
		"permitted_ip_ranges": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Permitted IP address ranges, in CIDR notation.",
		},
		"excluded_ip_ranges": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Excluded IP address ranges, in CIDR notation.",
		},
		"permitted_uri_domains": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Permitted URI subtrees.",
		},
		"excluded_uri_domains": schema.ListAttribute{
			Computed:            true,
			ElementType:         types.StringType,
			MarkdownDescription: "Excluded URI subtrees.",
		},
		"critical": schema.BoolAttribute{
			Computed:            true,
			MarkdownDescription: "Whether the extension is marked critical.",
		},
	}
}
