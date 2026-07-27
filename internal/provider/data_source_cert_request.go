// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var _ datasource.DataSource = (*certRequestDataSource)(nil)

// certRequestDataSource decodes a CSR that arrived from elsewhere — a device, a
// different team, a Kubernetes Secret — and reports its contents without signing
// anything. The signature_valid attribute is the point of the data source: a
// CSR whose signature does not verify is surfaced as data (signature_valid =
// false) rather than raised as an error, because the caller inspecting it wants
// to decide what to do with that fact.
type certRequestDataSource struct{}

// NewCertRequestDataSource returns the pki_cert_request data source.
func NewCertRequestDataSource() datasource.DataSource {
	return &certRequestDataSource{}
}

func (d *certRequestDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_request"
}

func (d *certRequestDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Decodes a certificate signing request that arrived from elsewhere — a " +
			"device, another team, a Kubernetes Secret — and reports its contents for inspection " +
			"or assertion before issuing.\n\n" +
			"Unlike the resource of the same name, this data source does not create anything: it " +
			"reads an existing CSR. A CSR whose signature does not verify is reported as " +
			"`signature_valid = false` rather than raised as an error, because refusing to decode " +
			"it would hide the only signal that matters.",
		Attributes: map[string]schema.Attribute{
			"content_pem": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The CSR as a PEM `CERTIFICATE REQUEST` block. Exactly one of " +
					"`content_pem` and `content_base64` must be set.",
			},
			"content_base64": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The CSR's DER, standard base64-encoded, so material read " +
					"straight out of a Kubernetes Secret needs no decoding step. Exactly one of " +
					"`content_pem` and `content_base64` must be set.",
			},
			"subject": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "The request's subject DN as a list of `{oid, value, " +
					"string_type}` objects in declaration order — the only order a parser can " +
					"report, because the DN's attribute order is part of its bytes. " +
					"`string_type` is always populated, so a caller comparing two requests sees " +
					"the ASN.1 encoding each attribute carries.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						// The nested attributes are Required because this is a computed
						// data source: the provider always populates every one of them,
						// and a null sub-attribute would mean the provider failed to
						// decode something it already parsed. string_type is the one the
						// brief calls out: it is populated even when the encoding is the
						// utf8 default, unlike the resource's input form which omits it.
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
					},
				},
			},
			"san": schema.SingleNestedAttribute{
				Computed: true,
				MarkdownDescription: "The `subjectAltName` extension, decoded into its four " +
					"GeneralName types. Null when the CSR carries no subjectAltName.",
				Attributes: map[string]schema.Attribute{
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
				},
			},
			"requested_extensions": schema.ListNestedAttribute{
				Computed: true,
				MarkdownDescription: "Every extension the CSR carries, in declaration order, " +
					"including the SAN. Each is reported unparsed — as its OID, criticality, and " +
					"the raw base64 of its `extnValue` — so nothing is lost to a parser this data " +
					"source does not have, and a caller can see extensions the typed `san` block " +
					"does not surface.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
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
					},
				},
			},
			"public_key_algorithm": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The public key's algorithm: `RSA`, `ECDSA`, or `ED25519`.",
			},
			"public_key_pem": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The CSR's public key, PKIX-encoded (`PUBLIC KEY`).",
			},
			"signature_algorithm": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The signature algorithm the request carries, one of " +
					quotedList(pki.SignatureAlgorithmNames()) + ".",
			},
			"signature_valid": schema.BoolAttribute{
				Computed: true,
				MarkdownDescription: "Whether the request's self-signature verifies. A `false` " +
					"value is **data, not an error**: the whole point of this data source is to " +
					"surface it so the caller can refuse to issue against a request whose " +
					"signature does not check out.",
			},
		},
	}
}

// ConfigValidators requires exactly one of content_pem and content_base64, using
// the datasourcevalidator package (not resourcevalidator). The framework's
// diagnostic for a violation includes "Invalid Attribute Combination", which is
// distinct from any configuration text and is what the acceptance test matches.
func (d *certRequestDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("content_pem"),
			path.MatchRoot("content_base64"),
		),
	}
}

// certRequestDataSourceModel is the data source's state model. The subject and
// extension lists reuse attributeModel and extraExtensionModel because their
// shapes — {oid, value, string_type} and {oid, value_base64, critical} — are the
// same shapes the resource's blocks use, and the tfsdk tags already match.
type certRequestDataSourceModel struct {
	ContentPEM          types.String          `tfsdk:"content_pem"`
	ContentBase64       types.String          `tfsdk:"content_base64"`
	Subject             []attributeModel      `tfsdk:"subject"`
	SAN                 *sanModel             `tfsdk:"san"`
	RequestedExtensions []extraExtensionModel `tfsdk:"requested_extensions"`
	PublicKeyAlgorithm  types.String          `tfsdk:"public_key_algorithm"`
	PublicKeyPEM        types.String          `tfsdk:"public_key_pem"`
	SignatureAlgorithm  types.String          `tfsdk:"signature_algorithm"`
	SignatureValid      types.Bool            `tfsdk:"signature_valid"`
}

func (d *certRequestDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config certRequestDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve the input to PEM bytes. content_pem is used verbatim;
	// content_base64 is decoded first, so a Kubernetes Secret's base64 needs no
	// manual decoding step.
	var pemBytes []byte
	if !config.ContentBase64.IsNull() {
		decoded, err := base64.StdEncoding.DecodeString(config.ContentBase64.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("content_base64"),
				"Invalid base64 in content_base64",
				"content_base64 must be the standard base64 encoding of the CSR's DER: "+err.Error())
			return
		}
		pemBytes = decoded
	} else {
		pemBytes = []byte(config.ContentPEM.ValueString())
	}

	// Parse without verifying the signature: a false signature is the data the
	// caller asked for, not an error. A malformed PEM is still an error, because
	// there is nothing to inspect in a request that could not be parsed.
	//
	// csr's type (*x509.CertificateRequest) arrives through pki's return and is
	// never named here, so crypto/x509 stays out of this file's import block.
	// Field access and method calls on the inferred type do not require the
	// caller to import the type's defining package.
	csr, signatureValid, err := pki.ParseCertRequestPEMUnverified(pemBytes)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate request", err.Error())
		return
	}

	config.SignatureValid = types.BoolValue(signatureValid)

	// Subject: the ordered form, with string_type always populated.
	// ParseSubjectDER sets StringType from the parsed ASN.1 tag, so it is never
	// empty for a successfully parsed DN attribute — the utf8 default is
	// explicit here, unlike the resource's input form which omits it.
	subject, err := pki.ParseSubjectDER(csr.RawSubject)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate request subject", err.Error())
		return
	}
	config.Subject = certRequestSubjectFromPKI(subject)

	// SAN: decoded if the extension is present, null otherwise. sanFromPKI
	// returns nil for an empty SAN, which serializes as a null attribute.
	//
	// The subjectAltName OID (2.5.29.17) is resolved through pki.ParseOID
	// rather than reached through crypto/x509/pkix, and ext.Id.Equal compares
	// the parsed values without the provider naming either type.
	sanOID, err := pki.ParseOID("2.5.29.17")
	if err != nil {
		resp.Diagnostics.AddError("Internal error resolving subjectAltName OID", err.Error())
		return
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(sanOID) {
			s, parseErr := pki.ParseSANExtension(ext)
			if parseErr != nil {
				resp.Diagnostics.AddError("Unable to parse subjectAltName extension", parseErr.Error())
				return
			}
			config.SAN = sanFromPKI(s)
			break
		}
	}

	// Requested extensions: every extension, unparsed, in declaration order.
	// Ranging over csr.Extensions with := avoids naming pkix.Extension here.
	requested := make([]extraExtensionModel, 0, len(csr.Extensions))
	for _, ext := range csr.Extensions {
		requested = append(requested, extraExtensionModel{
			OID:         types.StringValue(pki.FormatOID(ext.Id)),
			Critical:    types.BoolValue(ext.Critical),
			ValueBase64: types.StringValue(base64.StdEncoding.EncodeToString(ext.Value)),
		})
	}
	config.RequestedExtensions = requested

	// Public key algorithm. Go's x509.PublicKeyAlgorithm.String() returns
	// "Ed25519" for Ed25519, but the provider convention (matching
	// pki.Algorithm and the pki_private_key resource) is "ED25519". RSA and
	// ECDSA match between the two spellings.
	pubAlg := csr.PublicKeyAlgorithm.String()
	if pubAlg == "Ed25519" {
		pubAlg = "ED25519"
	}
	config.PublicKeyAlgorithm = types.StringValue(pubAlg)

	pubPEM, err := pki.EncodePublicKeyPEM(csr.PublicKey)
	if err != nil {
		resp.Diagnostics.AddError("Unable to encode public key", err.Error())
		return
	}
	config.PublicKeyPEM = types.StringValue(string(pubPEM))

	// An unsupported algorithm in a parsed CSR is still data the caller may want
	// to see; report the raw value rather than failing the read.
	if sigAlgName, err := pki.SignatureAlgorithmName(csr.SignatureAlgorithm); err != nil {
		config.SignatureAlgorithm = types.StringValue(fmt.Sprintf("%v", csr.SignatureAlgorithm))
	} else {
		config.SignatureAlgorithm = types.StringValue(sigAlgName)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// certRequestSubjectFromPKI converts a parsed subject to the data source's
// always-populated form. Unlike subjectFromPKI (the import direction, which
// writes null for the utf8 default), this always writes string_type, because
// the data source's computed subject documents the encoding every attribute
// carries — a caller comparing two requests needs to see it.
func certRequestSubjectFromPKI(s pki.Subject) []attributeModel {
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
