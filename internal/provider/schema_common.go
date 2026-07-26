// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// canonicalSubjectOrder is the order the named subject fields expand to, spelled
// the way pki.NamedSubject.Expand implements it. It appears verbatim in the
// generated documentation because it is a compatibility promise: changing it
// changes the DER of every DN built from named fields, and a DN that changes is
// a certificate that gets replaced.
const canonicalSubjectOrder = "`CN, UID, GN, SN, O, OU..., L, ST, street, postalCode, C, dnQualifier, serialNumber`"

// criticalAttribute builds the `critical` attribute shared by every extension
// block.
//
// Optional and Computed together are what booldefault.StaticBool requires, and
// that pairing is also what makes an omitted `critical` show its default in
// state rather than null -- state holding null where the certificate carries a
// real criticality flag would read as drift.
func criticalAttribute(defaultValue bool, description string) schema.BoolAttribute {
	return schema.BoolAttribute{
		Optional:            true,
		Computed:            true,
		Default:             booldefault.StaticBool(defaultValue),
		MarkdownDescription: description,
	}
}

// stringListAttribute builds an optional list-of-strings attribute. A list, not
// a set: entry order is preserved in the encoded extension, so a set would
// discard information the certificate carries.
func stringListAttribute(description string) schema.ListAttribute {
	return schema.ListAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		MarkdownDescription: description,
	}
}

// subjectAttributeObjectType is the attr.Type of one attribute or
// extra_attribute block, which the validator and its tests need in order to
// build values of the subject object.
func subjectAttributeObjectType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"oid":         types.StringType,
		"value":       types.StringType,
		"string_type": types.StringType,
	}}
}

// dnAttributeBlock builds the attribute or extra_attribute block. Both have the
// same shape and differ only in where their attributes land in the DN, so they
// share one constructor and differ only in description.
//
// A ListNestedBlock, never a SetNestedBlock: DN attribute order is significant
// in DER, and a set discards it.
func dnAttributeBlock(description string) schema.ListNestedBlock {
	return schema.ListNestedBlock{
		MarkdownDescription: description,
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"oid": schema.StringAttribute{
					Required: true,
					MarkdownDescription: "Dotted-decimal OID of the DN attribute type, such as " +
						"`2.5.4.3` for `commonName`. The `provider::pki::oid` function resolves a " +
						"friendly name to this value.",
				},
				"value": schema.StringAttribute{
					Required: true,
					MarkdownDescription: "The attribute's value. An empty value is rejected: " +
						"openssl's configuration format cannot express one either, so a certificate " +
						"carrying it would be reproducible by nothing else.",
				},
				"string_type": schema.StringAttribute{
					Optional: true,
					MarkdownDescription: "ASN.1 string encoding for `value`, one of " +
						quotedList(subjectStringTypeNames()) + ". Defaults to `utf8`, which is what " +
						"reproduces a DN written by openssl with `string_mask = utf8only`. This is " +
						"not cosmetic: the encoding is part of the DN's bytes, so a certificate " +
						"whose DN uses `printable` must say so here or it will never compare equal. " +
						"Import populates this attribute from the parsed DER, and omits it when the " +
						"parsed type is the `utf8` default.",
				},
			},
		},
	}
}

// subjectBlock returns the `subject` block, shared by every resource and data
// source that carries a distinguished name.
func subjectBlock() schema.Block {
	return schema.SingleNestedBlock{
		MarkdownDescription: "The certificate's subject distinguished name, in either of two mutually " +
			"exclusive forms.\n\n" +
			"**Named fields** are the terse form and what hand-written configuration should prefer. " +
			"They expand to the canonical order " + canonicalSubjectOrder + ", and `extra_attribute` " +
			"blocks append after all of them in declaration order.\n\n" +
			"**The ordered `attribute` form** spells out every DN attribute in the order given. It " +
			"exists because the canonical order above cannot produce every DN: an attribute with no " +
			"named field, such as `displayName`, can only be appended at the end by the named form, " +
			"so a DN that interleaves one must use this form. Import always writes this form, which " +
			"is what makes an adopted certificate's DN reproducible byte-for-byte regardless of how " +
			"the original was produced.\n\n" +
			"The two forms may not be combined: setting any named field or `extra_attribute` block " +
			"alongside an `attribute` block is an error.\n\n" +
			"Drift is compared on the **encoded DN bytes**, not on the shape of the configuration, " +
			"so any configuration that encodes to the same DN plans clean — including a named-field " +
			"configuration whose canonical order happens to match an ordered-form original.",
		Validators: []validator.Object{subjectFormsValidator{}},
		Attributes: map[string]schema.Attribute{
			"common_name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`commonName` (OID 2.5.4.3).",
			},
			"country": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "`countryName` (OID 2.5.4.6), conventionally a two-letter " +
					"ISO 3166-1 alpha-2 code such as `US`.",
			},
			"organization": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`organizationName` (OID 2.5.4.10).",
			},
			"organizational_units": stringListAttribute(
				"`organizationalUnitName` (OID 2.5.4.11), one DN attribute per element, in order."),
			"locality": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`localityName` (OID 2.5.4.7).",
			},
			"province": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "`stateOrProvinceName` (OID 2.5.4.8), rendered `ST` in " +
					"human-readable DN output.",
			},
			"street_addresses": stringListAttribute(
				"`streetAddress` (OID 2.5.4.9), one DN attribute per element, in order."),
			"postal_code": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`postalCode` (OID 2.5.4.17).",
			},
			"serial_number": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The `serialNumber` **DN attribute** (OID 2.5.4.5), not the " +
					"certificate's serial number. The certificate's serial is the top-level " +
					"`serial_number` attribute. This collision exists in `hashicorp/tls` too and is " +
					"documented rather than renamed.",
			},
			"surname": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`surname` (OID 2.5.4.4), rendered `SN`.",
			},
			"given_name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`givenName` (OID 2.5.4.42), rendered `GN`.",
			},
			"uid": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`uid` (OID 0.9.2342.19200300.100.1.1).",
			},
			"dn_qualifier": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "`dnQualifier` (OID 2.5.4.46).",
			},
		},
		Blocks: map[string]schema.Block{
			"extra_attribute": dnAttributeBlock(
				"DN attributes with no named field above, appended after every named field in " +
					"declaration order. Repeatable. Because they can only be appended, a DN that " +
					"needs one of them positioned earlier must use the ordered `attribute` form " +
					"instead."),
			"attribute": dnAttributeBlock(
				"One DN attribute, in the exact position it should occupy. Repeatable, and " +
					"significant in order. Mutually exclusive with every named field and with " +
					"`extra_attribute`; this is the form import writes."),
		},
	}
}

// subjectFormsValidator refuses a subject block that mixes the named fields
// with the ordered `attribute` form.
//
// This is hand-written rather than assembled from
// terraform-plugin-framework-validators' stringvalidator.ConflictsWith and
// friends for one reason: it produces a single diagnostic naming both forms and
// explaining the choice, where ConflictsWith on each of the fourteen named
// fields would produce up to fourteen generic "Invalid Attribute Combination"
// errors for one mistake. It also avoids a dependency the module does not
// otherwise need.
//
// It is NOT because ConflictsWith would misbehave on the block collections.
// An absent block collection arrives as null -- including a `dynamic` block
// with an empty for_each, measured against OpenTofu 1.12 and framework v1.19 --
// so ConflictsWith's null gate would work correctly here. Later tasks needing a
// mutual-exclusivity or requires-together check should reach for the stock
// validators first; they are sound for blocks.
//
// It reads the raw attribute values rather than reflecting into subjectModel
// because during validation a nested value may still be unknown, which decoding
// into the model's []attributeModel would reject outright.
type subjectFormsValidator struct{}

var _ validator.Object = subjectFormsValidator{}

func (v subjectFormsValidator) Description(ctx context.Context) string {
	return v.MarkdownDescription(ctx)
}

func (v subjectFormsValidator) MarkdownDescription(_ context.Context) string {
	return "the named fields and the ordered `attribute` blocks are mutually exclusive"
}

func (v subjectFormsValidator) ValidateObject(_ context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	named, ordered := subjectFormsInUse(req.ConfigValue.Attributes())
	if !named || !ordered {
		return
	}
	resp.Diagnostics.AddAttributeError(req.Path,
		"Conflicting subject forms",
		"The subject block accepts either the named fields ("+
			strings.Join(namedSubjectFieldNames, ", ")+
			") or the ordered `attribute` blocks, but not both. The named fields expand to a fixed "+
			"canonical order; the `attribute` form spells out every DN attribute in the order "+
			"given. Remove one of the two forms.")
}

// sanBlock returns the `san` block: the subjectAltName extension in the four
// GeneralName types this provider represents.
func sanBlock() schema.Block {
	return schema.SingleNestedBlock{
		MarkdownDescription: "The `subjectAltName` extension (RFC 5280 4.2.1.6). Entry order is " +
			"preserved within each type, and the types themselves are always encoded in the order " +
			"`dns_names`, `email_addresses`, `ip_addresses`, `uris`, which is what openssl produces " +
			"from an `[alt]` section listing DNS first.\n\n" +
			"`otherName`, `registeredID`, and `directoryName` are out of scope; `extra_extension` " +
			"is the escape hatch if one is ever needed.",
		Attributes: map[string]schema.Attribute{
			"dns_names": stringListAttribute(
				"`dNSName` entries. Values must be ASCII, the repertoire `IA5String` can encode; " +
					"an internationalized name must be supplied in its A-label (punycode) form."),
			"email_addresses": stringListAttribute(
				"`rfc822Name` entries. Mailbox syntax is not validated beyond the `IA5String` " +
					"repertoire, because the existing issuer did not validate it either and " +
					"rejecting a name it already issued would block adoption."),
			"ip_addresses": stringListAttribute(
				"`iPAddress` entries, as plain addresses such as `10.0.0.5` or `fd00::5`. CIDR " +
					"notation is rejected. An IPv4 address is encoded as four bytes, matching " +
					"openssl, so it renders as `10.0.0.5` rather than `::ffff:10.0.0.5`."),
			"uris": stringListAttribute(
				"`uniformResourceIdentifier` entries, such as `spiffe://homelab/nick-ipad`. Each " +
					"must be an absolute URI; the string is written to the certificate verbatim, " +
					"not re-serialized."),
			"critical": criticalAttribute(false,
				"Defaults to `false`, and is forced to `true` when the subject is empty, as "+
					"RFC 5280 requires: with no subject DN the `subjectAltName` is the "+
					"certificate's only identity."),
		},
	}
}

// basicConstraintsBlock returns the `basic_constraints` block. defaultCA is a
// parameter because the CA resource defaults `ca = true` while the leaf
// certificate resource defaults `ca = false`, and the difference is stated in
// the description so each resource's generated documentation is accurate.
func basicConstraintsBlock(defaultCA bool) schema.Block {
	caDefault := "false"
	if defaultCA {
		caDefault = "true"
	}
	return schema.SingleNestedBlock{
		MarkdownDescription: "The `basicConstraints` extension (RFC 5280 4.2.1.9). Omitting the block " +
			"applies this resource's defaults, `ca = " + caDefault + "` and `critical = true`, " +
			"rather than emitting no extension.",
		Attributes: map[string]schema.Attribute{
			"ca": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(defaultCA),
				MarkdownDescription: "Whether the certificate may act as a certificate authority. " +
					"Defaults to `" + caDefault + "` for this resource.",
			},
			"path_len": schema.Int64Attribute{
				Optional: true,
				MarkdownDescription: "Maximum number of intermediate CA certificates that may " +
					"follow this one in a valid chain (`pathLenConstraint`).\n\n" +
					"**Unset and `0` are different.** Null means no path length constraint at all; " +
					"`0` means this CA may not issue further CA certificates. X.509 draws a real " +
					"distinction between the two, so this attribute has no default and is left " +
					"null when omitted.\n\n" +
					"Only valid when `ca` is `true`.",
			},
			"critical": criticalAttribute(true,
				"Defaults to `true`. RFC 5280 requires `basicConstraints` to be marked critical "+
					"in a CA certificate."),
		},
	}
}

// keyUsageBlock returns the `key_usage` block.
func keyUsageBlock() schema.Block {
	return schema.SingleNestedBlock{
		MarkdownDescription: "The `keyUsage` extension (RFC 5280 4.2.1.3).\n\n" +
			"Because `keyUsage` is a `BIT STRING`, the order entries appear in is not " +
			"representable and does not affect the encoding; state always holds them in RFC 5280 " +
			"bit order. Omitting the block applies the resource's documented default rather than " +
			"emitting no extension.",
		Attributes: map[string]schema.Attribute{
			"usages": stringListAttribute(
				"Key usage names, such as `digitalSignature`, `keyEncipherment`, `keyCertSign`, " +
					"and `crlSign`. The `pki_oids` data source's `key_usages` group lists every " +
					"accepted name against its RFC 5280 bit position. Duplicates are rejected, and " +
					"at least one usage is required."),
			"critical": criticalAttribute(true, "Defaults to `true`."),
		},
	}
}

// extendedKeyUsageBlock returns the `extended_key_usage` block.
func extendedKeyUsageBlock() schema.Block {
	return schema.SingleNestedBlock{
		MarkdownDescription: "The `extendedKeyUsage` extension (RFC 5280 4.2.1.12).\n\n" +
			"Unlike `key_usage`, order **is** significant here: `extendedKeyUsage` is a " +
			"`SEQUENCE OF`, so entries are encoded in the order given and read back in the order " +
			"the certificate carries.",
		Attributes: map[string]schema.Attribute{
			"usages": stringListAttribute(
				"Extended key usage purposes, each either a friendly name such as `clientAuth` or " +
					"a dotted OID such as `1.3.6.1.4.1.311.20.2.2`. The two spellings may be " +
					"mixed, but naming the same purpose twice in either spelling is rejected as " +
					"the duplicate it is."),
			"critical": criticalAttribute(false, "Defaults to `false`."),
		},
	}
}

// nameConstraintsBlock returns the `name_constraints` block, which is
// meaningful only on a CA certificate.
func nameConstraintsBlock() schema.Block {
	return schema.SingleNestedBlock{
		MarkdownDescription: "The `nameConstraints` extension (RFC 5280 4.2.1.10), which limits the " +
			"names this CA and every CA beneath it may certify. Meaningful only on a CA " +
			"certificate.\n\n" +
			"At least one entry across all eight lists is required: RFC 5280 forbids an empty " +
			"`nameConstraints`, so a CA with nothing to constrain must omit the block entirely.",
		Attributes: map[string]schema.Attribute{
			"permitted_dns_domains": stringListAttribute(
				"DNS name subtrees this CA may certify. A leading dot, as in " +
					"`.ha.apps.somemissing.info`, constrains subdomains."),
			"excluded_dns_domains": stringListAttribute(
				"DNS name subtrees this CA may not certify, in the same form as " +
					"`permitted_dns_domains`."),
			"permitted_email_domains": stringListAttribute(
				"`rfc822Name` subtrees this CA may certify."),
			"excluded_email_domains": stringListAttribute(
				"`rfc822Name` subtrees this CA may not certify."),
			"permitted_ip_ranges": stringListAttribute(
				"IP address ranges this CA may certify, in CIDR notation such as `10.0.0.0/8` or " +
					"`fd00::/8`. A bare address is rejected rather than treated as a `/32`, and " +
					"host bits are normalized away. An IPv4-mapped IPv6 CIDR such as " +
					"`::ffff:10.0.0.0/104` is rejected because it cannot round-trip through the " +
					"`iPAddress` encoding; write it as plain IPv4 instead."),
			"excluded_ip_ranges": stringListAttribute(
				"IP address ranges this CA may not certify, in the same form as " +
					"`permitted_ip_ranges`."),
			"permitted_uri_domains": stringListAttribute(
				"URI subtrees this CA may certify. A leading dot constrains subdomains."),
			"excluded_uri_domains": stringListAttribute(
				"URI subtrees this CA may not certify."),
			"critical": criticalAttribute(true,
				"Defaults to `true`. RFC 5280 requires `nameConstraints` to be marked critical."),
		},
	}
}

// extraExtensionBlock returns the repeatable `extra_extension` block, the
// escape hatch for any extension the provider has no typed support for.
//
// A ListNestedBlock, never a SetNestedBlock: extensions are encoded in
// declaration order, and a set would discard it.
func extraExtensionBlock() schema.Block {
	return schema.ListNestedBlock{
		MarkdownDescription: "An extension the provider has no typed support for, written verbatim. " +
			"Repeatable, and encoded in declaration order.\n\n" +
			"Use this for anything the typed blocks above do not cover, including the " +
			"`GeneralName` forms `san` omits. The provider neither parses nor re-encodes the " +
			"value, so nothing is lost to a round trip through a parser this provider does not " +
			"have — and nothing is validated either.",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"oid": schema.StringAttribute{
					Required: true,
					MarkdownDescription: "Dotted-decimal OID of the extension, such as " +
						"`1.3.6.1.5.5.7.1.24`. Must have at least two arcs.",
				},
				"value_base64": schema.StringAttribute{
					Required: true,
					MarkdownDescription: "Base64 of the raw DER of the extension's `extnValue`. " +
						"The provider does not interpret it. This is the content of `extnValue` " +
						"only, not the whole `Extension` SEQUENCE and not the `OCTET STRING` " +
						"wrapper: `MAMCAQU=`, for example, is the DER `SEQUENCE { INTEGER 5 }`.",
				},
				"critical": criticalAttribute(false,
					"Defaults to `false`. A relying party that does not recognize a critical "+
						"extension must reject the certificate, so mark an extension critical "+
						"only deliberately."),
			},
		},
	}
}

// quotedList renders names as a backtick-quoted, comma-separated list for use
// in a MarkdownDescription.
func quotedList(names []string) string {
	quoted := make([]string, 0, len(names))
	for _, n := range names {
		quoted = append(quoted, "`"+n+"`")
	}
	return strings.Join(quoted, ", ")
}
