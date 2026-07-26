// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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
//
// The variadic validators are for rules internal/pki also enforces at encode
// time. Duplicating one there and here is deliberate: the schema copy reports it
// at plan time against the exact attribute, and internal/pki's copy keeps
// holding for callers that never pass through a schema (import, and its own
// tests).
func stringListAttribute(description string, validators ...validator.List) schema.ListAttribute {
	return schema.ListAttribute{
		Optional:            true,
		ElementType:         types.StringType,
		Validators:          validators,
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

// nonEmptyBlockValidator refuses a block that is present but leaves every one of
// its list attributes empty: `key_usage {}`, `extended_key_usage {}`, and a
// `name_constraints` block with nothing in any of its eight lists.
//
// internal/pki already refuses all three at encode time -- "key usage has no
// usages", "name constraints has no entries" -- but that happens during apply,
// and the diagnostic carries no attribute path, so the operator gets a resource
// error with no line to look at. Here it lands at plan time against the
// attribute the operator has to edit.
//
// A stock listvalidator on the list itself cannot express the null half of this
// rule, which is the half `key_usage {}` needs. listvalidator.SizeAtLeast(1) is
// on `usages` as well, but it skips null, as every stock validator does, and an
// attribute the block leaves out arrives null rather than empty. It therefore
// covers only the explicitly written `usages = []` -- which this validator also
// catches, since an empty collection counts as unset; measured against OpenTofu
// 1.12, the block-level diagnostic is the one reported when both apply.
//
// listvalidator.IsRequired() does fire on null, and is exactly wrong here: the
// framework runs a single-nested block's nested attribute validators even when
// the block itself is absent (fwserver's BlockValidate descends into
// BlockNestingModeSingle unconditionally, unlike nested *attributes*, which it
// skips on a null parent). Adding it to `usages` and planning a configuration
// with no key_usage block at all produced "Block key_usage.usages must have a
// configuration value as the provider has marked it as required" -- measured
// against OpenTofu 1.12 and framework v1.19, and the reason
// TestAccSharedBlocksAcceptEveryBlockOnceAndOmitted plans a resource with every
// optional block left out.
//
// objectvalidator.AtLeastOneOf is not usable either: it returns immediately when
// the value it is attached to is non-null, which for a block validator is
// exactly the case that needs checking. Attaching the list-level form to all
// eight name_constraints lists would work but emit eight identical diagnostics
// for one mistake, the same failure mode subjectFormsValidator was hand-written
// to avoid.
type nonEmptyBlockValidator struct {
	// lists names the block's list attributes, at least one of which must have
	// an entry.
	//
	// A name the block does not actually have is skipped, so a wrong name here
	// fails closed: the rule then reports every present block as empty rather
	// than quietly exempting one list from it. That is the safer direction, but
	// it is still wrong, which is what TestNameConstraintsListNamesMatchTheBlock
	// is for -- the eight name_constraints names are derived from the model, and
	// the derivation has to keep matching the schema.
	lists []string
	// pointAt is the attribute the diagnostic is attached to. Empty attaches it
	// to the block itself, which is the honest path when the rule spans several
	// attributes and no single one of them is at fault.
	pointAt string
	summary string
	detail  string
}

var _ validator.Object = nonEmptyBlockValidator{}

func (v nonEmptyBlockValidator) Description(ctx context.Context) string {
	return v.MarkdownDescription(ctx)
}

func (v nonEmptyBlockValidator) MarkdownDescription(_ context.Context) string {
	return "the block must have at least one entry across " + strings.Join(v.lists, ", ")
}

func (v nonEmptyBlockValidator) ValidateObject(_ context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	// A block the configuration omits arrives as a null object, and the
	// framework calls this validator for it anyway. Absence is not the mistake
	// this validator is looking for.
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	attrs := req.ConfigValue.Attributes()
	for _, name := range v.lists {
		value, ok := attrs[name]
		if !ok || value == nil {
			continue
		}
		// Defer on unknown rather than guessing, which is what every stock
		// validator does ("delay validation until all involved attributes have
		// a known value"). An unknown list may resolve to a non-empty one, and
		// a plan-time error over it would reject a configuration that applies
		// cleanly. isSet is not the predicate to reach for here; see its own
		// comment on why it reports unknown as set.
		if value.IsUnknown() {
			return
		}
		if isSet(value) {
			return
		}
	}

	p := req.Path
	if v.pointAt != "" {
		p = p.AtName(v.pointAt)
	}
	resp.Diagnostics.AddAttributeError(p, v.summary, v.detail)
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
		Validators: []validator.Object{nonEmptyBlockValidator{
			lists:   []string{"usages"},
			pointAt: "usages",
			summary: "Missing key usages",
			detail: "A `key_usage` block must name at least one usage: RFC 5280 4.2.1.3 has no " +
				"encoding for a `keyUsage` extension with no bits set. Omit the block entirely " +
				"to apply this resource's documented default instead.",
		}},
		Attributes: map[string]schema.Attribute{
			"usages": stringListAttribute(
				"Key usage names, such as `digitalSignature`, `keyEncipherment`, `keyCertSign`, "+
					"and `crlSign`. The `pki_oids` data source's `key_usages` group lists every "+
					"accepted name against its RFC 5280 bit position. Duplicates are rejected, and "+
					"at least one usage is required.",
				listvalidator.SizeAtLeast(1),
				listvalidator.UniqueValues()),
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
		Validators: []validator.Object{nonEmptyBlockValidator{
			lists:   []string{"usages"},
			pointAt: "usages",
			summary: "Missing extended key usages",
			detail: "An `extended_key_usage` block must name at least one purpose: " +
				"`extendedKeyUsage` is a `SEQUENCE OF` with no valid empty form. Omit the block " +
				"entirely to emit no `extendedKeyUsage` extension at all.",
		}},
		Attributes: map[string]schema.Attribute{
			"usages": stringListAttribute(
				"Extended key usage purposes, each either a friendly name such as `clientAuth` or "+
					"a dotted OID such as `1.3.6.1.4.1.311.20.2.2`. The two spellings may be "+
					"mixed, but naming the same purpose twice in either spelling is rejected as "+
					"the duplicate it is.",
				listvalidator.SizeAtLeast(1),
				// Only the same-spelling duplicate is catchable here. Naming one
				// purpose by name and by OID is a duplicate too, and resolving
				// the two spellings to compare them is what internal/pki's own
				// check does after ExtKeyUsageOID.
				listvalidator.UniqueValues()),
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
		Validators: []validator.Object{nonEmptyBlockValidator{
			lists:   nameConstraintsListNames,
			summary: "Empty name constraints",
			detail: "A `name_constraints` block must have at least one entry across its eight " +
				"lists (" + strings.Join(nameConstraintsListNames, ", ") + "). RFC 5280 4.2.1.10 " +
				"requires at least one of the permitted and excluded subtree sets, so a CA with " +
				"nothing to constrain must omit the block entirely rather than declare it empty.",
		}},
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
						"`1.3.6.1.5.5.7.1.24`.\n\n" +
						"It must be a structurally valid ASN.1 object identifier, which is stricter " +
						"than \"two or more numbers separated by dots\": at least two arcs, a first " +
						"arc of `0`, `1` or `2`, and — under a first arc of `0` or `1` only — a " +
						"second arc no greater than `39`. X.690 encodes the first two arcs as the " +
						"single subidentifier `40*first + second`, which is reversible only within " +
						"those limits, so `5.99` and `1.40` are refused with a message naming the " +
						"OID instead of failing later as `encoding/asn1`'s \"invalid object " +
						"identifier\", which would name neither the extension nor this attribute. " +
						"The `2` arc deliberately has no such ceiling, so the arc reserved for " +
						"examples, `2.999.x`, is accepted.",
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
