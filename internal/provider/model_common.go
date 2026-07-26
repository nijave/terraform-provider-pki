// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

// subjectModel is the subject block in both of its forms.
//
// The two forms are mutually exclusive (spec section 5.1): named fields expand
// to a documented canonical order, while the ordered form spells out every
// attribute so a DN that the canonical order cannot produce -- engine.py places
// displayName between UID and GN -- can still be expressed exactly. Import
// always writes the ordered form, which is what makes an adopted certificate
// plan clean.
type subjectModel struct {
	CommonName          types.String `tfsdk:"common_name"`
	Country             types.String `tfsdk:"country"`
	Organization        types.String `tfsdk:"organization"`
	OrganizationalUnits types.List   `tfsdk:"organizational_units"`
	Locality            types.String `tfsdk:"locality"`
	Province            types.String `tfsdk:"province"`
	StreetAddresses     types.List   `tfsdk:"street_addresses"`
	PostalCode          types.String `tfsdk:"postal_code"`

	// SerialNumber is the DN attribute 2.5.4.5, not the certificate serial.
	// The collision exists in hashicorp/tls too and is documented rather than
	// renamed; the certificate's serial is the top-level serial_number
	// attribute on the certificate resources.
	SerialNumber types.String `tfsdk:"serial_number"`

	Surname     types.String `tfsdk:"surname"`
	GivenName   types.String `tfsdk:"given_name"`
	UID         types.String `tfsdk:"uid"`
	DNQualifier types.String `tfsdk:"dn_qualifier"`

	ExtraAttributes []attributeModel `tfsdk:"extra_attribute"`
	Attributes      []attributeModel `tfsdk:"attribute"`
}

type attributeModel struct {
	OID   types.String `tfsdk:"oid"`
	Value types.String `tfsdk:"value"`

	// StringType controls the ASN.1 encoding of Value. It is optional and
	// defaults to utf8, which is what reproduces the certificates the homelab
	// issuer already produced (it runs openssl with string_mask = utf8only).
	// Import populates it from the parsed DER, so a certificate carrying a
	// PrintableString value re-encodes byte-exact.
	StringType types.String `tfsdk:"string_type"`
}

// sanModel is the san block: the four GeneralName types internal/pki
// represents, plus the criticality flag.
type sanModel struct {
	DNSNames       types.List `tfsdk:"dns_names"`
	EmailAddresses types.List `tfsdk:"email_addresses"`
	IPAddresses    types.List `tfsdk:"ip_addresses"`
	URIs           types.List `tfsdk:"uris"`
	Critical       types.Bool `tfsdk:"critical"`
}

// basicConstraintsModel is the basic_constraints block.
//
// PathLen is types.Int64 rather than a bare int precisely so null survives as
// null: X.509 distinguishes an absent pathLenConstraint from a present one of
// 0, and pki.BasicConstraints.PathLen is a *int for the same reason.
type basicConstraintsModel struct {
	CA       types.Bool  `tfsdk:"ca"`
	PathLen  types.Int64 `tfsdk:"path_len"`
	Critical types.Bool  `tfsdk:"critical"`
}

// keyUsageModel is the key_usage block. Usages holds names from the key_usages
// table; order is not significant, because keyUsage is a BIT STRING.
type keyUsageModel struct {
	Usages   types.List `tfsdk:"usages"`
	Critical types.Bool `tfsdk:"critical"`
}

// extKeyUsageModel is the extended_key_usage block. Unlike key_usage, order is
// significant: extendedKeyUsage is a SEQUENCE OF.
type extKeyUsageModel struct {
	Usages   types.List `tfsdk:"usages"`
	Critical types.Bool `tfsdk:"critical"`
}

// nameConstraintsModel is the name_constraints block, symmetric in permitted
// and excluded subtrees across all four GeneralName types.
type nameConstraintsModel struct {
	PermittedDNSDomains   types.List `tfsdk:"permitted_dns_domains"`
	ExcludedDNSDomains    types.List `tfsdk:"excluded_dns_domains"`
	PermittedEmailDomains types.List `tfsdk:"permitted_email_domains"`
	ExcludedEmailDomains  types.List `tfsdk:"excluded_email_domains"`
	PermittedIPRanges     types.List `tfsdk:"permitted_ip_ranges"`
	ExcludedIPRanges      types.List `tfsdk:"excluded_ip_ranges"`
	PermittedURIDomains   types.List `tfsdk:"permitted_uri_domains"`
	ExcludedURIDomains    types.List `tfsdk:"excluded_uri_domains"`
	Critical              types.Bool `tfsdk:"critical"`
}

// extraExtensionModel is one extra_extension block: an OID plus the raw DER of
// the extension's extnValue, base64-encoded because HCL has no byte type.
type extraExtensionModel struct {
	OID         types.String `tfsdk:"oid"`
	ValueBase64 types.String `tfsdk:"value_base64"`
	Critical    types.Bool   `tfsdk:"critical"`
}

// subjectStringTypes maps the string_type attribute's accepted values to
// internal/pki's StringType. It is the single source of truth for both the
// converter and the error message that lists the accepted values.
var subjectStringTypes = map[string]pki.StringType{
	"utf8":      pki.StringTypeUTF8,
	"printable": pki.StringTypePrintable,
	"ia5":       pki.StringTypeIA5,
	"bmp":       pki.StringTypeBMP,
	"t61":       pki.StringTypeT61,
}

// subjectStringTypeNames lists the keys of subjectStringTypes in a stable
// order, so a diagnostic and the generated documentation do not reorder
// between runs the way a bare map range would.
func subjectStringTypeNames() []string {
	names := make([]string, 0, len(subjectStringTypes))
	for name := range subjectStringTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// orderedSubjectFieldName is the tfsdk name of the one subject field that
// constitutes the ordered form. Every other field belongs to the named form.
const orderedSubjectFieldName = "attribute"

// subjectFieldIndex maps each subjectModel field's tfsdk name to its struct
// field index, and namedSubjectFieldNames lists every one of those names except
// the ordered form's, in declaration order.
//
// Both are derived from subjectModel by reflection rather than written out,
// because a hand-maintained list is exactly the kind of thing that goes stale:
// a named field added to the model and the schema but missed here would be
// accepted alongside an `attribute` block by both the validator and the
// converter, and then silently dropped, because the ordered branch is the one
// that runs. TestSubjectFieldListsCoverTheWholeModel pins the derivation
// against the schema block so neither can drift from the other.
var subjectFieldIndex, namedSubjectFieldNames = func() (map[string]int, []string) {
	t := reflect.TypeOf(subjectModel{})
	index := make(map[string]int, t.NumField())
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("tfsdk")
		if tag == "" {
			continue
		}
		index[tag] = i
		if tag != orderedSubjectFieldName {
			names = append(names, tag)
		}
	}
	return index, names
}()

// stringsFromList converts a types.List of strings to a []string, treating
// null and unknown as absent rather than as an error: an optional list
// attribute the user did not write is not a problem for the caller to report.
//
// ElementsAs produces diagnostics with no path, so they are re-attached at p --
// otherwise an error on a list buried inside a nested block would render
// against the resource as a whole.
func stringsFromList(ctx context.Context, list types.List, p path.Path) ([]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if list.IsNull() || list.IsUnknown() {
		return nil, diags
	}
	var out []string
	if d := list.ElementsAs(ctx, &out, false); d.HasError() {
		for _, err := range d.Errors() {
			diags.AddAttributeError(p, err.Summary(), err.Detail())
		}
		return nil, diags
	}
	return out, diags
}

// stringsToList is the inverse of stringsFromList, for the import direction. An
// empty slice becomes a null list rather than an empty one, because an optional
// list attribute the config omits is null, and state that said [] instead
// would show as drift forever.
func stringsToList(values []string) types.List {
	if len(values) == 0 {
		return types.ListNull(types.StringType)
	}
	elems := make([]attr.Value, 0, len(values))
	for _, v := range values {
		elems = append(elems, types.StringValue(v))
	}
	return types.ListValueMust(types.StringType, elems)
}

// attributesToPKI converts a list of attribute or extra_attribute blocks,
// attaching each failure at base.AtListIndex(i) so the diagnostic lands on the
// offending block rather than on the subject as a whole.
//
// Every block is visited even after a failure, so a config with three bad OIDs
// reports three errors in one plan instead of one per run.
func attributesToPKI(models []attributeModel, base path.Path) ([]pki.Attribute, diag.Diagnostics) {
	var diags diag.Diagnostics
	if len(models) == 0 {
		return nil, diags
	}

	out := make([]pki.Attribute, 0, len(models))
	for i, am := range models {
		ap := base.AtListIndex(i)

		oid, err := pki.ParseOID(am.OID.ValueString())
		if err != nil {
			diags.AddAttributeError(ap.AtName("oid"), "Invalid OID", err.Error())
			continue
		}

		st := pki.StringTypeUTF8
		if !am.StringType.IsNull() && !am.StringType.IsUnknown() {
			mapped, ok := subjectStringTypes[am.StringType.ValueString()]
			if !ok {
				diags.AddAttributeError(ap.AtName("string_type"),
					"Unknown ASN.1 string type",
					fmt.Sprintf("%q is not a recognized string type. The accepted values are: %s.",
						am.StringType.ValueString(), strings.Join(subjectStringTypeNames(), ", ")))
				continue
			}
			st = mapped
		}

		out = append(out, pki.Attribute{OID: oid, Value: am.Value.ValueString(), StringType: st})
	}
	return out, diags
}

// isSet reports whether a config value was written by the user: null means it
// was not, and unknown means it was but its value is not resolved yet.
//
// An empty collection also counts as unset. That is not about blocks -- a block
// collection that appears zero times arrives as null, including a `dynamic`
// block whose for_each is empty (measured against OpenTofu 1.12 and framework
// v1.19). It is about an explicitly written `organizational_units = []`, which
// arrives as a known, zero-element list and says nothing about the subject.
func isSet(v attr.Value) bool {
	if v == nil || v.IsNull() {
		return false
	}
	if v.IsUnknown() {
		return true
	}
	switch typed := v.(type) {
	case types.List:
		return len(typed.Elements()) > 0
	case types.Set:
		return len(typed.Elements()) > 0
	case types.Map:
		return len(typed.Elements()) > 0
	}
	return true
}

// subjectFormsInUse reports which of the subject block's two mutually
// exclusive forms the given attribute values use. It takes the raw attribute
// map rather than a subjectModel so the schema-level validator can call it on
// a types.Object whose nested values may still be unknown, which reflecting
// into the model would reject.
func subjectFormsInUse(attrs map[string]attr.Value) (named, ordered bool) {
	ordered = isSet(attrs[orderedSubjectFieldName])
	for _, name := range namedSubjectFieldNames {
		if isSet(attrs[name]) {
			named = true
			break
		}
	}
	return named, ordered
}

// fieldIsSet reports whether the model field carrying the given tfsdk name was
// written in configuration. It reaches the field through subjectFieldIndex so
// that adding a field to subjectModel needs no change here.
//
// A field of an unrecognized kind reports false, which would be a silent gap --
// TestSubjectModelFieldsAreAllRecognizedKinds exists to make it impossible to
// reach by asserting every subjectModel field is one of the two kinds handled.
func (m *subjectModel) fieldIsSet(name string) bool {
	i, ok := subjectFieldIndex[name]
	if !ok {
		return false
	}
	switch field := reflect.ValueOf(*m).Field(i).Interface().(type) {
	case attr.Value:
		return isSet(field)
	case []attributeModel:
		return len(field) > 0
	default:
		return false
	}
}

// namedFormInUse is subjectFormsInUse's named half, for a decoded model. Both
// walk namedSubjectFieldNames, so the converter and the schema-level validator
// cannot disagree about which fields constitute the named form.
func (m *subjectModel) namedFormInUse() bool {
	for _, name := range namedSubjectFieldNames {
		if m.fieldIsSet(name) {
			return true
		}
	}
	return false
}

// toPKI converts the subject block to an ordered pki.Subject.
//
// Mixing the two forms is refused rather than resolved. The schema-level
// validator catches it at plan time as well, but a converter that silently
// preferred one form would turn a future schema refactor into a silent change
// of every DN it touches.
func (m *subjectModel) toPKI(ctx context.Context, p path.Path) (pki.Subject, diag.Diagnostics) {
	var diags diag.Diagnostics

	ordered := len(m.Attributes) > 0
	named := m.namedFormInUse()

	if ordered && named {
		diags.AddAttributeError(p,
			"Conflicting subject forms",
			"The subject block accepts either the named fields ("+
				strings.Join(namedSubjectFieldNames, ", ")+
				") or the ordered `attribute` blocks, but not both. The named fields expand to a "+
				"fixed canonical order; the `attribute` form spells out every DN attribute in the "+
				"order given. Remove one of the two forms.")
		return pki.Subject{}, diags
	}

	if ordered {
		attrs, d := attributesToPKI(m.Attributes, p.AtName("attribute"))
		diags.Append(d...)
		if diags.HasError() {
			return pki.Subject{}, diags
		}
		return pki.Subject{Attributes: attrs}, diags
	}

	ous, d := stringsFromList(ctx, m.OrganizationalUnits, p.AtName("organizational_units"))
	diags.Append(d...)
	streets, d := stringsFromList(ctx, m.StreetAddresses, p.AtName("street_addresses"))
	diags.Append(d...)
	extra, d := attributesToPKI(m.ExtraAttributes, p.AtName("extra_attribute"))
	diags.Append(d...)
	if diags.HasError() {
		return pki.Subject{}, diags
	}

	return pki.NamedSubject{
		CommonName:          m.CommonName.ValueString(),
		UID:                 m.UID.ValueString(),
		GivenName:           m.GivenName.ValueString(),
		Surname:             m.Surname.ValueString(),
		Organization:        m.Organization.ValueString(),
		Locality:            m.Locality.ValueString(),
		Province:            m.Province.ValueString(),
		PostalCode:          m.PostalCode.ValueString(),
		Country:             m.Country.ValueString(),
		DNQualifier:         m.DNQualifier.ValueString(),
		SerialNumber:        m.SerialNumber.ValueString(),
		OrganizationalUnits: ous,
		StreetAddresses:     streets,
		ExtraAttributes:     extra,
	}.Expand(), diags
}

// subjectFromPKI converts a parsed DN to the subject block, always in the
// ordered form and never in the named one. That is what makes an adopted
// certificate's DN reproducible byte-for-byte regardless of how the original
// was produced: the canonical order of the named form cannot express every DN,
// and guessing which named fields a parsed DN corresponds to would silently
// reorder the ones it cannot.
//
// string_type is written only when the parsed type is not utf8. utf8 is the
// default, so emitting it explicitly would make a hand-written config and
// imported state differ cosmetically for no benefit.
//
// ExtraAttributes is an empty slice rather than nil, so it converts to an empty
// list rather than a null one. Configuration that declares no `extra_attribute`
// block actually sends null, not an empty list, so the two do not match
// literally -- but Terraform treats a null and an empty block collection as the
// same absence, and an ExpectEmptyPlan check against an imported certificate
// confirmed no drift either way. Either representation works; this one is kept
// because it makes len() the only emptiness test the code needs.
func subjectFromPKI(s pki.Subject) subjectModel {
	m := subjectModel{
		CommonName:          types.StringNull(),
		Country:             types.StringNull(),
		Organization:        types.StringNull(),
		OrganizationalUnits: types.ListNull(types.StringType),
		Locality:            types.StringNull(),
		Province:            types.StringNull(),
		StreetAddresses:     types.ListNull(types.StringType),
		PostalCode:          types.StringNull(),
		SerialNumber:        types.StringNull(),
		Surname:             types.StringNull(),
		GivenName:           types.StringNull(),
		UID:                 types.StringNull(),
		DNQualifier:         types.StringNull(),
		ExtraAttributes:     []attributeModel{},
		Attributes:          make([]attributeModel, 0, len(s.Attributes)),
	}

	for _, a := range s.Attributes {
		am := attributeModel{
			OID:        types.StringValue(pki.FormatOID(a.OID)),
			Value:      types.StringValue(a.Value),
			StringType: types.StringNull(),
		}
		// A zero StringType means utf8 in internal/pki, so both spellings of
		// the default map to a null string_type.
		if a.StringType != "" && a.StringType != pki.StringTypeUTF8 {
			am.StringType = types.StringValue(string(a.StringType))
		}
		m.Attributes = append(m.Attributes, am)
	}
	return m
}

// toPKI converts the san block. The IP addresses are parsed here rather than in
// internal/pki's encoder so an unparseable address is reported against
// ip_addresses at plan time instead of surfacing as a marshalling failure.
func (m *sanModel) toPKI(ctx context.Context, p path.Path) (pki.SAN, diag.Diagnostics) {
	var diags diag.Diagnostics

	dns, d := stringsFromList(ctx, m.DNSNames, p.AtName("dns_names"))
	diags.Append(d...)
	emails, d := stringsFromList(ctx, m.EmailAddresses, p.AtName("email_addresses"))
	diags.Append(d...)
	ipStrings, d := stringsFromList(ctx, m.IPAddresses, p.AtName("ip_addresses"))
	diags.Append(d...)
	uris, d := stringsFromList(ctx, m.URIs, p.AtName("uris"))
	diags.Append(d...)
	if diags.HasError() {
		return pki.SAN{}, diags
	}

	ips, err := pki.ParseIPs(ipStrings)
	if err != nil {
		diags.AddAttributeError(p.AtName("ip_addresses"), "Invalid IP address", err.Error())
		return pki.SAN{}, diags
	}

	return pki.SAN{
		DNSNames:       dns,
		EmailAddresses: emails,
		IPAddresses:    ips,
		URIs:           uris,
		Critical:       m.Critical.ValueBool(),
	}, diags
}

// sanFromPKI converts a parsed subjectAltName to the san block, returning nil
// for an empty SAN so the block is absent from state rather than present and
// empty -- a certificate with no subjectAltName extension has no san block.
func sanFromPKI(s pki.SAN) *sanModel {
	if s.IsEmpty() {
		return nil
	}
	ips := make([]string, 0, len(s.IPAddresses))
	for _, ip := range s.IPAddresses {
		ips = append(ips, ip.String())
	}
	return &sanModel{
		DNSNames:       stringsToList(s.DNSNames),
		EmailAddresses: stringsToList(s.EmailAddresses),
		IPAddresses:    stringsToList(ips),
		URIs:           stringsToList(s.URIs),
		Critical:       types.BoolValue(s.Critical),
	}
}

// toPKI converts the basic_constraints block. It takes no context because the
// block holds no collections.
//
// A null path_len stays nil: that is the whole reason the attribute is
// types.Int64 and pki.BasicConstraints.PathLen is a *int. path_len = 0 becomes
// a pointer to 0, which means "this CA may not issue further CA certificates" --
// a different certificate from one with no constraint at all.
func (m *basicConstraintsModel) toPKI(p path.Path) (pki.BasicConstraints, diag.Diagnostics) {
	var diags diag.Diagnostics

	bc := pki.BasicConstraints{
		CA:       m.CA.ValueBool(),
		Critical: m.Critical.ValueBool(),
	}

	if m.PathLen.IsNull() || m.PathLen.IsUnknown() {
		return bc, diags
	}

	v := m.PathLen.ValueInt64()
	if v < 0 {
		diags.AddAttributeError(p.AtName("path_len"), "Invalid path_len",
			fmt.Sprintf("path_len must not be negative, got %d. Omit the attribute entirely to "+
				"place no path length constraint on the certificate.", v))
		return pki.BasicConstraints{}, diags
	}
	// pki.BasicConstraints.PathLen is an int, which is 32-bit on some
	// platforms, so a value that would wrap is refused rather than truncated
	// into a plausible-looking but different constraint.
	if v > math.MaxInt32 {
		diags.AddAttributeError(p.AtName("path_len"), "Invalid path_len",
			fmt.Sprintf("path_len %d is too large; the maximum is %d.", v, math.MaxInt32))
		return pki.BasicConstraints{}, diags
	}

	n := int(v)
	bc.PathLen = &n
	return bc, diags
}

// basicConstraintsFromPKI converts a parsed basicConstraints extension,
// preserving the absent-versus-zero distinction in the import direction too: a
// nil PathLen becomes a null path_len, never 0.
func basicConstraintsFromPKI(bc pki.BasicConstraints) *basicConstraintsModel {
	m := &basicConstraintsModel{
		CA:       types.BoolValue(bc.CA),
		PathLen:  types.Int64Null(),
		Critical: types.BoolValue(bc.Critical),
	}
	if bc.PathLen != nil {
		m.PathLen = types.Int64Value(int64(*bc.PathLen))
	}
	return m
}

// toPKI converts the key_usage block. Unknown usage names are left for
// pki.KeyUsage.Extension to reject, which keeps the name table in one place.
func (m *keyUsageModel) toPKI(ctx context.Context, p path.Path) (pki.KeyUsage, diag.Diagnostics) {
	usages, diags := stringsFromList(ctx, m.Usages, p.AtName("usages"))
	if diags.HasError() {
		return pki.KeyUsage{}, diags
	}
	return pki.KeyUsage{Usages: usages, Critical: m.Critical.ValueBool()}, diags
}

// keyUsageFromPKI converts a parsed keyUsage extension. ParseKeyUsage already
// returns the usages in RFC 5280 bit order, so state is canonical regardless
// of the order the config listed them in.
func keyUsageFromPKI(ku pki.KeyUsage) *keyUsageModel {
	return &keyUsageModel{
		Usages:   stringsToList(ku.Usages),
		Critical: types.BoolValue(ku.Critical),
	}
}

// toPKI converts the extended_key_usage block. Entries may be friendly names
// or dotted OIDs; pki.ExtKeyUsageOID resolves both.
func (m *extKeyUsageModel) toPKI(ctx context.Context, p path.Path) (pki.ExtKeyUsage, diag.Diagnostics) {
	usages, diags := stringsFromList(ctx, m.Usages, p.AtName("usages"))
	if diags.HasError() {
		return pki.ExtKeyUsage{}, diags
	}
	return pki.ExtKeyUsage{Usages: usages, Critical: m.Critical.ValueBool()}, diags
}

// extKeyUsageFromPKI converts a parsed extendedKeyUsage extension, keeping the
// certificate's order because extendedKeyUsage is a SEQUENCE OF.
func extKeyUsageFromPKI(eku pki.ExtKeyUsage) *extKeyUsageModel {
	return &extKeyUsageModel{
		Usages:   stringsToList(eku.Usages),
		Critical: types.BoolValue(eku.Critical),
	}
}

// toPKI converts the name_constraints block. CIDR and GeneralName syntax are
// validated by pki.NameConstraints.Extension, which reports which entry failed.
func (m *nameConstraintsModel) toPKI(ctx context.Context, p path.Path) (pki.NameConstraints, diag.Diagnostics) {
	var diags diag.Diagnostics

	nc := pki.NameConstraints{Critical: m.Critical.ValueBool()}
	fields := []struct {
		name string
		list types.List
		dst  *[]string
	}{
		{"permitted_dns_domains", m.PermittedDNSDomains, &nc.PermittedDNSDomains},
		{"excluded_dns_domains", m.ExcludedDNSDomains, &nc.ExcludedDNSDomains},
		{"permitted_email_domains", m.PermittedEmailDomains, &nc.PermittedEmailDomains},
		{"excluded_email_domains", m.ExcludedEmailDomains, &nc.ExcludedEmailDomains},
		{"permitted_ip_ranges", m.PermittedIPRanges, &nc.PermittedIPRanges},
		{"excluded_ip_ranges", m.ExcludedIPRanges, &nc.ExcludedIPRanges},
		{"permitted_uri_domains", m.PermittedURIDomains, &nc.PermittedURIDomains},
		{"excluded_uri_domains", m.ExcludedURIDomains, &nc.ExcludedURIDomains},
	}
	for _, f := range fields {
		values, d := stringsFromList(ctx, f.list, p.AtName(f.name))
		diags.Append(d...)
		*f.dst = values
	}
	if diags.HasError() {
		return pki.NameConstraints{}, diags
	}
	return nc, diags
}

// nameConstraintsFromPKI converts a parsed nameConstraints extension,
// returning nil when nothing is constrained so the block is absent from state.
func nameConstraintsFromPKI(nc pki.NameConstraints) *nameConstraintsModel {
	if nc.IsEmpty() {
		return nil
	}
	return &nameConstraintsModel{
		PermittedDNSDomains:   stringsToList(nc.PermittedDNSDomains),
		ExcludedDNSDomains:    stringsToList(nc.ExcludedDNSDomains),
		PermittedEmailDomains: stringsToList(nc.PermittedEmailDomains),
		ExcludedEmailDomains:  stringsToList(nc.ExcludedEmailDomains),
		PermittedIPRanges:     stringsToList(nc.PermittedIPRanges),
		ExcludedIPRanges:      stringsToList(nc.ExcludedIPRanges),
		PermittedURIDomains:   stringsToList(nc.PermittedURIDomains),
		ExcludedURIDomains:    stringsToList(nc.ExcludedURIDomains),
		Critical:              types.BoolValue(nc.Critical),
	}
}

// toPKI converts one extra_extension block. The base64 is decoded here so a
// malformed value is reported against value_base64 rather than producing a
// certificate carrying garbage.
func (m *extraExtensionModel) toPKI(p path.Path) (pki.ExtraExtension, diag.Diagnostics) {
	var diags diag.Diagnostics

	oid, err := pki.ParseOID(m.OID.ValueString())
	if err != nil {
		diags.AddAttributeError(p.AtName("oid"), "Invalid OID", err.Error())
	}

	value, err := base64.StdEncoding.DecodeString(m.ValueBase64.ValueString())
	if err != nil {
		diags.AddAttributeError(p.AtName("value_base64"), "Invalid base64",
			"value_base64 must be the standard base64 encoding of the extension's raw DER extnValue: "+err.Error())
	}

	if diags.HasError() {
		return pki.ExtraExtension{}, diags
	}
	return pki.ExtraExtension{OID: oid, Value: value, Critical: m.Critical.ValueBool()}, diags
}

// extraExtensionFromPKI converts an extension the provider has no typed
// support for back to config form, re-encoding the DER verbatim.
func extraExtensionFromPKI(e pki.ExtraExtension) extraExtensionModel {
	return extraExtensionModel{
		OID:         types.StringValue(pki.FormatOID(e.OID)),
		ValueBase64: types.StringValue(base64.StdEncoding.EncodeToString(e.Value)),
		Critical:    types.BoolValue(e.Critical),
	}
}

// parseDurationAttr parses a duration attribute, threading pki.ParseDuration's
// error into a diagnostic at p.
//
// A null or unknown value returns (0, nil) rather than an error: whether the
// attribute is required is the caller's decision, and the framework already
// enforces Required at the schema level.
func parseDurationAttr(value types.String, p path.Path) (time.Duration, diag.Diagnostics) {
	var diags diag.Diagnostics
	if value.IsNull() || value.IsUnknown() {
		return 0, diags
	}
	d, err := pki.ParseDuration(value.ValueString())
	if err != nil {
		diags.AddAttributeError(p, "Invalid duration", err.Error())
		return 0, diags
	}
	return d, diags
}
