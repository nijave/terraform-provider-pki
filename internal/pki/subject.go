// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// StringType names the ASN.1 string encoding used for a DN attribute value.
//
// This is not a cosmetic detail. The homelab issuer runs openssl with
// string_mask = utf8only, so every certificate already installed on a device
// encodes its DN values as UTF8String. Go's asn1.Marshal, handed a Go string,
// emits PrintableString whenever the value fits -- so re-encoding a parsed DN
// without remembering its original string type produces different bytes for the
// same logical name, and every imported certificate would plan a replace.
type StringType string

const (
	StringTypeUTF8      StringType = "utf8"
	StringTypePrintable StringType = "printable"
	StringTypeIA5       StringType = "ia5"
	StringTypeBMP       StringType = "bmp"
	StringTypeT61       StringType = "t61"
)

// asn1Tag maps a StringType to its ASN.1 universal tag number.
var asn1Tag = map[StringType]int{
	StringTypeUTF8:      asn1.TagUTF8String,      // 12
	StringTypePrintable: asn1.TagPrintableString, // 19
	StringTypeIA5:       asn1.TagIA5String,       // 22
	StringTypeBMP:       asn1.TagBMPString,       // 30
	StringTypeT61:       asn1.TagT61String,       // 20
}

// stringTypeByTag is the exact reverse of asn1Tag, used on parse. It is built
// from asn1Tag rather than written out a second time so the two directions
// cannot drift.
var stringTypeByTag = func() map[int]StringType {
	m := make(map[int]StringType, len(asn1Tag))
	for st, tag := range asn1Tag {
		m[tag] = st
	}
	return m
}()

// printableExtra are the non-alphanumeric characters the ASN.1 PrintableString
// repertoire allows, beyond A-Z, a-z, and 0-9.
const printableExtra = " '()+,-./:=?"

// Attribute is one DN attribute: an OID, a value, and the ASN.1 string type the
// value encodes as. A zero StringType means StringTypeUTF8.
type Attribute struct {
	OID        asn1.ObjectIdentifier
	Value      string
	StringType StringType
}

// Subject is a distinguished name as an ordered list of attributes, each of
// which becomes its own single-element RDN SET on encode.
//
// Order is significant in DER, so this type is a slice and never a map. The
// provider's ordered subject form maps to it directly; the named-field form
// reaches it through NamedSubject.Expand.
type Subject struct {
	Attributes []Attribute
}

// NamedSubject is the friendly, named-field form of a distinguished name. It
// expands to an ordered Subject in one documented canonical order, which is
// what makes the common case terse at the cost of not being able to express
// every possible DN -- see Expand.
type NamedSubject struct {
	CommonName   string
	UID          string
	GivenName    string
	Surname      string
	Organization string
	Locality     string
	Province     string
	PostalCode   string
	Country      string
	DNQualifier  string
	SerialNumber string

	OrganizationalUnits []string
	StreetAddresses     []string

	// ExtraAttributes are appended verbatim after every named field, in
	// declaration order.
	ExtraAttributes []Attribute
}

// Expand converts the named fields to an ordered Subject in the canonical
// order: CN, UID, GN, SN, O, OU..., L, ST, street, postalCode, C, dnQualifier,
// serialNumber, then ExtraAttributes verbatim.
//
// This order is a compatibility promise, not an implementation detail: changing
// it changes the DER of every DN built from named fields, and a DN that changes
// is a certificate that gets replaced.
//
// The canonical order deliberately cannot express every DN. An attribute with
// no named field can only be appended at the end via ExtraAttributes, so a DN
// that interleaves one -- displayName between UID and GN, as the existing
// issuer emits -- must use the ordered Subject form instead. See
// TestExpandCannotReproduceEnginePyOrder.
//
// An empty string means "unset", not "present and empty", for named fields and
// for list elements alike: openssl's config format cannot express an empty DN
// value either, so emitting one would produce a DN no other tool reproduces.
func (n NamedSubject) Expand() Subject {
	var s Subject
	add := func(name, value string) {
		if value == "" {
			return
		}
		oid, err := DNAttributeOID(name)
		if err != nil {
			// Unreachable: every name passed below is a literal key of the
			// dn_attributes table, and TestNamedSubjectExpandCanonicalOrder
			// resolves all of them. Dropping the attribute rather than
			// panicking keeps Expand total.
			return
		}
		s.Attributes = append(s.Attributes, Attribute{OID: oid, Value: value})
	}

	add("commonName", n.CommonName)
	add("uid", n.UID)
	add("givenName", n.GivenName)
	add("surname", n.Surname)
	add("organization", n.Organization)
	for _, ou := range n.OrganizationalUnits {
		add("organizationalUnit", ou)
	}
	add("locality", n.Locality)
	add("province", n.Province)
	for _, street := range n.StreetAddresses {
		add("streetAddress", street)
	}
	add("postalCode", n.PostalCode)
	add("country", n.Country)
	add("dnQualifier", n.DNQualifier)
	add("serialNumber", n.SerialNumber)

	s.Attributes = append(s.Attributes, n.ExtraAttributes...)
	return s
}

// EncodeDER encodes the subject as a DER RDNSequence, the form that goes into
// x509.Certificate.RawSubject.
//
// Each attribute becomes its own single-element RDN SET. Multi-valued RDNs are
// not produced: openssl's [dn] config section cannot express them, so no
// certificate this provider needs to reproduce contains one. ParseSubjectDER
// still reads them, flattening in wire order -- see its doc comment for why
// that is not the same as the order a producer declared.
//
// Emitting one attribute per RDN is also what keeps the output stable: DER
// requires the members of a SET OF to be sorted by their encodings (X.690
// 11.6), so a SET holding two or more attributes would be reordered underneath
// us, while a single-element SET has nothing to sort.
func (s Subject) EncodeDER() ([]byte, error) {
	if len(s.Attributes) == 0 {
		// An empty DN is legal DER (an empty SEQUENCE) and is what a
		// subject-less certificate carries, so this is not an error.
		return asn1.Marshal(pkix.RDNSequence{})
	}

	rdns := make(pkix.RDNSequence, 0, len(s.Attributes))
	for i, a := range s.Attributes {
		if len(a.OID) == 0 {
			return nil, fmt.Errorf("subject attribute %d has no OID", i)
		}
		if a.Value == "" {
			return nil, fmt.Errorf("subject attribute %d (%s) has an empty value", i, FormatOID(a.OID))
		}
		st := a.StringType
		if st == "" {
			st = StringTypeUTF8
		}
		tag, ok := asn1Tag[st]
		if !ok {
			return nil, fmt.Errorf("subject attribute %d (%s): unknown string type %q", i, FormatOID(a.OID), a.StringType)
		}
		raw, err := encodeDirectoryString(st, tag, a.Value)
		if err != nil {
			return nil, fmt.Errorf("subject attribute %d (%s): %w", i, FormatOID(a.OID), err)
		}
		rdns = append(rdns, pkix.RelativeDistinguishedNameSET{
			{Type: a.OID, Value: raw},
		})
	}
	return asn1.Marshal(rdns)
}

// encodeDirectoryString validates value against st's repertoire and returns the
// content bytes wrapped in an asn1.RawValue carrying tag.
//
// Only Bytes is set, never FullBytes: that makes asn1.Marshal write the tag and
// length itself, which is what keeps the output canonical DER. It is also what
// stops asn1.Marshal from choosing the string type on its own -- handed a plain
// Go string it would emit PrintableString whenever the value fits.
func encodeDirectoryString(st StringType, tag int, value string) (asn1.RawValue, error) {
	var content []byte
	switch st {
	case StringTypeUTF8:
		if !utf8.ValidString(value) {
			return asn1.RawValue{}, fmt.Errorf("value is not valid UTF-8")
		}
		content = []byte(value)

	case StringTypePrintable:
		for _, r := range value {
			if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				continue
			}
			if strings.ContainsRune(printableExtra, r) {
				continue
			}
			return asn1.RawValue{}, fmt.Errorf("value contains %q, which PrintableString cannot encode", r)
		}
		content = []byte(value)

	case StringTypeIA5:
		for _, r := range value {
			if r > unicode.MaxASCII {
				return asn1.RawValue{}, fmt.Errorf("value contains non-ASCII %q, which IA5String cannot encode", r)
			}
		}
		content = []byte(value)

	case StringTypeT61:
		// T.61's full repertoire is a multi-byte escape-driven mess and no
		// input this provider handles needs it, so ASCII is accepted as an
		// approximation and everything else is refused rather than
		// mis-encoded.
		for _, r := range value {
			if r > unicode.MaxASCII {
				return asn1.RawValue{}, fmt.Errorf("value contains non-ASCII %q; only the ASCII subset of T61String is supported", r)
			}
		}
		content = []byte(value)

	case StringTypeBMP:
		if !utf8.ValidString(value) {
			return asn1.RawValue{}, fmt.Errorf("value is not valid UTF-8")
		}
		units := utf16.Encode([]rune(value))
		content = make([]byte, 0, len(units)*2)
		for _, u := range units {
			if u >= 0xd800 && u <= 0xdfff {
				// A surrogate code unit means the value contains a character
				// outside the Basic Multilingual Plane, which BMPString's
				// two-bytes-per-character encoding cannot represent.
				return asn1.RawValue{}, fmt.Errorf("value contains a character outside the Basic Multilingual Plane, which BMPString cannot encode")
			}
			content = append(content, byte(u>>8), byte(u))
		}

	default:
		return asn1.RawValue{}, fmt.Errorf("unknown string type %q", st)
	}

	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: content}, nil
}

// rawAttributeTypeAndValue mirrors pkix.AttributeTypeAndValue but keeps the
// value's ASN.1 tag, which pkix's `Value any` field throws away.
type rawAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// The "SET" suffix on this type name is load-bearing, not decoration:
// encoding/asn1's getUniversalType decides whether a slice is a SET OF or a
// SEQUENCE OF by testing whether the type's name ends in "SET". Rename this and
// the parse fails with "sequence tag mismatch".
// pkix.RelativeDistinguishedNameSET is named for the same reason.
type rawRelativeDistinguishedNameSET []rawAttributeTypeAndValue

type rawRDNSequence []rawRelativeDistinguishedNameSET

// ParseSubjectDER parses a DER RDNSequence into an ordered Subject, preserving
// both attribute order and each value's ASN.1 string type.
//
// It deliberately does not go through pkix.RDNSequence: that type's
// AttributeTypeAndValue.Value is an `any` which encoding/asn1 fills with a
// plain Go string, discarding the tag -- exactly the information a byte-exact
// re-encode needs.
//
// A multi-valued RDN is flattened into consecutive attributes in wire order,
// which is not necessarily the order a producer declared: DER requires the
// members of a SET OF to be sorted by their encodings (X.690 11.6), so a
// lower-sorting attribute comes first regardless of how it was written. Wire
// order is the only order the bytes carry, so it is the only order a parser can
// report. See TestParseSubjectDERFlattensMultiValuedRDNs, which pins this.
//
// Re-encoding a flattened multi-valued RDN produces single-attribute RDNs, so
// that one shape is deliberately not byte-exact; callers that care compare the
// DER themselves.
func ParseSubjectDER(der []byte) (Subject, error) {
	var seq rawRDNSequence
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return Subject{}, fmt.Errorf("parsing subject DN: %w", err)
	}
	if len(rest) != 0 {
		return Subject{}, fmt.Errorf("parsing subject DN: %d trailing bytes after the RDNSequence", len(rest))
	}

	var s Subject
	for i, rdn := range seq {
		for j, atv := range rdn {
			if len(atv.Type) == 0 {
				return Subject{}, fmt.Errorf("subject RDN %d attribute %d has no OID", i, j)
			}
			if atv.Value.IsCompound {
				// BER lets a string be sent constructed: a chain of primitive
				// fragments under a compound tag, 0x2c for a UTF8String rather
				// than 0x0c. Without this check the fragments' own tag and
				// length bytes are taken for content, so the DN parses to a
				// value full of ASN.1 header bytes and re-encodes to something
				// that is neither the original nor valid -- the exact
				// byte-exactness failure this parser exists to prevent. DER
				// forbids constructed strings outright (X.690 8.21.6, 10.2).
				//
				// crypto/x509 rejects the tag before RawSubject is ever
				// populated ("x509: invalid RDNSequence: invalid attribute
				// value: unsupported string type: 44"), so no certificate can
				// reach here carrying one. This is defence in depth on an
				// exported parser that callers may hand DER from anywhere. See
				// TestParseSubjectDERRejectsConstructedStrings.
				return Subject{}, fmt.Errorf("subject RDN %d attribute %d (%s): ASN.1 string tag %d is constructed; only primitive DER string encodings are supported",
					i, j, FormatOID(atv.Type), atv.Value.Tag)
			}
			st, ok := stringTypeByTag[atv.Value.Tag]
			if !ok || atv.Value.Class != asn1.ClassUniversal {
				// An unrecognized tag is an error, not a passthrough:
				// silently dropping a value's string type is precisely what
				// would make every imported certificate plan a replace.
				return Subject{}, fmt.Errorf("subject RDN %d attribute %d (%s): unsupported ASN.1 string tag %d (class %d)",
					i, j, FormatOID(atv.Type), atv.Value.Tag, atv.Value.Class)
			}
			value, err := decodeDirectoryString(st, atv.Value.Bytes)
			if err != nil {
				return Subject{}, fmt.Errorf("subject RDN %d attribute %d (%s): %w", i, j, FormatOID(atv.Type), err)
			}
			s.Attributes = append(s.Attributes, Attribute{OID: atv.Type, Value: value, StringType: st})
		}
	}
	return s, nil
}

// decodeDirectoryString turns an attribute value's content bytes back into a Go
// string, inverting encodeDirectoryString so a parsed subject re-encodes to the
// identical bytes.
func decodeDirectoryString(st StringType, content []byte) (string, error) {
	if st != StringTypeBMP {
		// UTF8String, PrintableString, IA5String, and the accepted ASCII
		// subset of T61String all carry their characters as-is.
		return string(content), nil
	}
	if len(content)%2 != 0 {
		return "", fmt.Errorf("BMPString has an odd length of %d bytes", len(content))
	}
	units := make([]uint16, 0, len(content)/2)
	for i := 0; i < len(content); i += 2 {
		u := uint16(content[i])<<8 | uint16(content[i+1])
		if u >= 0xd800 && u <= 0xdfff {
			// utf16.Decode would turn a surrogate into U+FFFD, which
			// re-encodes to different bytes. Refuse instead of round-tripping
			// a DN into one that no longer matches the certificate.
			return "", fmt.Errorf("BMPString contains a surrogate code unit U+%04X", u)
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units)), nil
}

// IsEmpty reports whether the subject has no attributes. An empty DN is legal:
// a certificate may carry no subject at all and hold its identity in the
// subjectAltName extension instead.
func (s Subject) IsEmpty() bool {
	return len(s.Attributes) == 0
}

// Equal reports whether two subjects encode to identical DER.
//
// Comparing encoded bytes rather than struct fields is what lets a
// hand-written named-field config plan clean against state imported in the
// ordered form: any two configs that produce the same DN are the same DN.
//
// Equal is therefore NOT reflexive: a subject that cannot be encoded compares
// unequal to everything, including itself. A DN can parse yet fail to
// re-encode -- a PrintableString holding '@' or '_', a zero-length value, or a
// UTF8String carrying invalid UTF-8 all do -- and this predicate has nowhere to
// report the reason. A caller that needs the cause, rather than a bare "these
// differ", must call EncodeDER itself and inspect the error; reporting such a
// subject as drift would be misleading, because nothing has changed.
func (s Subject) Equal(other Subject) bool {
	a, err := s.EncodeDER()
	if err != nil {
		return false
	}
	b, err := other.EncodeDER()
	if err != nil {
		return false
	}
	return bytes.Equal(a, b)
}

// dnShortNames maps a dn_attributes friendly name to the conventional RFC 4514
// short form used in human-readable DN output.
var dnShortNames = map[string]string{
	"commonName":         "CN",
	"organization":       "O",
	"organizationalUnit": "OU",
	"country":            "C",
	"locality":           "L",
	"province":           "ST",
	"streetAddress":      "STREET",
	"serialNumber":       "SERIALNUMBER",
	"surname":            "SN",
	"givenName":          "GN",
	"uid":                "UID",
	"dnQualifier":        "DNQ",
	"postalCode":         "POSTALCODE",
	"emailAddress":       "EMAIL",
}

// String renders the DN as comma-separated SHORTNAME=value pairs in attribute
// order, falling back to the dotted OID for any attribute with no conventional
// short form so a drift report never hides an attribute.
//
// This output is for error messages and drift reports only. It is deliberately
// NOT RFC 4514: values are not escaped, so a value containing ',' or '='
// produces ambiguous output. Never parse it, and never compare two DNs by it --
// use Equal, which compares the encoded DER.
func (s Subject) String() string {
	parts := make([]string, 0, len(s.Attributes))
	for _, a := range s.Attributes {
		dotted := FormatOID(a.OID)
		label := dotted
		if name, err := NameByOID(dotted); err == nil {
			if short, ok := dnShortNames[name]; ok {
				label = short
			}
		}
		parts = append(parts, label+"="+a.Value)
	}
	return strings.Join(parts, ",")
}
