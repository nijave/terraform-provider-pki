// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

func attr(t *testing.T, name, value string) Attribute {
	t.Helper()
	oid, err := DNAttributeOID(name)
	if err != nil {
		t.Fatalf("DNAttributeOID(%q): %v", name, err)
	}
	return Attribute{OID: oid, Value: value}
}

// TestNamedSubjectExpandCanonicalOrder pins the documented canonical order from
// spec section 5.1: CN, UID, GN, SN, O, OU..., L, ST, street, postalCode, C,
// dnQualifier, serialNumber. Changing this order changes every DN produced from
// a named-field config, which means every certificate replaces.
func TestNamedSubjectExpandCanonicalOrder(t *testing.T) {
	t.Parallel()
	n := NamedSubject{
		CommonName:          "cn",
		UID:                 "uid",
		GivenName:           "gn",
		Surname:             "sn",
		Organization:        "o",
		OrganizationalUnits: []string{"ou1", "ou2"},
		Locality:            "l",
		Province:            "st",
		StreetAddresses:     []string{"street1", "street2"},
		PostalCode:          "postal",
		Country:             "US",
		DNQualifier:         "dnq",
		SerialNumber:        "dnserial",
	}
	want := []string{
		"commonName", "uid", "givenName", "surname", "organization",
		"organizationalUnit", "organizationalUnit",
		"locality", "province", "streetAddress", "streetAddress",
		"postalCode", "country", "dnQualifier", "serialNumber",
	}
	got := n.Expand()
	if len(got.Attributes) != len(want) {
		t.Fatalf("Expand produced %d attributes, want %d: %s", len(got.Attributes), len(want), got.String())
	}
	for i, wantName := range want {
		gotName, err := NameByOID(FormatOID(got.Attributes[i].OID))
		if err != nil {
			t.Errorf("attribute %d has unknown OID %s", i, FormatOID(got.Attributes[i].OID))
			continue
		}
		if gotName != wantName {
			t.Errorf("attribute %d = %q, want %q", i, gotName, wantName)
		}
	}
	// Repeated attributes keep declaration order.
	if got.Attributes[5].Value != "ou1" || got.Attributes[6].Value != "ou2" {
		t.Errorf("OU order = %q, %q; want ou1, ou2", got.Attributes[5].Value, got.Attributes[6].Value)
	}
	if got.Attributes[9].Value != "street1" || got.Attributes[10].Value != "street2" {
		t.Errorf("street order = %q, %q; want street1, street2", got.Attributes[9].Value, got.Attributes[10].Value)
	}
}

func TestNamedSubjectExpandOmitsUnsetFields(t *testing.T) {
	t.Parallel()
	n := NamedSubject{CommonName: "only-cn"}
	got := n.Expand()
	if len(got.Attributes) != 1 {
		t.Fatalf("Expand produced %d attributes, want 1: %s", len(got.Attributes), got.String())
	}
	// An empty string is "unset", not "present and empty": openssl's config
	// format cannot express an empty DN value either, and emitting one would
	// produce a DN no other tool can reproduce.
	n2 := NamedSubject{CommonName: "cn", Organization: "", OrganizationalUnits: []string{"ou", "", "ou2"}}
	got2 := n2.Expand()
	if len(got2.Attributes) != 3 {
		t.Fatalf("Expand produced %d attributes, want 3 (cn, ou, ou2): %s", len(got2.Attributes), got2.String())
	}
}

func TestNamedSubjectExpandAppendsExtraAttributes(t *testing.T) {
	t.Parallel()
	// Spec section 5.1: extra_attribute blocks append after the named fields,
	// in declaration order.
	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	n := NamedSubject{
		CommonName:      "cn",
		Organization:    "o",
		ExtraAttributes: []Attribute{{OID: display, Value: "Nick V"}, {OID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "custom"}},
	}
	got := n.Expand()
	if len(got.Attributes) != 4 {
		t.Fatalf("Expand produced %d attributes, want 4: %s", len(got.Attributes), got.String())
	}
	if !got.Attributes[2].OID.Equal(display) || got.Attributes[2].Value != "Nick V" {
		t.Errorf("attribute 2 = %v/%q, want displayName/\"Nick V\"", got.Attributes[2].OID, got.Attributes[2].Value)
	}
	if !got.Attributes[3].OID.Equal(asn1.ObjectIdentifier{1, 2, 3, 4}) {
		t.Errorf("attribute 3 = %v, want 1.2.3.4", got.Attributes[3].OID)
	}
}

// TestMustDNAttributeOIDPanicsOnAnUnknownName pins Expand's failure mode for a
// name literal that does not resolve.
//
// Expand used to drop such an attribute and carry on, so a typo in one of its
// literals produced a DN quietly missing a field -- a wrong certificate, and one
// that only the attribute-count assertion in
// TestNamedSubjectExpandCanonicalOrder could have noticed. Expand has no error
// to return, so the loud failure is a panic; it is unreachable from any
// configuration, because every name Expand passes is a literal in subject.go
// looked up in a hardcoded table.
func TestMustDNAttributeOIDPanicsOnAnUnknownName(t *testing.T) {
	t.Parallel()
	if got := mustDNAttributeOID("commonName"); !got.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
		t.Errorf("mustDNAttributeOID(\"commonName\") = %v, want 2.5.4.3", got)
	}

	defer func() {
		r := recover()
		if r == nil {
			t.Error("mustDNAttributeOID on an unresolvable name returned normally; a typo in one of Expand's name literals would silently drop an attribute")
			return
		}
		if msg, ok := r.(string); !ok || !strings.Contains(msg, "commonNam") {
			t.Errorf("panic value = %v, want a message naming the unresolvable attribute", r)
		}
	}()
	mustDNAttributeOID("commonNam") // the typo the old silent drop would have swallowed
}

// TestExpandCannotReproduceEnginePyOrder documents the exact limitation that
// forces the ordered form to exist (spec section 5.1). engine.py emits
// displayName between UID and GN; the canonical order cannot, because
// displayName has no named field and therefore appends last.
func TestExpandCannotReproduceEnginePyOrder(t *testing.T) {
	t.Parallel()
	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	named := NamedSubject{
		CommonName:      "nick-ipad.ha.apps.somemissing.info",
		UID:             "nick",
		GivenName:       "Nick",
		Surname:         "Venenga",
		Organization:    "homelab",
		ExtraAttributes: []Attribute{{OID: display, Value: "Nick V"}},
	}.Expand()

	// The ordered form places displayName where engine.py puts it: after UID,
	// before GN (reconcile/engine.py lines 49-55).
	ordered := Subject{Attributes: []Attribute{
		attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
		attr(t, "uid", "nick"),
		{OID: display, Value: "Nick V"},
		attr(t, "givenName", "Nick"),
		attr(t, "surname", "Venenga"),
		attr(t, "organization", "homelab"),
	}}

	if named.Equal(ordered) {
		t.Fatal("named-field expansion matched engine.py's DN order; if the canonical order ever gains a displayName slot, update spec section 5.1 and this test together")
	}
}

// TestEncodeDEROneAttributePerRDN pins the structure: each attribute is its own
// single-element RDN SET, matching what openssl produces from a [dn] section.
// A multi-valued RDN would encode the same attributes into different bytes.
func TestEncodeDEROneAttributePerRDN(t *testing.T) {
	t.Parallel()
	s := Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		attr(t, "organization", "o"),
	}}
	der, err := s.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdns); err != nil {
		t.Fatalf("emitted DN does not unmarshal as an RDNSequence: %v", err)
	}
	if len(rdns) != 2 {
		t.Fatalf("DN has %d RDNs, want 2", len(rdns))
	}
	for i, rdn := range rdns {
		if len(rdn) != 1 {
			t.Errorf("RDN %d holds %d attributes, want exactly 1", i, len(rdn))
		}
	}
}

// TestEncodeDERDefaultsToUTF8String is the single most consequential assertion
// in this file. engine.py sets string_mask = utf8only (reconcile/engine.py line
// 62), so every certificate already on a device has a UTF8String DN. Go's
// asn1.Marshal of a Go string emits PrintableString when the value fits, which
// would produce different bytes for the same DN and make every imported
// certificate plan a replace.
func TestEncodeDERDefaultsToUTF8String(t *testing.T) {
	t.Parallel()
	s := Subject{Attributes: []Attribute{attr(t, "commonName", "plain-ascii")}}
	der, err := s.EncodeDER()
	if err != nil {
		t.Fatalf("EncodeDER: %v", err)
	}
	// ASN.1 tag 12 (0x0c) is UTF8String; tag 19 (0x13) is PrintableString.
	if bytes.IndexByte(der, 0x13) != -1 {
		t.Errorf("DN contains a PrintableString tag (0x13); every value must encode as UTF8String by default:\n% x", der)
	}
	if bytes.IndexByte(der, 0x0c) == -1 {
		t.Errorf("DN contains no UTF8String tag (0x0c):\n% x", der)
	}
}

func TestEncodeDERHonorsExplicitStringType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stringType StringType
		wantTag    byte
	}{
		{StringTypeUTF8, 0x0c},
		{StringTypePrintable, 0x13},
		{StringTypeIA5, 0x16},
	} {
		oid, err := DNAttributeOID("commonName")
		if err != nil {
			t.Fatalf("DNAttributeOID: %v", err)
		}
		s := Subject{Attributes: []Attribute{{OID: oid, Value: "value", StringType: tc.stringType}}}
		der, err := s.EncodeDER()
		if err != nil {
			t.Errorf("EncodeDER(%s): %v", tc.stringType, err)
			continue
		}
		if bytes.IndexByte(der, tc.wantTag) == -1 {
			t.Errorf("string type %s did not produce tag 0x%02x:\n% x", tc.stringType, tc.wantTag, der)
		}
	}
}

// TestEncodeDERBMPAndT61UseCorrectUniversalTags pins the two string types the
// brief's table got wrong. BMPString is ASN.1 universal tag 30 (0x1e), NOT 28 --
// tag 28 is UniversalString (UCS-4), a different encoding entirely, which
// openssl asn1parse reports as UNIVERSALSTRING. Emitting 28 for a "bmp" value
// would label two-byte-per-character data as four-byte-per-character data, so
// every consumer would misread it. T61String is tag 20 (0x14).
func TestEncodeDERBMPAndT61UseCorrectUniversalTags(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stringType  StringType
		value       string
		wantTag     int
		wantContent []byte
	}{
		{StringTypeBMP, "AB", 30, []byte{0x00, 'A', 0x00, 'B'}},
		{StringTypeT61, "AB", 20, []byte{'A', 'B'}},
	} {
		s := Subject{Attributes: []Attribute{
			{OID: mustDNOID(t, "commonName"), Value: tc.value, StringType: tc.stringType},
		}}
		der, err := s.EncodeDER()
		if err != nil {
			t.Errorf("EncodeDER(%s): %v", tc.stringType, err)
			continue
		}
		// Read the tag back off the wire rather than trusting the constant.
		var seq rawRDNSequence
		if _, err := asn1.Unmarshal(der, &seq); err != nil {
			t.Errorf("%s: unmarshalling emitted DN: %v", tc.stringType, err)
			continue
		}
		gotTag := seq[0][0].Value.Tag
		if gotTag != tc.wantTag {
			t.Errorf("string type %s encoded with universal tag %d, want %d", tc.stringType, gotTag, tc.wantTag)
		}
		if !bytes.Equal(seq[0][0].Value.Bytes, tc.wantContent) {
			t.Errorf("string type %s content = % x, want % x", tc.stringType, seq[0][0].Value.Bytes, tc.wantContent)
		}

		// And the tag survives a parse/re-encode cycle byte-for-byte.
		parsed, err := ParseSubjectDER(der)
		if err != nil {
			t.Errorf("%s: ParseSubjectDER: %v", tc.stringType, err)
			continue
		}
		if parsed.Attributes[0].StringType != tc.stringType {
			t.Errorf("%s: parsed string type = %s", tc.stringType, parsed.Attributes[0].StringType)
		}
		if parsed.Attributes[0].Value != tc.value {
			t.Errorf("%s: parsed value = %q, want %q", tc.stringType, parsed.Attributes[0].Value, tc.value)
		}
		reencoded, err := parsed.EncodeDER()
		if err != nil {
			t.Errorf("%s: re-encode: %v", tc.stringType, err)
			continue
		}
		if !bytes.Equal(der, reencoded) {
			t.Errorf("%s: re-encode is not byte-exact\n original: % x\nre-encoded: % x", tc.stringType, der, reencoded)
		}
	}
}

// TestEncodeDERRejectsUnencodableBMPAndT61 covers the two repertoire limits that
// would otherwise silently mangle a value.
func TestEncodeDERRejectsUnencodableBMPAndT61(t *testing.T) {
	t.Parallel()
	oid := mustDNOID(t, "commonName")
	for label, s := range map[string]Subject{
		// U+1F600 is outside the BMP, so it needs a surrogate pair that
		// BMPString's two-bytes-per-character encoding cannot represent.
		"astral char in bmp": {Attributes: []Attribute{{OID: oid, Value: "grin \U0001F600", StringType: StringTypeBMP}}},
		"non-ascii in t61":   {Attributes: []Attribute{{OID: oid, Value: "nïck", StringType: StringTypeT61}}},
	} {
		if _, err := s.EncodeDER(); err == nil {
			t.Errorf("EncodeDER(%s) returned nil error, want an error", label)
		}
	}
}

// TestParseSubjectDERRejectsUnknownStringTag locks the "unknown tag is an error,
// not a passthrough" rule. Tag 28 (UniversalString) stands in for any string
// type this package does not model: accepting it silently would drop the value's
// real encoding and make the re-encode differ from the certificate on the wire.
func TestParseSubjectDERRejectsUnknownStringTag(t *testing.T) {
	t.Parallel()
	for _, tag := range []int{18 /* NumericString */, 28 /* UniversalString */, 2 /* INTEGER */} {
		der, err := asn1.Marshal(pkix.RDNSequence{pkix.RelativeDistinguishedNameSET{{
			Type:  mustDNOID(t, "commonName"),
			Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte{0x41}},
		}}})
		if err != nil {
			t.Fatalf("asn1.Marshal: %v", err)
		}
		if _, err := ParseSubjectDER(der); err == nil {
			t.Errorf("ParseSubjectDER accepted universal tag %d, want an error", tag)
		}
	}
}

func TestEncodeDERRejectsInvalidStringTypeAndValue(t *testing.T) {
	t.Parallel()
	oid, err := DNAttributeOID("commonName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	for label, s := range map[string]Subject{
		"unknown string type":        {Attributes: []Attribute{{OID: oid, Value: "v", StringType: "ebcdic"}}},
		"non-ascii in ia5":           {Attributes: []Attribute{{OID: oid, Value: "nïck", StringType: StringTypeIA5}}},
		"non-printable in printable": {Attributes: []Attribute{{OID: oid, Value: "a@b", StringType: StringTypePrintable}}},
		"nil oid":                    {Attributes: []Attribute{{Value: "v"}}},
		"empty value":                {Attributes: []Attribute{{OID: oid, Value: ""}}},
		"empty ia5 value":            {Attributes: []Attribute{{OID: oid, Value: "", StringType: StringTypeIA5}}},
	} {
		if _, err := s.EncodeDER(); err == nil {
			t.Errorf("EncodeDER(%s) returned nil error, want an error", label)
		}
	}

	// An empty DN value is refused by EncodeDER, which knows which attribute it
	// was, and not by the shared IA5 validator, which does not. That is why the
	// DN path calls validateIA5Repertoire rather than validateIA5: if the
	// emptiness check moved down into the shared validator, this message would
	// degrade to a bare "value is empty" with no attribute named.
	s := Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		{OID: mustDNOID(t, "organization"), Value: "", StringType: StringTypeIA5},
	}}
	_, err = s.EncodeDER()
	if err == nil {
		t.Fatal("EncodeDER accepted an empty IA5 attribute value")
	}
	if !strings.Contains(err.Error(), "attribute 1") || !strings.Contains(err.Error(), "2.5.4.10") {
		t.Errorf("error = %q, want one naming attribute 1 and its OID 2.5.4.10", err)
	}
}

// TestParseSubjectDERRoundTripsByteExact is the property spec section 8 needs:
// import parses a DN out of DER, and re-encoding what was parsed must produce
// the identical bytes -- otherwise the first plan after import is a replace.
func TestParseSubjectDERRoundTripsByteExact(t *testing.T) {
	t.Parallel()
	for label, original := range map[string]Subject{
		"utf8 default": {Attributes: []Attribute{
			attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
			attr(t, "uid", "nick"),
			attr(t, "givenName", "Nick"),
			attr(t, "surname", "Venenga"),
			attr(t, "organization", "homelab"),
		}},
		"mixed string types": {Attributes: []Attribute{
			{OID: mustDNOID(t, "commonName"), Value: "cn", StringType: StringTypePrintable},
			{OID: mustDNOID(t, "emailAddress"), Value: "nick@venenga.com", StringType: StringTypeIA5},
			{OID: mustDNOID(t, "organization"), Value: "homelab", StringType: StringTypeUTF8},
		}},
		"non-ascii value": {Attributes: []Attribute{
			attr(t, "commonName", "nïck-ipåd"),
			attr(t, "surname", "Venenga"),
		}},
		"repeated ou": {Attributes: []Attribute{
			attr(t, "commonName", "cn"),
			attr(t, "organizationalUnit", "infra"),
			attr(t, "organizationalUnit", "clients"),
		}},
		"unknown oid": {Attributes: []Attribute{
			attr(t, "commonName", "cn"),
			{OID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: "vendor-specific"},
		}},
	} {
		der, err := original.EncodeDER()
		if err != nil {
			t.Errorf("%s: EncodeDER: %v", label, err)
			continue
		}
		parsed, err := ParseSubjectDER(der)
		if err != nil {
			t.Errorf("%s: ParseSubjectDER: %v", label, err)
			continue
		}
		if len(parsed.Attributes) != len(original.Attributes) {
			t.Errorf("%s: parsed %d attributes, want %d", label, len(parsed.Attributes), len(original.Attributes))
			continue
		}
		for i := range parsed.Attributes {
			if !parsed.Attributes[i].OID.Equal(original.Attributes[i].OID) {
				t.Errorf("%s: attribute %d OID = %v, want %v", label, i, parsed.Attributes[i].OID, original.Attributes[i].OID)
			}
			if parsed.Attributes[i].Value != original.Attributes[i].Value {
				t.Errorf("%s: attribute %d value = %q, want %q", label, i, parsed.Attributes[i].Value, original.Attributes[i].Value)
			}
		}
		reencoded, err := parsed.EncodeDER()
		if err != nil {
			t.Errorf("%s: re-encoding a parsed subject: %v", label, err)
			continue
		}
		if !bytes.Equal(der, reencoded) {
			t.Errorf("%s: re-encode is not byte-exact\n original: % x\nre-encoded: % x", label, der, reencoded)
		}
	}
}

func TestParseSubjectDERFlattensMultiValuedRDNs(t *testing.T) {
	t.Parallel()
	// A DN produced elsewhere may pack several attributes into one RDN SET.
	// Parsing must not lose them; the ordered form flattens them into the order
	// they appear on the wire. Re-encoding will produce single-attribute RDNs,
	// so this case is deliberately NOT byte-exact -- it is the one shape import
	// cannot reproduce, and callers detect it by comparing the DER themselves.
	//
	// The OU-before-O literal order below is not arbitrary. A DER SET OF must
	// carry its members in ascending octet order (X.690 section 11.6) and
	// asn1.Marshal enforces that, so the encoded SET holds the OU attribute
	// ("30 0c ...") ahead of the O attribute ("30 0e ..."), whatever order this
	// literal declares. Parsing reports wire order, which is the only order the
	// bytes contain.
	rdns := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			{Type: mustDNOID(t, "organizationalUnit"), Value: "infra"},
			{Type: mustDNOID(t, "organization"), Value: "homelab"},
		},
		pkix.RelativeDistinguishedNameSET{
			{Type: mustDNOID(t, "commonName"), Value: "cn"},
		},
	}
	der, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	// Guard the fixture itself: if this ever stops being a 2-RDN DN whose first
	// RDN is multi-valued, the test would still see 3 attributes but would no
	// longer be exercising flattening at all.
	var check pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &check); err != nil {
		t.Fatalf("unmarshalling the fixture: %v", err)
	}
	if len(check) != 2 || len(check[0]) != 2 {
		t.Fatalf("fixture is not a multi-valued RDN: %d RDNs, first holds %d attributes", len(check), len(check[0]))
	}

	parsed, err := ParseSubjectDER(der)
	if err != nil {
		t.Fatalf("ParseSubjectDER: %v", err)
	}
	if len(parsed.Attributes) != 3 {
		t.Fatalf("parsed %d attributes, want 3", len(parsed.Attributes))
	}
	if parsed.Attributes[0].Value != "infra" || parsed.Attributes[1].Value != "homelab" || parsed.Attributes[2].Value != "cn" {
		t.Fatalf("flattened order = %q, %q, %q; want infra, homelab, cn",
			parsed.Attributes[0].Value, parsed.Attributes[1].Value, parsed.Attributes[2].Value)
	}
}

// TestParseSubjectDERRejectsConstructedStrings covers the BER shape no
// certificate can carry but an exported parser can still be handed: a DN
// attribute value whose tag is constructed (0x2c, UTF8String with the compound
// bit set) rather than primitive, holding the value split into primitive
// fragments the way BER permits.
//
// It has to be built by hand, because crypto/x509 refuses the tag before
// RawSubject is ever populated -- the sub-test below proves that, and is what
// makes this defence in depth rather than a live bug. Without the check,
// ParseSubjectDER takes the fragments' own tag and length bytes for content: the
// DN "parses" to a value containing raw ASN.1 headers and re-encodes to bytes
// that match neither the input nor any valid DN.
func TestParseSubjectDERRejectsConstructedStrings(t *testing.T) {
	t.Parallel()

	// "ab" and "c" as two primitive UTF8String fragments, which is how BER
	// spells a constructed string carrying "abc".
	first, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte("ab")})
	if err != nil {
		t.Fatalf("marshalling the first fragment: %v", err)
	}
	second, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: []byte("c")})
	if err != nil {
		t.Fatalf("marshalling the second fragment: %v", err)
	}
	fragments := append(append([]byte{}, first...), second...)

	der, err := asn1.Marshal(rawRDNSequence{
		rawRelativeDistinguishedNameSET{
			{
				Type: mustDNOID(t, "commonName"),
				Value: asn1.RawValue{
					Class:      asn1.ClassUniversal,
					Tag:        asn1.TagUTF8String,
					IsCompound: true,
					Bytes:      fragments,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshalling the constructed-string DN: %v", err)
	}

	// Guard the fixture: the value's TLV must really open with 0x2c, or this
	// test is not exercising a constructed string at all.
	if want := byte(0x2c); !bytes.Contains(der, []byte{want, byte(len(fragments))}) {
		t.Fatalf("fixture does not carry a constructed UTF8String tag 0x%02x:\n% x", want, der)
	}

	if _, err := ParseSubjectDER(der); err == nil {
		t.Error("ParseSubjectDER accepted a constructed UTF8String; the value would re-encode to different bytes than it parsed from")
	} else if !strings.Contains(err.Error(), "constructed") {
		t.Errorf("error = %q, want one naming the constructed tag", err)
	}

	// The unreachability half of the claim: a certificate cannot deliver this
	// DN, because crypto/x509 rejects the tag while parsing the name. If a
	// future Go release starts accepting it, the check above stops being
	// defence in depth and starts being the only thing standing there -- so
	// pin it rather than asserting it in a comment.
	t.Run("crypto/x509 rejects it first", func(t *testing.T) {
		t.Parallel()
		k, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			RawSubject:   der,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
		}
		// CreateCertificate copies RawSubject verbatim, so it will emit the
		// constructed tag without complaint.
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, PublicKeyOf(k), k)
		if err != nil {
			t.Fatalf("CreateCertificate with a constructed-string subject: %v", err)
		}
		if _, err := x509.ParseCertificate(certDER); err == nil {
			t.Error("crypto/x509 parsed a certificate whose subject holds a constructed string; ParseSubjectDER's check is now the only guard")
		}
	})
}

func TestParseSubjectDERRejectsGarbage(t *testing.T) {
	t.Parallel()
	for label, in := range map[string][]byte{
		"empty":     {},
		"not asn1":  []byte("hello"),
		"truncated": {0x30, 0x10, 0x31},
	} {
		if _, err := ParseSubjectDER(in); err == nil {
			t.Errorf("ParseSubjectDER(%s) returned nil error, want an error", label)
		}
	}
}

func TestSubjectIsEmpty(t *testing.T) {
	t.Parallel()
	if !(Subject{}).IsEmpty() {
		t.Error("a zero Subject is not reported empty")
	}
	if !(Subject{Attributes: []Attribute{}}).IsEmpty() {
		t.Error("a Subject with an empty attribute slice is not reported empty")
	}
	if (Subject{Attributes: []Attribute{attr(t, "commonName", "cn")}}).IsEmpty() {
		t.Error("a Subject with one attribute is reported empty")
	}
}

// TestSubjectEqualComparesEncodedBytes is what makes a hand-written
// named-field config plan clean against an imported ordered-form state, per
// spec section 5.1: any config that encodes to the same DN must compare equal.
func TestSubjectEqualComparesEncodedBytes(t *testing.T) {
	t.Parallel()
	named := NamedSubject{CommonName: "cn", UID: "uid", GivenName: "gn", Surname: "sn", Organization: "o"}.Expand()
	ordered := Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		attr(t, "uid", "uid"),
		attr(t, "givenName", "gn"),
		attr(t, "surname", "sn"),
		attr(t, "organization", "o"),
	}}
	if !named.Equal(ordered) {
		t.Error("a named-field subject and the equivalent ordered subject did not compare equal")
	}

	reordered := Subject{Attributes: []Attribute{
		attr(t, "uid", "uid"),
		attr(t, "commonName", "cn"),
		attr(t, "givenName", "gn"),
		attr(t, "surname", "sn"),
		attr(t, "organization", "o"),
	}}
	if named.Equal(reordered) {
		t.Error("subjects differing only in attribute order compared equal; DN order is significant in DER")
	}

	differentStringType := Subject{Attributes: []Attribute{
		{OID: mustDNOID(t, "commonName"), Value: "cn", StringType: StringTypePrintable},
	}}
	sameValueUTF8 := Subject{Attributes: []Attribute{attr(t, "commonName", "cn")}}
	if differentStringType.Equal(sameValueUTF8) {
		t.Error("subjects differing only in ASN.1 string type compared equal; they encode to different bytes")
	}
}

func TestSubjectString(t *testing.T) {
	t.Parallel()
	// String() is for diagnostics only. It must render unknown OIDs in dotted
	// form rather than dropping them, so a drift report never hides an
	// attribute.
	s := Subject{Attributes: []Attribute{
		attr(t, "commonName", "cn"),
		{OID: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "custom"},
	}}
	got := s.String()
	if got != "CN=cn,1.2.3.4=custom" {
		t.Fatalf("String() = %q, want \"CN=cn,1.2.3.4=custom\"", got)
	}
	if (Subject{}).String() != "" {
		t.Fatalf("String() on an empty subject = %q, want \"\"", (Subject{}).String())
	}
}

// TestSubjectDERIsReadableByOpenSSL confirms an outside parser renders the DN
// the way this package intends, including the attributes openssl has no short
// name for. Byte-level assertions can pass while producing a DN nothing else
// reads correctly.
func TestSubjectDERIsReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)

	display, err := DNAttributeOID("displayName")
	if err != nil {
		t.Fatalf("DNAttributeOID: %v", err)
	}
	subject := Subject{Attributes: []Attribute{
		attr(t, "commonName", "nick-ipad.ha.apps.somemissing.info"),
		attr(t, "uid", "nick"),
		{OID: display, Value: "Nick V"},
		attr(t, "givenName", "Nick"),
		attr(t, "surname", "Venenga"),
		attr(t, "organization", "homelab"),
		attr(t, "organizationalUnit", "infra"),
		attr(t, "organizationalUnit", "clients"),
	}}

	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:   subject,
		Serial:    big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}, PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	text := opensslText(t, certPEM)
	for _, want := range []string{
		"CN = nick-ipad.ha.apps.somemissing.info",
		"UID = nick",
		"2.16.840.1.113730.3.1.241 = Nick V",
		"GN = Nick",
		"SN = Venenga",
		"O = homelab",
		"OU = infra",
		"OU = clients",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl output does not contain %q; full Subject line:\n%s", want, subjectLine(text))
		}
	}
}

// subjectLine extracts the Subject: line from openssl x509 -text output, for
// readable failure messages.
func subjectLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "Subject:") {
			return strings.TrimSpace(line)
		}
	}
	return "(no Subject line found)"
}
