// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func intPtr(n int) *int { return &n }

// TestBasicConstraintsPathLenNullVersusZero is the distinction spec section 5.3
// calls out: X.509 draws a real difference between pathLenConstraint = 0 (this
// CA may not issue further CAs) and no constraint at all (unlimited depth).
// A zero-defaulted int cannot express it.
func TestBasicConstraintsPathLenNullVersusZero(t *testing.T) {
	t.Parallel()

	unlimited, err := BasicConstraints{CA: true, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension (unlimited): %v", err)
	}
	zero, err := BasicConstraints{CA: true, PathLen: intPtr(0), Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension (pathLen 0): %v", err)
	}
	if string(unlimited.Value) == string(zero.Value) {
		t.Fatal("pathLen unset and pathLen 0 encoded to the same bytes; they are different constraints")
	}

	back, err := ParseBasicConstraints(unlimited)
	if err != nil {
		t.Fatalf("ParseBasicConstraints (unlimited): %v", err)
	}
	if back.PathLen != nil {
		t.Errorf("unlimited round-tripped to PathLen = %d, want nil", *back.PathLen)
	}
	back, err = ParseBasicConstraints(zero)
	if err != nil {
		t.Fatalf("ParseBasicConstraints (pathLen 0): %v", err)
	}
	if back.PathLen == nil || *back.PathLen != 0 {
		t.Errorf("pathLen 0 round-tripped to %v, want a pointer to 0", back.PathLen)
	}
}

func TestBasicConstraintsRoundTrip(t *testing.T) {
	t.Parallel()
	for label, bc := range map[string]BasicConstraints{
		"ca unlimited": {CA: true, Critical: true},
		"ca pathlen 0": {CA: true, PathLen: intPtr(0), Critical: true},
		"ca pathlen 3": {CA: true, PathLen: intPtr(3), Critical: true},
		"leaf":         {CA: false, Critical: true},
		"leaf noncrit": {CA: false, Critical: false},
	} {
		ext, err := bc.Extension()
		if err != nil {
			t.Errorf("%s: Extension: %v", label, err)
			continue
		}
		if FormatOID(ext.Id) != "2.5.29.19" {
			t.Errorf("%s: OID = %s, want 2.5.29.19", label, FormatOID(ext.Id))
		}
		if ext.Critical != bc.Critical {
			t.Errorf("%s: Critical = %v, want %v", label, ext.Critical, bc.Critical)
		}
		got, err := ParseBasicConstraints(ext)
		if err != nil {
			t.Errorf("%s: ParseBasicConstraints: %v", label, err)
			continue
		}
		if got.CA != bc.CA || got.Critical != bc.Critical {
			t.Errorf("%s: round-tripped to %+v, want CA=%v Critical=%v", label, got, bc.CA, bc.Critical)
		}
	}
}

func TestBasicConstraintsRejectsPathLenOnNonCA(t *testing.T) {
	t.Parallel()
	// pathLenConstraint is meaningful only when cA is true (RFC 5280 4.2.1.9).
	// Silently dropping it would hide a config error.
	if _, err := (BasicConstraints{CA: false, PathLen: intPtr(0)}).Extension(); err == nil {
		t.Error("Extension with pathLen on a non-CA returned nil error, want an error")
	}
	if _, err := (BasicConstraints{CA: true, PathLen: intPtr(-1)}).Extension(); err == nil {
		t.Error("Extension with a negative pathLen returned nil error, want an error")
	}
}

func TestKeyUsageRoundTrip(t *testing.T) {
	t.Parallel()
	ku := KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment", "keyCertSign", "crlSign"}, Critical: true}
	ext, err := ku.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.15" {
		t.Fatalf("OID = %s, want 2.5.29.15", FormatOID(ext.Id))
	}
	if !ext.Critical {
		t.Error("Critical = false, want true")
	}
	got, err := ParseKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseKeyUsage: %v", err)
	}
	// Parsing returns usages in RFC 5280 bit order, which is canonical and
	// independent of config order.
	want := []string{"digitalSignature", "keyEncipherment", "keyCertSign", "crlSign"}
	if len(got.Usages) != len(want) {
		t.Fatalf("parsed usages = %v, want %v", got.Usages, want)
	}
	for i := range want {
		if got.Usages[i] != want[i] {
			t.Errorf("usage %d = %q, want %q", i, got.Usages[i], want[i])
		}
	}
}

// TestKeyUsageConfigOrderDoesNotChangeBytes prevents a spurious replace when
// someone reorders the usages list in HCL. Key usage is a BIT STRING; order is
// not representable and must not be treated as significant.
func TestKeyUsageConfigOrderDoesNotChangeBytes(t *testing.T) {
	t.Parallel()
	a, err := KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	b, err := KeyUsage{Usages: []string{"keyEncipherment", "digitalSignature"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if string(a.Value) != string(b.Value) {
		t.Fatal("reordering the usages list changed the encoded bytes")
	}
}

func TestKeyUsageRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, ku := range map[string]KeyUsage{
		"empty":     {Usages: nil, Critical: true},
		"unknown":   {Usages: []string{"digitalSignatures"}},
		"duplicate": {Usages: []string{"crlSign", "crlSign"}},
		"blank":     {Usages: []string{""}},
	} {
		if _, err := ku.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestKeyUsageDecipherOnlyCrossesTheByteBoundary(t *testing.T) {
	t.Parallel()
	// decipherOnly is bit 8, the first bit in the second octet. A BIT STRING
	// encoder that assumes one byte silently drops it.
	ext, err := KeyUsage{Usages: []string{"decipherOnly"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	got, err := ParseKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseKeyUsage: %v", err)
	}
	if len(got.Usages) != 1 || got.Usages[0] != "decipherOnly" {
		t.Fatalf("round-tripped to %v, want [decipherOnly]", got.Usages)
	}
}

func TestExtKeyUsageRoundTripWithNamesAndRawOIDs(t *testing.T) {
	t.Parallel()
	// Spec section 5.3 mixes both forms in one list.
	eku := ExtKeyUsage{Usages: []string{"clientAuth", "1.3.6.1.4.1.311.20.2.2"}, Critical: false}
	ext, err := eku.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.37" {
		t.Fatalf("OID = %s, want 2.5.29.37", FormatOID(ext.Id))
	}
	if ext.Critical {
		t.Error("Critical = true, want false; extendedKeyUsage defaults to non-critical")
	}
	got, err := ParseExtKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}
	// Parsing renders a known OID as its friendly name and an unknown one in
	// dotted form, preserving the order the extension carries.
	if len(got.Usages) != 2 || got.Usages[0] != "clientAuth" || got.Usages[1] != "microsoftSmartcardLogon" {
		t.Fatalf("parsed usages = %v, want [clientAuth microsoftSmartcardLogon]", got.Usages)
	}
}

func TestExtKeyUsageParsesTrulyUnknownOIDAsDotted(t *testing.T) {
	t.Parallel()
	ext, err := ExtKeyUsage{Usages: []string{"1.3.6.1.4.1.99999.7"}}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	got, err := ParseExtKeyUsage(ext)
	if err != nil {
		t.Fatalf("ParseExtKeyUsage: %v", err)
	}
	if len(got.Usages) != 1 || got.Usages[0] != "1.3.6.1.4.1.99999.7" {
		t.Fatalf("parsed usages = %v, want [1.3.6.1.4.1.99999.7]", got.Usages)
	}
}

func TestExtKeyUsageRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, eku := range map[string]ExtKeyUsage{
		"empty":        {Usages: nil},
		"unknown name": {Usages: []string{"clientAuthh"}},
		"bad oid":      {Usages: []string{"1.2.x"}},
		"duplicate":    {Usages: []string{"clientAuth", "clientAuth"}},
	} {
		if _, err := eku.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

func TestNameConstraintsRoundTrip(t *testing.T) {
	t.Parallel()
	nc := NameConstraints{
		PermittedDNSDomains:   []string{".ha.apps.somemissing.info"},
		ExcludedDNSDomains:    []string{"bad.example"},
		PermittedEmailDomains: []string{"venenga.com"},
		PermittedIPRanges:     []string{"10.0.0.0/8", "fd00::/8"},
		PermittedURIDomains:   []string{".homelab"},
		Critical:              true,
	}
	ext, err := nc.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.30" {
		t.Fatalf("OID = %s, want 2.5.29.30", FormatOID(ext.Id))
	}
	if !ext.Critical {
		t.Error("Critical = false, want true; nameConstraints defaults to critical")
	}
	got, err := ParseNameConstraints(ext)
	if err != nil {
		t.Fatalf("ParseNameConstraints: %v", err)
	}
	if len(got.PermittedDNSDomains) != 1 || got.PermittedDNSDomains[0] != ".ha.apps.somemissing.info" {
		t.Errorf("permitted DNS = %v, want [.ha.apps.somemissing.info]", got.PermittedDNSDomains)
	}
	if len(got.ExcludedDNSDomains) != 1 || got.ExcludedDNSDomains[0] != "bad.example" {
		t.Errorf("excluded DNS = %v, want [bad.example]", got.ExcludedDNSDomains)
	}
	if len(got.PermittedIPRanges) != 2 {
		t.Errorf("permitted IP ranges = %v, want 2 entries", got.PermittedIPRanges)
	}
}

func TestNameConstraintsRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, nc := range map[string]NameConstraints{
		"all empty": {Critical: true},
		"bad cidr":  {PermittedIPRanges: []string{"10.0.0.0/33"}},
		"bare ip":   {PermittedIPRanges: []string{"10.0.0.1"}},
		"empty dns": {PermittedDNSDomains: []string{""}},
	} {
		if _, err := nc.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

// TestNameConstraintsRejectsIPv4MappedIPv6CIDR covers the one CIDR form that
// cannot round-trip, and so would show as a diff that never converges.
//
// "::ffff:10.0.0.0/104" encodes as a 32-byte IPv6 subtree, but net.IPNet.String()
// collapses 4-in-6 when rendering it back, giving "10.0.0.0/8", which re-encodes
// as an 8-byte IPv4 subtree. Encode -> parse -> encode therefore changes the
// bytes, and a configuration written in the mapped form would replan forever.
// Rejecting it at encode time, naming the plain form to write instead, is the
// only outcome that converges.
func TestNameConstraintsRejectsIPv4MappedIPv6CIDR(t *testing.T) {
	t.Parallel()
	_, err := NameConstraints{PermittedIPRanges: []string{"::ffff:10.0.0.0/104"}, Critical: true}.Extension()
	if err == nil {
		t.Fatal("Extension accepted an IPv4-mapped IPv6 CIDR, which does not round-trip")
	}
	// The operator has to be told what to write instead, not merely that this is
	// wrong.
	if !strings.Contains(err.Error(), "10.0.0.0/8") {
		t.Errorf("error = %q, want it to name the plain IPv4 form 10.0.0.0/8", err)
	}
	if _, err := (NameConstraints{ExcludedIPRanges: []string{"::ffff:192.168.1.0/120"}, Critical: true}).Extension(); err == nil {
		t.Fatal("Extension accepted an IPv4-mapped IPv6 CIDR in the excluded subtrees")
	}

	// Every other form is idempotent under encode -> parse -> encode and must
	// stay accepted: the check is on 4-in-6 specifically, not on IPv6.
	for _, cidr := range []string{"10.0.0.0/8", "fd00::/8", "0.0.0.0/0", "::/0"} {
		ext, err := NameConstraints{PermittedIPRanges: []string{cidr}, Critical: true}.Extension()
		if err != nil {
			t.Errorf("Extension(%q): %v", cidr, err)
			continue
		}
		back, err := ParseNameConstraints(ext)
		if err != nil {
			t.Errorf("ParseNameConstraints(%q): %v", cidr, err)
			continue
		}
		if len(back.PermittedIPRanges) != 1 || back.PermittedIPRanges[0] != cidr {
			t.Errorf("%q round-tripped to %v, want [%s]", cidr, back.PermittedIPRanges, cidr)
			continue
		}
		again, err := back.Extension()
		if err != nil {
			t.Errorf("re-encoding %q: %v", cidr, err)
			continue
		}
		if !bytes.Equal(again.Value, ext.Value) {
			t.Errorf("%q re-encodes to different bytes, so it would show a perpetual diff", cidr)
		}
	}
}

func TestExtraExtension(t *testing.T) {
	t.Parallel()
	// Spec section 5.3's example: raw DER of the extnValue, supplied base64 in
	// HCL and decoded before it reaches this type.
	value := []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	ext, err := ExtraExtension{OID: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}, Value: value, Critical: false}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if FormatOID(ext.Id) != "1.3.6.1.5.5.7.1.24" {
		t.Errorf("OID = %s, want 1.3.6.1.5.5.7.1.24", FormatOID(ext.Id))
	}
	if string(ext.Value) != string(value) {
		t.Errorf("Value = % x, want % x; the DER must pass through untouched", ext.Value, value)
	}
	for label, e := range map[string]ExtraExtension{
		"no oid":    {Value: value},
		"no value":  {OID: asn1.ObjectIdentifier{1, 2, 3}},
		"short oid": {OID: asn1.ObjectIdentifier{1}, Value: value},
	} {
		if _, err := e.Extension(); err == nil {
			t.Errorf("Extension(%s) returned nil error, want an error", label)
		}
	}
}

// TestExtraExtensionRejectsStructurallyImpossibleOIDs covers the arcs an OID
// cannot have, which "at least two arcs" does not.
//
// Every rejected case below is one encoding/asn1 either refuses outright or --
// worse -- encodes as a *different* OID than the one written, and all of them are
// reachable from configuration because an extra_extension OID is whatever the
// operator typed. Catching them here reports the block and the value; letting
// them through surfaces encoding/asn1's "invalid object identifier" from inside
// x509.CreateCertificate, or nothing at all.
//
// The legal cases matter just as much: arc 2 has no 40-limit, so 2.999.x -- the
// arc reserved for examples, and the one an operator experiments with -- must
// keep working, as must the boundary values 0.39 and 1.39.
func TestExtraExtensionRejectsStructurallyImpossibleOIDs(t *testing.T) {
	t.Parallel()
	value := []byte{0x05, 0x00} // DER NULL, a valid extnValue

	for label, oid := range map[string]asn1.ObjectIdentifier{
		"first arc 3":           {3, 1},
		"first arc 5":           {5, 99},
		"first arc 40":          {40, 1},
		"second arc 40 under 0": {0, 40},
		"second arc 40 under 1": {1, 40},
		"second arc 99 under 1": {1, 99},
		"negative first arc":    {-1, 2},
		"negative second arc":   {1, -2},
		"negative later arc":    {1, 3, 6, -1},
		"one arc":               {2},
		"no arcs":               {},
	} {
		if _, err := (ExtraExtension{OID: oid, Value: value}).Extension(); err == nil {
			t.Errorf("Extension(%s, %v) returned nil error, want a structural OID error", label, oid)
		}
	}

	// Each rejected shape is rejected because encoding/asn1 cannot faithfully
	// carry it, not because this package invented a rule. Two distinct failures
	// are demonstrated: an outright marshal error, and a silent change of value.
	if _, err := asn1.Marshal(asn1.ObjectIdentifier{5, 99}); err == nil {
		t.Error("encoding/asn1 marshalled 5.99; the structural check would then be this package's own invention")
	}
	if _, err := asn1.Marshal(asn1.ObjectIdentifier{1, 40}); err == nil {
		t.Error("encoding/asn1 marshalled 1.40; the second-arc ceiling would then be this package's own invention")
	}
	// A negative arc is the dangerous one: encoding/asn1 marshals it happily and
	// the bytes decode as a different OID entirely, so an unchecked config would
	// ship a certificate carrying an extension nobody asked for.
	der, err := asn1.Marshal(asn1.ObjectIdentifier{1, -2})
	if err != nil {
		t.Fatalf("Marshal(1.-2): %v", err)
	}
	var back asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(der, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if FormatOID(back) == "1.-2" {
		t.Error("1.-2 round-tripped unchanged; the negative-arc check has no hazard to prevent")
	}

	// Legal OIDs must still pass, and must still reach a real certificate: a
	// check that over-rejects would make arc 2 unusable, which is where every
	// private and example OID lives.
	for label, oid := range map[string]asn1.ObjectIdentifier{
		"example arc 2.999":      {2, 999, 1},
		"arc 2 second arc 48":    {2, 48},
		"arc 2 large second arc": {2, 12345},
		"boundary 0.39":          {0, 39},
		"boundary 1.39":          {1, 39},
		"private enterprise":     {1, 3, 6, 1, 4, 1, 99999, 1},
		"a real extension OID":   {1, 3, 6, 1, 5, 5, 7, 1, 24},
	} {
		ext, err := (ExtraExtension{OID: oid, Value: value}).Extension()
		if err != nil {
			t.Errorf("Extension(%s, %v): %v", label, oid, err)
			continue
		}
		cert := selfSignedWith(t, ext)
		got, ok := FindExtension(cert.Extensions, oid)
		if !ok {
			t.Errorf("%s: certificate does not carry extension %s", label, FormatOID(oid))
			continue
		}
		if !bytes.Equal(got.Value, value) {
			t.Errorf("%s: extension value = % x, want % x", label, got.Value, value)
		}
	}
}

// TestKeyUsageBoundIsDerivedFromTheTable pins that maxKeyUsageBit comes from
// oids.go's key_usages table rather than from a hand-written constant.
//
// The bound decides how far ParseKeyUsage scans, so a usage added to the table
// above it would encode and then vanish on import. A constant cannot be tested
// against that future; the derivation can, by running it over a table holding a
// bit this package has never seen.
func TestKeyUsageBoundIsDerivedFromTheTable(t *testing.T) {
	t.Parallel()

	// The derivation follows a table it has never seen, including past the
	// one-octet boundary a hand-maintained 8 would sit on.
	for want, table := range map[int]map[string]string{
		16: {"digitalSignature": "0", "hypotheticalUsage": "16"},
		9:  {"decipherOnly": "8", "hypotheticalUsage": "9"},
		0:  {"digitalSignature": "0"},
		31: {"a": "31", "b": "2"},
	} {
		if got := highestKeyUsageBit(table); got != want {
			t.Errorf("highestKeyUsageBit(%v) = %d, want %d", table, got, want)
		}
	}

	// And the real table yields the bound the rest of the package uses.
	if got := highestKeyUsageBit(keyUsages); got != maxKeyUsageBit() {
		t.Errorf("maxKeyUsageBit = %d, but the key_usages table's highest bit is %d", maxKeyUsageBit(), got)
	}
	// 8 is decipherOnly, the highest RFC 5280 4.2.1.3 assigns today. This is the
	// value the encoding tests' expected bytes are written against, so it is
	// pinned rather than left implicit.
	if maxKeyUsageBit() != 8 {
		t.Errorf("maxKeyUsageBit = %d, want 8 (decipherOnly)", maxKeyUsageBit())
	}
}

// TestKeyUsagesTableHoldsOnlyBitPositions rules out the one input
// highestKeyUsageBit has to skip. A row whose value is not a non-negative
// decimal integer contributes no bit and is unusable through KeyUsageBit too, so
// it would be a usage the schema advertises and the encoder refuses.
func TestKeyUsagesTableHoldsOnlyBitPositions(t *testing.T) {
	t.Parallel()
	for name, position := range keyUsages {
		bit, err := strconv.Atoi(position)
		if err != nil {
			t.Errorf("key usage %q has value %q, which is not a decimal bit position: %v", name, position, err)
			continue
		}
		if bit < 0 {
			t.Errorf("key usage %q has bit position %d, which cannot be encoded", name, bit)
		}
		if got, err := KeyUsageBit(name); err != nil || got != bit {
			t.Errorf("KeyUsageBit(%q) = %d, %v; want %d, nil", name, got, err, bit)
		}
	}
}

// TestParseKeyUsageDistinguishesNoBitsFromUnrepresentableBits covers the two
// ways a keyUsage extension can yield no usages, which used to report the same
// misleading "no bits are set".
//
// A certificate setting only bit 9 HAS bits set; they were dropped because this
// encoder's vocabulary stops at maxKeyUsageBit. An operator told "no bits are
// set" about that certificate would go looking for a missing extension instead of
// an unsupported usage.
func TestParseKeyUsageDistinguishesNoBitsFromUnrepresentableBits(t *testing.T) {
	t.Parallel()

	// Bit 9 alone: two octets, the second holding 0x40, BitLength 10.
	onlyBitNine, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x00, 0x40}, BitLength: 10})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = ParseKeyUsage(pkix.Extension{Id: oidKeyUsage, Value: onlyBitNine})
	if err == nil {
		t.Fatal("ParseKeyUsage accepted a keyUsage naming no representable usage")
	}
	if strings.Contains(err.Error(), "no bits are set") {
		t.Errorf("error = %q, but bits WERE set; the message must not send the operator looking for a missing extension", err)
	}
	if !strings.Contains(err.Error(), "9") {
		t.Errorf("error = %q, want it to name bit 9, the usage that could not be represented", err)
	}

	// All-zero bits: nothing was named at all, and that is what the message says.
	allZero, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x00, 0x00}, BitLength: 16})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = ParseKeyUsage(pkix.Extension{Id: oidKeyUsage, Value: allZero})
	if err == nil {
		t.Fatal("ParseKeyUsage accepted a keyUsage with no bits set")
	}
	if !strings.Contains(err.Error(), "no bits are set") {
		t.Errorf("error = %q, want it to report that no bits are set", err)
	}

	// A usage above the bound alongside a named one is imported, not rejected:
	// the extra bit is ignored and the real usage survives. This is what makes
	// the rejection above specifically about naming *nothing*.
	mixed, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80, 0x40}, BitLength: 10})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	ku, err := ParseKeyUsage(pkix.Extension{Id: oidKeyUsage, Value: mixed})
	if err != nil {
		t.Fatalf("ParseKeyUsage (bit 0 plus bit 9): %v", err)
	}
	if len(ku.Usages) != 1 || ku.Usages[0] != "digitalSignature" {
		t.Errorf("parsed usages = %v, want [digitalSignature]", ku.Usages)
	}
}

func TestDefaultKeyUsages(t *testing.T) {
	t.Parallel()
	ca := DefaultCAKeyUsage()
	if !ca.Critical {
		t.Error("the default CA key usage is not critical")
	}
	if len(ca.Usages) != 2 || ca.Usages[0] != "keyCertSign" || ca.Usages[1] != "crlSign" {
		t.Errorf("default CA usages = %v, want [keyCertSign crlSign]", ca.Usages)
	}

	// The leaf default reproduces reconcile/engine.py line 84:
	// keyUsage = critical, digitalSignature, keyEncipherment
	leaf := DefaultLeafKeyUsage()
	if !leaf.Critical {
		t.Error("the default leaf key usage is not critical")
	}
	if len(leaf.Usages) != 2 || leaf.Usages[0] != "digitalSignature" || leaf.Usages[1] != "keyEncipherment" {
		t.Errorf("default leaf usages = %v, want [digitalSignature keyEncipherment]", leaf.Usages)
	}
}

// TestDefaultKeyUsagePointersCarryTheDefaults pins the two Ptr helpers'
// contents, not merely that they return something.
//
// Both exist for CertTemplate.KeyUsage, which is a pointer so that "not
// configured" stays distinguishable from "configured empty" -- and nil is the
// legal way to say "not configured". So `return nil` is a body that compiles,
// issues certificates, and silently drops the keyUsage extension from every CA
// and every leaf the provider creates with a default. Asserting non-nilness alone
// would not catch a helper returning the *other* default either, which is the
// mistake a copy-paste actually makes.
func TestDefaultKeyUsagePointersCarryTheDefaults(t *testing.T) {
	t.Parallel()

	ca := DefaultCAKeyUsagePtr()
	if ca == nil {
		t.Fatal("DefaultCAKeyUsagePtr returned nil; a nil KeyUsage means no keyUsage extension at all")
	}
	if !ca.Critical {
		t.Error("the default CA key usage is not critical")
	}
	if !slices.Equal(ca.Usages, []string{"keyCertSign", "crlSign"}) {
		t.Errorf("DefaultCAKeyUsagePtr usages = %v, want [keyCertSign crlSign]", ca.Usages)
	}

	leaf := DefaultLeafKeyUsagePtr()
	if leaf == nil {
		t.Fatal("DefaultLeafKeyUsagePtr returned nil; a nil KeyUsage means no keyUsage extension at all")
	}
	if !leaf.Critical {
		t.Error("the default leaf key usage is not critical")
	}
	if !slices.Equal(leaf.Usages, []string{"digitalSignature", "keyEncipherment"}) {
		t.Errorf("DefaultLeafKeyUsagePtr usages = %v, want [digitalSignature keyEncipherment]", leaf.Usages)
	}

	// Each pointer must agree with its value-returning twin, so the two cannot
	// drift into disagreeing about what the default is.
	if !slices.Equal(ca.Usages, DefaultCAKeyUsage().Usages) || ca.Critical != DefaultCAKeyUsage().Critical {
		t.Errorf("DefaultCAKeyUsagePtr = %+v, DefaultCAKeyUsage = %+v", *ca, DefaultCAKeyUsage())
	}
	if !slices.Equal(leaf.Usages, DefaultLeafKeyUsage().Usages) || leaf.Critical != DefaultLeafKeyUsage().Critical {
		t.Errorf("DefaultLeafKeyUsagePtr = %+v, DefaultLeafKeyUsage = %+v", *leaf, DefaultLeafKeyUsage())
	}

	// A fresh pointer per call, not a shared package-level value: a caller that
	// edited the returned KeyUsage would otherwise change the default for every
	// later resource in the same process.
	if ca == DefaultCAKeyUsagePtr() {
		t.Error("DefaultCAKeyUsagePtr returns the same pointer twice; a caller could mutate the package's default")
	}
	if leaf == DefaultLeafKeyUsagePtr() {
		t.Error("DefaultLeafKeyUsagePtr returns the same pointer twice; a caller could mutate the package's default")
	}

	// The defaults must be encodable: a default that fails Extension() would
	// break every resource that relies on it.
	for label, ku := range map[string]*KeyUsage{"ca": ca, "leaf": leaf} {
		if _, err := ku.Extension(); err != nil {
			t.Errorf("%s default does not encode: %v", label, err)
		}
	}
}

// TestSubjectKeyIDExtension pins the RFC 5280 method 1 computation: the SHA-1
// of the subjectPublicKey BIT STRING contents. engine.py asks openssl for
// "subjectKeyIdentifier = hash", which is the same algorithm, so an imported
// certificate's SKI must match what this produces.
func TestSubjectKeyIDExtension(t *testing.T) {
	t.Parallel()
	k, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ext, err := SubjectKeyIDExtension(PublicKeyOf(k))
	if err != nil {
		t.Fatalf("SubjectKeyIDExtension: %v", err)
	}
	if FormatOID(ext.Id) != "2.5.29.14" {
		t.Errorf("OID = %s, want 2.5.29.14", FormatOID(ext.Id))
	}
	if ext.Critical {
		t.Error("Critical = true; subjectKeyIdentifier must be non-critical per RFC 5280 4.2.1.2")
	}
	var ski []byte
	if _, err := asn1.Unmarshal(ext.Value, &ski); err != nil {
		t.Fatalf("SKI value does not unmarshal as an OCTET STRING: %v", err)
	}
	if len(ski) != 20 {
		t.Fatalf("SKI is %d bytes, want 20 (SHA-1)", len(ski))
	}
	// Deterministic for a given key.
	again, err := SubjectKeyIDExtension(PublicKeyOf(k))
	if err != nil {
		t.Fatalf("SubjectKeyIDExtension (second call): %v", err)
	}
	if string(again.Value) != string(ext.Value) {
		t.Fatal("SubjectKeyIDExtension is not deterministic for the same key")
	}
}

// TestExtensionOIDValues pins each package-level OID var against its dotted
// form. oidAuthorityKeyID in particular has no other test: nothing in this file
// uses it (the signing code does), so a wrong arc would sit undetected until it
// produced a certificate with an unrecognized extension.
func TestExtensionOIDValues(t *testing.T) {
	t.Parallel()
	for want, oid := range map[string]asn1.ObjectIdentifier{
		"2.5.29.14": oidSubjectKeyID,
		"2.5.29.15": oidKeyUsage,
		"2.5.29.19": oidBasicConstraints,
		"2.5.29.30": oidNameConstraints,
		"2.5.29.35": oidAuthorityKeyID,
		"2.5.29.37": oidExtKeyUsage,
	} {
		if got := FormatOID(oid); got != want {
			t.Errorf("OID = %s, want %s", got, want)
		}
		// The user-facing table in oids.go must agree, or a name lookup and a
		// typed value would disagree about the same extension.
		if _, err := NameByOID(want); err != nil {
			t.Errorf("NameByOID(%s): %v", want, err)
		}
	}
}

// TestKeyUsageEncodesMinimalBitString pins the exact DER. A round-trip test
// cannot catch a bit order that is wrong but self-consistent — an encoder that
// numbered bits least-significant-first would still be order-independent and
// still round-trip through this package, while producing certificates every
// other implementation reads as different usages. These bytes are the ones
// openssl emits.
func TestKeyUsageEncodesMinimalBitString(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		usages []string
		want   []byte
	}{
		// bit 0 -> 0x80, 7 unused bits, one octet.
		{[]string{"digitalSignature"}, []byte{0x03, 0x02, 0x07, 0x80}},
		// bits 0 and 2 -> 0xa0, BitLength 3: the leaf default openssl writes.
		{[]string{"digitalSignature", "keyEncipherment"}, []byte{0x03, 0x02, 0x05, 0xa0}},
		// bits 5 and 6 -> 0x06, BitLength 7: the CA default openssl writes.
		{[]string{"keyCertSign", "crlSign"}, []byte{0x03, 0x02, 0x01, 0x06}},
		// bit 7 fills the first octet exactly: no unused bits, still one octet.
		{[]string{"encipherOnly"}, []byte{0x03, 0x02, 0x00, 0x01}},
		// bit 8 forces a second octet whose first bit is set.
		{[]string{"decipherOnly"}, []byte{0x03, 0x03, 0x07, 0x00, 0x80}},
		{[]string{"digitalSignature", "decipherOnly"}, []byte{0x03, 0x03, 0x07, 0x80, 0x80}},
	} {
		ext, err := KeyUsage{Usages: tc.usages, Critical: true}.Extension()
		if err != nil {
			t.Errorf("%v: Extension: %v", tc.usages, err)
			continue
		}
		if string(ext.Value) != string(tc.want) {
			t.Errorf("%v: Value = % x, want % x", tc.usages, ext.Value, tc.want)
		}
	}
}

// TestKeyUsageRejectsAllZeroBits ties the rejection to two stated requirements
// rather than to taste.
//
// The first is RFC 5280 4.2.1.3: "When the keyUsage extension appears in a
// certificate, at least one of the bits MUST be set to 1." An all-zero keyUsage
// is therefore not a certificate this provider should claim to understand.
//
// The second is internal and is what makes returning one actively wrong:
// KeyUsage.Extension refuses an empty Usages list, so a KeyUsage parsed out of an
// all-zero extension could not be encoded back. Every parse in this package feeds
// a comparison against a re-encoded template, so a value that parses but cannot
// re-encode is a permanent, unfixable diff. The test asserts that asymmetry
// directly instead of only asserting the rejection.
func TestKeyUsageRejectsAllZeroBits(t *testing.T) {
	t.Parallel()

	// Every shape an all-zero keyUsage can take: one octet, two octets, and the
	// empty BIT STRING openssl emits for `keyUsage = ` with no names.
	for label, bs := range map[string]asn1.BitString{
		"one zero octet":  {Bytes: []byte{0x00}, BitLength: 8},
		"two zero octets": {Bytes: []byte{0x00, 0x00}, BitLength: 16},
		"empty":           {Bytes: nil, BitLength: 0},
	} {
		value, err := asn1.Marshal(bs)
		if err != nil {
			t.Fatalf("Marshal(%s): %v", label, err)
		}
		got, err := ParseKeyUsage(pkix.Extension{Id: oidKeyUsage, Value: value})
		if err == nil {
			t.Errorf("ParseKeyUsage(%s) accepted a keyUsage with no bits set, returning %+v", label, got)
			continue
		}
		if !strings.Contains(err.Error(), "no bits are set") {
			t.Errorf("ParseKeyUsage(%s) error = %q, want it to say no bits are set", label, err)
		}
	}

	// The asymmetry that makes acceptance impossible: were ParseKeyUsage to
	// return the empty KeyUsage instead of erroring, this is the call the caller
	// would then make, and it fails.
	if _, err := (KeyUsage{Critical: true}).Extension(); err == nil {
		t.Error("KeyUsage with no usages encodes successfully; accepting an all-zero keyUsage on parse would then be harmless, and this test would be arbitrary")
	}
}

// TestBasicConstraintsPathLenValueRoundTrips covers what the round-trip table
// above does not: it compares only CA and Critical, so a parser that dropped or
// mangled the pathLen value would pass it.
func TestBasicConstraintsPathLenValueRoundTrips(t *testing.T) {
	t.Parallel()
	for _, want := range []int{0, 1, 3, 127, 300} {
		ext, err := BasicConstraints{CA: true, PathLen: intPtr(want), Critical: true}.Extension()
		if err != nil {
			t.Errorf("pathLen %d: Extension: %v", want, err)
			continue
		}
		got, err := ParseBasicConstraints(ext)
		if err != nil {
			t.Errorf("pathLen %d: ParseBasicConstraints: %v", want, err)
			continue
		}
		if got.PathLen == nil || *got.PathLen != want {
			t.Errorf("pathLen %d round-tripped to %v", want, got.PathLen)
		}
	}
}

// TestNameConstraintsSymmetricRoundTrip exercises all eight lists and compares
// values rather than counts. The round-trip test above never populates
// ExcludedEmailDomains, ExcludedIPRanges, or ExcludedURIDomains, and checks only
// the length of the IP ranges — so a field wired to the wrong subtree set, or a
// mask encoded at the wrong length, would go unnoticed.
func TestNameConstraintsSymmetricRoundTrip(t *testing.T) {
	t.Parallel()
	nc := NameConstraints{
		PermittedDNSDomains:   []string{".ha.apps.somemissing.info", "example.test"},
		ExcludedDNSDomains:    []string{"bad.example"},
		PermittedEmailDomains: []string{"venenga.com"},
		ExcludedEmailDomains:  []string{"spam.example"},
		PermittedIPRanges:     []string{"10.0.0.0/8", "fd00::/8"},
		ExcludedIPRanges:      []string{"192.168.1.0/24"},
		PermittedURIDomains:   []string{".homelab"},
		ExcludedURIDomains:    []string{".bad.example"},
		Critical:              true,
	}
	ext, err := nc.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	got, err := ParseNameConstraints(ext)
	if err != nil {
		t.Fatalf("ParseNameConstraints: %v", err)
	}
	for label, pair := range map[string][2][]string{
		"permitted DNS":   {got.PermittedDNSDomains, nc.PermittedDNSDomains},
		"excluded DNS":    {got.ExcludedDNSDomains, nc.ExcludedDNSDomains},
		"permitted email": {got.PermittedEmailDomains, nc.PermittedEmailDomains},
		"excluded email":  {got.ExcludedEmailDomains, nc.ExcludedEmailDomains},
		"permitted IP":    {got.PermittedIPRanges, nc.PermittedIPRanges},
		"excluded IP":     {got.ExcludedIPRanges, nc.ExcludedIPRanges},
		"permitted URI":   {got.PermittedURIDomains, nc.PermittedURIDomains},
		"excluded URI":    {got.ExcludedURIDomains, nc.ExcludedURIDomains},
	} {
		if !slices.Equal(pair[0], pair[1]) {
			t.Errorf("%s = %v, want %v", label, pair[0], pair[1])
		}
	}

	// Host bits are masked off rather than written verbatim, per RFC 5280
	// 4.2.1.10: the base is a network address.
	masked, err := NameConstraints{PermittedIPRanges: []string{"10.1.2.3/8"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension (host bits): %v", err)
	}
	back, err := ParseNameConstraints(masked)
	if err != nil {
		t.Fatalf("ParseNameConstraints (host bits): %v", err)
	}
	if len(back.PermittedIPRanges) != 1 || back.PermittedIPRanges[0] != "10.0.0.0/8" {
		t.Errorf("10.1.2.3/8 round-tripped to %v, want [10.0.0.0/8]", back.PermittedIPRanges)
	}
}

// TestNameConstraintsMatchesGoParser cross-validates the structure against a
// second implementation. Encoding and parsing with the same wrong context tag
// would round-trip cleanly inside this package while producing an extension no
// verifier understands; crypto/x509 reading the same values back is what rules
// that out. openssl x509 -text renders the same five permitted and two excluded
// entries.
func TestNameConstraintsMatchesGoParser(t *testing.T) {
	t.Parallel()
	nc := NameConstraints{
		PermittedDNSDomains:   []string{".ha.apps.somemissing.info"},
		ExcludedDNSDomains:    []string{"bad.example"},
		PermittedEmailDomains: []string{"venenga.com"},
		PermittedIPRanges:     []string{"10.0.0.0/8", "fd00::/8"},
		ExcludedIPRanges:      []string{"192.168.1.0/24"},
		PermittedURIDomains:   []string{".homelab"},
		Critical:              true,
	}
	ext, err := nc.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	cert := selfSignedWith(t, ext)

	if !slices.Equal(cert.PermittedDNSDomains, nc.PermittedDNSDomains) {
		t.Errorf("crypto/x509 permitted DNS = %v, want %v", cert.PermittedDNSDomains, nc.PermittedDNSDomains)
	}
	if !slices.Equal(cert.ExcludedDNSDomains, nc.ExcludedDNSDomains) {
		t.Errorf("crypto/x509 excluded DNS = %v, want %v", cert.ExcludedDNSDomains, nc.ExcludedDNSDomains)
	}
	if !slices.Equal(cert.PermittedEmailAddresses, nc.PermittedEmailDomains) {
		t.Errorf("crypto/x509 permitted email = %v, want %v", cert.PermittedEmailAddresses, nc.PermittedEmailDomains)
	}
	if !slices.Equal(cert.PermittedURIDomains, nc.PermittedURIDomains) {
		t.Errorf("crypto/x509 permitted URI = %v, want %v", cert.PermittedURIDomains, nc.PermittedURIDomains)
	}
	gotIPs := make([]string, 0, len(cert.PermittedIPRanges))
	for _, n := range cert.PermittedIPRanges {
		gotIPs = append(gotIPs, n.String())
	}
	if !slices.Equal(gotIPs, nc.PermittedIPRanges) {
		t.Errorf("crypto/x509 permitted IP = %v, want %v", gotIPs, nc.PermittedIPRanges)
	}
	if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "192.168.1.0/24" {
		t.Errorf("crypto/x509 excluded IP = %v, want [192.168.1.0/24]", cert.ExcludedIPRanges)
	}
}

// TestKeyUsageMatchesGoParser confirms the bits land where crypto/x509 expects,
// which is the same check openssl x509 -text performs by name.
func TestKeyUsageMatchesGoParser(t *testing.T) {
	t.Parallel()
	ext, err := KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment", "decipherOnly"}, Critical: true}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	cert := selfSignedWith(t, ext)
	want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDecipherOnly
	if cert.KeyUsage != want {
		t.Errorf("crypto/x509 KeyUsage = %b, want %b", cert.KeyUsage, want)
	}
}

// TestSubjectKeyIDMatchesOpenSSLHash is the check the brief's SKI test cannot
// make: a digest over the whole SubjectPublicKeyInfo DER, or over the BIT STRING
// including its unused-bit octet, would also be 20 bytes and also
// deterministic. Only a second implementation pins the input to the hash.
//
// openssl is the right second implementation because it is the one that matters:
// the existing issuer writes `subjectKeyIdentifier = hash`, so what openssl
// computes is by definition what an adopted certificate contains.
//
// crypto/x509 is deliberately not used here. It can compute the identifier for a
// CA whose SubjectKeyId is empty, but as of Go 1.25 that path defaults to RFC
// 7093 method 1 (the leftmost 160 bits of SHA-256) and only computes RFC 5280
// method 1 under GODEBUG=x509sha256skid=0 — so agreeing with the Go default
// would mean disagreeing with every certificate this provider must adopt.
func TestSubjectKeyIDMatchesOpenSSLHash(t *testing.T) {
	t.Parallel()
	openssl := requireOpenSSL(t)

	for _, params := range []KeyParams{
		{Algorithm: AlgorithmRSA},
		{Algorithm: AlgorithmECDSA},
		{Algorithm: AlgorithmED25519},
	} {
		key, err := GenerateKey(params)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", params.Algorithm, err)
		}
		ext, err := SubjectKeyIDExtension(PublicKeyOf(key))
		if err != nil {
			t.Fatalf("SubjectKeyIDExtension(%s): %v", params.Algorithm, err)
		}
		var ours []byte
		if _, err := asn1.Unmarshal(ext.Value, &ours); err != nil {
			t.Fatalf("unmarshaling SKI (%s): %v", params.Algorithm, err)
		}

		keyPEM, err := EncodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM(%s): %v", params.Algorithm, err)
		}
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatalf("writing key: %v", err)
		}
		certPath := filepath.Join(dir, "cert.der")
		cmd := exec.Command(openssl, "req", "-x509", "-key", keyPath,
			"-subj", "/CN=ski", "-days", "1",
			"-addext", "subjectKeyIdentifier=hash",
			"-outform", "DER", "-out", certPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("openssl req (%s): %v\n%s", params.Algorithm, err, out)
		}
		der, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatalf("reading certificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate(%s): %v", params.Algorithm, err)
		}
		if !bytes.Equal(ours, cert.SubjectKeyId) {
			t.Errorf("%s: SKI = % x, openssl computed % x", params.Algorithm, ours, cert.SubjectKeyId)
		}
	}
}

// selfSignedWith issues a throwaway self-signed certificate carrying ext and
// returns it as crypto/x509 parses it back, so an extension's structure is
// validated by an implementation that did not encode it.
func selfSignedWith(t *testing.T, exts ...pkix.Extension) *x509.Certificate {
	t.Helper()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "extension probe"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, PublicKeyOf(key), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// TestParsersRejectWrongOID confirms each parser checks the extension's OID.
//
// Each case must carry a value that is VALID for that parser's own extension,
// presented under the wrong OID. Sharing one placeholder value across all four
// -- an empty SEQUENCE, say -- makes the test near-vacuous: every parser then
// fails on the malformed value rather than on the OID, so deleting three of the
// four OID guards leaves the suite green. Verified by doing exactly that.
func TestParsersRejectWrongOID(t *testing.T) {
	t.Parallel()
	const wrongOID = "2.5.29.99"

	// A valid basicConstraints value: SEQUENCE { cA TRUE }.
	bcValue, err := (BasicConstraints{CA: true, Critical: true}).Extension()
	if err != nil {
		t.Fatalf("building a valid basicConstraints value: %v", err)
	}
	// A valid keyUsage BIT STRING.
	kuValue, err := (KeyUsage{Usages: []string{"digitalSignature"}, Critical: true}).Extension()
	if err != nil {
		t.Fatalf("building a valid keyUsage value: %v", err)
	}
	// A valid extendedKeyUsage SEQUENCE OF OID.
	ekuValue, err := (ExtKeyUsage{Usages: []string{"clientAuth"}}).Extension()
	if err != nil {
		t.Fatalf("building a valid extendedKeyUsage value: %v", err)
	}
	// A valid nameConstraints SEQUENCE with one permitted subtree.
	ncValue, err := (NameConstraints{PermittedDNSDomains: []string{".example"}, Critical: true}).Extension()
	if err != nil {
		t.Fatalf("building a valid nameConstraints value: %v", err)
	}

	misfiled := func(v pkix.Extension) pkix.Extension {
		return pkix.Extension{Id: mustOID(t, wrongOID), Critical: v.Critical, Value: v.Value}
	}

	if _, err := ParseBasicConstraints(misfiled(bcValue)); err == nil {
		t.Error("ParseBasicConstraints accepted a valid value under the wrong OID")
	}
	if _, err := ParseKeyUsage(misfiled(kuValue)); err == nil {
		t.Error("ParseKeyUsage accepted a valid value under the wrong OID")
	}
	if _, err := ParseExtKeyUsage(misfiled(ekuValue)); err == nil {
		t.Error("ParseExtKeyUsage accepted a valid value under the wrong OID")
	}
	if _, err := ParseNameConstraints(misfiled(ncValue)); err == nil {
		t.Error("ParseNameConstraints accepted a valid value under the wrong OID")
	}

	// Sanity check the fixtures: each value must parse cleanly under its own
	// OID, or the assertions above would pass for the wrong reason.
	if _, err := ParseBasicConstraints(bcValue); err != nil {
		t.Errorf("the basicConstraints fixture does not parse under its own OID: %v", err)
	}
	if _, err := ParseKeyUsage(kuValue); err != nil {
		t.Errorf("the keyUsage fixture does not parse under its own OID: %v", err)
	}
	if _, err := ParseExtKeyUsage(ekuValue); err != nil {
		t.Errorf("the extendedKeyUsage fixture does not parse under its own OID: %v", err)
	}
	if _, err := ParseNameConstraints(ncValue); err != nil {
		t.Errorf("the nameConstraints fixture does not parse under its own OID: %v", err)
	}
}
