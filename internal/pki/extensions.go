// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
)

// Extension OIDs this file builds and parses. They duplicate entries in the
// extensions table in oids.go deliberately: that table is the user-facing
// name<->OID lookup, while these are typed values used in code paths that must
// not be able to fail on a lookup.
//
// oidAuthorityKeyID is declared here rather than at its point of use because
// the authorityKeyIdentifier extension is written by the signing code (Task 9),
// which needs the issuer's identifier rather than the subject's.
var (
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// maxKeyUsageBit is the highest bit RFC 5280 4.2.1.3 assigns (decipherOnly).
const maxKeyUsageBit = 8

// BasicConstraints is the basicConstraints extension (RFC 5280 4.2.1.9).
//
// PathLen is a pointer because X.509 distinguishes an absent
// pathLenConstraint (unlimited CA depth) from a present one of 0 (this CA may
// not issue further CAs). A zero-defaulted int cannot express that difference,
// and collapsing the two would silently change the meaning of a CA
// certificate.
type BasicConstraints struct {
	CA       bool
	PathLen  *int
	Critical bool
}

// basicConstraintsPathLen and basicConstraintsNoPathLen are the two DER shapes
// of basicConstraints. Two structs are needed rather than one field tagged
// `asn1:"optional,default:-1"`: that tag makes encoding/asn1 omit the field
// whenever it equals -1, which conflates "no constraint" with a real (invalid)
// -1 and gives the caller no way to emit pathLenConstraint at all when it
// happens to be the sentinel. Choosing the struct on PathLen == nil keeps the
// two cases distinguishable in both directions.
//
// cA is tagged optional so DER's DEFAULT FALSE rule is honoured: a non-CA
// encodes as an empty SEQUENCE.
type basicConstraintsPathLen struct {
	CA      bool `asn1:"optional"`
	PathLen int
}

type basicConstraintsNoPathLen struct {
	CA bool `asn1:"optional"`
}

// Extension encodes bc as the basicConstraints (2.5.29.19) extension.
//
// A pathLen on a non-CA is rejected rather than dropped: pathLenConstraint is
// meaningful only when cA is asserted (RFC 5280 4.2.1.9), so a config that
// sets both is a mistake worth reporting instead of quietly ignoring.
func (bc BasicConstraints) Extension() (pkix.Extension, error) {
	var (
		value []byte
		err   error
	)
	switch {
	case bc.PathLen == nil:
		value, err = asn1.Marshal(basicConstraintsNoPathLen{CA: bc.CA})
	case !bc.CA:
		return pkix.Extension{}, fmt.Errorf("path_len is only valid when ca is true")
	case *bc.PathLen < 0:
		return pkix.Extension{}, fmt.Errorf("path_len %d is negative", *bc.PathLen)
	default:
		value, err = asn1.Marshal(basicConstraintsPathLen{CA: bc.CA, PathLen: *bc.PathLen})
	}
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling basicConstraints: %w", err)
	}
	return pkix.Extension{Id: oidBasicConstraints, Critical: bc.Critical, Value: value}, nil
}

// ParseBasicConstraints parses a basicConstraints extension.
//
// The pathLen-bearing shape is tried first; a SEQUENCE without a
// pathLenConstraint fails to fill its final non-optional field, which is how
// the absent case is recognized without a sentinel value.
func ParseBasicConstraints(ext pkix.Extension) (BasicConstraints, error) {
	if !ext.Id.Equal(oidBasicConstraints) {
		return BasicConstraints{}, fmt.Errorf("extension OID %s is not basicConstraints (2.5.29.19)", FormatOID(ext.Id))
	}

	var withPathLen basicConstraintsPathLen
	if rest, err := asn1.Unmarshal(ext.Value, &withPathLen); err == nil && len(rest) == 0 {
		if !withPathLen.CA {
			return BasicConstraints{}, fmt.Errorf("parsing basicConstraints: pathLenConstraint is present but cA is false")
		}
		if withPathLen.PathLen < 0 {
			return BasicConstraints{}, fmt.Errorf("parsing basicConstraints: pathLenConstraint %d is negative", withPathLen.PathLen)
		}
		pathLen := withPathLen.PathLen
		return BasicConstraints{CA: true, PathLen: &pathLen, Critical: ext.Critical}, nil
	}

	var noPathLen basicConstraintsNoPathLen
	rest, err := asn1.Unmarshal(ext.Value, &noPathLen)
	if err != nil {
		return BasicConstraints{}, fmt.Errorf("parsing basicConstraints: %w", err)
	}
	if len(rest) != 0 {
		return BasicConstraints{}, fmt.Errorf("parsing basicConstraints: %d trailing bytes", len(rest))
	}
	return BasicConstraints{CA: noPathLen.CA, Critical: ext.Critical}, nil
}

// KeyUsage is the keyUsage extension (RFC 5280 4.2.1.3). Usages holds the
// names from the key_usages table in oids.go.
//
// The list is a set, not a sequence: keyUsage is a BIT STRING, so the order
// entries appear in configuration is not representable and must not affect the
// encoding.
type KeyUsage struct {
	Usages   []string
	Critical bool
}

// Extension encodes ku as the keyUsage (2.5.29.15) extension.
//
// The BIT STRING is emitted in DER minimal form: bits are set
// most-significant-first within each octet, BitLength comes from the highest
// bit actually set, and octets past that bit are dropped. A non-minimal
// encoding is not valid DER and renders differently under
// `openssl x509 -text`, which would show up as permanent drift against an
// openssl-issued certificate.
func (ku KeyUsage) Extension() (pkix.Extension, error) {
	if len(ku.Usages) == 0 {
		return pkix.Extension{}, fmt.Errorf("key usage has no usages")
	}

	seen := make(map[int]bool, len(ku.Usages))
	highest := -1
	for i, name := range ku.Usages {
		bit, err := KeyUsageBit(name)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("key usage %d: %w", i, err)
		}
		if seen[bit] {
			return pkix.Extension{}, fmt.Errorf("duplicate key usage %q", name)
		}
		seen[bit] = true
		if bit > highest {
			highest = bit
		}
	}

	bytes := make([]byte, maxKeyUsageBit/8+1)
	for bit := range seen {
		bytes[bit/8] |= 0x80 >> (bit % 8)
	}

	bs := asn1.BitString{Bytes: bytes[:highest/8+1], BitLength: highest + 1}
	value, err := asn1.Marshal(bs)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling keyUsage: %w", err)
	}
	return pkix.Extension{Id: oidKeyUsage, Critical: ku.Critical, Value: value}, nil
}

// ParseKeyUsage parses a keyUsage extension, returning usages in RFC 5280 bit
// order so the result is canonical regardless of how the extension was
// written.
//
// Bits above decipherOnly are ignored: RFC 5280 assigns none, and a
// certificate that sets one is better imported than rejected. A keyUsage with
// no bits set at all is rejected, because RFC 5280 4.2.1.3 requires at least
// one and an empty KeyUsage cannot be re-encoded.
func ParseKeyUsage(ext pkix.Extension) (KeyUsage, error) {
	if !ext.Id.Equal(oidKeyUsage) {
		return KeyUsage{}, fmt.Errorf("extension OID %s is not keyUsage (2.5.29.15)", FormatOID(ext.Id))
	}

	var bs asn1.BitString
	rest, err := asn1.Unmarshal(ext.Value, &bs)
	if err != nil {
		return KeyUsage{}, fmt.Errorf("parsing keyUsage: %w", err)
	}
	if len(rest) != 0 {
		return KeyUsage{}, fmt.Errorf("parsing keyUsage: %d trailing bytes", len(rest))
	}

	var usages []string
	for bit := 0; bit <= maxKeyUsageBit; bit++ {
		if bs.At(bit) == 0 {
			continue
		}
		name, err := KeyUsageBitName(bit)
		if err != nil {
			return KeyUsage{}, fmt.Errorf("parsing keyUsage: %w", err)
		}
		usages = append(usages, name)
	}
	if len(usages) == 0 {
		return KeyUsage{}, fmt.Errorf("parsing keyUsage: no bits are set")
	}
	return KeyUsage{Usages: usages, Critical: ext.Critical}, nil
}

// DefaultCAKeyUsage is the key usage applied to a CA certificate when
// configuration does not specify one.
func DefaultCAKeyUsage() KeyUsage {
	return KeyUsage{Usages: []string{"keyCertSign", "crlSign"}, Critical: true}
}

// DefaultLeafKeyUsage is the key usage applied to an end-entity certificate
// when configuration does not specify one. It reproduces the existing
// issuer's `keyUsage = critical, digitalSignature, keyEncipherment`, so
// adopting a certificate it issued does not show drift.
func DefaultLeafKeyUsage() KeyUsage {
	return KeyUsage{Usages: []string{"digitalSignature", "keyEncipherment"}, Critical: true}
}

// DefaultCAKeyUsagePtr returns DefaultCAKeyUsage as a pointer, for the
// certificate template's optional KeyUsage field.
func DefaultCAKeyUsagePtr() *KeyUsage {
	ku := DefaultCAKeyUsage()
	return &ku
}

// DefaultLeafKeyUsagePtr returns DefaultLeafKeyUsage as a pointer, for the
// certificate template's optional KeyUsage field.
func DefaultLeafKeyUsagePtr() *KeyUsage {
	ku := DefaultLeafKeyUsage()
	return &ku
}

// ExtKeyUsage is the extendedKeyUsage extension (RFC 5280 4.2.1.12). Each
// entry is either a name from the extended_key_usages table or a dotted OID.
//
// Unlike KeyUsage, order is significant: extendedKeyUsage is a SEQUENCE OF,
// so the list is emitted in the order given and parsed back in the order the
// certificate carries.
type ExtKeyUsage struct {
	Usages   []string
	Critical bool
}

// Extension encodes eku as the extendedKeyUsage (2.5.29.37) extension.
//
// Duplicates are detected after resolution to an OID, so listing both
// "clientAuth" and "1.3.6.1.5.5.7.3.2" is caught as the duplicate it is.
func (eku ExtKeyUsage) Extension() (pkix.Extension, error) {
	if len(eku.Usages) == 0 {
		return pkix.Extension{}, fmt.Errorf("extended key usage has no usages")
	}

	seen := make(map[string]bool, len(eku.Usages))
	oids := make([]asn1.ObjectIdentifier, 0, len(eku.Usages))
	for i, nameOrOID := range eku.Usages {
		oid, err := ExtKeyUsageOID(nameOrOID)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("extended key usage %d: %w", i, err)
		}
		dotted := FormatOID(oid)
		if seen[dotted] {
			return pkix.Extension{}, fmt.Errorf("duplicate extended key usage %q", nameOrOID)
		}
		seen[dotted] = true
		oids = append(oids, oid)
	}

	value, err := asn1.Marshal(oids)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling extendedKeyUsage: %w", err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: eku.Critical, Value: value}, nil
}

// ParseExtKeyUsage parses an extendedKeyUsage extension, rendering each OID as
// its friendly name when the table knows it and in dotted form when it does
// not, so an unrecognized purpose survives a round trip.
func ParseExtKeyUsage(ext pkix.Extension) (ExtKeyUsage, error) {
	if !ext.Id.Equal(oidExtKeyUsage) {
		return ExtKeyUsage{}, fmt.Errorf("extension OID %s is not extendedKeyUsage (2.5.29.37)", FormatOID(ext.Id))
	}

	var oids []asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(ext.Value, &oids)
	if err != nil {
		return ExtKeyUsage{}, fmt.Errorf("parsing extendedKeyUsage: %w", err)
	}
	if len(rest) != 0 {
		return ExtKeyUsage{}, fmt.Errorf("parsing extendedKeyUsage: %d trailing bytes", len(rest))
	}
	if len(oids) == 0 {
		return ExtKeyUsage{}, fmt.Errorf("parsing extendedKeyUsage: sequence is empty")
	}

	usages := make([]string, 0, len(oids))
	for _, oid := range oids {
		dotted := FormatOID(oid)
		if name, err := NameByOID(dotted); err == nil {
			usages = append(usages, name)
			continue
		}
		usages = append(usages, dotted)
	}
	return ExtKeyUsage{Usages: usages, Critical: ext.Critical}, nil
}

// NameConstraints is the nameConstraints extension (RFC 5280 4.2.1.10),
// symmetric in permitted and excluded subtrees across all four GeneralName
// types this provider represents.
//
// IP ranges are CIDR strings; the other three are the GeneralName forms
// described in RFC 5280 4.2.1.10, where a leading dot on a DNS name or URI
// constrains subdomains.
type NameConstraints struct {
	PermittedDNSDomains   []string
	ExcludedDNSDomains    []string
	PermittedEmailDomains []string
	ExcludedEmailDomains  []string
	PermittedIPRanges     []string
	ExcludedIPRanges      []string
	PermittedURIDomains   []string
	ExcludedURIDomains    []string
	Critical              bool
}

// generalSubtree is RFC 5280's
// GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] BaseDistance
// DEFAULT 0, maximum [1] BaseDistance OPTIONAL }.
//
// Minimum and Maximum are modelled even though this provider always emits
// them absent (RFC 5280 requires minimum 0 and forbids maximum), because
// encoding/asn1 rejects a SEQUENCE carrying fields the target struct does not
// declare, and a certificate issued elsewhere may include them.
type generalSubtree struct {
	Base    asn1.RawValue
	Minimum int `asn1:"optional,default:0,tag:0"`
	Maximum int `asn1:"optional,tag:1"`
}

// nameConstraintsDER is RFC 5280's
// NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
// OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }. A nil slice is
// omitted entirely, which is what OPTIONAL means here; an empty-but-non-nil
// slice would encode as a present, empty SEQUENCE OF and be invalid.
type nameConstraintsDER struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

// IsEmpty reports whether nc constrains nothing.
func (nc NameConstraints) IsEmpty() bool {
	return len(nc.PermittedDNSDomains) == 0 && len(nc.ExcludedDNSDomains) == 0 &&
		len(nc.PermittedEmailDomains) == 0 && len(nc.ExcludedEmailDomains) == 0 &&
		len(nc.PermittedIPRanges) == 0 && len(nc.ExcludedIPRanges) == 0 &&
		len(nc.PermittedURIDomains) == 0 && len(nc.ExcludedURIDomains) == 0
}

// Extension encodes nc as the nameConstraints (2.5.29.30) extension.
//
// An empty NameConstraints is an error: RFC 5280 4.2.1.10 requires at least
// one of the two subtree sets, so a caller with nothing to constrain must omit
// the extension rather than emit an empty one.
func (nc NameConstraints) Extension() (pkix.Extension, error) {
	if nc.IsEmpty() {
		return pkix.Extension{}, fmt.Errorf("name constraints has no entries")
	}

	permitted, err := generalSubtrees(nc.PermittedDNSDomains, nc.PermittedEmailDomains, nc.PermittedIPRanges, nc.PermittedURIDomains)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("permitted: %w", err)
	}
	excluded, err := generalSubtrees(nc.ExcludedDNSDomains, nc.ExcludedEmailDomains, nc.ExcludedIPRanges, nc.ExcludedURIDomains)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("excluded: %w", err)
	}

	value, err := asn1.Marshal(nameConstraintsDER{Permitted: permitted, Excluded: excluded})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling nameConstraints: %w", err)
	}
	return pkix.Extension{Id: oidNameConstraints, Critical: nc.Critical, Value: value}, nil
}

// generalSubtrees builds one subtree list, emitting the types in the same
// fixed order SAN uses (dns, email, ip, uri) so the encoding is stable.
func generalSubtrees(dns, email, ipRanges, uris []string) ([]generalSubtree, error) {
	var subtrees []generalSubtree

	for i, name := range dns {
		if err := validateIA5(name); err != nil {
			return nil, fmt.Errorf("DNS domain %d (%q): %w", i, name, err)
		}
		subtrees = append(subtrees, subtreeOf(sanTagDNS, []byte(name)))
	}
	for i, name := range email {
		if err := validateIA5(name); err != nil {
			return nil, fmt.Errorf("email domain %d (%q): %w", i, name, err)
		}
		subtrees = append(subtrees, subtreeOf(sanTagEmail, []byte(name)))
	}
	for i, cidr := range ipRanges {
		b, err := ipRangeBytes(cidr)
		if err != nil {
			return nil, fmt.Errorf("IP range %d (%q): %w", i, cidr, err)
		}
		subtrees = append(subtrees, subtreeOf(sanTagIP, b))
	}
	for i, uri := range uris {
		if err := validateIA5(uri); err != nil {
			return nil, fmt.Errorf("URI domain %d (%q): %w", i, uri, err)
		}
		subtrees = append(subtrees, subtreeOf(sanTagURI, []byte(uri)))
	}

	return subtrees, nil
}

func subtreeOf(tag int, bytes []byte) generalSubtree {
	return generalSubtree{Base: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: bytes}}
}

// ipRangeBytes encodes a CIDR as an iPAddress GeneralName inside a
// GeneralSubtree: the network address followed by an equal-length mask, so 8
// bytes for IPv4 and 32 for IPv6 (RFC 5280 4.2.1.10). This is why a
// nameConstraints iPAddress cannot be encoded by san.go's ipBytes, which emits
// the address alone.
//
// net.ParseCIDR rejects a bare address, so "10.0.0.1" is an error rather than
// a silent /32. The masked network address is used, so host bits in the
// configured value are normalized away rather than written to the certificate.
func ipRangeBytes(cidr string) ([]byte, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parsing CIDR: %w", err)
	}
	if len(network.IP) != len(network.Mask) {
		return nil, fmt.Errorf("address is %d bytes but mask is %d", len(network.IP), len(network.Mask))
	}
	if len(network.IP) != net.IPv4len && len(network.IP) != net.IPv6len {
		return nil, fmt.Errorf("address is %d bytes, want 4 or 16", len(network.IP))
	}
	out := make([]byte, 0, 2*len(network.IP))
	out = append(out, network.IP...)
	out = append(out, network.Mask...)
	return out, nil
}

// ParseNameConstraints parses a nameConstraints extension.
//
// A base whose GeneralName type this provider does not represent is skipped
// rather than rejected, matching ParseSANExtension: a certificate constrained
// by a directoryName should still be importable, and Task 14 compares raw
// extension bytes, so a dropped base cannot be mistaken for agreement.
func ParseNameConstraints(ext pkix.Extension) (NameConstraints, error) {
	if !ext.Id.Equal(oidNameConstraints) {
		return NameConstraints{}, fmt.Errorf("extension OID %s is not nameConstraints (2.5.29.30)", FormatOID(ext.Id))
	}

	var der nameConstraintsDER
	rest, err := asn1.Unmarshal(ext.Value, &der)
	if err != nil {
		return NameConstraints{}, fmt.Errorf("parsing nameConstraints: %w", err)
	}
	if len(rest) != 0 {
		return NameConstraints{}, fmt.Errorf("parsing nameConstraints: %d trailing bytes", len(rest))
	}
	if len(der.Permitted) == 0 && len(der.Excluded) == 0 {
		return NameConstraints{}, fmt.Errorf("parsing nameConstraints: no subtrees are present")
	}

	nc := NameConstraints{Critical: ext.Critical}
	if err := readSubtrees(der.Permitted, &nc.PermittedDNSDomains, &nc.PermittedEmailDomains, &nc.PermittedIPRanges, &nc.PermittedURIDomains); err != nil {
		return NameConstraints{}, fmt.Errorf("parsing nameConstraints permittedSubtrees: %w", err)
	}
	if err := readSubtrees(der.Excluded, &nc.ExcludedDNSDomains, &nc.ExcludedEmailDomains, &nc.ExcludedIPRanges, &nc.ExcludedURIDomains); err != nil {
		return NameConstraints{}, fmt.Errorf("parsing nameConstraints excludedSubtrees: %w", err)
	}
	return nc, nil
}

func readSubtrees(subtrees []generalSubtree, dns, email, ipRanges, uris *[]string) error {
	for _, subtree := range subtrees {
		if subtree.Base.Class != asn1.ClassContextSpecific {
			continue
		}
		switch subtree.Base.Tag {
		case sanTagDNS:
			*dns = append(*dns, string(subtree.Base.Bytes))
		case sanTagEmail:
			*email = append(*email, string(subtree.Base.Bytes))
		case sanTagURI:
			*uris = append(*uris, string(subtree.Base.Bytes))
		case sanTagIP:
			cidr, err := ipRangeString(subtree.Base.Bytes)
			if err != nil {
				return err
			}
			*ipRanges = append(*ipRanges, cidr)
		default:
			// otherName, x400Address, directoryName, ediPartyName,
			// registeredID: unsupported, dropped rather than rejected. See the
			// doc comment on ParseNameConstraints.
		}
	}
	return nil
}

// ipRangeString renders an address-plus-mask iPAddress base back to CIDR.
func ipRangeString(b []byte) (string, error) {
	if len(b) != 2*net.IPv4len && len(b) != 2*net.IPv6len {
		return "", fmt.Errorf("iPAddress subtree has %d bytes, want 8 or 32", len(b))
	}
	half := len(b) / 2
	network := net.IPNet{IP: net.IP(b[:half]), Mask: net.IPMask(b[half:])}
	return network.String(), nil
}

// ExtraExtension is any extension this provider has no typed support for. The
// caller supplies the DER of the extnValue content and it is written verbatim,
// so an extension the provider does not understand can still be issued.
type ExtraExtension struct {
	OID      asn1.ObjectIdentifier
	Value    []byte
	Critical bool
}

// Extension returns e as a pkix.Extension. The value is neither parsed nor
// re-encoded: it is already the DER the caller wants in the certificate, and
// round-tripping it through a parser this provider does not have would be the
// one thing this type exists to avoid.
func (e ExtraExtension) Extension() (pkix.Extension, error) {
	if len(e.OID) < 2 {
		return pkix.Extension{}, fmt.Errorf("extra extension OID must have at least two arcs, got %d", len(e.OID))
	}
	if len(e.Value) == 0 {
		return pkix.Extension{}, fmt.Errorf("extra extension %s has an empty value", FormatOID(e.OID))
	}
	return pkix.Extension{Id: e.OID, Critical: e.Critical, Value: e.Value}, nil
}

// subjectPublicKeyInfo is the SubjectPublicKeyInfo shape needed to reach the
// subjectPublicKey BIT STRING's contents, which is what the key identifier is
// computed over.
type subjectPublicKeyInfo struct {
	Algo             pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// SubjectKeyIDExtension builds the subjectKeyIdentifier (2.5.29.14) extension
// for pub using RFC 5280 4.2.1.2 method 1: the 160-bit SHA-1 of the
// subjectPublicKey BIT STRING's contents, excluding the tag, length, and
// unused-bit count.
//
// The SHA-1 here is a key identifier, not a signature: it is a fixed part of
// the wire format that every other implementation computes the same way. The
// existing issuer asks openssl for `subjectKeyIdentifier = hash`, which is
// this same algorithm, so a certificate being adopted must hash to the same 20
// bytes or it would look like drift forever. Substituting a stronger digest
// would break that interoperability, so this is not a security decision open
// to revision.
//
// The extension is non-critical, which RFC 5280 4.2.1.2 requires.
func SubjectKeyIDExtension(pub crypto.PublicKey) (pkix.Extension, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling public key: %w", err)
	}

	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return pkix.Extension{}, fmt.Errorf("parsing SubjectPublicKeyInfo: %w", err)
	}

	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	value, err := asn1.Marshal(sum[:])
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling subjectKeyIdentifier: %w", err)
	}
	return pkix.Extension{Id: oidSubjectKeyID, Critical: false, Value: value}, nil
}
