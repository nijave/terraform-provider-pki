// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
)

// GeneralName context-specific tags from RFC 5280 4.2.1.6. otherName [0],
// x400Address [3], directoryName [4], ediPartyName [5], and registeredID [8]
// are out of scope for this provider; extra_extension is the escape hatch if
// one is ever needed.
const (
	sanTagEmail = 1
	sanTagDNS   = 2
	sanTagURI   = 6
	sanTagIP    = 7
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// SAN is a subjectAltName extension in the four GeneralName types Go's
// x509.Certificate represents natively.
//
// Entry order within a type is preserved on encode; types are emitted in the
// fixed order dns, email, ip, uri. That order matches what openssl produces
// from an [alt] config section listing DNS before email, which is what the
// certificates this provider must adopt contain.
type SAN struct {
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []net.IP
	URIs           []string
	Critical       bool
}

// IsEmpty reports whether the SAN carries no names at all. Critical alone
// does not count: there is nothing for it to mark critical.
func (s SAN) IsEmpty() bool {
	return len(s.DNSNames) == 0 && len(s.EmailAddresses) == 0 && len(s.IPAddresses) == 0 && len(s.URIs) == 0
}

// Extension validates s and encodes it as the subjectAltName (2.5.29.17)
// extension.
//
// An empty SAN is an error, not an empty extension: GeneralNames must have at
// least one entry to be valid DER (RFC 5280 4.2.1.6), so a caller with
// nothing to say must omit the extension entirely rather than call this.
//
// Critical is forced true when subjectEmpty is true, per RFC 5280 4.2.1.6:
// with no subject DN, the SAN is the certificate's only identity.
func (s SAN) Extension(subjectEmpty bool) (pkix.Extension, error) {
	if s.IsEmpty() {
		return pkix.Extension{}, fmt.Errorf("subject alternative name has no entries")
	}

	var names []asn1.RawValue

	for i, name := range s.DNSNames {
		if err := validateIA5(name); err != nil {
			return pkix.Extension{}, fmt.Errorf("DNS name %d (%q): %w", i, name, err)
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagDNS, Bytes: []byte(name)})
	}

	for i, email := range s.EmailAddresses {
		if err := validateIA5(email); err != nil {
			return pkix.Extension{}, fmt.Errorf("email address %d (%q): %w", i, email, err)
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagEmail, Bytes: []byte(email)})
	}

	for i, ip := range s.IPAddresses {
		b, err := ipBytes(ip)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("IP address %d: %w", i, err)
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagIP, Bytes: b})
	}

	for i, uri := range s.URIs {
		if err := validateURI(uri); err != nil {
			return pkix.Extension{}, fmt.Errorf("URI %d (%q): %w", i, uri, err)
		}
		names = append(names, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: sanTagURI, Bytes: []byte(uri)})
	}

	value, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshaling subject alternative name: %w", err)
	}

	return pkix.Extension{
		Id:       oidSubjectAltName,
		Critical: s.Critical || subjectEmpty,
		Value:    value,
	}, nil
}

// validateURI checks that s parses and is absolute (url.IsAbs), which is
// what rejects a bare path such as "/just/a/path". The caller writes the
// original string to the DER, not u.String(), so a URI survives a round trip
// unchanged.
func validateURI(s string) error {
	if s == "" {
		return fmt.Errorf("value is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("parsing URI: %w", err)
	}
	if !u.IsAbs() {
		return fmt.Errorf("URI is not absolute")
	}
	return nil
}

// ipBytes returns the DER payload for ip: 4 bytes for an IPv4 address, 16 for
// an IPv6 address. ip.To4() is tried first so an IPv4 address is written as 4
// bytes, matching what openssl and Go both do; writing the 16-byte
// IPv4-mapped form instead would produce a SAN that renders as
// "::ffff:10.0.0.5".
func ipBytes(ip net.IP) ([]byte, error) {
	if ip == nil {
		return nil, fmt.Errorf("IP address is nil")
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, nil
	}
	if v6 := ip.To16(); v6 != nil {
		return v6, nil
	}
	return nil, fmt.Errorf("IP address %v is neither 4 nor 16 bytes", ip)
}

// ParseSANExtension parses a subjectAltName extension into a SAN.
//
// Any GeneralName tag other than the four this type supports (rfc822Name,
// dNSName, uniformResourceIdentifier, iPAddress) is skipped silently rather
// than rejected: a certificate issued elsewhere may carry an otherName, and
// failing to parse would make it unimportable, which is worse than dropping a
// name this provider cannot represent. A dropped name means re-encoding this
// SAN is not byte-exact with the original extension; Task 14 catches this by
// comparing raw extension bytes rather than parsed structs.
func ParseSANExtension(ext pkix.Extension) (SAN, error) {
	if !ext.Id.Equal(oidSubjectAltName) {
		return SAN{}, fmt.Errorf("extension OID %s is not subjectAltName (2.5.29.17)", FormatOID(ext.Id))
	}

	var names []asn1.RawValue
	rest, err := asn1.Unmarshal(ext.Value, &names)
	if err != nil {
		return SAN{}, fmt.Errorf("parsing subjectAltName: %w", err)
	}
	if len(rest) != 0 {
		return SAN{}, fmt.Errorf("parsing subjectAltName: %d trailing bytes after GeneralNames", len(rest))
	}

	var s SAN
	for _, name := range names {
		if name.Class != asn1.ClassContextSpecific {
			continue
		}
		switch name.Tag {
		case sanTagDNS:
			s.DNSNames = append(s.DNSNames, string(name.Bytes))
		case sanTagEmail:
			s.EmailAddresses = append(s.EmailAddresses, string(name.Bytes))
		case sanTagURI:
			s.URIs = append(s.URIs, string(name.Bytes))
		case sanTagIP:
			if len(name.Bytes) != 4 && len(name.Bytes) != 16 {
				return SAN{}, fmt.Errorf("iPAddress GeneralName has %d bytes, want 4 or 16", len(name.Bytes))
			}
			s.IPAddresses = append(s.IPAddresses, net.IP(name.Bytes))
		default:
			// otherName, x400Address, directoryName, ediPartyName,
			// registeredID: unsupported, dropped rather than rejected. See the
			// doc comment above.
		}
	}
	return s, nil
}

// ParseIPs parses each string in values as a net.IP, for the framework
// layer's string-typed config. net.ParseIP already rejects CIDR notation and
// the empty string.
func ParseIPs(values []string) ([]net.IP, error) {
	ips := make([]net.IP, 0, len(values))
	for _, v := range values {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", v)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// FindExtension returns the first extension in exts whose OID matches oid, a
// linear scan: extensions are a handful of entries, so no indexing.
func FindExtension(exts []pkix.Extension, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, ext := range exts {
		if ext.Id.Equal(oid) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}
