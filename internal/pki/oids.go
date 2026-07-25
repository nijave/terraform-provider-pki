// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Table is one named group of the hardcoded name<->OID lookup, exposed to
// callers as a pair of maps that are the exact reverse of each other.
type Table struct {
	Name   string
	ByName map[string]string
	ByOID  map[string]string
}

// dnAttributes are the distinguished-name attribute types recognized in
// subject and issuer configuration.
var dnAttributes = map[string]string{
	"commonName":             "2.5.4.3",
	"surname":                "2.5.4.4",
	"serialNumber":           "2.5.4.5",
	"country":                "2.5.4.6",
	"locality":               "2.5.4.7",
	"province":               "2.5.4.8",
	"streetAddress":          "2.5.4.9",
	"organization":           "2.5.4.10",
	"organizationalUnit":     "2.5.4.11",
	"title":                  "2.5.4.12",
	"description":            "2.5.4.13",
	"postalCode":             "2.5.4.17",
	"name":                   "2.5.4.41",
	"givenName":              "2.5.4.42",
	"initials":               "2.5.4.43",
	"generationQualifier":    "2.5.4.44",
	"dnQualifier":            "2.5.4.46",
	"pseudonym":              "2.5.4.65",
	"emailAddress":           "1.2.840.113549.1.9.1",
	"uid":                    "0.9.2342.19200300.100.1.1",
	"domainComponent":        "0.9.2342.19200300.100.1.25",
	"displayName":            "2.16.840.1.113730.3.1.241",
	"jurisdictionCountry":    "1.3.6.1.4.1.311.60.2.1.3",
	"organizationIdentifier": "2.5.4.97",
}

// extensions are the X.509v3 extension types recognized in extension
// configuration blocks.
var extensions = map[string]string{
	"subjectKeyIdentifier":   "2.5.29.14",
	"keyUsage":               "2.5.29.15",
	"subjectAltName":         "2.5.29.17",
	"issuerAltName":          "2.5.29.18",
	"basicConstraints":       "2.5.29.19",
	"nameConstraints":        "2.5.29.30",
	"crlDistributionPoints":  "2.5.29.31",
	"certificatePolicies":    "2.5.29.32",
	"policyMappings":         "2.5.29.33",
	"authorityKeyIdentifier": "2.5.29.35",
	"policyConstraints":      "2.5.29.36",
	"extendedKeyUsage":       "2.5.29.37",
	"freshestCRL":            "2.5.29.46",
	"inhibitAnyPolicy":       "2.5.29.54",
	"authorityInfoAccess":    "1.3.6.1.5.5.7.1.1",
	"subjectInfoAccess":      "1.3.6.1.5.5.7.1.11",
	"cRLNumber":              "2.5.29.20",
	"reasonCode":             "2.5.29.21",
	"invalidityDate":         "2.5.29.24",
	"certificateIssuer":      "2.5.29.29",
}

// extendedKeyUsages are the EKU purposes recognized in
// extended_key_usage.usages.
var extendedKeyUsages = map[string]string{
	"any":                            "2.5.29.37.0",
	"serverAuth":                     "1.3.6.1.5.5.7.3.1",
	"clientAuth":                     "1.3.6.1.5.5.7.3.2",
	"codeSigning":                    "1.3.6.1.5.5.7.3.3",
	"emailProtection":                "1.3.6.1.5.5.7.3.4",
	"ipsecEndSystem":                 "1.3.6.1.5.5.7.3.5",
	"ipsecTunnel":                    "1.3.6.1.5.5.7.3.6",
	"ipsecUser":                      "1.3.6.1.5.5.7.3.7",
	"timeStamping":                   "1.3.6.1.5.5.7.3.8",
	"ocspSigning":                    "1.3.6.1.5.5.7.3.9",
	"microsoftServerGatedCrypto":     "1.3.6.1.4.1.311.10.3.3",
	"netscapeServerGatedCrypto":      "2.16.840.1.113730.4.1",
	"microsoftCommercialCodeSigning": "1.3.6.1.4.1.311.2.1.22",
	"microsoftKernelCodeSigning":     "1.3.6.1.4.1.311.61.1.1",
	"microsoftSmartcardLogon":        "1.3.6.1.4.1.311.20.2.2",
}

// keyUsages deliberately has no OIDs: RFC 5280 key usages are bits in a
// BIT STRING, not OID-identified. For this group only, the value on both
// sides of the table is the decimal bit position as a string, so it can
// share the same Table shape as the OID-keyed groups.
var keyUsages = map[string]string{
	"digitalSignature": "0",
	"nonRepudiation":   "1",
	"keyEncipherment":  "2",
	"dataEncipherment": "3",
	"keyAgreement":     "4",
	"keyCertSign":      "5",
	"crlSign":          "6",
	"encipherOnly":     "7",
	"decipherOnly":     "8",
}

// signatureAlgorithms maps the names Go's x509.SignatureAlgorithm.String()
// produces to the OID of the algorithm identifier. MD5, SHA-1, and DSA
// signature algorithms are deliberately omitted: SHA-1 and MD5 signatures
// are not offered, and Go cannot create DSA certificates.
//
// RSASSA-PSS is a real exception to "one name, one OID": RFC 8017 registers a
// single id-RSASSA-PSS OID (1.2.840.113549.1.1.10) for all hash sizes — the
// hash lives in the AlgorithmIdentifier's PSS parameters, not in a distinct
// OID arc (this matches Go's own internal table in crypto/x509/x509.go,
// which also uses one shared OID constant for all three RSAPSS
// SignatureAlgorithm values). So all three RSAPSS entries below map to that
// same real OID; this table is therefore the one group that is not a strict
// bijection, and Tables() below omits the shared OID from ByOID rather than
// picking one PSS name to answer for it or fabricating a sub-arc that no
// implementation would recognize. See TestSignatureAlgorithmTableIsNotBijective.
var signatureAlgorithms = map[string]string{
	"SHA256-RSA":    "1.2.840.113549.1.1.11",
	"SHA384-RSA":    "1.2.840.113549.1.1.12",
	"SHA512-RSA":    "1.2.840.113549.1.1.13",
	"SHA256-RSAPSS": "1.2.840.113549.1.1.10",
	"SHA384-RSAPSS": "1.2.840.113549.1.1.10",
	"SHA512-RSAPSS": "1.2.840.113549.1.1.10",
	"ECDSA-SHA256":  "1.2.840.10045.4.3.2",
	"ECDSA-SHA384":  "1.2.840.10045.4.3.3",
	"ECDSA-SHA512":  "1.2.840.10045.4.3.4",
	"Ed25519":       "1.3.101.112",
}

// signatureAlgorithmValues maps the table's names to the typed
// x509.SignatureAlgorithm constants. A second map is needed alongside
// signatureAlgorithms because a plain map[string]string cannot hold a typed
// constant, and Go has no built-in string-to-SignatureAlgorithm parser; the
// two maps share exactly the same key set by construction.
var signatureAlgorithmValues = map[string]x509.SignatureAlgorithm{
	"SHA256-RSA":    x509.SHA256WithRSA,
	"SHA384-RSA":    x509.SHA384WithRSA,
	"SHA512-RSA":    x509.SHA512WithRSA,
	"SHA256-RSAPSS": x509.SHA256WithRSAPSS,
	"SHA384-RSAPSS": x509.SHA384WithRSAPSS,
	"SHA512-RSAPSS": x509.SHA512WithRSAPSS,
	"ECDSA-SHA256":  x509.ECDSAWithSHA256,
	"ECDSA-SHA384":  x509.ECDSAWithSHA384,
	"ECDSA-SHA512":  x509.ECDSAWithSHA512,
	"Ed25519":       x509.PureEd25519,
}

func copyMap(m map[string]string) map[string]string {
	r := make(map[string]string, len(m))
	for k, v := range m {
		r[k] = v
	}
	return r
}

// invert builds the reverse of m, value->key. A value claimed by more than
// one key (currently only the shared RSASSA-PSS OID in signatureAlgorithms)
// is omitted rather than resolved by picking a winner: a value that does not
// determine a single key cannot answer a reverse lookup, so silently
// choosing one name would misreport the others.
func invert(m map[string]string) map[string]string {
	counts := make(map[string]int, len(m))
	for _, v := range m {
		counts[v]++
	}
	r := make(map[string]string, len(m))
	for k, v := range m {
		if counts[v] > 1 {
			continue
		}
		r[v] = k
	}
	return r
}

// Tables returns the five hardcoded name<->OID groups, in a stable order:
// dn_attributes, extensions, extended_key_usages, key_usages,
// signature_algorithms.
var Tables = sync.OnceValue(func() []Table {
	return []Table{
		{Name: "dn_attributes", ByName: copyMap(dnAttributes), ByOID: invert(dnAttributes)},
		{Name: "extensions", ByName: copyMap(extensions), ByOID: invert(extensions)},
		{Name: "extended_key_usages", ByName: copyMap(extendedKeyUsages), ByOID: invert(extendedKeyUsages)},
		{Name: "key_usages", ByName: copyMap(keyUsages), ByOID: invert(keyUsages)},
		{Name: "signature_algorithms", ByName: copyMap(signatureAlgorithms), ByOID: invert(signatureAlgorithms)},
	}
})

// lookupTables are the three groups searched by OIDByName and NameByOID, in
// order. key_usages has no OIDs, and signature_algorithms adds nothing to
// this terse lookup path.
func lookupTables() []Table {
	all := Tables()
	return []Table{all[0], all[1], all[2]}
}

// OIDByName searches dn_attributes, extensions, then extended_key_usages
// (in that order) and returns the dotted OID for name.
func OIDByName(name string) (string, error) {
	for _, tbl := range lookupTables() {
		if oid, ok := tbl.ByName[name]; ok {
			return oid, nil
		}
	}
	return "", fmt.Errorf("unknown OID name %q", name)
}

// NameByOID searches dn_attributes, extensions, then extended_key_usages
// (in that order) and returns the friendly name for oid.
func NameByOID(oid string) (string, error) {
	for _, tbl := range lookupTables() {
		if name, ok := tbl.ByOID[oid]; ok {
			return name, nil
		}
	}
	return "", fmt.Errorf("unknown OID %q", oid)
}

// ParseOID parses a dotted-decimal OID string, rejecting empty arcs,
// non-numeric arcs, and fewer than two arcs.
func ParseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q: must have at least two arcs", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("invalid OID %q: empty arc", s)
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("invalid OID %q: non-numeric arc %q", s, p)
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid OID %q: %w", s, err)
		}
		oid[i] = n
	}
	return oid, nil
}

// FormatOID formats an OID as a dotted-decimal string.
func FormatOID(oid asn1.ObjectIdentifier) string {
	return oid.String()
}

// DNAttributeOID looks up name in the dn_attributes table only.
func DNAttributeOID(name string) (asn1.ObjectIdentifier, error) {
	oid, ok := dnAttributes[name]
	if !ok {
		return nil, fmt.Errorf("unknown DN attribute %q", name)
	}
	return ParseOID(oid)
}

// ExtKeyUsageOID accepts either a friendly name from the
// extended_key_usages table or a dotted OID string, so
// extended_key_usage.usages can mix them per spec section 5.3.
func ExtKeyUsageOID(nameOrOID string) (asn1.ObjectIdentifier, error) {
	if oid, ok := extendedKeyUsages[nameOrOID]; ok {
		return ParseOID(oid)
	}
	if oid, err := ParseOID(nameOrOID); err == nil {
		return oid, nil
	}
	return nil, fmt.Errorf("unknown extended key usage %q", nameOrOID)
}

// KeyUsageBit returns the RFC 5280 4.2.1.3 bit position for name.
func KeyUsageBit(name string) (int, error) {
	bit, ok := keyUsages[name]
	if !ok {
		return 0, fmt.Errorf("unknown key usage %q", name)
	}
	n, err := strconv.Atoi(bit)
	if err != nil {
		return 0, fmt.Errorf("unknown key usage %q", name)
	}
	return n, nil
}

// KeyUsageBitName reverse-looks-up the key usage name for an RFC 5280
// 4.2.1.3 bit position.
func KeyUsageBitName(bit int) (string, error) {
	want := strconv.Itoa(bit)
	for name, b := range keyUsages {
		if b == want {
			return name, nil
		}
	}
	return "", fmt.Errorf("unknown key usage bit %d", bit)
}

// SignatureAlgorithmByName looks up the x509.SignatureAlgorithm for name.
func SignatureAlgorithmByName(name string) (x509.SignatureAlgorithm, error) {
	a, ok := signatureAlgorithmValues[name]
	if !ok {
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown signature algorithm %q", name)
	}
	return a, nil
}

// SignatureAlgorithmName reverse-looks-up the table's name for a, via
// a.String(), so the two directions cannot drift.
func SignatureAlgorithmName(a x509.SignatureAlgorithm) (string, error) {
	name := a.String()
	if _, ok := signatureAlgorithmValues[name]; !ok {
		return "", fmt.Errorf("unsupported signature algorithm %v", a)
	}
	return name, nil
}

// SignatureAlgorithmNames returns the accepted signature algorithm names,
// sorted, for schema validation.
func SignatureAlgorithmNames() []string {
	return slices.Sorted(maps.Keys(signatureAlgorithmValues))
}
