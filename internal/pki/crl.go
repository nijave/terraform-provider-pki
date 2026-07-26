// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// pemTypeCRL is the PEM block type CreateCRL writes and ParseCRLPEM requires.
// Downstream consumers (Envoy, HTTPProxy) key on this exact string, so a
// mistyped block type would be a silent interoperability failure.
const pemTypeCRL = "X509 CRL"

// reasonCodes maps the RFC 5280 5.3.1 CRLReason names to their enumeration
// values. Value 7 is unused in the RFC and is deliberately absent, so a config
// cannot request it.
var reasonCodes = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"cACompromise":         2,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
	"certificateHold":      6,
	"removeFromCRL":        8,
	"privilegeWithdrawn":   9,
	"aACompromise":         10,
}

// ReasonCode looks up the RFC 5280 5.3.1 enumeration value for a revocation
// reason name. Matching is case-sensitive: the schema's values are the RFC's
// exact spellings, and silently accepting "keycompromise" would let a config
// drift from the name it will be rendered back as.
func ReasonCode(name string) (int, error) {
	code, ok := reasonCodes[name]
	if !ok {
		return 0, fmt.Errorf("unknown crl revocation reason %q; valid reasons are %v", name, ReasonNames())
	}
	return code, nil
}

// ReasonName is the inverse of ReasonCode. Code 7 is unused in RFC 5280 and
// always returns an error, even though it is a plausible-looking int.
func ReasonName(code int) (string, error) {
	for name, c := range reasonCodes {
		if c == code {
			return name, nil
		}
	}
	return "", fmt.Errorf("unknown crl revocation reason code %d", code)
}

// ReasonNames returns every valid revocation reason name, sorted by numeric
// code rather than alphabetically, so generated documentation reads in the
// order RFC 5280 5.3.1 lists them.
func ReasonNames() []string {
	names := make([]string, 0, len(reasonCodes))
	for name := range reasonCodes {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return reasonCodes[names[i]] < reasonCodes[names[j]] })
	return names
}

// RevokedCert is one entry in a CRL.
//
// Reason is a name from ReasonNames, or the empty string. Both an empty Reason
// and Reason: "unspecified" produce ReasonCode 0, which makes Go omit the
// reasonCode extension entirely -- the RFC-correct encoding for "no reason
// given" (RFC 5280 5.3.1).
type RevokedCert struct {
	Serial    *big.Int
	Reason    string
	RevokedAt time.Time
}

// CRLTemplate describes a certificate revocation list to issue.
//
// A zero SignatureAlgorithm means "pick the conventional one for the signing
// key", via DefaultSignatureAlgorithm.
type CRLTemplate struct {
	Number             *big.Int
	ThisUpdate         time.Time
	NextUpdate         time.Time
	Revoked            []RevokedCert
	SignatureAlgorithm x509.SignatureAlgorithm
}

// validate checks the fields x509.CreateRevocationList either accepts
// silently or reports badly, plus the duplicate-serial check that is this
// package's own policy rather than an RFC requirement.
func (t CRLTemplate) validate() error {
	if t.Number == nil {
		return errors.New("crl number is required")
	}
	if t.Number.Sign() <= 0 {
		return fmt.Errorf("crl number %s must be positive", t.Number)
	}
	// RFC 5280 5.2.3: CRLNumber is an INTEGER that must fit in 20 octets.
	//
	// This mirrors x509.CreateRevocationList's own boundary check exactly
	// (len(numBytes) > 20, or == 20 with the sign bit set) rather than the
	// simpler-looking t.Number.BitLen() > 160: a positive Number with
	// BitLen() == 160 always has its top byte's high bit set, which needs an
	// extra sign-padding byte in the DER INTEGER encoding and so still exceeds
	// 20 octets once encoded. Checking BitLen() > 160 alone would let such a
	// value through this validation, only to fail later with Go's own opaque
	// "x509: CRL number exceeds 20 octets" -- exactly the outcome this check
	// exists to avoid.
	if numBytes := t.Number.Bytes(); len(numBytes) > 20 || (len(numBytes) == 20 && numBytes[0]&0x80 != 0) {
		return fmt.Errorf("crl number %s exceeds the 20-octet limit RFC 5280 places on CRLNumber", t.Number)
	}
	if t.ThisUpdate.IsZero() {
		return errors.New("this_update is required")
	}
	if t.NextUpdate.IsZero() {
		return errors.New("next_update is required")
	}
	if !t.NextUpdate.After(t.ThisUpdate) {
		return fmt.Errorf("next_update %s is not after this_update %s",
			t.NextUpdate.Format(time.RFC3339), t.ThisUpdate.Format(time.RFC3339))
	}

	seen := make(map[string]bool, len(t.Revoked))
	for i, rc := range t.Revoked {
		if rc.Serial == nil {
			return fmt.Errorf("revoked entry %d: serial number is required", i)
		}
		if rc.Serial.Sign() <= 0 {
			return fmt.Errorf("revoked entry %d: serial number %s must be positive", i, rc.Serial)
		}
		if rc.RevokedAt.IsZero() {
			return fmt.Errorf("revoked entry %d: revoked_at is required", i)
		}
		if rc.Reason != "" {
			if _, err := ReasonCode(rc.Reason); err != nil {
				return fmt.Errorf("revoked entry %d: %w", i, err)
			}
		}
		key := FormatSerial(rc.Serial)
		if seen[key] {
			return fmt.Errorf("revoked entry %d: serial %s is already present in this CRL", i, FormatSerial(rc.Serial))
		}
		seen[key] = true
	}
	return nil
}

// CheckCRLSigner reports whether a certificate can sign a CRL.
//
// Go's x509.CreateRevocationList enforces two preconditions that cfssl did
// not, and both produce opaque errors from deep inside the standard library.
// The homelab CA is delivered from Bitwarden and cannot be inspected before an
// apply, so a caller needs to be told exactly which property is missing and
// that the fix is to reissue the CA, not to retry.
func CheckCRLSigner(caCert *x509.Certificate) error {
	if caCert == nil {
		return errors.New("no CA certificate supplied")
	}
	if caCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("CA certificate %q cannot sign CRLs: its keyUsage extension does not include crlSign; reissue the CA with crlSign in key_usage.usages", caCert.Subject.String())
	}
	if len(caCert.SubjectKeyId) == 0 {
		return fmt.Errorf("CA certificate %q cannot sign CRLs: it has no subjectKeyIdentifier extension, which RFC 5280 requires for the CRL's authorityKeyIdentifier; reissue the CA with this provider, which always emits one", caCert.Subject.String())
	}
	return nil
}

// CreateCRL issues a certificate revocation list signed by caKey, the private
// key matching caCert's public key.
//
// The returned bytes are a PEM X509 CRL block.
func CreateCRL(t CRLTemplate, caCert *x509.Certificate, caKey crypto.Signer) ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	if err := CheckCRLSigner(caCert); err != nil {
		return nil, err
	}
	if caKey == nil {
		return nil, errors.New("signing key is required")
	}

	// resolveSignatureAlgorithm, not just DefaultSignatureAlgorithm: the
	// defaulting is only half of what the certificate path does. The other half
	// is the offered-algorithm allow-list, which is what keeps a SHA-1 or MD5
	// signature out of a CRL this library could not then verify, and the family
	// check, which reports a mismatch against the algorithm and key the operator
	// named rather than leaving crypto/x509's "requested SignatureAlgorithm does
	// not match private key type" to surface.
	sigAlg, err := resolveSignatureAlgorithm(t.SignatureAlgorithm, caKey)
	if err != nil {
		return nil, err
	}

	// Reason goes in ReasonCode, never in ExtraExtensions: Go rejects a
	// reasonCode OID appearing there (x509.CreateRevocationList returns "template
	// contains entry with ReasonCode ExtraExtension; use ReasonCode field
	// instead"). A zero ReasonCode -- the empty Reason or "unspecified" -- makes
	// Go omit the extension entirely, which is the RFC-correct encoding and is
	// deliberately not special-cased here.
	entries := make([]x509.RevocationListEntry, len(t.Revoked))
	for i, rc := range t.Revoked {
		reasonCode := 0
		if rc.Reason != "" {
			code, err := ReasonCode(rc.Reason)
			if err != nil {
				return nil, fmt.Errorf("revoked entry %d: %w", i, err)
			}
			reasonCode = code
		}
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   rc.Serial,
			RevocationTime: rc.RevokedAt,
			ReasonCode:     reasonCode,
		}
	}

	tmpl := &x509.RevocationList{
		Number:                    t.Number,
		ThisUpdate:                t.ThisUpdate,
		NextUpdate:                t.NextUpdate,
		RevokedCertificateEntries: entries,
		SignatureAlgorithm:        sigAlg,
	}

	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating crl: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCRL, Bytes: der}), nil
}

// ParseCRLPEM decodes and parses a single PEM X509 CRL block.
func ParseCRLPEM(b []byte) (*x509.RevocationList, error) {
	block, err := decodeSinglePEMBlock(b, pemTypeCRL)
	if err != nil {
		return nil, fmt.Errorf("crl: %w", err)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing crl: %w", err)
	}
	return crl, nil
}
