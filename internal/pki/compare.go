// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"
)

// maxDriftValueHexChars caps how much of an extension value a Drift renders.
// Extension values are arbitrary DER and a nameConstraints or SAN value runs to
// hundreds of bytes; a drift report is read in a Terraform plan, where a
// thousand hex characters obscures the one line that matters. The prefix is
// enough to see that two values differ, which is all a drift entry claims.
const maxDriftValueHexChars = 64

// Drift is one difference between a desired certificate and the one in state.
// Field is either an attribute name from the provider's schema ("subject",
// "serial_number") or, for extensions, the extension's dotted OID.
type Drift struct {
	Field string
	Want  string
	Got   string
}

// String renders a drift entry for a plan explanation, naming the field and
// both sides.
func (d Drift) String() string {
	return fmt.Sprintf("%s: want %q, got %q", d.Field, d.Want, d.Got)
}

// CompareInput is everything needed to decide whether a certificate must be
// reissued.
//
// Note what is absent. There is no field for the CA's private key, the
// certificate subject's private key, or the CSR, because none of those can be
// derived from an issued certificate. Spec section 9 excludes them by design:
// the homelab CA key arrives from a rotating Bitwarden Secret, and a comparison
// that noticed the rotation would replace every certificate under it -- which,
// for 20-year certificates installed on phones and tablets, means a manual
// re-enrollment per device. False positives are the expensive failure here, so
// unavailable inputs are omitted from the type rather than defaulted.
type CompareInput struct {
	Desired          CertTemplate
	DesiredPublicKey crypto.PublicKey
	Actual           *x509.Certificate

	// CA is the issuer to verify the signature against. Nil means the
	// certificate is expected to be self-signed.
	CA *x509.Certificate
}

// CompareCertificate reports every content difference between the desired
// template and the certificate in state. An empty result means no drift, and
// therefore no reissue.
//
// Entries come back in a fixed order -- subject, public key, serial, validity,
// extensions, issuer, signature -- so a plan explanation reads the same way
// twice. Nothing here iterates a map.
//
// A missing Actual or DesiredPublicKey is an error rather than drift, and so is
// a desired subject that cannot be encoded: see the checks below for why each
// distinction matters. The rule throughout is that an input this function
// cannot evaluate is reported as such, never as a difference, because a
// difference means a replacement and a replacement means re-enrolling a device.
func CompareCertificate(in CompareInput) ([]Drift, error) {
	if in.Actual == nil {
		// A caller with no certificate to compare has a bug, not a diff.
		return nil, fmt.Errorf("actual certificate is required")
	}
	if in.DesiredPublicKey == nil {
		// CertTemplate.Extensions needs the subject public key to compute the
		// subjectKeyIdentifier and fails without it, so the extension
		// comparison below could not run at all. Every real caller has one --
		// from the CSR in csr_pem mode, or from public_key_pem inline -- so
		// stating the precondition here costs nothing and turns an
		// unexplained Extensions() failure into a clear one.
		return nil, fmt.Errorf("desired public key is required")
	}
	if in.Desired.Serial == nil {
		// FormatSerial and Cmp both dereference, and a template with no serial
		// cannot be issued either (see CertTemplate.validate), so it must not
		// be reported as matching.
		return nil, fmt.Errorf("desired serial number is required")
	}
	if in.Actual.SerialNumber == nil {
		return nil, fmt.Errorf("actual certificate has no serial number")
	}

	drift := make([]Drift, 0, 4)

	// Subject. The DER is compared, not the struct, so any configuration that
	// encodes to the same DN plans clean: the named-field form and the ordered
	// form of one name are the same name.
	//
	// EncodeDER's error is returned rather than reported as drift. Subject.Equal
	// swallows it and returns false, which is right for a boolean but wrong
	// here: a subject that cannot be encoded would show as permanent drift with
	// no stated cause, and the operator would watch the same replacement
	// proposed on every plan with no way to see why. The realistic trigger is an
	// adopted certificate whose DN carries a value violating its own declared
	// string type -- a PrintableString holding a character outside that
	// repertoire, which ParseSubjectDER accepts and EncodeDER refuses.
	wantSubject, err := in.Desired.Subject.EncodeDER()
	if err != nil {
		return nil, fmt.Errorf("encoding the desired subject: %w", err)
	}
	if !bytes.Equal(wantSubject, in.Actual.RawSubject) {
		drift = append(drift, Drift{
			Field: "subject",
			Want:  in.Desired.Subject.String(),
			Got:   describeRawDN(in.Actual.RawSubject, in.Actual.Subject),
		})
	}

	// Public key. A rotated subject key means the certificate no longer matches
	// it and must be reissued -- in deliberate contrast to a rotated CA key,
	// which is not represented here at all. Fingerprints are reported, never
	// key material.
	if !PublicKeysEqual(in.DesiredPublicKey, in.Actual.PublicKey) {
		drift = append(drift, Drift{
			Field: "public_key",
			Want:  describePublicKey(in.DesiredPublicKey),
			Got:   describePublicKey(in.Actual.PublicKey),
		})
	}

	if in.Desired.Serial.Cmp(in.Actual.SerialNumber) != 0 {
		drift = append(drift, Drift{
			Field: "serial_number",
			Want:  FormatSerial(in.Desired.Serial),
			Got:   FormatSerial(in.Actual.SerialNumber),
		})
	}

	// Validity. Both sides are truncated to a second before comparing, because
	// DER encodes UTCTime and GeneralizedTime at second granularity here: a
	// template carrying the sub-second precision of time.Now would otherwise
	// differ from its own issued certificate forever. Time.Equal then compares
	// instants, so a template in local time matches a certificate parsed as UTC.
	if !in.Desired.NotBefore.Truncate(time.Second).Equal(in.Actual.NotBefore.Truncate(time.Second)) {
		drift = append(drift, Drift{
			Field: "not_before",
			Want:  in.Desired.NotBefore.Format(time.RFC3339),
			Got:   in.Actual.NotBefore.Format(time.RFC3339),
		})
	}
	if !in.Desired.NotAfter.Truncate(time.Second).Equal(in.Actual.NotAfter.Truncate(time.Second)) {
		drift = append(drift, Drift{
			Field: "not_after",
			Want:  in.Desired.NotAfter.Format(time.RFC3339),
			Got:   in.Actual.NotAfter.Format(time.RFC3339),
		})
	}

	desiredExts, err := in.Desired.Extensions(in.DesiredPublicKey)
	if err != nil {
		return nil, fmt.Errorf("building the desired extension list: %w", err)
	}
	drift = append(drift, compareExtensions(desiredExts, in.Actual.Extensions)...)

	drift = append(drift, compareIssuer(in)...)

	return drift, nil
}

// compareExtensions diffs two extension lists by OID, in both directions.
//
// Extensions are indexed by OID and never compared positionally.
// CertTemplate.Extensions returns its documented order, but the order in an
// issued certificate is not the same: x509.CreateCertificate prepends the
// authorityKeyIdentifier it synthesizes from the parent, so a template yielding
// [2.5.29.19, 2.5.29.15, 2.5.29.37, 2.5.29.17, 2.5.29.14] produces a
// certificate carrying [2.5.29.35, 2.5.29.19, ...]. A positional comparison
// would report drift on every extension of every certificate.
//
// The reverse sweep -- extensions the certificate carries and the template does
// not -- is what catches a removed extra_extension or a removed
// extendedKeyUsage. authorityKeyIdentifier is excluded from it for the same
// reason it appears in an issued certificate at all: it identifies the issuer,
// so no template ever contains it, and reporting it would make every CA-signed
// certificate drift.
func compareExtensions(desired, actual []pkix.Extension) []Drift {
	var drift []Drift

	// First occurrence wins, matching FindExtension. RFC 5280 4.2 forbids a
	// duplicate OID and rejectDuplicateExtensionOIDs enforces that on anything
	// this package issues, but an adopted certificate is not under that
	// guarantee.
	actualByOID := make(map[string]pkix.Extension, len(actual))
	for _, ext := range actual {
		dotted := FormatOID(ext.Id)
		if _, seen := actualByOID[dotted]; !seen {
			actualByOID[dotted] = ext
		}
	}

	desiredOIDs := make(map[string]bool, len(desired))
	for _, want := range desired {
		dotted := FormatOID(want.Id)
		desiredOIDs[dotted] = true

		got, ok := actualByOID[dotted]
		if !ok {
			drift = append(drift, Drift{
				Field: extensionField(want.Id),
				Want:  describeExtension(want),
				Got:   "absent",
			})
			continue
		}
		// Criticality is part of the extension, not decoration: a keyUsage that
		// stops being critical is a different certificate to a verifier that
		// enforces unknown critical extensions.
		if want.Critical != got.Critical || !bytes.Equal(want.Value, got.Value) {
			drift = append(drift, Drift{
				Field: extensionField(want.Id),
				Want:  describeExtension(want),
				Got:   describeExtension(got),
			})
		}
	}

	for _, got := range actual {
		if got.Id.Equal(oidAuthorityKeyID) {
			continue
		}
		if desiredOIDs[FormatOID(got.Id)] {
			continue
		}
		drift = append(drift, Drift{
			Field: extensionField(got.Id),
			Want:  "absent",
			Got:   describeExtension(got),
		})
	}

	return drift
}

// compareIssuer checks the certificate against the configured CA: its issuer DN
// and its signature. A nil CA means the certificate is expected to be
// self-signed, so the signature is checked against the certificate itself --
// which is a real check, not a formality: a CA-signed certificate compared with
// no CA fails it, as it should.
func compareIssuer(in CompareInput) []Drift {
	if in.CA == nil {
		if err := in.Actual.CheckSignatureFrom(in.Actual); err != nil {
			return []Drift{{
				Field: "signature",
				Want:  "a valid self-signature",
				Got:   err.Error(),
			}}
		}
		return nil
	}

	var drift []Drift
	// The DN is compared as DER rather than through CheckSignatureFrom, which
	// never looks at names: a second CA holding the same key under a different
	// DN would otherwise pass unnoticed.
	if !bytes.Equal(in.CA.RawSubject, in.Actual.RawIssuer) {
		drift = append(drift, Drift{
			Field: "issuer",
			Want:  describeRawDN(in.CA.RawSubject, in.CA.Subject),
			Got:   describeRawDN(in.Actual.RawIssuer, in.Actual.Issuer),
		})
	}
	// And the signature is checked as well as the DN, because two CAs can share
	// a DN and hold different keys, which the DN comparison cannot see.
	if err := in.Actual.CheckSignatureFrom(in.CA); err != nil {
		drift = append(drift, Drift{
			Field: "signature",
			Want:  "a signature verifiable with the configured CA certificate",
			Got:   err.Error(),
		})
	}
	return drift
}

// extensionField names an extension in a Drift. The dotted OID is used so the
// message is unambiguous even for an extension the provider has no friendly
// name for. subjectAltName is the one exception: it is reported as "san",
// because that is the schema block a user would edit in response.
func extensionField(oid asn1.ObjectIdentifier) string {
	if oid.Equal(oidSubjectAltName) {
		return "san"
	}
	return FormatOID(oid)
}

// describeExtension renders an extension's criticality and value for a Drift.
func describeExtension(ext pkix.Extension) string {
	if ext.Critical {
		return "critical " + hexPreview(ext.Value)
	}
	return hexPreview(ext.Value)
}

// hexPreview renders b as hex, truncated to maxDriftValueHexChars with an
// ellipsis.
func hexPreview(b []byte) string {
	s := hex.EncodeToString(b)
	if len(s) > maxDriftValueHexChars {
		return s[:maxDriftValueHexChars] + "..."
	}
	return s
}

// describeRawDN renders a DN for a Drift, preferring this package's Subject
// rendering so both sides of a subject or issuer entry read the same way.
//
// The fallback exists because a DN that a certificate carries need not be one
// ParseSubjectDER accepts -- an unrecognized string tag is an error there --
// and a drift report must still be able to describe it.
func describeRawDN(raw []byte, parsed pkix.Name) string {
	if s, err := ParseSubjectDER(raw); err == nil {
		return s.String()
	}
	return parsed.String()
}

// describePublicKey renders a public key's fingerprint for a Drift. Key
// material never appears in a Drift; a fingerprint is enough to see that two
// keys differ.
func describePublicKey(pub crypto.PublicKey) string {
	fp, err := PublicKeyFingerprintSHA256(pub)
	if err != nil {
		return "<unfingerprintable key>"
	}
	return fp
}

// CompareValidity reports whether a certificate is close enough to expiry to be
// renewed: whether now plus earlyRenewal has reached actual.NotAfter.
//
// The single Before test covers three cases at once -- inside the early-renewal
// window, exactly at its boundary, and already expired -- and matches
// hashicorp/tls's semantics, which existing configurations may depend on. A
// zero earlyRenewal reduces it to "has this certificate expired".
//
// This is deliberately separate from CompareCertificate: expiry is a function of
// the clock, not of configuration, so it is the one reason to reissue that has
// no corresponding Drift.
func CompareValidity(actual *x509.Certificate, earlyRenewal time.Duration, now time.Time) (readyForRenewal bool) {
	return !now.Add(earlyRenewal).Before(actual.NotAfter)
}
