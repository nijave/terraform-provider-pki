// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// PEM block types this file writes and requires on parse. They are constants
// because a mistyped block type is a silent interoperability failure: openssl
// will not read a certificate in a block labelled anything but CERTIFICATE.
const (
	pemTypeCertificate = "CERTIFICATE"
	pemTypeCertRequest = "CERTIFICATE REQUEST"
)

// CertRequestTemplate describes a certificate signing request.
//
// A zero SignatureAlgorithm means "pick the conventional one for the key", via
// DefaultSignatureAlgorithm.
type CertRequestTemplate struct {
	Subject            Subject
	SAN                SAN
	ExtraExtensions    []ExtraExtension
	SignatureAlgorithm x509.SignatureAlgorithm
}

// CertTemplate describes a certificate to issue. Every field the provider
// exposes is represented here and reaches the certificate through RawSubject or
// Extensions -- never through one of x509.Certificate's convenience fields. See
// CreateCertificate for why that distinction matters.
//
// The four extension pointers are pointers rather than values so that "not
// configured" is distinguishable from "configured empty": a nil KeyUsage means
// no keyUsage extension, while a non-nil one holding no usages is a
// configuration error KeyUsage.Extension reports.
type CertTemplate struct {
	Subject            Subject
	SAN                SAN
	Serial             *big.Int
	NotBefore          time.Time
	NotAfter           time.Time
	BasicConstraints   *BasicConstraints
	KeyUsage           *KeyUsage
	ExtKeyUsage        *ExtKeyUsage
	NameConstraints    *NameConstraints
	ExtraExtensions    []ExtraExtension
	SignatureAlgorithm x509.SignatureAlgorithm
}

// Extensions returns the certificate's extension list for the subject public
// key pub, in this fixed order:
//
//	basicConstraints, keyUsage, extendedKeyUsage, subjectAltName,
//	nameConstraints, subjectKeyIdentifier, then ExtraExtensions in
//	declaration order.
//
// The order is a compatibility promise, not an implementation detail. It is
// exported rather than kept private to CreateCertificate because Task 14
// compares a desired template against an existing certificate by building this
// list and diffing it, and a second implementation of the same logic there
// would be free to disagree with what issuance actually writes.
//
// Each nil pointer contributes nothing, an empty SAN contributes nothing, and
// subjectKeyIdentifier always contributes.
//
// Note that authorityKeyIdentifier is deliberately absent: it identifies the
// issuer, not the subject, so it is not derivable from a template alone.
// crypto/x509 writes it from the parent certificate during issuance.
func (t CertTemplate) Extensions(pub crypto.PublicKey) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	if t.BasicConstraints != nil {
		ext, err := t.BasicConstraints.Extension()
		if err != nil {
			return nil, fmt.Errorf("basic constraints: %w", err)
		}
		exts = append(exts, ext)
	}
	if t.KeyUsage != nil {
		ext, err := t.KeyUsage.Extension()
		if err != nil {
			return nil, fmt.Errorf("key usage: %w", err)
		}
		exts = append(exts, ext)
	}
	if t.ExtKeyUsage != nil {
		ext, err := t.ExtKeyUsage.Extension()
		if err != nil {
			return nil, fmt.Errorf("extended key usage: %w", err)
		}
		exts = append(exts, ext)
	}
	if !t.SAN.IsEmpty() {
		// RFC 5280 4.2.1.6 forces criticality when the certificate has no DN,
		// which SAN.Extension applies from this flag.
		ext, err := t.SAN.Extension(t.Subject.IsEmpty())
		if err != nil {
			return nil, fmt.Errorf("subject alternative name: %w", err)
		}
		exts = append(exts, ext)
	}
	if t.NameConstraints != nil {
		ext, err := t.NameConstraints.Extension()
		if err != nil {
			return nil, fmt.Errorf("name constraints: %w", err)
		}
		exts = append(exts, ext)
	}

	ski, err := SubjectKeyIDExtension(pub)
	if err != nil {
		return nil, fmt.Errorf("subject key identifier: %w", err)
	}
	exts = append(exts, ski)

	for i, extra := range t.ExtraExtensions {
		ext, err := extra.Extension()
		if err != nil {
			return nil, fmt.Errorf("extra extension %d: %w", i, err)
		}
		exts = append(exts, ext)
	}

	if err := rejectDuplicateExtensionOIDs(exts); err != nil {
		return nil, err
	}
	return exts, nil
}

// rejectDuplicateExtensionOIDs reports an error when any OID appears twice in
// exts.
//
// RFC 5280 4.2 forbids a certificate from carrying two extensions with the same
// OID, and an extra_extension block colliding with a managed extension is a
// configuration mistake rather than an intentional override: the caller cannot
// tell which copy a given parser will honour. Checking here rather than in
// CreateCertificate means both the issuance path and Task 14's comparison path
// see the same rejection, so a template that cannot be issued also cannot be
// reported as matching.
func rejectDuplicateExtensionOIDs(exts []pkix.Extension) error {
	seen := make(map[string]bool, len(exts))
	for _, ext := range exts {
		dotted := FormatOID(ext.Id)
		if seen[dotted] {
			return fmt.Errorf("extension %s is present more than once; an extra_extension may not duplicate a managed extension or another extra_extension", dotted)
		}
		seen[dotted] = true
	}
	return nil
}

// validate checks the fields crypto/x509 either accepts silently or reports
// badly.
//
// Every check here earns its place against a specific weakness in
// x509.CreateCertificate: a nil SerialNumber makes it invent a random 20-byte
// serial rather than fail, which would produce a certificate whose serial the
// caller never chose and cannot predict; a zero serial passes its only serial
// check, which rejects just the negative case, even though RFC 5280 4.1.2.2
// requires a positive integer; and zero timestamps encode as year-1 validity
// dates instead of erroring.
func (t CertTemplate) validate() error {
	if t.Serial == nil {
		return fmt.Errorf("serial number is required")
	}
	if t.Serial.Sign() <= 0 {
		return fmt.Errorf("serial number %s must be positive (RFC 5280 4.1.2.2)", t.Serial)
	}
	if t.NotBefore.IsZero() {
		return fmt.Errorf("not_before is required")
	}
	if t.NotAfter.IsZero() {
		return fmt.Errorf("not_after is required")
	}
	if !t.NotAfter.After(t.NotBefore) {
		return fmt.Errorf("not_after %s is not after not_before %s",
			t.NotAfter.Format(time.RFC3339), t.NotBefore.Format(time.RFC3339))
	}
	if t.Subject.IsEmpty() && t.SAN.IsEmpty() {
		// RFC 5280 4.1.2.6: a certificate with an empty subject must carry a
		// subjectAltName, or it identifies nothing at all.
		return fmt.Errorf("a certificate must have a subject, a subject alternative name, or both")
	}
	return nil
}

// CreateCertificate issues a certificate for pub, signed by signerKey. A nil
// parent self-signs; otherwise parent is the issuing certificate.
//
// The returned bytes are a PEM CERTIFICATE block.
//
// The extension order in the issued certificate is NOT the order Extensions
// returns. crypto/x509 appends ExtraExtensions after the extensions it builds
// itself, and authorityKeyIdentifier is the one it still builds here, so a
// CA-signed certificate carries:
//
//	authorityKeyIdentifier, then Extensions()' list in its documented order.
//
// A self-signed certificate has no authorityKeyIdentifier at all -- crypto/x509
// omits it when issuer and subject DNs are equal -- so its order is exactly
// Extensions()'. Any comparison against an issued certificate has to account for
// both shapes rather than assuming Extensions()' order appears verbatim.
func CreateCertificate(t CertTemplate, pub crypto.PublicKey, parent *x509.Certificate, signerKey crypto.Signer) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("subject public key is required")
	}
	if signerKey == nil {
		return nil, fmt.Errorf("signing key is required")
	}
	if err := t.validate(); err != nil {
		return nil, err
	}

	rawSubject, err := t.Subject.EncodeDER()
	if err != nil {
		return nil, fmt.Errorf("encoding subject: %w", err)
	}
	exts, err := t.Extensions(pub)
	if err != nil {
		return nil, err
	}
	sigAlg, err := resolveSignatureAlgorithm(t.SignatureAlgorithm, signerKey)
	if err != nil {
		return nil, err
	}

	// The raw key identifier is unwrapped from the extension Extensions already
	// built rather than recomputed, so the subjectKeyIdentifier this certificate
	// carries and the SubjectKeyId field crypto/x509 reads can never disagree.
	skiExt, ok := FindExtension(exts, oidSubjectKeyID)
	if !ok {
		return nil, fmt.Errorf("internal error: extension list has no subjectKeyIdentifier")
	}
	subjectKeyID, err := unwrapKeyIdentifier(skiExt.Value)
	if err != nil {
		return nil, err
	}

	// Assemble the x509.Certificate Go needs. Note what is NOT set: Subject,
	// DNSNames, EmailAddresses, IPAddresses, URIs, KeyUsage, ExtKeyUsage,
	// BasicConstraintsValid, IsCA, MaxPathLen, and the name constraint fields are
	// all left zero. Every one of those has an equivalent in t.Extensions().
	//
	// Setting one would not duplicate the extension: crypto/x509 guards every
	// convenience field with !oidInExtensions(oid, template.ExtraExtensions)
	// (x509.go ~1187-1281), so whenever Extensions() already supplies that OID Go
	// silently ignores the field. The reason to leave them zero is that the guard
	// only holds while Extensions() supplies the OID -- a field set
	// unconditionally emits its extension for a template that asked for *none*,
	// which adds an extension the configuration never requested and makes an
	// adopted certificate drift forever against its reissued form.
	//
	// Leaving them zero makes t.Extensions() the single thing deciding what a
	// certificate carries, which is exactly what lets Task 14 compare a desired
	// template against an issued certificate by calling that same function.
	// TestCreateCertificateEmitsNothingBeyondTheTemplate enforces it.
	//
	// SubjectKeyId is the one identifier-bearing field that IS set, always, from
	// the same computation the extension uses. It is set for two reasons, only
	// the first of which is active in this design:
	//
	//   - crypto/x509 copies a *parent's* SubjectKeyId into each child's
	//     authorityKeyIdentifier. Parents reach this function as parsed
	//     certificates, where ParseCertificate fills the field from the
	//     extension, so that path is covered -- except when self-signing, where
	//     the parent is synthesized below and the field is the only place the
	//     identifier can come from. Task 10's CRL signing reads the same field.
	//
	//   - Since Go 1.25, x509.CreateCertificate fills an *empty* SubjectKeyId
	//     using RFC 7093 method 1 (SHA-256 truncated to 160 bits) rather than
	//     RFC 5280 method 1 (SHA-1), reversible only via
	//     GODEBUG=x509sha256skid=0. Both are 20 bytes, so the substitution is
	//     invisible to any length check, and every adopted certificate -- whose
	//     SKI came from openssl's `subjectKeyIdentifier = hash`, i.e. RFC 5280
	//     -- would then differ from its reissued form in the SKI alone and drift
	//     forever. That synthesis is gated on template.IsCA, which this code
	//     never sets, so it cannot fire here today; setting the field explicitly
	//     is what keeps that true regardless of how the gate changes.
	tmpl := &x509.Certificate{
		SerialNumber:       t.Serial,
		RawSubject:         rawSubject,
		NotBefore:          t.NotBefore,
		NotAfter:           t.NotAfter,
		SignatureAlgorithm: sigAlg,
		ExtraExtensions:    exts,
		SubjectKeyId:       subjectKeyID,
	}

	issuer := parent
	if issuer == nil {
		// Self-signing. crypto/x509 needs a parent to read the issuer DN and the
		// authority key identifier from, and for a self-signed certificate that
		// parent is this certificate. A fresh value is built rather than passing
		// tmpl itself so the two fields Go actually reads are visible here, and
		// so no other field of tmpl can influence the issuer DN through Go's
		// RawSubject-versus-Subject fallback.
		issuer = &x509.Certificate{
			RawSubject:   rawSubject,
			SubjectKeyId: subjectKeyID,
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, signerKey)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}
	return EncodeCertificatePEM(der), nil
}

// CreateCertRequest builds a PEM certificate signing request for key.
//
// The SAN goes into ExtraExtensions rather than the x509.CertificateRequest
// DNSNames/EmailAddresses/IPAddresses/URIs fields. Those fields would not
// duplicate the extension -- crypto/x509 guards them with the same
// !oidInExtensions(oid, template.ExtraExtensions) test it uses for certificates
// (x509.go ~1491) -- but they would encode the SAN with Go's own GeneralName
// ordering and criticality instead of this package's, and it is this package's
// ordering that an adopted request has to match.
func CreateCertRequest(key crypto.Signer, t CertRequestTemplate) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("private key is required")
	}

	rawSubject, err := t.Subject.EncodeDER()
	if err != nil {
		return nil, fmt.Errorf("encoding subject: %w", err)
	}

	var exts []pkix.Extension
	if !t.SAN.IsEmpty() {
		ext, err := t.SAN.Extension(t.Subject.IsEmpty())
		if err != nil {
			return nil, fmt.Errorf("subject alternative name: %w", err)
		}
		exts = append(exts, ext)
	}
	for i, extra := range t.ExtraExtensions {
		ext, err := extra.Extension()
		if err != nil {
			return nil, fmt.Errorf("extra extension %d: %w", i, err)
		}
		exts = append(exts, ext)
	}
	if err := rejectDuplicateExtensionOIDs(exts); err != nil {
		return nil, err
	}

	sigAlg, err := resolveSignatureAlgorithm(t.SignatureAlgorithm, key)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject:         rawSubject,
		ExtraExtensions:    exts,
		SignatureAlgorithm: sigAlg,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertRequest, Bytes: der}), nil
}

// ParseCertRequestPEM decodes and parses a PEM certificate signing request, and
// verifies its self-signature.
//
// Verifying is the right default for this package because every caller is about
// to issue against the request: a CSR whose signature does not check out does
// not prove the requester holds the private key for the public key it carries,
// which is the only thing a CSR is for. A caller that wants to inspect an
// unverifiable request must reach for crypto/x509 directly and say so.
func ParseCertRequestPEM(b []byte) (*x509.CertificateRequest, error) {
	block, err := decodeSinglePEMBlock(b, pemTypeCertRequest)
	if err != nil {
		return nil, fmt.Errorf("certificate request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request signature does not verify: %w", err)
	}
	return csr, nil
}

// ParseCertificatePEM decodes and parses a single PEM certificate.
//
// More than one PEM block is an error rather than a silent "first one wins": a
// chain handed to a single-certificate attribute is a configuration mistake, and
// ParseCertificateChainPEM is the function that wants it.
func ParseCertificatePEM(b []byte) (*x509.Certificate, error) {
	block, err := decodeSinglePEMBlock(b, pemTypeCertificate)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

// ParseCertificateChainPEM parses a concatenation of PEM certificates,
// preserving order: the leaf-adjacent certificate comes first, as it does in
// every chain file this provider reads or writes.
//
// A block whose type is not CERTIFICATE is an error, never a skip. That is the
// check that stops a private key concatenated into a chain -- by a careless
// `cat`, or by a template that interpolated the wrong attribute -- from being
// carried along into a certificate_chain_pem attribute, where it would be
// written to state and to disk in the clear.
func ParseCertificateChainPEM(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			return nil, fmt.Errorf("certificate chain contains a %q PEM block at position %d; only %s blocks are allowed",
				block.Type, len(certs), pemTypeCertificate)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d in chain: %w", len(certs), err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no %s PEM blocks found in certificate chain", pemTypeCertificate)
	}
	return certs, nil
}

// EncodeCertificatePEM wraps certificate DER in a PEM CERTIFICATE block.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

// decodeSinglePEMBlock decodes exactly one PEM block of the given type,
// rejecting a wrong type and any further block.
func decodeSinglePEMBlock(b []byte, wantType string) (*pem.Block, error) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != wantType {
		return nil, fmt.Errorf("PEM block type is %q, want %q", block.Type, wantType)
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return nil, fmt.Errorf("input carries more than one PEM block")
	}
	return block, nil
}

// unwrapKeyIdentifier extracts the raw identifier from a subjectKeyIdentifier
// extension value, which is an OCTET STRING wrapping the bytes.
func unwrapKeyIdentifier(value []byte) ([]byte, error) {
	var id []byte
	rest, err := asn1.Unmarshal(value, &id)
	if err != nil {
		return nil, fmt.Errorf("parsing subjectKeyIdentifier: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("parsing subjectKeyIdentifier: %d trailing bytes", len(rest))
	}
	return id, nil
}

// DefaultSignatureAlgorithm returns the conventional signature algorithm for k:
// SHA-256 with RSA, Ed25519's single pure algorithm, and for ECDSA the hash
// matched to the curve's field size (P-224 and P-256 to SHA-256, P-384 to
// SHA-384, P-521 to SHA-512).
//
// The ECDSA pairing is RFC 5480 section 4's recommendation and is what openssl
// picks unprompted, which matters here for the usual reason: a certificate
// adopted from the existing issuer carries openssl's choice, and defaulting
// differently would show as drift on a certificate nobody changed.
func DefaultSignatureAlgorithm(k crypto.Signer) (x509.SignatureAlgorithm, error) {
	if k == nil {
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("signing key is nil")
	}
	switch key := k.(type) {
	case *rsa.PrivateKey:
		return x509.SHA256WithRSA, nil
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P224(), elliptic.P256():
			return x509.ECDSAWithSHA256, nil
		case elliptic.P384():
			return x509.ECDSAWithSHA384, nil
		case elliptic.P521():
			return x509.ECDSAWithSHA512, nil
		default:
			return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported ecdsa curve %q", key.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		return x509.PureEd25519, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unsupported signing key type %T", k)
	}
}

// signatureAlgorithmKeyTypes maps each signature algorithm this package will
// sign with to the public key family it requires. It serves two purposes: a
// mismatch between a requested signature_algorithm and the signing key is
// reported against the two names the operator wrote, rather than as
// crypto/x509's "requested SignatureAlgorithm does not match private key type",
// which names neither; and the map's domain is the allow-list of algorithms this
// package offers at all.
//
// The domain is derived from signatureAlgorithmValues rather than written out
// again, so the two cannot drift. That derivation is what keeps MD5, SHA-1 and
// DSA out: oids.go omits them deliberately, because Go's own CheckSignature
// refuses a SHA-1 or MD5 signature with InsecureAlgorithmError -- accepting one
// here would mint a certificate this library cannot then verify, with no error
// at issuance. DSA is doubly unreachable, since publicKeyAlgorithmOf can never
// return x509.DSA.
//
// An algorithm added to oids.go but not classified in the switch below is absent
// from the map and therefore rejected, which fails closed.
// TestSignatureAlgorithmKeyTypesCoversEveryOfferedAlgorithm catches the omission.
var signatureAlgorithmKeyTypes = func() map[x509.SignatureAlgorithm]x509.PublicKeyAlgorithm {
	m := make(map[x509.SignatureAlgorithm]x509.PublicKeyAlgorithm, len(signatureAlgorithmValues))
	for _, a := range signatureAlgorithmValues {
		switch a {
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
			x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			m[a] = x509.RSA
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			m[a] = x509.ECDSA
		case x509.PureEd25519:
			m[a] = x509.Ed25519
		}
	}
	return m
}()

// resolveSignatureAlgorithm returns the algorithm to sign with: the requested
// one when it is compatible with signerKey, or the key's default when none was
// requested.
func resolveSignatureAlgorithm(requested x509.SignatureAlgorithm, signerKey crypto.Signer) (x509.SignatureAlgorithm, error) {
	if requested == x509.UnknownSignatureAlgorithm {
		return DefaultSignatureAlgorithm(signerKey)
	}
	needs, ok := signatureAlgorithmKeyTypes[requested]
	if !ok {
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("signature algorithm %v is not offered; supported algorithms are %v", requested, SignatureAlgorithmNames())
	}
	have, err := publicKeyAlgorithmOf(signerKey)
	if err != nil {
		return x509.UnknownSignatureAlgorithm, err
	}
	if needs != have {
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("signature algorithm %v requires a %v signing key, but the signing key is %v", requested, needs, have)
	}
	return requested, nil
}

// publicKeyAlgorithmOf reports the key family of k.
func publicKeyAlgorithmOf(k crypto.Signer) (x509.PublicKeyAlgorithm, error) {
	switch k.(type) {
	case *rsa.PrivateKey:
		return x509.RSA, nil
	case *ecdsa.PrivateKey:
		return x509.ECDSA, nil
	case ed25519.PrivateKey:
		return x509.Ed25519, nil
	default:
		return x509.UnknownPublicKeyAlgorithm, fmt.Errorf("unsupported signing key type %T", k)
	}
}
