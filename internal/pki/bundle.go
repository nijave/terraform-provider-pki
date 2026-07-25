// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/smallstep/pkcs7"
)

// Format names an output encoding for a certificate bundle.
type Format string

const (
	FormatPEM    Format = "pem"
	FormatDER    Format = "der"
	FormatPKCS7  Format = "pkcs7"
	FormatPKCS12 Format = "pkcs12"
	FormatJKS    Format = "jks"
)

// Formats returns every bundle format this package supports, in the order
// declared above. It exists for schema validation in Plan 2, so the provider's
// allowed-values list can be derived from this package rather than duplicated.
func Formats() []Format {
	return []Format{FormatPEM, FormatDER, FormatPKCS7, FormatPKCS12, FormatJKS}
}

// IsText reports whether f is a text encoding. It is true for pem only, and
// drives whether the provider's content attribute is set or left null;
// content_base64 is always set regardless.
func (f Format) IsText() bool {
	return f == FormatPEM
}

// PKCS12Encoding selects the PKCS#12 encryption/MAC scheme EncodeBundle uses
// for FormatPKCS12. It is declared here because BundleInput needs the type;
// its constants and behavior are implemented in Task 12.
type PKCS12Encoding string

// BundleInput describes what to encode. Which fields are set is the interface:
// omitting PrivateKey produces a certificate-only bundle, and omitting Chain
// produces one with no chain. There is no include_chain-style boolean, because
// a field's presence already carries that information.
//
// Not every format accepts every combination. der holds exactly one
// certificate, and pkcs7 as produced here is a degenerate certs-only
// structure; supplying a private key to either is an error rather than a
// silent omission, because silently dropping a key produces a bundle that
// looks complete and is not.
type BundleInput struct {
	Format         Format
	Certificate    *x509.Certificate
	PrivateKey     crypto.Signer
	Chain          []*x509.Certificate
	FriendlyName   string
	PKCS12Encoding PKCS12Encoding
	Password       string

	// Rand overrides the entropy source. Leave nil for crypto/rand; tests set
	// it to make PKCS#12 salt and IV generation reproducible.
	Rand io.Reader
}

// EncodeBundle encodes in.Certificate, in.PrivateKey, and in.Chain into the
// format named by in.Format.
//
// An input with nothing to encode is rejected: every field is individually
// optional, but a bundle encoding nothing is never meaningful, regardless of
// format.
func EncodeBundle(in BundleInput) ([]byte, error) {
	if in.Certificate == nil && in.PrivateKey == nil && len(in.Chain) == 0 {
		return nil, fmt.Errorf("bundle has nothing to encode: certificate, private key, and chain are all absent")
	}

	switch in.Format {
	case FormatPEM:
		return encodePEM(in)
	case FormatDER:
		return encodeDER(in)
	case FormatPKCS7:
		return encodePKCS7(in)
	case FormatPKCS12:
		return encodePKCS12(in)
	case FormatJKS:
		return encodeJKS(in)
	default:
		return nil, fmt.Errorf("unknown bundle format %q", in.Format)
	}
}

// encodePEM concatenates, in order: the certificate, each chain entry
// (leaf-adjacent first), then the private key. That order is a compatibility
// promise, not an implementation detail: a consumer that reads only the first
// PEM block must get the end-entity certificate.
func encodePEM(in BundleInput) ([]byte, error) {
	var buf bytes.Buffer
	if in.Certificate != nil {
		buf.Write(EncodeCertificatePEM(in.Certificate.Raw))
	}
	for _, c := range in.Chain {
		buf.Write(EncodeCertificatePEM(c.Raw))
	}
	if in.PrivateKey != nil {
		keyPEM, err := EncodePrivateKeyPEM(in.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("encoding private key: %w", err)
		}
		buf.Write(keyPEM)
	}
	return buf.Bytes(), nil
}

// encodeDER returns the raw DER of exactly one certificate. A private key or a
// chain is an error rather than a silent omission: DER has no way to carry
// either, and quietly dropping them would produce a bundle that looks
// complete and is missing half its contents.
func encodeDER(in BundleInput) ([]byte, error) {
	if in.Certificate == nil {
		return nil, fmt.Errorf("der bundle requires a certificate")
	}
	if in.PrivateKey != nil {
		return nil, fmt.Errorf("der bundle cannot carry a private key")
	}
	if len(in.Chain) != 0 {
		return nil, fmt.Errorf("der bundle cannot carry a chain")
	}
	return in.Certificate.Raw, nil
}

// encodePKCS7 builds a degenerate (certs-only) PKCS#7 structure holding the
// certificate, if any, followed by the chain, leaf-adjacent first. A private
// key is an error: this shape cannot carry one, and silently discarding it
// would be a data-loss bug. Certificate is not mandatory here the way it is
// for der: a chain with no designated leaf is still a meaningful degenerate
// PKCS#7 (e.g. exporting just a chain of trust), and the top-level
// nothing-to-encode check in EncodeBundle already rejects the case where
// Certificate and Chain are both absent.
//
// pkcs7.DegenerateCertificate takes the concatenated raw DER of the whole
// chain, not a single certificate and not a slice, as verified against
// smallstep/pkcs7 v0.2.2 by round-tripping two certificates through it.
func encodePKCS7(in BundleInput) ([]byte, error) {
	if in.PrivateKey != nil {
		return nil, fmt.Errorf("pkcs7 bundle cannot carry a private key")
	}

	var der bytes.Buffer
	if in.Certificate != nil {
		der.Write(in.Certificate.Raw)
	}
	for _, c := range in.Chain {
		der.Write(c.Raw)
	}
	out, err := pkcs7.DegenerateCertificate(der.Bytes())
	if err != nil {
		return nil, fmt.Errorf("building pkcs7 bundle: %w", err)
	}
	return out, nil
}

// encodePKCS12 is implemented in Task 12.
func encodePKCS12(in BundleInput) ([]byte, error) {
	return nil, fmt.Errorf("pkcs12 bundle encoding is not yet implemented")
}

// encodeJKS is implemented in Task 13.
func encodeJKS(in BundleInput) ([]byte, error) {
	return nil, fmt.Errorf("jks bundle encoding is not yet implemented")
}
