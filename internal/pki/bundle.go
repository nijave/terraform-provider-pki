// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"time"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/smallstep/pkcs7"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
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

// PKCS12Encoding selects the algorithm suite for a PKCS#12 bundle.
//
// Only three of go-pkcs12's encoders are exposed, and the omissions are
// deliberate. LegacyRC2 emits RC2-40, which OpenSSL 3 refuses to decrypt.
// Modern2026 uses PBMAC1, which needs OpenSSL 3.4+ or Java 26+ and which no
// mobile platform reads.
type PKCS12Encoding string

const (
	// PKCS12Modern is AES-256-CBC content encryption with PBKDF2 and an
	// HMAC-SHA256 MAC. It is the default because it is what a bare
	// `openssl pkcs12 -export` produces under OpenSSL 3, which is what the
	// homelab reconciler already emits, so migrating to this provider does not
	// change what lands on a device.
	//
	// Requires iOS/iPadOS 18+, macOS 15+, or Android 14+ (Android 12-13 depends
	// on the device's Play system update).
	PKCS12Modern PKCS12Encoding = "modern"

	// PKCS12Legacy is 3DES content encryption with a SHA-1 MAC. It is the only
	// combination that is universally importable on older devices. Encryption
	// and MAC are independent failure axes: Android 12 rejects a SHA-256 MAC
	// even when the content is 3DES, so switching only the cipher is not
	// enough.
	PKCS12Legacy PKCS12Encoding = "legacy"

	// PKCS12Passwordless has no encryption and no MAC. go-pkcs12 requires the
	// password to be empty with it, and it is really only useful for Java
	// truststores.
	PKCS12Passwordless PKCS12Encoding = "passwordless"
)

// PKCS12Encodings returns every PKCS#12 encoding this package supports, in the
// order declared above. It exists for schema validation in Plan 2, so the
// provider's allowed-values list can be derived from this package rather than
// duplicated.
func PKCS12Encodings() []PKCS12Encoding {
	return []PKCS12Encoding{PKCS12Modern, PKCS12Legacy, PKCS12Passwordless}
}

// pkcs12Encoders maps the exposed encodings to go-pkcs12's encoders. It is the
// only place an encoder is named, so an encoding absent from this table is
// unreachable no matter what a caller puts in BundleInput.PKCS12Encoding.
var pkcs12Encoders = map[PKCS12Encoding]*pkcs12.Encoder{
	PKCS12Modern:       pkcs12.Modern2023,
	PKCS12Legacy:       pkcs12.LegacyDES,
	PKCS12Passwordless: pkcs12.Passwordless,
}

// BundleInput describes what to encode. Which fields are set is the interface:
// omitting PrivateKey produces a certificate-only bundle, and omitting Chain
// produces one with no chain. There is no include_chain-style boolean, because
// a field's presence already carries that information.
//
// Not every format accepts every combination. der holds exactly one
// certificate, and pkcs7 as produced here is a degenerate certs-only
// structure; supplying a private key to either is an error rather than a
// silent omission, because silently dropping a key produces a bundle that
// looks complete and is not. Password is the same kind of rule and the sharpest
// of them: only pkcs12 and jks can encrypt, so a non-empty Password with pem,
// der, or pkcs7 is an error rather than a plaintext bundle the operator believes
// is encrypted.
//
// FriendlyName is the one field that IS silently ignored, by pem, der, and
// pkcs7, all three of which have nowhere to record an alias. It is metadata --
// the operator sees a missing name, not a missing protection -- so the
// asymmetry with Password is deliberate.
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
//
// Every error this file returns names the schema attribute the operator has to
// edit -- certificate_pem, private_key_pem, chain_pem, format, pkcs12_encoding,
// password_wo -- rather than only the internal field. A bundle error is read in
// a `tofu plan` diagnostic with no stack trace and no line number attached to
// it, so an error that says only "requires a certificate" leaves the operator
// guessing which of three certificate-shaped attributes it meant. None of them
// ever includes an attribute *value*: private_key_pem is the whole problem this
// package's error discipline exists for, and there is nothing an operator gains
// from seeing key bytes echoed into a log that a device-facing attacker does not
// gain more from. See TestEncodeBundleErrorsNameAttributesWithoutEchoingKeys.
func EncodeBundle(in BundleInput) ([]byte, error) {
	if in.Certificate == nil && in.PrivateKey == nil && len(in.Chain) == 0 {
		return nil, fmt.Errorf("bundle has nothing to encode: set at least one of certificate_pem, private_key_pem, or chain_pem")
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
		return nil, fmt.Errorf("unknown bundle format %q: set format to one of %v", in.Format, Formats())
	}
}

// formatsCarrying renders a "choose format ..." fragment for an error, listing
// the formats that can hold whatever the caller asked the current format to
// hold. It exists so the two data-loss messages below (a private key or a chain
// handed to a format with nowhere to put it) name the alternatives rather than
// only the refusal, and so that list stays in one place per capability.
func formatsCarrying(fs ...Format) string {
	quoted := make([]string, len(fs))
	for i, f := range fs {
		quoted[i] = fmt.Sprintf("%q", f)
	}
	return strings.Join(quoted, ", ")
}

// rejectPassword refuses a non-empty Password for a format that cannot encrypt
// anything. Only pkcs12 and jks can, and for them a password is required rather
// than merely allowed, so this is the whole of the rule for the other three.
//
// It is an error rather than a no-op because the failure mode is asymmetric: a
// dropped FriendlyName costs the operator an alias they will notice, while a
// dropped password means a key they believe is encrypted is sitting in state and
// in a Secret in the clear.
func rejectPassword(in BundleInput, f Format) error {
	if in.Password == "" {
		return nil
	}
	return fmt.Errorf("%s bundle cannot be encrypted: clear password_wo, or choose format %q or %q", f, FormatPKCS12, FormatJKS)
}

// encodePEM concatenates, in order: the certificate, each chain entry
// (leaf-adjacent first), then the private key. That order is a compatibility
// promise, not an implementation detail: a consumer that reads only the first
// PEM block must get the end-entity certificate.
//
// A password is an error rather than a silent omission, and it is the one
// silent omission in this file with a security consequence: this encoder writes
// an unencrypted PRIVATE KEY block, so accepting a password would hand the
// operator a plaintext key while they believed they had asked for encryption.
func encodePEM(in BundleInput) ([]byte, error) {
	if err := rejectPassword(in, FormatPEM); err != nil {
		return nil, err
	}

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
	if err := rejectPassword(in, FormatDER); err != nil {
		return nil, err
	}
	if in.Certificate == nil {
		return nil, fmt.Errorf("der bundle requires a certificate: set certificate_pem")
	}
	if in.PrivateKey != nil {
		return nil, fmt.Errorf("der bundle cannot carry a private key: clear private_key_pem, or choose format %s",
			formatsCarrying(FormatPEM, FormatPKCS12, FormatJKS))
	}
	if len(in.Chain) != 0 {
		return nil, fmt.Errorf("der bundle cannot carry a chain: clear chain_pem, or choose format %s",
			formatsCarrying(FormatPEM, FormatPKCS7, FormatPKCS12, FormatJKS))
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
	if err := rejectPassword(in, FormatPKCS7); err != nil {
		return nil, err
	}
	if in.PrivateKey != nil {
		return nil, fmt.Errorf("pkcs7 bundle cannot carry a private key: clear private_key_pem, or choose format %s",
			formatsCarrying(FormatPEM, FormatPKCS12, FormatJKS))
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

// encodePKCS12 builds a PKCS#12 file. With a private key it is a keystore; with
// no private key it is a Java truststore, which is a structurally different
// artifact and not merely a keystore with the key left out.
//
// The certificate is mandatory when a key is present, which is not true of
// pkcs7 above. The asymmetry is deliberate: a degenerate PKCS#7 is a flat bag of
// certificates with no designated end entity, so a chain-only bundle is
// meaningful there. A PKCS#12 keystore entry pairs the key with one specific
// certificate, so the certificate is not optional — and the key must actually
// match it, because pairing one device's key with another's certificate produces
// a bundle that installs cleanly and then fails every TLS handshake.
//
// An unrecognized encoding is an error rather than a fall-through to
// PKCS12Modern: a typo in pkcs12_encoding must fail at plan time, not quietly
// emit algorithms an older device cannot read.
func encodePKCS12(in BundleInput) ([]byte, error) {
	encoding := in.PKCS12Encoding
	if encoding == "" {
		encoding = PKCS12Modern
	}
	encoder, ok := pkcs12Encoders[encoding]
	if !ok {
		return nil, fmt.Errorf("unknown pkcs12 encoding %q: supported encodings are %v", in.PKCS12Encoding, PKCS12Encodings())
	}
	if in.Rand != nil {
		// WithRand has a value receiver and returns a new *Encoder, so this does
		// not mutate the package-level encoder in pkcs12Encoders.
		encoder = encoder.WithRand(in.Rand)
	}

	// go-pkcs12 rejects a non-empty password with Passwordless itself, saying
	// "password must be empty", which is accurate but does not name the
	// attribute to change. An empty password with the other two encodings is
	// worse than useless: it produces a file whose MAC is keyed on the empty
	// string, which some tools accept and others reject.
	if encoding == PKCS12Passwordless {
		if in.Password != "" {
			return nil, fmt.Errorf("pkcs12_encoding %q cannot carry a password: clear password_wo or choose another pkcs12_encoding", PKCS12Passwordless)
		}
		// Passwordless.Encode emits an unshrouded key bag. openssl reads it and
		// so does go-pkcs12's DecodeChain, but Java reports "0 entries" — and
		// Java truststores are the only thing this encoding is good for, so the
		// result is a bundle whose sole intended consumer sees it as empty.
		// Rejecting is the only honest option; a keyless truststore is fine.
		if in.PrivateKey != nil {
			return nil, fmt.Errorf("pkcs12_encoding %q cannot carry a private key: Java reads such a bundle as empty, so drop private_key_pem to build a truststore, choose another pkcs12_encoding, or use format = \"pem\" for an unencrypted private key", PKCS12Passwordless)
		}
	} else if in.Password == "" {
		return nil, fmt.Errorf("pkcs12_encoding %q requires a password: set password_wo, or use pkcs12_encoding %q for an unencrypted bundle", encoding, PKCS12Passwordless)
	}

	if in.PrivateKey == nil {
		return encodePKCS12TrustStore(encoder, in)
	}
	if in.Certificate == nil {
		return nil, fmt.Errorf("pkcs12 bundle with a private key requires a certificate: set certificate_pem, or clear private_key_pem to build a truststore -- a keystore entry pairs the key with one specific certificate")
	}
	if !PublicKeysEqual(PublicKeyOf(in.PrivateKey), in.Certificate.PublicKey) {
		return nil, fmt.Errorf("pkcs12 bundle private key does not match the certificate's public key: point private_key_pem and certificate_pem at the same device's key pair")
	}

	// go-pkcs12 accepts a crypto.Signer for RSA, ECDSA, and Ed25519 alike, so
	// there is no PKCS#8 conversion here. That is only the jks path.
	//
	// FriendlyName is not applied on this branch. go-pkcs12 v0.7.3's
	// Encoder.Encode sets only the localKeyId attribute and exposes no way to
	// add a friendlyName, so Java synthesizes the alias instead. jks honours
	// FriendlyName, and so does the truststore path below.
	out, err := encoder.Encode(in.PrivateKey, in.Certificate, in.Chain, in.Password)
	if err != nil {
		return nil, fmt.Errorf("building pkcs12 keystore: %w", err)
	}
	return out, nil
}

// encodePKCS12TrustStore builds a Java truststore: every certificate is a peer
// marked as a trust anchor and none is designated the end entity.
//
// It uses EncodeTrustStoreEntries rather than EncodeTrustStore because
// EncodeTrustStore derives each alias from the certificate's subject, and two
// certificates sharing a subject — a re-keyed or cross-signed root — then
// collapse into a single keytool entry, silently dropping a trust anchor.
func encodePKCS12TrustStore(encoder *pkcs12.Encoder, in BundleInput) ([]byte, error) {
	certs := make([]*x509.Certificate, 0, 1+len(in.Chain))
	if in.Certificate != nil {
		certs = append(certs, in.Certificate)
	}
	certs = append(certs, in.Chain...)

	aliases := trustStoreAliases(in.FriendlyName, certs)
	entries := make([]pkcs12.TrustStoreEntry, len(certs))
	for i, cert := range certs {
		entries[i] = pkcs12.TrustStoreEntry{Cert: cert, FriendlyName: aliases[i]}
	}
	out, err := encoder.EncodeTrustStoreEntries(entries, in.Password)
	if err != nil {
		return nil, fmt.Errorf("building pkcs12 truststore: %w", err)
	}
	return out, nil
}

// trustStoreAliases derives one alias per certificate for a truststore, in the
// same order as certs. It is shared with the jks encoder, where duplicate
// aliases silently overwrite each other rather than merely merging.
//
// A supplied friendlyName is used verbatim for a single certificate and
// suffixed -1, -2, ... across several. Otherwise each certificate's common name
// is used, falling back to its serial when the common name is empty. Any
// remaining collision is broken with a numeric suffix, because a duplicate alias
// is exactly the silent trust-anchor loss this function exists to prevent.
//
// Collisions are detected case-insensitively. Java folds PKCS#12 aliases to
// lowercase, so common names of "Root" and "root" are one alias to keytool and
// one of the two anchors would vanish. keystore-go lowercases aliases too, and
// there the second entry overwrites the first rather than merging with it.
func trustStoreAliases(friendlyName string, certs []*x509.Certificate) []string {
	aliases := make([]string, len(certs))
	used := make(map[string]bool, len(certs))
	for i, cert := range certs {
		var alias string
		switch {
		case friendlyName != "" && len(certs) == 1:
			alias = friendlyName
		case friendlyName != "":
			alias = fmt.Sprintf("%s-%d", friendlyName, i+1)
		case cert.Subject.CommonName != "":
			alias = cert.Subject.CommonName
		default:
			alias = FormatSerial(cert.SerialNumber)
		}
		candidate := alias
		for n := 2; used[strings.ToLower(candidate)]; n++ {
			candidate = fmt.Sprintf("%s-%d", alias, n)
		}
		used[strings.ToLower(candidate)] = true
		aliases[i] = candidate
	}
	return aliases
}

// encodeJKS builds a Java keystore (JKS).
//
// Two properties of keystore-go make this less mechanical than it looks. It
// does not validate the private key encoding, so handing it a SEC1 blob
// produces a file that Store() accepts and Java rejects -- the key must be
// PKCS#8 DER, which is why this function calls EncodePrivateKeyPKCS8DER rather
// than any of key.go's PEM encoders. And every Certificate.Type here must be
// the literal string "X509": that is what keystore-go's own decoder writes,
// and "X.509" produces an entry Java does not recognize.
//
// keystore-go's default minimum password length is zero, so a two-character
// store password would be accepted silently; JKS's own floor is six, which
// this function enforces itself with a clear error, in addition to passing
// WithMinPasswordLen(6) to the store.
//
// Determinism is only a property of the truststore path (no PrivateKey).
// There, WithOrderedAliases and the fixed creationTime below are the entire
// story, and two encodes of the same input are byte-identical. The keyed
// path cannot make that promise: keystore-go's Sun key protector draws a
// fresh random 20-byte salt from its random source on every
// SetPrivateKeyEntry, the same way a PKCS#12 keystore is freshly salted on
// every encodePKCS12 call. Pinning that salt in production would be a
// security regression, not a determinism win, so this function does not
// attempt it -- it only threads in.Rand through when a caller supplies one
// (as tests do, mirroring encodePKCS12's WithRand above), leaving
// crypto/rand as the production default.
//
// None of this churns the Kubernetes Secret a keyed bundle lands in, despite
// the random salt: the provider encodes once at resource creation, holds the
// resulting bytes under UseStateForUnknown, and Read never re-encodes to
// compare, because the password is write-only and is not itself persisted in
// state. A truststore (no key, no password-gated secret) has no such
// protection, which is exactly why its path is held to full determinism.
func encodeJKS(in BundleInput) ([]byte, error) {
	if len(in.Password) < 6 {
		return nil, fmt.Errorf("jks bundle requires a password of at least 6 characters: set password_wo to a longer value")
	}
	if in.PrivateKey != nil && in.Certificate == nil {
		return nil, fmt.Errorf("jks bundle with a private key requires a certificate: set certificate_pem, or clear private_key_pem to build a truststore -- a keystore entry pairs the key with one specific certificate")
	}

	// creationTime is a fixed value derived from the input, never time.Now():
	// a wall-clock timestamp in the file would make every apply produce
	// different bytes and churn the Kubernetes Secret it lands in.
	var creationTime time.Time
	switch {
	case in.Certificate != nil:
		creationTime = in.Certificate.NotBefore
	case len(in.Chain) > 0:
		creationTime = in.Chain[0].NotBefore
	default:
		// Unreachable: EncodeBundle's own nothing-to-encode check rejects
		// Certificate, PrivateKey, and Chain all being absent, and the guard
		// above already rejects PrivateKey set with Certificate absent -- so
		// reaching here with both Certificate and Chain empty would require
		// PrivateKey alone to be set, which is exactly the case that guard
		// catches first. Kept anyway so this function stays correct if that
		// ordering ever changes.
		return nil, fmt.Errorf("jks bundle requires a certificate or a chain entry: set certificate_pem or chain_pem")
	}

	// WithOrderedAliases makes Aliases() -- and therefore Store()'s entry
	// order -- deterministic for a given input, for the same reason as
	// creationTime above. WithCustomRandomNumberGenerator is added only when
	// the caller supplies in.Rand (tests do, for reproducible bytes);
	// production leaves it nil and keystore-go falls back to crypto/rand.
	opts := []keystore.Option{keystore.WithOrderedAliases(), keystore.WithMinPasswordLen(6)}
	if in.Rand != nil {
		opts = append(opts, keystore.WithCustomRandomNumberGenerator(in.Rand))
	}
	ks := keystore.New(opts...)

	if in.PrivateKey != nil {
		if !PublicKeysEqual(PublicKeyOf(in.PrivateKey), in.Certificate.PublicKey) {
			return nil, fmt.Errorf("jks bundle private key does not match the certificate's public key: point private_key_pem and certificate_pem at the same device's key pair")
		}
		keyDER, err := EncodePrivateKeyPKCS8DER(in.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("encoding private key: %w", err)
		}

		chain := make([]keystore.Certificate, 0, 1+len(in.Chain))
		chain = append(chain, keystore.Certificate{Type: "X509", Content: in.Certificate.Raw})
		for _, c := range in.Chain {
			chain = append(chain, keystore.Certificate{Type: "X509", Content: c.Raw})
		}

		alias := in.FriendlyName
		if alias == "" {
			alias = in.Certificate.Subject.CommonName
		}
		if alias == "" {
			alias = "key"
		}

		if err := ks.SetPrivateKeyEntry(alias, keystore.PrivateKeyEntry{
			CreationTime:     creationTime,
			PrivateKey:       keyDER,
			CertificateChain: chain,
		}, []byte(in.Password)); err != nil {
			return nil, fmt.Errorf("adding jks private key entry: %w", err)
		}
	} else {
		// Trust anchors only. Aliases are derived by trustStoreAliases, shared
		// with the pkcs12 truststore path above -- not re-derived here. The
		// consequence of a collision is strictly worse in jks than in pkcs12:
		// keystore-go lowercases aliases and a duplicate silently overwrites the
		// previous entry rather than merging with it, so a colliding alias means
		// this keystore holds fewer trust anchors than the configuration asked
		// for, with no error anywhere.
		certs := make([]*x509.Certificate, 0, 1+len(in.Chain))
		if in.Certificate != nil {
			certs = append(certs, in.Certificate)
		}
		certs = append(certs, in.Chain...)

		aliases := trustStoreAliases(in.FriendlyName, certs)
		for i, cert := range certs {
			if err := ks.SetTrustedCertificateEntry(aliases[i], keystore.TrustedCertificateEntry{
				CreationTime: creationTime,
				Certificate:  keystore.Certificate{Type: "X509", Content: cert.Raw},
			}); err != nil {
				return nil, fmt.Errorf("adding jks trusted certificate entry %q: %w", aliases[i], err)
			}
		}
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(in.Password)); err != nil {
		return nil, fmt.Errorf("writing jks bundle: %w", err)
	}
	return buf.Bytes(), nil
}
