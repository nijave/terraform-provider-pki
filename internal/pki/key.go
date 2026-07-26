// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Algorithm names a private key algorithm as the provider's schema spells it.
// The values are uppercase and matched case-sensitively, so a config typo fails
// at plan time rather than silently generating a different kind of key.
type Algorithm string

const (
	AlgorithmRSA     Algorithm = "RSA"
	AlgorithmECDSA   Algorithm = "ECDSA"
	AlgorithmED25519 Algorithm = "ED25519"
)

// minRSABits is the floor for generated RSA keys. 2048 is the NIST and
// CA/Browser Forum minimum; anything smaller is not worth the support burden of
// offering.
const minRSABits = 2048

// KeyParams describes a key to generate, or the shape of a key that was parsed.
// Zero values mean "use the default": 2048 bits for RSA, P-256 for ECDSA.
// Fields that do not apply to the chosen algorithm must be left zero, so a
// config that sets rsa_bits on an Ed25519 key is rejected instead of ignored.
type KeyParams struct {
	Algorithm  Algorithm
	RSABits    int
	ECDSACurve string
}

// curveByName maps the schema's curve names to Go's elliptic.Curve values.
// The schema spells curves "P256" while Go spells them "P-256"; this map is
// explicit in both directions rather than derived, so validation on the
// schema's own names does not depend on Go's naming.
var curveByName = map[string]elliptic.Curve{
	"P224": elliptic.P224(),
	"P256": elliptic.P256(),
	"P384": elliptic.P384(),
	"P521": elliptic.P521(),
}

// curveNameFromGo is the reverse of curveByName, keyed by
// elliptic.Curve.Params().Name, for DescribeKey to report the schema's
// spelling back.
var curveNameFromGo = map[string]string{
	"P-224": "P224",
	"P-256": "P256",
	"P-384": "P384",
	"P-521": "P521",
}

// GenerateKey generates a new private key according to p, applying the
// defaults RSABits 2048 and ECDSACurve "P256" when those fields are zero.
//
// Within each case, validation happens before defaulting is applied to the
// fields that select the algorithm's non-default parameters (RSABits for a
// non-RSA algorithm, ECDSACurve for a non-ECDSA algorithm): those are rejected
// outright rather than silently ignored, so a copy-pasted config block cannot
// quietly produce a key with settings its author believes are in effect.
//
// This is deliberately one switch and not two. Validating in a first switch and
// generating in a second one, both over p.Algorithm, forced a trailing return
// after the second switch that no input could reach -- an unreachable branch
// that no test could cover and that would silently absorb a future case added
// to the first switch but forgotten in the second. With a single switch whose
// default returns and whose every case returns, Go's terminating-statement rule
// is satisfied without a trailing return, so unreachability is expressed by the
// language rather than by a comment.
func GenerateKey(p KeyParams) (crypto.Signer, error) {
	switch p.Algorithm {
	case AlgorithmRSA:
		if p.ECDSACurve != "" {
			return nil, fmt.Errorf("ecdsa_curve is not valid for algorithm %s", p.Algorithm)
		}
		bits := p.RSABits
		if bits == 0 {
			bits = minRSABits
		}
		if bits < minRSABits || bits%8 != 0 {
			return nil, fmt.Errorf("rsa_bits %d is invalid: must be at least %d and a multiple of 8", bits, minRSABits)
		}
		return rsa.GenerateKey(rand.Reader, bits)

	case AlgorithmECDSA:
		if p.RSABits != 0 {
			return nil, fmt.Errorf("rsa_bits is not valid for algorithm %s", p.Algorithm)
		}
		name := p.ECDSACurve
		if name == "" {
			name = "P256"
		}
		curve, ok := curveByName[name]
		if !ok {
			return nil, fmt.Errorf("unknown ecdsa curve %q", name)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)

	case AlgorithmED25519:
		if p.RSABits != 0 {
			return nil, fmt.Errorf("rsa_bits is not valid for algorithm %s", p.Algorithm)
		}
		if p.ECDSACurve != "" {
			return nil, fmt.Errorf("ecdsa_curve is not valid for algorithm %s", p.Algorithm)
		}
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ed25519 key: %w", err)
		}
		return priv, nil

	default:
		return nil, fmt.Errorf("unknown key algorithm %q", p.Algorithm)
	}
}

// DescribeKey is the inverse of GenerateKey, reconstructing the KeyParams a
// parsed or generated key would have been created with, so pki_private_key
// can round-trip its input attributes on import.
func DescribeKey(k crypto.Signer) (KeyParams, error) {
	switch key := k.(type) {
	case *rsa.PrivateKey:
		return KeyParams{Algorithm: AlgorithmRSA, RSABits: key.N.BitLen()}, nil
	case *ecdsa.PrivateKey:
		name, ok := curveNameFromGo[key.Curve.Params().Name]
		if !ok {
			return KeyParams{}, fmt.Errorf("unsupported ecdsa curve %q", key.Curve.Params().Name)
		}
		return KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: name}, nil
	case ed25519.PrivateKey:
		return KeyParams{Algorithm: AlgorithmED25519}, nil
	default:
		return KeyParams{}, fmt.Errorf("unsupported private key type %T", k)
	}
}

// ParsePrivateKeyPEM decodes the first PEM block in b and parses it as a
// private key, accepting PKCS#8, PKCS#1, and SEC1 (in that order, matching the
// attempts below; order matters only for speed, since the three encodings are
// mutually unparseable). This is the path CA keys take on the way in: a
// Bitwarden-delivered Secret can hold any of these forms and the provider must
// not care which.
//
// Errors never include the PEM block's bytes or the raw input, since this
// function's errors surface as Terraform diagnostics that get printed to
// consoles and CI logs. The total-failure message does wrap the PKCS#8
// attempt's error, which is safe: crypto/x509's private-key parse errors are
// structural, describing tags, lengths, offsets, and failed arithmetic
// invariants ("asn1: syntax error: data truncated", "asn1: structure error:
// tags don't match (16 vs {class:3 tag:15 length:1213 ...})", "crypto/rsa:
// p * q != n"), and none of them quote input bytes. The one that echoes
// anything from the input at all is "PKCS#8 wrapping contained private key with
// unknown algorithm: <oid>", and an AlgorithmIdentifier OID is public metadata
// sitting outside the privateKey OCTET STRING that holds the secret.
//
// That survey is not taken on trust: TestParsePrivateKeyPEMErrorNeverEchoesRealKeyBytes
// mangles real keys of all three algorithms in every position and asserts the
// message shares no run of the input, and
// TestParsePrivateKeyPEMUnknownAlgorithmErrorLeaksOnlyTheOID covers the
// unknown-algorithm case against an intact key.
//
// The PKCS#8 error is the one wrapped because it is the most informative of the
// three for the failures that actually happen: an encrypted or truncated PEM, or
// a block that is really a certificate, all fail PKCS#8 with a message naming
// what was wrong structurally, while ParsePKCS1PrivateKey and ParseECPrivateKey
// only report that the input was not their format.
func ParsePrivateKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key input")
	}

	key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("parsed PKCS#8 key of type %T does not support signing", key)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse private key: not valid PKCS#8, PKCS#1, or SEC1: %w", pkcs8Err)
}

// ParsePublicKeyPEM decodes the first PEM block in b and parses it as a
// PKIX-encoded public key.
func ParsePublicKeyPEM(b []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key input")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key: %w", err)
	}
	return pub, nil
}

// EncodePrivateKeyPEM encodes k in its algorithm's conventional legacy
// format: PKCS#1 for RSA, SEC1 for ECDSA, PKCS#8 for Ed25519 (which has no
// legacy encoding of its own).
func EncodePrivateKeyPEM(k crypto.Signer) ([]byte, error) {
	switch key := k.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshaling ecdsa private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case ed25519.PrivateKey:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshaling ed25519 private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", k)
	}
}

// EncodePrivateKeyPKCS8DER encodes k as PKCS#8 DER, with no PEM wrapping.
// Task 13's JKS encoder needs this form directly: keystore-go accepts a raw
// byte slice and silently produces an unreadable keystore if handed SEC1
// instead of PKCS#8.
func EncodePrivateKeyPKCS8DER(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("marshaling pkcs#8 private key: %w", err)
	}
	return der, nil
}

// EncodePrivateKeyPKCS8PEM encodes k as PKCS#8, wrapped in a "PRIVATE KEY"
// PEM block, regardless of algorithm.
func EncodePrivateKeyPKCS8PEM(k crypto.Signer) ([]byte, error) {
	der, err := EncodePrivateKeyPKCS8DER(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodePublicKeyPEM encodes pub as a PKIX "PUBLIC KEY" PEM block.
func EncodePublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodePublicKeyOpenSSH renders pub in OpenSSH authorized_keys form,
// including the trailing newline ssh.MarshalAuthorizedKey already appends.
func EncodePublicKeyOpenSSH(pub crypto.PublicKey) ([]byte, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("converting public key to ssh wire format: %w", err)
	}
	return ssh.MarshalAuthorizedKey(sshPub), nil
}

// PublicKeyFingerprintSHA256 renders pub's OpenSSH SHA256 fingerprint:
// "SHA256:" followed by the unpadded standard base64 encoding of the SHA-256
// hash of the SSH wire-format key. This matches hashicorp/tls exactly, since
// configurations may already depend on the precise shape.
func PublicKeyFingerprintSHA256(pub crypto.PublicKey) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("converting public key to ssh wire format: %w", err)
	}
	sum := sha256.Sum256(sshPub.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// PublicKeyOf returns k's public key. It exists only to keep call sites free
// of a type switch of their own.
func PublicKeyOf(k crypto.Signer) crypto.PublicKey {
	return k.Public()
}

// PublicKeysEqual reports whether a and b are the same public key. It uses
// the Equal method every stdlib public key type implements rather than
// reflect.DeepEqual, which for ECDSA keys compares unexported curve internals
// and produces false negatives between otherwise-identical keys.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	ae, ok := a.(interface{ Equal(x crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return ae.Equal(b)
}
