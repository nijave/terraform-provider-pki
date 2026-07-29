// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"testing"
	"time"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

// TestCrlSameSigningKeyIgnoresPEMEncoding is the load-bearing proof for the
// review's Important finding: crlDrifts must not compare ca_private_key_pem PEM
// bytes directly, because a Bitwarden-managed key re-serialized between PKCS#1
// and PKCS#8 (both of which pki_private_key produces) would otherwise flag as
// drift and regenerate the CRL for a cryptographically identical key. The same
// key in two encodings must compare equal; a different key must not.
func TestCrlSameSigningKeyIgnoresPEMEncoding(t *testing.T) {
	t.Parallel()
	key, err := pki.GenerateKey(pki.KeyParams{Algorithm: pki.AlgorithmRSA, RSABits: 2048})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// RSA's native PEM is PKCS#1; PKCS#8 is the other encoding pki_private_key
	// produces. Same key, different PEM bytes.
	pkcs1, err := pki.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	pkcs8, err := pki.EncodePrivateKeyPKCS8PEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPKCS8PEM: %v", err)
	}
	if string(pkcs1) == string(pkcs8) {
		t.Fatal("setup invariant failed: the two encodings produced identical PEM, so the test would prove nothing")
	}
	if !crlSameSigningKey(string(pkcs1), string(pkcs8)) {
		t.Errorf("crlSameSigningKey rejected the same key in two PEM encodings; a re-encoded CA key would spuriously regenerate the CRL")
	}
	// A genuinely different key must still compare unequal.
	other, err := pki.GenerateKey(pki.KeyParams{Algorithm: pki.AlgorithmRSA, RSABits: 2048})
	if err != nil {
		t.Fatalf("GenerateKey (other): %v", err)
	}
	otherPEM, err := pki.EncodePrivateKeyPEM(other)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM (other): %v", err)
	}
	if crlSameSigningKey(string(pkcs1), string(otherPEM)) {
		t.Error("crlSameSigningKey reported two different keys as the same")
	}
}

// TestCrlSameCACertificateIgnoresReserialization covers the symmetric property
// for the CA certificate: a re-serialized (e.g. trailing-newline-varied) PEM of
// the same certificate must compare equal, while a different certificate must
// not.
func TestCrlSameCACertificateIgnoresReserialization(t *testing.T) {
	t.Parallel()
	cert := selfSignedCertPEM(t)
	variant := cert + "\n" // a trailing-newline variant is the realistic reserialization case
	if cert == variant {
		t.Fatal("setup invariant failed: variant did not differ from the original")
	}
	if !crlSameCACertificate(cert, variant) {
		t.Errorf("crlSameCACertificate rejected a reserialized (trailing-newline) variant of the same certificate; it would spuriously regenerate the CRL")
	}
	if crlSameCACertificate(cert, selfSignedCertPEM(t)) {
		t.Error("crlSameCACertificate reported two different certificates as the same")
	}
}

// selfSignedCertPEM issues a throwaway self-signed cert and returns its PEM, for
// the certificate-comparison fixtures above.
func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := pki.GenerateKey(pki.KeyParams{Algorithm: pki.AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := pki.RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	pemBytes, err := pki.CreateCertificate(pki.CertTemplate{
		Subject:          pki.NamedSubject{CommonName: "crl-test-ca"}.Expand(),
		Serial:           serial,
		NotBefore:        now,
		NotAfter:         now.Add(24 * time.Hour),
		BasicConstraints: &pki.BasicConstraints{CA: true, Critical: true},
		KeyUsage:         pki.DefaultCAKeyUsagePtr(),
	}, pki.PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pemBytes)
}
