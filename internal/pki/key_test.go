// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestGenerateKeyDefaults(t *testing.T) {
	t.Parallel()

	rsaKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey(RSA): %v", err)
	}
	rk, ok := rsaKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("GenerateKey(RSA) returned %T, want *rsa.PrivateKey", rsaKey)
	}
	if got := rk.N.BitLen(); got != 2048 {
		t.Errorf("default RSA size = %d bits, want 2048", got)
	}

	ecKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey(ECDSA): %v", err)
	}
	ek, ok := ecKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("GenerateKey(ECDSA) returned %T, want *ecdsa.PrivateKey", ecKey)
	}
	if got := ek.Curve.Params().Name; got != "P-256" {
		t.Errorf("default ECDSA curve = %q, want \"P-256\"", got)
	}

	edKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmED25519})
	if err != nil {
		t.Fatalf("GenerateKey(ED25519): %v", err)
	}
	if _, ok := edKey.(ed25519.PrivateKey); !ok {
		t.Fatalf("GenerateKey(ED25519) returned %T, want ed25519.PrivateKey", edKey)
	}
}

func TestGenerateKeyExplicitParams(t *testing.T) {
	t.Parallel()

	k, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA, RSABits: 3072})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if got := k.(*rsa.PrivateKey).N.BitLen(); got != 3072 {
		t.Errorf("RSA size = %d, want 3072", got)
	}

	for _, curve := range []struct{ name, want string }{
		{"P224", "P-224"},
		{"P256", "P-256"},
		{"P384", "P-384"},
		{"P521", "P-521"},
	} {
		k, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA, ECDSACurve: curve.name})
		if err != nil {
			t.Errorf("GenerateKey(%s): %v", curve.name, err)
			continue
		}
		if got := k.(*ecdsa.PrivateKey).Curve.Params().Name; got != curve.want {
			t.Errorf("curve %s produced %q, want %q", curve.name, got, curve.want)
		}
	}
}

func TestGenerateKeyRejectsBadParams(t *testing.T) {
	t.Parallel()
	for _, p := range []KeyParams{
		{Algorithm: "DSA"},
		{Algorithm: ""},
		{Algorithm: "rsa"},                       // case-sensitive: the schema surfaces RSA/ECDSA/ED25519
		{Algorithm: AlgorithmRSA, RSABits: 512},  // below the 2048 floor
		{Algorithm: AlgorithmRSA, RSABits: 2047}, // not a multiple of 8 and below floor
		{Algorithm: AlgorithmECDSA, ECDSACurve: "P192"},
		{Algorithm: AlgorithmECDSA, ECDSACurve: "p256"},
		{Algorithm: AlgorithmECDSA, RSABits: 2048},   // rsa_bits is meaningless here
		{Algorithm: AlgorithmED25519, RSABits: 2048}, // rsa_bits is meaningless here
		{Algorithm: AlgorithmED25519, ECDSACurve: "P256"},
		{Algorithm: AlgorithmRSA, ECDSACurve: "P256"}, // ecdsa_curve is meaningless here
	} {
		if _, err := GenerateKey(p); err == nil {
			t.Errorf("GenerateKey(%+v) returned nil error, want an error", p)
		}
	}
}

// TestDescribeKeyRoundTrip is what makes pki_private_key import cleanly: every
// input attribute must be recoverable from the parsed key, or the first plan
// after import proposes a replacement.
func TestDescribeKeyRoundTrip(t *testing.T) {
	t.Parallel()
	for _, want := range []KeyParams{
		{Algorithm: AlgorithmRSA, RSABits: 2048},
		{Algorithm: AlgorithmRSA, RSABits: 3072},
		{Algorithm: AlgorithmECDSA, ECDSACurve: "P256"},
		{Algorithm: AlgorithmECDSA, ECDSACurve: "P384"},
		{Algorithm: AlgorithmED25519},
	} {
		k, err := GenerateKey(want)
		if err != nil {
			t.Fatalf("GenerateKey(%+v): %v", want, err)
		}
		got, err := DescribeKey(k)
		if err != nil {
			t.Errorf("DescribeKey(%+v): %v", want, err)
			continue
		}
		if got != want {
			t.Errorf("DescribeKey round-trip = %+v, want %+v", got, want)
		}
	}
}

func TestEncodePrivateKeyPEMUsesTheExpectedBlockTypes(t *testing.T) {
	t.Parallel()
	// The block type is what openssl and every other consumer keys off, and it
	// differs per algorithm: PKCS#1 for RSA, SEC1 for ECDSA, PKCS#8 for
	// Ed25519 (which has no legacy format).
	for _, tc := range []struct {
		params    KeyParams
		wantBlock string
	}{
		{KeyParams{Algorithm: AlgorithmRSA}, "RSA PRIVATE KEY"},
		{KeyParams{Algorithm: AlgorithmECDSA}, "EC PRIVATE KEY"},
		{KeyParams{Algorithm: AlgorithmED25519}, "PRIVATE KEY"},
	} {
		k, err := GenerateKey(tc.params)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		out, err := EncodePrivateKeyPEM(k)
		if err != nil {
			t.Errorf("EncodePrivateKeyPEM(%s): %v", tc.params.Algorithm, err)
			continue
		}
		block, rest := pem.Decode(out)
		if block == nil {
			t.Errorf("EncodePrivateKeyPEM(%s) produced undecodable PEM", tc.params.Algorithm)
			continue
		}
		if block.Type != tc.wantBlock {
			t.Errorf("%s block type = %q, want %q", tc.params.Algorithm, block.Type, tc.wantBlock)
		}
		if len(rest) != 0 {
			t.Errorf("%s: %d trailing bytes after the PEM block, want 0", tc.params.Algorithm, len(rest))
		}
		if !strings.HasSuffix(string(out), "\n") {
			t.Errorf("%s: PEM output does not end in a newline", tc.params.Algorithm)
		}
	}
}

func TestEncodePrivateKeyPKCS8PEM(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		k, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		out, err := EncodePrivateKeyPKCS8PEM(k)
		if err != nil {
			t.Errorf("EncodePrivateKeyPKCS8PEM(%s): %v", alg, err)
			continue
		}
		block, _ := pem.Decode(out)
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Errorf("%s: PKCS#8 block type is not \"PRIVATE KEY\"", alg)
			continue
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			t.Errorf("%s: emitted PKCS#8 does not parse: %v", alg, err)
		}
	}
}

// TestParsePrivateKeyPEMAcceptsAllThreeEncodings matters because CA keys arrive
// from outside the provider -- a Bitwarden-delivered Secret can hold any of
// these forms and the provider must not care which.
func TestParsePrivateKeyPEMAcceptsAllThreeEncodings(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		orig, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		native, err := EncodePrivateKeyPEM(orig)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM: %v", err)
		}
		pkcs8, err := EncodePrivateKeyPKCS8PEM(orig)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8PEM: %v", err)
		}
		for label, encoded := range map[string][]byte{"native": native, "pkcs8": pkcs8} {
			parsed, err := ParsePrivateKeyPEM(encoded)
			if err != nil {
				t.Errorf("%s/%s: ParsePrivateKeyPEM: %v", alg, label, err)
				continue
			}
			if !PublicKeysEqual(PublicKeyOf(parsed), PublicKeyOf(orig)) {
				t.Errorf("%s/%s: parsed key's public key differs from the original", alg, label)
			}
		}
	}
}

func TestParsePrivateKeyPEMRejectsBadInput(t *testing.T) {
	t.Parallel()
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	for label, in := range map[string]string{
		"empty":            "",
		"not pem":          "hello",
		"wrong block type": certPEM,
		"truncated body":   "-----BEGIN RSA PRIVATE KEY-----\nZm9v\n-----END RSA PRIVATE KEY-----\n",
	} {
		if _, err := ParsePrivateKeyPEM([]byte(in)); err == nil {
			t.Errorf("ParsePrivateKeyPEM(%s) returned nil error, want an error", label)
		}
	}
}

func TestParsePrivateKeyPEMErrorDoesNotLeakKeyMaterial(t *testing.T) {
	t.Parallel()
	// Errors from this function reach Terraform diagnostics, which are printed
	// to the console and to CI logs. The message must never echo the input.
	const secret = "-----BEGIN RSA PRIVATE KEY-----\nc3VwZXJzZWNyZXQ=\n-----END RSA PRIVATE KEY-----\n"
	_, err := ParsePrivateKeyPEM([]byte(secret))
	if err == nil {
		t.Fatal("expected an error for a malformed key")
	}
	if strings.Contains(err.Error(), "c3VwZXJzZWNyZXQ") || strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error message contains key material: %q", err.Error())
	}
}

// TestParsePrivateKeyPEMErrorNeverEchoesRealKeyBytes is the audit behind the
// wrapped error in ParsePrivateKeyPEM's total-failure path. That path reports
// crypto/x509's PKCS#8 error verbatim, and this package's rule is that no error
// may echo key material -- so the claim that x509's private-key parse errors are
// purely structural has to be enforced, not assumed.
//
// It takes real generated keys, mangles them in every position and length a
// corrupted secret realistically arrives in, and hands each resulting message to
// assertNoEcho -- the package's single leak guard, in testhelper_test.go, which
// is where the thresholds and the reasoning behind them live.
func TestParsePrivateKeyPEMErrorNeverEchoesRealKeyBytes(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		k, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		native, err := EncodePrivateKeyPEM(k)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM(%s): %v", alg, err)
		}
		pkcs8, err := EncodePrivateKeyPKCS8PEM(k)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8PEM(%s): %v", alg, err)
		}

		for _, encoded := range [][]byte{native, pkcs8} {
			block, _ := pem.Decode(encoded)
			if block == nil {
				t.Fatalf("%s: encoded key is not PEM", alg)
			}
			for _, m := range manglings(block.Bytes) {
				mangled := pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: m.der})
				_, err := ParsePrivateKeyPEM(mangled)
				if err == nil {
					// A few manglings land on a still-valid key (flipping a
					// byte of an unused field, say). Nothing to audit.
					continue
				}
				assertNoEcho(t, fmt.Sprintf("%s/%s/%s", alg, block.Type, m.name), err.Error(), m.der)
			}
		}
	}
}

// TestParsePrivateKeyPEMUnknownAlgorithmErrorLeaksOnlyTheOID covers the single
// crypto/x509 private-key error that does put something from the input in its
// text: "PKCS#8 wrapping contained private key with unknown algorithm: <oid>".
//
// The input here is a real, intact RSA private key still sitting in the
// privateKey OCTET STRING, with only the AlgorithmIdentifier OID replaced -- the
// worst case for the claim that the echoed OID is public metadata and not key
// material. If that reasoning is ever wrong, this is where it shows.
func TestParsePrivateKeyPEMUnknownAlgorithmErrorLeaksOnlyTheOID(t *testing.T) {
	t.Parallel()
	k, err := GenerateKey(KeyParams{Algorithm: AlgorithmRSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := EncodePrivateKeyPKCS8DER(k)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPKCS8DER: %v", err)
	}

	// The PKCS#8 PrivateKeyInfo prefix, enough to reach and rewrite the
	// algorithm OID while leaving the wrapped key bytes untouched.
	var info struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		t.Fatalf("unmarshalling PKCS#8 PrivateKeyInfo: %v", err)
	}
	info.Algo.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 99999, 31337}
	rewritten, err := asn1.Marshal(info)
	if err != nil {
		t.Fatalf("re-marshalling PKCS#8 PrivateKeyInfo: %v", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rewritten})
	_, err = ParsePrivateKeyPEM(encoded)
	if err == nil {
		t.Fatal("a PKCS#8 key with an unregistered algorithm OID parsed, want an error")
	}
	if !strings.Contains(err.Error(), "unknown algorithm") {
		t.Fatalf("error = %q, want crypto/x509's unknown-algorithm error; this test no longer covers the path it was written for", err)
	}
	assertNoEcho(t, "pkcs8/unknown-algorithm", err.Error(), rewritten)
}

// mangling is one corruption of a DER-encoded key, named for test output.
type mangling struct {
	name string
	der  []byte
}

// manglings returns the ways a private key realistically arrives corrupted:
// truncated at various points (a clipped copy-paste), a single byte flipped at
// the head, in the middle, and at the tail (a transcription slip), and trailing
// garbage appended.
func manglings(der []byte) []mangling {
	out := []mangling{
		{"empty", nil},
		{"truncated-1", der[:len(der)-1]},
		{"truncated-quarter", der[:len(der)/4]},
		{"truncated-half", der[:len(der)/2]},
		{"trailing-garbage", append(append([]byte{}, der...), 0xde, 0xad, 0xbe, 0xef)},
	}
	for _, i := range []int{0, 1, 2, len(der) / 3, len(der) / 2, (2 * len(der)) / 3, len(der) - 1} {
		flipped := append([]byte{}, der...)
		flipped[i] ^= 0xff
		out = append(out, mangling{fmt.Sprintf("flip-%d", i), flipped})
	}
	return out
}

func TestEncodePublicKeyPEMAndParseRoundTrip(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		k, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		encoded, err := EncodePublicKeyPEM(PublicKeyOf(k))
		if err != nil {
			t.Errorf("EncodePublicKeyPEM(%s): %v", alg, err)
			continue
		}
		block, _ := pem.Decode(encoded)
		if block == nil || block.Type != "PUBLIC KEY" {
			t.Errorf("%s: public key block type is not \"PUBLIC KEY\"", alg)
			continue
		}
		parsed, err := ParsePublicKeyPEM(encoded)
		if err != nil {
			t.Errorf("%s: ParsePublicKeyPEM: %v", alg, err)
			continue
		}
		if !PublicKeysEqual(parsed, PublicKeyOf(k)) {
			t.Errorf("%s: public key did not survive the PEM round trip", alg)
		}
	}
}

func TestEncodePublicKeyOpenSSHAndFingerprint(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		alg        Algorithm
		wantPrefix string
	}{
		{AlgorithmRSA, "ssh-rsa "},
		{AlgorithmECDSA, "ecdsa-sha2-nistp256 "},
		{AlgorithmED25519, "ssh-ed25519 "},
	} {
		k, err := GenerateKey(KeyParams{Algorithm: tc.alg})
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		authorized, err := EncodePublicKeyOpenSSH(PublicKeyOf(k))
		if err != nil {
			t.Errorf("EncodePublicKeyOpenSSH(%s): %v", tc.alg, err)
			continue
		}
		if !strings.HasPrefix(string(authorized), tc.wantPrefix) {
			t.Errorf("%s: openssh output %q does not start with %q", tc.alg, authorized, tc.wantPrefix)
		}
		if !strings.HasSuffix(string(authorized), "\n") {
			t.Errorf("%s: openssh output does not end in a newline", tc.alg)
		}

		fp, err := PublicKeyFingerprintSHA256(PublicKeyOf(k))
		if err != nil {
			t.Errorf("PublicKeyFingerprintSHA256(%s): %v", tc.alg, err)
			continue
		}
		// The OpenSSH form: "SHA256:" plus unpadded standard base64 of the
		// SHA-256 of the wire-format public key. This is what hashicorp/tls
		// emits, and configs may already depend on the exact shape.
		if !strings.HasPrefix(fp, "SHA256:") {
			t.Errorf("%s: fingerprint %q does not start with \"SHA256:\"", tc.alg, fp)
		}
		if strings.Contains(fp, "=") {
			t.Errorf("%s: fingerprint %q is padded; OpenSSH uses unpadded base64", tc.alg, fp)
		}
		if len(fp) != len("SHA256:")+43 {
			t.Errorf("%s: fingerprint %q has length %d, want %d", tc.alg, fp, len(fp), len("SHA256:")+43)
		}
	}
}

func TestPublicKeysEqual(t *testing.T) {
	t.Parallel()
	a, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !PublicKeysEqual(PublicKeyOf(a), PublicKeyOf(a)) {
		t.Error("PublicKeysEqual said a key differs from itself")
	}
	if PublicKeysEqual(PublicKeyOf(a), PublicKeyOf(b)) {
		t.Error("PublicKeysEqual said two independently generated keys match")
	}
	if PublicKeysEqual(nil, PublicKeyOf(a)) || PublicKeysEqual(PublicKeyOf(a), nil) {
		t.Error("PublicKeysEqual matched a nil key against a real one")
	}
}

func TestEmittedKeysAreReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	bin := requireOpenSSL(t)

	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		k, err := GenerateKey(KeyParams{Algorithm: alg})
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		native, err := EncodePrivateKeyPEM(k)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM(%s): %v", alg, err)
		}
		pkcs8, err := EncodePrivateKeyPKCS8PEM(k)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8PEM(%s): %v", alg, err)
		}
		for label, encoded := range map[string][]byte{"native": native, "pkcs8": pkcs8} {
			cmd := exec.Command(bin, "pkey", "-noout", "-check")
			cmd.Stdin = bytes.NewReader(encoded)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("openssl pkey -check rejected the %s/%s key: %v\n%s", alg, label, err, out)
			}
		}
	}
}
