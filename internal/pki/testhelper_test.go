// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// assertNoEcho is the single guard behind this package's one critical
// invariant: no error message may ever echo private key material. Every test
// that checks that property goes through here, and there is deliberately only
// one of these functions.
//
// There used to be two -- a strong one over parse errors in key_test.go and a
// weaker one over bundle errors in bundle_test.go -- and the weak one had a hole
// exactly where the two disagreed: it checked the whole raw DER and 16-character
// windows of its base64, so an error appending the entire PKCS#8 DER as *hex*, or
// quoting a raw 32-byte slice of it with %q, passed while leaking a whole key.
// Two helpers for one invariant is how that hole appeared, so the strengths are
// merged here and there is no weaker path left to reach for.
//
// The rendering a leak arrives in is whichever fmt verb the author reached for,
// so every verb that takes a []byte is covered, plus the base64 a PEM body
// carries:
//
//   - %s and string(): the raw bytes, 4-byte window.
//   - %x and %X: hex, 8-character window, matched case-insensitively.
//   - PEM/base64: 8-character window, in all three phase alignments.
//   - %q: Go's quoted form, 16-character window. This one is not optional and is
//     not implied by the raw check -- %q escapes every unprintable byte as \xNN,
//     which shatters the raw run into fragments no substring search finds. It is
//     the shape hexPreview in compare.go is one careless copy away from, and it
//     is the mutation that survived every earlier version of this helper.
//   - %v: space-separated decimals, 24-character window. The one rendering that
//     shares no substring with any of the above.
//
// Every window is stepped one unit at a time, never by the window length. A
// stride equal to the window only catches a leak that happens to be aligned to
// it: measured during this campaign, an error echoing 32 base64 characters
// starting mid-line contained no whole 24-aligned run and slipped past a strided
// check.
//
// The three base64 phases matter for the same reason. base64 encodes each 3-byte
// group independently, so the base64 of secret[k:] shares no long substring with
// the base64 of secret[0:] unless k is a multiple of 3. Encoding at offsets 0, 1,
// and 2 covers every k, since secret[k:] with k congruent to phase p mod 3 is
// group-aligned inside the phase-p encoding. The %q and %v renderings need no
// such treatment because both encode each byte independently of its position;
// %q's only context sensitivity is UTF-8 rune boundaries, which can differ at a
// quoted slice's two edges and not in its interior.
//
// Thresholds are short enough that quoting so much as a fragment of a key fails,
// and long enough that the structural numbers crypto/x509 does report
// ("length:1213", tag numbers, byte offsets) cannot collide by accident: 4 raw
// bytes and 8 hex characters are both 2^32 of entropy, and 8 base64 characters
// is 6 bytes of key.
func assertNoEcho(t *testing.T, label, msg string, secret []byte) {
	t.Helper()

	// hex.EncodeToString emits lowercase, so a lowered copy of the message is
	// what the hex pass searches; a leak written with %X is then caught by the
	// same pass. Every other rendering is compared against the message as it is.
	lowered := strings.ToLower(msg)

	// Quoted and decimal renderings are taken over the whole secret and then
	// windowed, rather than rendered per window, because both are what fmt would
	// have produced for the whole thing and a window of that is what a partial
	// leak looks like. strconv.Quote's outer quotes are stripped so a window can
	// start anywhere.
	quoted := strconv.Quote(string(secret))
	quoted = quoted[1 : len(quoted)-1]

	renderings := []struct {
		name        string
		text        string
		window      int
		searchLower bool
	}{
		{"raw bytes (%s)", string(secret), 4, false},
		{"hex (%x)", hex.EncodeToString(secret), 8, true},
		{"Go-quoted (%q)", quoted, 16, false},
		{"decimals (%v)", strings.Trim(fmt.Sprint(secret), "[]"), 24, false},
	}
	for phase := 0; phase < 3 && phase < len(secret); phase++ {
		renderings = append(renderings, struct {
			name        string
			text        string
			window      int
			searchLower bool
		}{
			fmt.Sprintf("base64 (phase %d)", phase),
			base64.StdEncoding.EncodeToString(secret[phase:]),
			8,
			false,
		})
	}

	for _, r := range renderings {
		haystack := msg
		if r.searchLower {
			haystack = lowered
		}
		for i := 0; i+r.window <= len(r.text); i++ {
			window := r.text[i : i+r.window]
			if strings.Contains(haystack, window) {
				t.Errorf("%s: error message echoes the secret as %s from offset %d (%q): %q",
					label, r.name, i, window, msg)
				return
			}
		}
	}
}

// assertNoKeyMaterial runs assertNoEcho over every encoding of every given key.
// It is a thin adapter, not a second guard: all it adds is the list of byte
// strings a key can be leaked as.
//
// Both PEM encodings are checked, and both matter: EncodePrivateKeyPEM emits
// SEC1 for an ECDSA key while EncodePrivateKeyPKCS8DER emits PKCS#8, so their
// bodies share no long substring and checking one would miss a leak of the
// other.
func assertNoKeyMaterial(t *testing.T, label, msg string, keys ...crypto.Signer) {
	t.Helper()
	for i, key := range keys {
		pkcs8, err := EncodePrivateKeyPKCS8DER(key)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPKCS8DER: %v", err)
		}
		keyPEM, err := EncodePrivateKeyPEM(key)
		if err != nil {
			t.Fatalf("EncodePrivateKeyPEM: %v", err)
		}
		nativeBlock, _ := pem.Decode(keyPEM)
		if nativeBlock == nil {
			t.Fatalf("EncodePrivateKeyPEM did not produce a PEM block, so this test would check nothing")
		}
		for form, der := range map[string][]byte{"PKCS#8": pkcs8, nativeBlock.Type: nativeBlock.Bytes} {
			assertNoEcho(t, fmt.Sprintf("%s/key %d/%s", label, i, form), msg, der)
		}
	}
}

// mustDNOID looks up a DN attribute OID or fails the test. It exists so table
// literals can stay expressions.
func mustDNOID(t *testing.T, name string) asn1.ObjectIdentifier {
	t.Helper()
	oid, err := DNAttributeOID(name)
	if err != nil {
		t.Fatalf("DNAttributeOID(%q): %v", name, err)
	}
	return oid
}

// mustOID parses a dotted OID or fails the test.
func mustOID(t *testing.T, s string) asn1.ObjectIdentifier {
	t.Helper()
	oid, err := ParseOID(s)
	if err != nil {
		t.Fatalf("ParseOID(%q): %v", s, err)
	}
	return oid
}

// mustFindExt returns the extension with the given dotted OID or fails.
func mustFindExt(t *testing.T, exts []pkix.Extension, oid string) pkix.Extension {
	t.Helper()
	parsed, err := ParseOID(oid)
	if err != nil {
		t.Fatalf("ParseOID(%q): %v", oid, err)
	}
	ext, ok := FindExtension(exts, parsed)
	if !ok {
		t.Fatalf("extension %s not found", oid)
	}
	return ext
}

// requireOpenSSL returns the path to the openssl binary, skipping the test when
// it is not installed. Cross-validation against a real parser is valuable but
// must never be the reason a contributor's test run fails.
func requireOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH; skipping cross-validation")
	}
	return path
}

// testCA issues a CA certificate and returns it with its key. With a nil parent
// it self-signs a root; otherwise it issues an intermediate under the parent.
// The key is ECDSA P-256 because these fixtures are created in almost every
// test and RSA generation dominates the suite's runtime otherwise.
func testCA(t *testing.T, parent *x509.Certificate, parentKey crypto.Signer, cn string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signerKey := key
	if parentKey != nil {
		signerKey = parentKey
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: cn, Organization: "homelab"}.Expand(),
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: true, Critical: true},
		KeyUsage:         DefaultCAKeyUsagePtr(),
	}, PublicKeyOf(key), parent, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM(%s): %v", cn, err)
	}
	return cert, key
}

// opensslText runs `openssl x509 -text -noout` over a PEM certificate and
// returns its output, so tests can assert that a real parser agrees with what
// this package produced.
//
// -nameopt oneline is passed explicitly rather than relying on the default,
// because the default is not stable across builds: OpenSSL 3.5.7 renders a DN as
// "CN=homelab, UID=nick" while oneline renders it as "CN = homelab, UID = nick",
// and a test that hardcodes either form without pinning the flag fails on the
// other. oneline is the spaced form, which is what openssl documents as its
// name-printing default and what the assertions here are written against.
func opensslText(t *testing.T, certPEM []byte) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, "x509", "-noout", "-text", "-nameopt", "oneline")
	cmd.Stdin = bytes.NewReader(certPEM)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text failed: %v\n%s", err, out)
	}
	return string(out)
}

// opensslCRLText runs `openssl crl -text -noout` over a PEM CRL.
func opensslCRLText(t *testing.T, crlPEM []byte) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, "crl", "-noout", "-text")
	cmd.Stdin = bytes.NewReader(crlPEM)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl crl -text failed: %v\n%s", err, out)
	}
	return string(out)
}

// testLeaf issues a leaf certificate under a fresh CA and returns the leaf, the
// leaf's key, and the CA certificate.
func testLeaf(t *testing.T) (*x509.Certificate, crypto.Signer, *x509.Certificate) {
	t.Helper()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")
	key, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "nick-ipad.ha.apps.somemissing.info"}.Expand(),
		SAN:              SAN{DNSNames: []string{"nick-ipad.ha.apps.somemissing.info"}, EmailAddresses: []string{"nick@venenga.com"}},
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
		ExtKeyUsage:      &ExtKeyUsage{Usages: []string{"clientAuth"}},
	}, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	return leaf, key, ca
}

// testLeafWithAlgorithm is testLeaf with a caller-chosen key algorithm for the
// leaf. The CA stays ECDSA; the two are independent.
func testLeafWithAlgorithm(t *testing.T, alg Algorithm) (*x509.Certificate, crypto.Signer, *x509.Certificate) {
	t.Helper()
	ca, caKey := testCA(t, nil, nil, "homelab-ca")
	key, err := GenerateKey(KeyParams{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", alg, err)
	}
	serial, err := RandomSerial()
	if err != nil {
		t.Fatalf("RandomSerial: %v", err)
	}
	certPEM, err := CreateCertificate(CertTemplate{
		Subject:          NamedSubject{CommonName: "leaf-" + string(alg)}.Expand(),
		Serial:           serial,
		NotBefore:        time.Now().Add(-time.Hour),
		NotAfter:         time.Now().Add(24 * time.Hour),
		BasicConstraints: &BasicConstraints{CA: false, Critical: true},
		KeyUsage:         DefaultLeafKeyUsagePtr(),
	}, PublicKeyOf(key), ca, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", alg, err)
	}
	leaf, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	return leaf, key, ca
}

// pkcs12Algorithms summarizes a PKCS#12 file's algorithm identifiers, so tests
// can compare two files whose salts and IVs necessarily differ.
func pkcs12Algorithms(t *testing.T, pfx []byte) string {
	t.Helper()
	text := opensslRun(t, pfx, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+testPassword)
	var kept []string
	for _, line := range strings.Split(text, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(l, "encryption") || strings.Contains(l, "mac") || strings.Contains(l, "pbe") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "|")
}

// requireKeytool returns the path to keytool, or "" when it is absent. Pass
// mustHave = true to skip the test instead of returning empty.
func requireKeytool(t *testing.T, mustHave bool) string {
	t.Helper()
	path, err := exec.LookPath("keytool")
	if err != nil {
		if mustHave {
			t.Skip("keytool not found in PATH; skipping cross-validation")
		}
		return ""
	}
	return path
}

// keytoolList runs `keytool -list` over a PKCS#12 or JKS file.
func keytoolList(t *testing.T, store []byte, password string) string {
	t.Helper()
	bin := requireKeytool(t, true)
	dir := t.TempDir()
	path := filepath.Join(dir, "store")
	if err := os.WriteFile(path, store, 0o600); err != nil {
		t.Fatalf("writing the keystore: %v", err)
	}
	cmd := exec.Command(bin, "-list", "-keystore", path, "-storepass", password)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("keytool -list failed: %v\n%s", err, out)
	}
	return string(out)
}

// opensslRun pipes input to openssl with the given arguments and returns
// combined output, failing the test if openssl exits non-zero.
func opensslRun(t *testing.T, input []byte, args ...string) string {
	t.Helper()
	bin := requireOpenSSL(t)
	cmd := exec.Command(bin, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
