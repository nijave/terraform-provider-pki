// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/smallstep/pkcs7"
)

// testLeaf issues a leaf under a fresh CA and returns the leaf, its key, and the
// CA certificate, which is the shape every bundle test needs.
func TestEncodeBundlePEMOrdering(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format:      FormatPEM,
		Certificate: leaf,
		PrivateKey:  leafKey,
		Chain:       []*x509.Certificate{ca},
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	// Order is certificate, then chain leaf-adjacent first, then the private
	// key last. Documented and asserted because consumers that read only the
	// first block must get the end-entity certificate.
	var types []string
	rest := out
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		types = append(types, block.Type)
	}
	if len(rest) != 0 {
		t.Errorf("%d trailing bytes after the last PEM block", len(rest))
	}
	want := []string{"CERTIFICATE", "CERTIFICATE", "EC PRIVATE KEY"}
	if len(types) != len(want) {
		t.Fatalf("block types = %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Errorf("block %d = %q, want %q", i, types[i], want[i])
		}
	}
}

func TestEncodeBundlePEMOmitsAbsentParts(t *testing.T) {
	t.Parallel()
	// Spec section 6.6: the optional fields are the switches. No private_key_pem
	// yields a cert-only bundle; no chain_pem yields no chain.
	leaf, leafKey, ca := testLeaf(t)

	certOnly, err := EncodeBundle(BundleInput{Format: FormatPEM, Certificate: leaf})
	if err != nil {
		t.Fatalf("EncodeBundle (cert only): %v", err)
	}
	if strings.Contains(string(certOnly), "PRIVATE KEY") {
		t.Error("a bundle with no private key contains a PRIVATE KEY block")
	}
	if n := strings.Count(string(certOnly), "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("cert-only bundle has %d certificates, want 1", n)
	}

	keyOnly, err := EncodeBundle(BundleInput{Format: FormatPEM, PrivateKey: leafKey})
	if err != nil {
		t.Fatalf("EncodeBundle (key only): %v", err)
	}
	if strings.Contains(string(keyOnly), "BEGIN CERTIFICATE") {
		t.Error("a bundle with no certificate contains a CERTIFICATE block")
	}

	noChain, err := EncodeBundle(BundleInput{Format: FormatPEM, Certificate: leaf, PrivateKey: leafKey})
	if err != nil {
		t.Fatalf("EncodeBundle (no chain): %v", err)
	}
	if n := strings.Count(string(noChain), "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("no-chain bundle has %d certificates, want 1", n)
	}
	_ = ca
}

func TestEncodeBundleRejectsEmptyInput(t *testing.T) {
	t.Parallel()
	// Every field being optional does not make an empty bundle meaningful.
	for _, f := range Formats() {
		if _, err := EncodeBundle(BundleInput{Format: f}); err == nil {
			t.Errorf("EncodeBundle(%s) with nothing to encode returned nil error, want an error", f)
		}
	}
	// The unknown format carries a certificate on purpose. Without one, the
	// nothing-to-encode check above rejects the input first and the dispatch's
	// own default branch is never reached, so an unknown format that fell through
	// to pem instead of erroring would still look tested.
	leaf, _, _ := testLeaf(t)
	_, err := EncodeBundle(BundleInput{Format: "pkcs11", Certificate: leaf})
	if err == nil {
		t.Fatal("EncodeBundle accepted an unknown format")
	}
	if !strings.Contains(err.Error(), "unknown bundle format") {
		t.Errorf("error = %q, want the dispatch's own unknown-format message", err)
	}
}

func TestEncodeBundleDER(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{Format: FormatDER, Certificate: leaf})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	if !bytes.Equal(out, leaf.Raw) {
		t.Error("DER output is not the certificate's raw DER")
	}
	parsed, err := x509.ParseCertificate(out)
	if err != nil {
		t.Fatalf("emitted DER does not parse: %v", err)
	}
	if !bytes.Equal(parsed.RawSubject, leaf.RawSubject) {
		t.Error("round-tripped DER has a different subject")
	}

	// DER holds exactly one certificate and no key. Silently dropping the
	// extra parts would produce a bundle that looks fine and is missing half
	// its contents, so both are errors.
	for label, in := range map[string]BundleInput{
		"with key":   {Format: FormatDER, Certificate: leaf, PrivateKey: leafKey},
		"with chain": {Format: FormatDER, Certificate: leaf, Chain: []*x509.Certificate{ca}},
		"key only":   {Format: FormatDER, PrivateKey: leafKey},
	} {
		if _, err := EncodeBundle(in); err == nil {
			t.Errorf("EncodeBundle(der, %s) returned nil error, want an error", label)
		}
	}
}

func TestEncodeBundlePKCS7(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format:      FormatPKCS7,
		Certificate: leaf,
		Chain:       []*x509.Certificate{ca},
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	p7, err := pkcs7.Parse(out)
	if err != nil {
		t.Fatalf("emitted PKCS#7 does not parse: %v", err)
	}
	if len(p7.Certificates) != 2 {
		t.Fatalf("PKCS#7 holds %d certificates, want 2", len(p7.Certificates))
	}
	if !bytes.Equal(p7.Certificates[0].Raw, leaf.Raw) {
		t.Error("the first certificate in the PKCS#7 bundle is not the leaf")
	}
	if !bytes.Equal(p7.Certificates[1].Raw, ca.Raw) {
		t.Error("the second certificate in the PKCS#7 bundle is not the CA")
	}

	// PKCS#7 as produced here is a degenerate certs-only structure. It cannot
	// carry a private key, and quietly discarding one would be a data-loss bug.
	if _, err := EncodeBundle(BundleInput{Format: FormatPKCS7, Certificate: leaf, PrivateKey: leafKey}); err == nil {
		t.Error("EncodeBundle(pkcs7) accepted a private key, which the format cannot carry")
	}
}

// TestEncodeBundlePKCS7ChainOnly covers a case the brief's own examples never
// exercise: Certificate absent, only Chain set. der explicitly requires a
// certificate and rejects a chain-only input, but the brief states no such
// requirement for pkcs7, and pkcs7's degenerate SignedData has no concept of
// "the" certificate versus "the" chain -- it is just a set. Without this test,
// an implementation that dereferences Certificate.Raw unconditionally would
// panic on this input instead of erroring or succeeding, and nothing in the
// brief's test list would have caught it.
func TestEncodeBundlePKCS7ChainOnly(t *testing.T) {
	t.Parallel()
	_, _, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{Format: FormatPKCS7, Chain: []*x509.Certificate{ca}})
	if err != nil {
		t.Fatalf("EncodeBundle (chain only): %v", err)
	}
	p7, err := pkcs7.Parse(out)
	if err != nil {
		t.Fatalf("emitted PKCS#7 does not parse: %v", err)
	}
	if len(p7.Certificates) != 1 {
		t.Fatalf("PKCS#7 holds %d certificates, want 1", len(p7.Certificates))
	}
	if !bytes.Equal(p7.Certificates[0].Raw, ca.Raw) {
		t.Error("the certificate in the chain-only PKCS#7 bundle is not the CA")
	}
}

func TestEncodeBundlePKCS7IsReadableByOpenSSL(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	leaf, _, ca := testLeaf(t)
	out, err := EncodeBundle(BundleInput{Format: FormatPKCS7, Certificate: leaf, Chain: []*x509.Certificate{ca}})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	text := opensslRun(t, out, "pkcs7", "-inform", "DER", "-print_certs", "-noout")
	if n := strings.Count(text, "subject="); n != 2 {
		t.Fatalf("openssl pkcs7 -print_certs found %d certificates, want 2:\n%s", n, text)
	}
}

// TestEncodeBundleRejectsAPasswordOnUnencryptableFormats is the one silent-drop
// case in this file with a security consequence, and the only one that used to
// pass. pem, der, and pkcs7 have nowhere to put a password: pem emitted a
// plaintext PRIVATE KEY block while the operator had asked for encryption, and
// der and pkcs7 discarded the request outright. Every other silently-dropped
// combination here is already an error by name, so this one is too.
func TestEncodeBundleRejectsAPasswordOnUnencryptableFormats(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)

	for _, tc := range []struct {
		format Format
		in     BundleInput
	}{
		{FormatPEM, BundleInput{Format: FormatPEM, Certificate: leaf, PrivateKey: leafKey, Password: testPassword}},
		{FormatDER, BundleInput{Format: FormatDER, Certificate: leaf, Password: testPassword}},
		{FormatPKCS7, BundleInput{Format: FormatPKCS7, Certificate: leaf, Chain: []*x509.Certificate{ca}, Password: testPassword}},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			t.Parallel()
			out, err := EncodeBundle(tc.in)
			if err == nil {
				t.Fatalf("EncodeBundle(%s) with a password returned %d bytes and no error; the password was silently dropped",
					tc.format, len(out))
			}
			// The message has to name the attribute to clear, the way
			// pkcs12_encoding "passwordless" does.
			if !strings.Contains(err.Error(), "password_wo") {
				t.Errorf("error = %q, want it to name password_wo", err)
			}
		})
	}

	// The same inputs without a password are still accepted: this is a check on
	// the password, not a new restriction on the formats.
	for _, tc := range []struct {
		format Format
		in     BundleInput
	}{
		{FormatPEM, BundleInput{Format: FormatPEM, Certificate: leaf, PrivateKey: leafKey}},
		{FormatDER, BundleInput{Format: FormatDER, Certificate: leaf}},
		{FormatPKCS7, BundleInput{Format: FormatPKCS7, Certificate: leaf, Chain: []*x509.Certificate{ca}}},
	} {
		if _, err := EncodeBundle(tc.in); err != nil {
			t.Errorf("EncodeBundle(%s) without a password: %v", tc.format, err)
		}
	}
}

// TestEncodeBundleErrorsNameAttributesWithoutEchoingKeys pins both halves of this
// file's error discipline at once, over every rejected input EncodeBundle has.
//
// The naming half: a bundle error surfaces in a `tofu plan` diagnostic with no
// stack trace and no line number, so "requires a certificate" leaves the operator
// choosing between certificate_pem, private_key_pem and chain_pem by guesswork.
// TestEncodeBundleRejectsAPasswordOnUnencryptableFormats already held the password
// errors to this standard; the missing-certificate and key-mismatch errors were
// the ones that did not name anything, which is what this test closes.
//
// The no-echo half is the harder constraint and the reason the two are asserted
// together rather than in separate tests: the natural way to make an error more
// helpful is to show the value that was wrong, and for private_key_pem that would
// write key material into a plan log. Every case below therefore carries a real
// key, and the error is checked against that key's PEM, its base64 body, and its
// raw DER. Splitting the two assertions would let a future "helpful" error pass
// the naming test while leaking.
func TestEncodeBundleErrorsNameAttributesWithoutEchoingKeys(t *testing.T) {
	t.Parallel()
	leaf, leafKey, ca := testLeaf(t)
	otherKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	for label, tc := range map[string]struct {
		in   BundleInput
		want []string
	}{
		"nothing to encode": {
			BundleInput{Format: FormatPEM},
			[]string{"certificate_pem", "private_key_pem", "chain_pem"},
		},
		"unknown format": {
			BundleInput{Format: "pkcs11", Certificate: leaf},
			[]string{"format"},
		},
		// encodeDER checks for a missing certificate before it checks for an
		// unencodable private key, so these two inputs reach different branches
		// and both are listed.
		"der without a certificate": {
			BundleInput{Format: FormatDER, PrivateKey: leafKey},
			[]string{"certificate_pem"},
		},
		"der with a key": {
			BundleInput{Format: FormatDER, Certificate: leaf, PrivateKey: leafKey},
			[]string{"private_key_pem"},
		},
		"der with a chain": {
			BundleInput{Format: FormatDER, Certificate: leaf, Chain: []*x509.Certificate{ca}},
			[]string{"chain_pem"},
		},
		"pkcs7 with a key": {
			BundleInput{Format: FormatPKCS7, Certificate: leaf, PrivateKey: leafKey},
			[]string{"private_key_pem"},
		},
		"pkcs12 key without a certificate": {
			BundleInput{Format: FormatPKCS12, PrivateKey: leafKey, Password: testPassword},
			[]string{"certificate_pem", "private_key_pem"},
		},
		"pkcs12 mismatched key": {
			BundleInput{Format: FormatPKCS12, Certificate: leaf, PrivateKey: otherKey, Password: testPassword},
			[]string{"certificate_pem", "private_key_pem"},
		},
		"pkcs12 without a password": {
			BundleInput{Format: FormatPKCS12, Certificate: leaf, PrivateKey: leafKey},
			[]string{"password_wo", "pkcs12_encoding"},
		},
		"jks key without a certificate": {
			BundleInput{Format: FormatJKS, PrivateKey: leafKey, Password: testPassword},
			[]string{"certificate_pem", "private_key_pem"},
		},
		"jks mismatched key": {
			BundleInput{Format: FormatJKS, Certificate: leaf, PrivateKey: otherKey, Password: testPassword},
			[]string{"certificate_pem", "private_key_pem"},
		},
		"jks short password": {
			BundleInput{Format: FormatJKS, Certificate: leaf, PrivateKey: leafKey, Password: "12345"},
			[]string{"password_wo"},
		},
	} {
		out, err := EncodeBundle(tc.in)
		if err == nil {
			t.Errorf("EncodeBundle(%s) returned %d bytes and no error", label, len(out))
			continue
		}
		msg := err.Error()
		for _, want := range tc.want {
			if !strings.Contains(msg, want) {
				t.Errorf("EncodeBundle(%s) error = %q, want it to name %q", label, msg, want)
			}
		}
		assertNoKeyMaterial(t, label, msg, leafKey, otherKey)
	}
}

// assertNoKeyMaterial fails when msg contains any encoding of any of the given
// keys.
//
// Both PEM encodings are checked, and both matter: EncodePrivateKeyPEM emits SEC1
// for an ECDSA key while EncodePrivateKeyPKCS8DER emits PKCS#8, so their base64
// bodies share no long substring and checking one would miss a leak of the other.
// Each body is then checked in fixed-length slices rather than whole, because a
// message that quoted a single wrapped line of a key -- or truncated it, the way
// hexPreview in compare.go deliberately does for extension values -- would still
// be a leak, and comparing whole bodies would not see it.
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
			if strings.Contains(msg, string(der)) {
				t.Errorf("EncodeBundle(%s) error echoes key %d's raw %s DER: %q", label, i, form, msg)
			}
			b64 := base64.StdEncoding.EncodeToString(der)
			// Every 16-character window, stepped one character at a time -- not
			// every 16th window. A stride equal to the window length only catches
			// a leak that happens to be aligned to it: measured during this
			// change, an error echoing 32 characters starting mid-line contained
			// no whole 24-aligned run and slipped past a strided check. 16 base64
			// characters is 12 bytes of key, far past any chance of a
			// coincidental match, and the whole loop is a few hundred substring
			// searches over a one-line message.
			const window = 16
			for start := 0; start+window <= len(b64); start++ {
				if strings.Contains(msg, b64[start:start+window]) {
					t.Errorf("EncodeBundle(%s) error echoes key %d's %s base64 body at offset %d: %q", label, i, form, start, msg)
					break
				}
			}
		}
	}
}

func TestFormatIsText(t *testing.T) {
	t.Parallel()
	// Spec section 6.6: content is set for text formats and null for binary
	// ones; content_base64 is always set.
	for f, want := range map[Format]bool{
		FormatPEM:    true,
		FormatDER:    false,
		FormatPKCS7:  false,
		FormatPKCS12: false,
		FormatJKS:    false,
	} {
		if got := f.IsText(); got != want {
			t.Errorf("Format(%s).IsText() = %v, want %v", f, got, want)
		}
	}
}
