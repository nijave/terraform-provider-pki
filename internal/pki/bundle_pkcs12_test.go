// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"strings"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const testPassword = "password" // matches engine.py's default p12_password

func TestEncodePKCS12RoundTripsAllKeyAlgorithms(t *testing.T) {
	t.Parallel()
	// Spec section 10 requires all three algorithms, with and without a chain.
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		for _, withChain := range []bool{false, true} {
			leaf, key, ca := testLeafWithAlgorithm(t, alg)
			in := BundleInput{
				Format:      FormatPKCS12,
				Certificate: leaf,
				PrivateKey:  key,
				Password:    testPassword,
			}
			if withChain {
				in.Chain = []*x509.Certificate{ca}
			}
			out, err := EncodeBundle(in)
			if err != nil {
				t.Errorf("%s chain=%v: EncodeBundle: %v", alg, withChain, err)
				continue
			}
			gotKey, gotCert, gotChain, err := pkcs12.DecodeChain(out, testPassword)
			if err != nil {
				t.Errorf("%s chain=%v: DecodeChain: %v", alg, withChain, err)
				continue
			}
			if !bytes.Equal(gotCert.Raw, leaf.Raw) {
				t.Errorf("%s chain=%v: decoded certificate differs from the input", alg, withChain)
			}
			signer, ok := gotKey.(interface{ Public() crypto.PublicKey })
			if !ok {
				t.Errorf("%s chain=%v: decoded key %T is not a signer", alg, withChain, gotKey)
				continue
			}
			if !PublicKeysEqual(signer.Public(), PublicKeyOf(key)) {
				t.Errorf("%s chain=%v: decoded key does not match the input key", alg, withChain)
			}
			wantChain := 0
			if withChain {
				wantChain = 1
			}
			if len(gotChain) != wantChain {
				t.Errorf("%s chain=%v: decoded %d CA certificates, want %d", alg, withChain, len(gotChain), wantChain)
			}
		}
	}
}

func TestEncodePKCS12DefaultsToModern(t *testing.T) {
	t.Parallel()
	// Spec section 6.6: modern is the default because it is what engine.py's
	// bare `openssl pkcs12 -export` already produces under OpenSSL 3, making
	// the migration behavior-preserving.
	leaf, key, _ := testLeaf(t)
	withDefault, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (default encoding): %v", err)
	}
	explicit, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword,
		PKCS12Encoding: PKCS12Modern,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (explicit modern): %v", err)
	}
	// Salts and IVs are random, so compare the algorithms rather than the bytes.
	if a, b := pkcs12Algorithms(t, withDefault), pkcs12Algorithms(t, explicit); a != b {
		t.Fatalf("the default encoding produced %q but explicit modern produced %q", a, b)
	}
}

// TestEncodePKCS12EmittedAlgorithms is the assertion spec section 6.6 demands.
// Encryption and MAC are independent failure axes on mobile platforms: Android
// 12 rejects a SHA-256 MAC even when the content is 3DES, so a bundle that
// merely decodes in Go can still be unimportable on a device.
//
// The expected substrings are the labels OpenSSL 3.5.7 (9 Jun 2026) actually
// prints for a leaf plus a one-certificate chain. Recorded verbatim so a future
// failure can be attributed to a tool change rather than a code change:
//
//	modern:
//	  MAC: sha256, Iteration 2048
//	  MAC length: 32, salt length: 16
//	  PKCS7 Encrypted data: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256
//	  Certificate bag
//	  Certificate bag
//	  PKCS7 Data
//	  Shrouded Keybag: PBES2, PBKDF2, AES-256-CBC, Iteration 2048, PRF hmacWithSHA256
//
//	legacy:
//	  MAC: sha1, Iteration 1
//	  MAC length: 20, salt length: 8
//	  PKCS7 Encrypted data: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
//	  Certificate bag
//	  Certificate bag
//	  PKCS7 Data
//	  Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2048
//
// Note that OpenSSL names the 3DES PBE by its PKCS#12 algorithm identifier,
// pbeWithSHA1And3-KeyTripleDES-CBC, and never prints the cipher name
// "des-ede3-cbc" here. Asserting on the cipher name would fail always in the
// wantInOutput direction and pass vacuously in the notInOutput direction.
//
// keytool 25.0.3 (OpenJDK 25.0.3) reads both files and lists a single
// PrivateKeyEntry in each.
func TestEncodePKCS12EmittedAlgorithms(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	leaf, key, ca := testLeaf(t)

	for _, tc := range []struct {
		encoding     PKCS12Encoding
		password     string
		wantInOutput []string
		notInOutput  []string
	}{
		{
			encoding: PKCS12Modern,
			password: testPassword,
			// AES-256-CBC content encryption with PBKDF2, HMAC-SHA256 MAC.
			wantInOutput: []string{"PBES2", "PBKDF2", "AES-256-CBC", "MAC: sha256", "hmacWithSHA256"},
			notInOutput:  []string{"TripleDES", "RC2", "MAC: sha1"},
		},
		{
			encoding: PKCS12Legacy,
			password: testPassword,
			// 3DES content encryption, SHA-1 MAC. This is the only combination
			// that is universally importable on iOS < 18 and Android < 14.
			wantInOutput: []string{"pbeWithSHA1And3-KeyTripleDES-CBC", "MAC: sha1"},
			notInOutput:  []string{"PBES2", "AES-256-CBC", "RC2", "sha256"},
		},
	} {
		out, err := EncodeBundle(BundleInput{
			Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
			Chain: []*x509.Certificate{ca}, Password: tc.password, PKCS12Encoding: tc.encoding,
		})
		if err != nil {
			t.Errorf("%s: EncodeBundle: %v", tc.encoding, err)
			continue
		}
		// `openssl pkcs12 -info -nokeys -nocerts` prints the algorithm
		// identifiers for each SafeBag and the MAC without needing to decrypt
		// anything beyond the structure.
		text := opensslRun(t, out, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+tc.password)
		lower := strings.ToLower(text)
		for _, want := range tc.wantInOutput {
			if !strings.Contains(lower, strings.ToLower(want)) {
				t.Errorf("%s: openssl pkcs12 -info output does not mention %q:\n%s", tc.encoding, want, text)
			}
		}
		for _, unwanted := range tc.notInOutput {
			if strings.Contains(lower, strings.ToLower(unwanted)) {
				t.Errorf("%s: openssl pkcs12 -info output unexpectedly mentions %q:\n%s", tc.encoding, unwanted, text)
			}
		}
	}
}

// TestEncodePKCS12ModernAndLegacyDifferInBothAxes guards against a partial
// implementation that switches the content cipher but leaves the MAC alone.
// Android 12 would reject the result even though the content is 3DES.
func TestEncodePKCS12ModernAndLegacyDifferInBothAxes(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	leaf, key, _ := testLeaf(t)

	modern, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
		Password: testPassword, PKCS12Encoding: PKCS12Modern,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (modern): %v", err)
	}
	legacy, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
		Password: testPassword, PKCS12Encoding: PKCS12Legacy,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (legacy): %v", err)
	}

	modernText := strings.ToLower(opensslRun(t, modern, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+testPassword))
	legacyText := strings.ToLower(opensslRun(t, legacy, "pkcs12", "-info", "-nokeys", "-nocerts", "-passin", "pass:"+testPassword))

	if !strings.Contains(modernText, "mac: sha256") {
		t.Errorf("modern did not emit a SHA-256 MAC:\n%s", modernText)
	}
	if !strings.Contains(legacyText, "mac: sha1") {
		t.Errorf("legacy did not emit a SHA-1 MAC; Android 12 rejects SHA-256 even with 3DES content:\n%s", legacyText)
	}
	// The content cipher is the other axis, and it must differ too.
	if !strings.Contains(modernText, "aes-256-cbc") {
		t.Errorf("modern did not emit AES-256-CBC content encryption:\n%s", modernText)
	}
	if !strings.Contains(legacyText, "tripledes") {
		t.Errorf("legacy did not emit 3DES content encryption:\n%s", legacyText)
	}
}

func TestEncodePKCS12Passwordless(t *testing.T) {
	t.Parallel()
	// The Passwordless encoder has no encryption and no MAC, and go-pkcs12
	// rejects a non-empty password with it. The provider must translate that
	// into a clear error rather than passing the confusion through.
	leaf, _, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, Chain: []*x509.Certificate{ca},
		PKCS12Encoding: PKCS12Passwordless,
	})
	if err != nil {
		t.Fatalf("EncodeBundle (passwordless truststore): %v", err)
	}
	certs, err := pkcs12.DecodeTrustStore(out, "")
	if err != nil {
		t.Fatalf("DecodeTrustStore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("passwordless truststore holds %d certificates, want 2", len(certs))
	}

	_, err = EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf,
		PKCS12Encoding: PKCS12Passwordless, Password: testPassword,
	})
	if err == nil {
		t.Fatal("EncodeBundle accepted a password with the passwordless encoding")
	}
	if !strings.Contains(err.Error(), "passwordless") {
		t.Errorf("error %q does not mention the passwordless encoding", err.Error())
	}
}

// TestEncodePKCS12WithoutKeyBuildsATrustStore covers the structural distinction
// spec section 6.6 calls out: a PKCS#12 truststore is a different artifact from
// a cert-only keystore, and go-pkcs12 has a separate encoder for it.
func TestEncodePKCS12WithoutKeyBuildsATrustStore(t *testing.T) {
	t.Parallel()
	leaf, _, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, Chain: []*x509.Certificate{ca},
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	certs, err := pkcs12.DecodeTrustStore(out, testPassword)
	if err != nil {
		t.Fatalf("a keyless PKCS#12 bundle did not decode as a truststore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("truststore holds %d certificates, want 2", len(certs))
	}
	// DecodeChain expects a key entry and must fail on a truststore, which is
	// what proves the two artifacts really are structurally different.
	if _, _, _, err := pkcs12.DecodeChain(out, testPassword); err == nil {
		t.Error("DecodeChain succeeded on a truststore; the keyless path is not producing a truststore")
	}
}

func TestEncodePKCS12FriendlyName(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)

	// With a key, FriendlyName cannot become the keystore alias: go-pkcs12
	// v0.7.3's Encoder.Encode sets only the localKeyId attribute and offers no
	// way to add a friendlyName, so Java synthesizes the alias "1". Only
	// EncodeTrustStoreEntries, used by the keyless path below, carries names.
	//
	// This assertion is deliberately negative so it fails loudly if go-pkcs12
	// ever gains friendlyName support on Encode: when it does, honour
	// FriendlyName in encodePKCS12's keystore branch and flip this back to
	// asserting the alias is present.
	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
		Password: testPassword, FriendlyName: "nick-ipad",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	if requireKeytool(t, false) != "" {
		text := keytoolList(t, out, testPassword)
		if !strings.Contains(text, "PrivateKeyEntry") {
			t.Errorf("keytool -list does not show a PrivateKeyEntry:\n%s", text)
		}
		if strings.Contains(strings.ToLower(text), "nick-ipad") {
			t.Errorf("keytool -list shows the alias nick-ipad; go-pkcs12 gained friendlyName support on Encode, so encodePKCS12 should now use it:\n%s", text)
		}
	}

	// Without a key, distinct aliases still matter: go-pkcs12's
	// EncodeTrustStore derives names from each certificate's subject, so two
	// certificates sharing a subject collide into one entry. The truststore
	// path must use EncodeTrustStoreEntries with explicit names.
	out, err = EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, Chain: []*x509.Certificate{ca},
		Password: testPassword, FriendlyName: "homelab",
	})
	if err != nil {
		t.Fatalf("EncodeBundle (truststore with friendly name): %v", err)
	}
	certs, err := pkcs12.DecodeTrustStore(out, testPassword)
	if err != nil {
		t.Fatalf("DecodeTrustStore: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("truststore holds %d certificates, want 2; distinct aliases were not preserved", len(certs))
	}
	if requireKeytool(t, false) != "" {
		text := keytoolList(t, out, testPassword)
		for _, want := range []string{"homelab-1", "homelab-2"} {
			if !strings.Contains(strings.ToLower(text), want) {
				t.Errorf("keytool -list does not show the truststore alias %q:\n%s", want, text)
			}
		}
	}
}

// TestEncodePKCS12TrustStoreAliasesAreDistinct is the reason the truststore path
// uses EncodeTrustStoreEntries. Two certificates can share a subject -- a re-keyed
// or cross-signed root is the common case -- and keytool treats identical aliases
// as one entry, silently dropping a trust anchor. DecodeTrustStore returns both
// certificates either way, so only keytool can observe the collapse.
func TestEncodePKCS12TrustStoreAliasesAreDistinct(t *testing.T) {
	t.Parallel()
	requireKeytool(t, true)
	// Two independent self-signed roots with the same subject.
	first, _ := testCA(t, nil, nil, "duplicate-subject")
	second, _ := testCA(t, nil, nil, "duplicate-subject")

	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: first, Chain: []*x509.Certificate{second},
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	text := keytoolList(t, out, testPassword)
	if !strings.Contains(text, "contains 2 entries") {
		t.Errorf("keytool -list does not report 2 entries; certificates sharing a subject collapsed into one alias:\n%s", text)
	}
}

// TestEncodePKCS12TrustStoreAliasesAreCaseInsensitivelyDistinct is the same
// hazard one step subtler. Java folds PKCS#12 aliases to lowercase, so common
// names of "Root" and "root" are a collision even though the strings differ, and
// a dedup keyed on the raw string lets both through unchanged. Measured before
// the fix: aliases [Root root] and `keytool -list` reporting 1 entry, silently
// dropping a trust anchor.
//
// This is distinct from TestEncodePKCS12TrustStoreAliasesAreDistinct, which uses
// identical subjects and therefore passes even with a case-sensitive dedup.
func TestEncodePKCS12TrustStoreAliasesAreCaseInsensitivelyDistinct(t *testing.T) {
	t.Parallel()
	requireKeytool(t, true)
	upper, _ := testCA(t, nil, nil, "Root")
	lower, _ := testCA(t, nil, nil, "root")

	out, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: upper, Chain: []*x509.Certificate{lower},
		Password: testPassword,
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	text := keytoolList(t, out, testPassword)
	if !strings.Contains(text, "contains 2 entries") {
		t.Errorf("keytool -list does not report 2 entries; aliases differing only in case collapsed:\n%s", text)
	}
}

// TestEncodePKCS12PasswordlessRejectsAPrivateKey covers a combination that
// encodes without complaint and is then unreadable by the only consumer that
// wants it. pkcs12.Passwordless.Encode emits an unshrouded key bag: openssl
// prints the key bag and both certificates, and pkcs12.DecodeChain reads it back
// intact, but `keytool -list` reports 0 entries -- and Java truststores are the
// entire reason this encoding exists.
func TestEncodePKCS12PasswordlessRejectsAPrivateKey(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	_, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: key,
		Chain: []*x509.Certificate{ca}, PKCS12Encoding: PKCS12Passwordless,
	})
	if err == nil {
		t.Fatal("EncodeBundle accepted a private key with the passwordless encoding; Java reads the result as empty")
	}
	// The message has to tell an operator which attribute to change and where an
	// unencrypted private key does belong.
	for _, want := range []string{"pkcs12_encoding", "private_key_pem", "pem"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

func TestEncodePKCS12RejectsBadInput(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	for label, in := range map[string]BundleInput{
		"unknown encoding": {Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword, PKCS12Encoding: "ancient"},
		"legacy rc2":       {Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword, PKCS12Encoding: "legacy-rc2"},
		"modern 2026":      {Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, Password: testPassword, PKCS12Encoding: "modern2026"},
		"key without cert": {Format: FormatPKCS12, PrivateKey: key, Password: testPassword},
		"empty password":   {Format: FormatPKCS12, Certificate: leaf, PrivateKey: key, PKCS12Encoding: PKCS12Modern},
	} {
		if _, err := EncodeBundle(in); err == nil {
			t.Errorf("EncodeBundle(pkcs12, %s) returned nil error, want an error", label)
		}
	}
}

// TestEncodePKCS12MismatchedKeyAndCertificateIsRejected catches a wiring error
// in HCL -- pairing one device's key with another's certificate -- that would
// otherwise produce a bundle the device installs and then fails TLS with.
func TestEncodePKCS12MismatchedKeyAndCertificateIsRejected(t *testing.T) {
	t.Parallel()
	leaf, _, _ := testLeaf(t)
	otherKey, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := EncodeBundle(BundleInput{
		Format: FormatPKCS12, Certificate: leaf, PrivateKey: otherKey, Password: testPassword,
	}); err == nil {
		t.Fatal("EncodeBundle accepted a private key that does not match the certificate")
	}
}

func TestPKCS12EncodingsList(t *testing.T) {
	t.Parallel()
	got := PKCS12Encodings()
	want := []PKCS12Encoding{PKCS12Modern, PKCS12Legacy, PKCS12Passwordless}
	if len(got) != len(want) {
		t.Fatalf("PKCS12Encodings() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("PKCS12Encodings()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// LegacyRC2 must not be reachable: it emits RC2-40, which OpenSSL 3 cannot
	// decrypt (spec section 6.6). Modern2026 uses PBMAC1 and no mobile platform
	// reads it.
	for _, forbidden := range []PKCS12Encoding{"legacy-rc2", "legacyrc2", "rc2", "modern2026"} {
		for _, allowed := range got {
			if allowed == forbidden {
				t.Errorf("PKCS12Encodings() exposes %q, which must not be offered", forbidden)
			}
		}
	}
}
