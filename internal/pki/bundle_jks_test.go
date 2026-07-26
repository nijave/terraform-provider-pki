// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestEncodeJKSWithPrivateKeyEntry(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, PrivateKey: key,
		Chain: []*x509.Certificate{ca}, Password: testPassword, FriendlyName: "nick-ipad",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}

	// A JKS starts with the magic bytes 0xfeedfeed.
	if len(out) < 4 || !bytes.Equal(out[:4], []byte{0xfe, 0xed, 0xfe, 0xed}) {
		t.Fatalf("output does not start with the JKS magic 0xfeedfeed: % x", out[:min(4, len(out))])
	}

	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(out), []byte(testPassword)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 1 || aliases[0] != "nick-ipad" {
		t.Fatalf("aliases = %v, want [nick-ipad]", aliases)
	}
	if !ks.IsPrivateKeyEntry("nick-ipad") {
		t.Fatal("the entry is not a private key entry")
	}
	entry, err := ks.GetPrivateKeyEntry("nick-ipad", []byte(testPassword))
	if err != nil {
		t.Fatalf("GetPrivateKeyEntry: %v", err)
	}
	if len(entry.CertificateChain) != 2 {
		t.Fatalf("certificate chain has %d entries, want 2", len(entry.CertificateChain))
	}
	if !bytes.Equal(entry.CertificateChain[0].Content, leaf.Raw) {
		t.Error("the first chain entry is not the leaf certificate")
	}
	for i, c := range entry.CertificateChain {
		// keystore-go's own decoder writes "X509"; anything else is unreadable
		// by Java.
		if c.Type != "X509" {
			t.Errorf("chain entry %d has certificate type %q, want \"X509\"", i, c.Type)
		}
	}
}

// TestEncodeJKSStoresPKCS8PrivateKey is the assertion that catches the trap in
// keystore-go: it does not validate the key encoding, so storing a SEC1 blob
// succeeds and produces a file only Java rejects.
func TestEncodeJKSStoresPKCS8PrivateKey(t *testing.T) {
	t.Parallel()
	for _, alg := range []Algorithm{AlgorithmRSA, AlgorithmECDSA, AlgorithmED25519} {
		leaf, key, _ := testLeafWithAlgorithm(t, alg)
		out, err := EncodeBundle(BundleInput{
			Format: FormatJKS, Certificate: leaf, PrivateKey: key,
			Password: testPassword, FriendlyName: "alias",
		})
		if err != nil {
			t.Errorf("%s: EncodeBundle: %v", alg, err)
			continue
		}
		ks := keystore.New()
		if err := ks.Load(bytes.NewReader(out), []byte(testPassword)); err != nil {
			t.Errorf("%s: Load: %v", alg, err)
			continue
		}
		entry, err := ks.GetPrivateKeyEntry("alias", []byte(testPassword))
		if err != nil {
			t.Errorf("%s: GetPrivateKeyEntry: %v", alg, err)
			continue
		}
		if _, err := x509.ParsePKCS8PrivateKey(entry.PrivateKey); err != nil {
			t.Errorf("%s: the stored private key is not PKCS#8 DER, which Java requires: %v", alg, err)
		}
	}
}

func TestEncodeJKSTrustedCertificateEntries(t *testing.T) {
	t.Parallel()
	leaf, _, ca := testLeaf(t)

	out, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, Chain: []*x509.Certificate{ca},
		Password: testPassword, FriendlyName: "homelab",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(out), []byte(testPassword)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 2 {
		t.Fatalf("aliases = %v, want 2 distinct entries", aliases)
	}
	for _, a := range aliases {
		if !ks.IsTrustedCertificateEntry(a) {
			t.Errorf("alias %q is not a trusted certificate entry", a)
		}
	}
}

// TestEncodeJKSTrustStoreFromChainOnly covers a supported provider config that
// nothing else did: chain_pem set with no certificate_pem, i.e. a truststore
// built entirely from the Chain. It works, and the surrounding tests all set
// Certificate, so the creationTime fallback to Chain[0].NotBefore and the
// alias derivation over a Certificate-less list were both unexercised.
//
// Determinism is asserted here rather than only in
// TestEncodeJKSTrustStoreIsDeterministic because the truststore path is the one
// held to full byte-determinism -- it has no password-gated secret shielding it
// from re-encoding, so churn here churns the Kubernetes Secret -- and the
// creationTime this input takes comes from a different branch.
func TestEncodeJKSTrustStoreFromChainOnly(t *testing.T) {
	t.Parallel()
	root, rootKey := testCA(t, nil, nil, "root")
	inter, _ := testCA(t, root, rootKey, "intermediate")
	in := BundleInput{
		Format: FormatJKS, Chain: []*x509.Certificate{inter, root},
		Password: testPassword,
	}

	out, err := EncodeBundle(in)
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(out), []byte(testPassword)); err != nil {
		t.Fatalf("Load: %v", err)
	}
	aliases := ks.Aliases()
	if len(aliases) != 2 {
		t.Fatalf("aliases = %v, want 2 entries, one per chain certificate", aliases)
	}
	for _, a := range aliases {
		if !ks.IsTrustedCertificateEntry(a) {
			t.Errorf("alias %q is not a trusted certificate entry", a)
		}
	}
	// creationTime falls back to Chain[0].NotBefore when Certificate is absent;
	// a time.Now() there would be invisible in the alias list and fatal to
	// determinism.
	entry, err := ks.GetTrustedCertificateEntry("intermediate")
	if err != nil {
		t.Fatalf("GetTrustedCertificateEntry: %v", err)
	}
	if !entry.CreationTime.Equal(inter.NotBefore) {
		t.Errorf("creationTime = %v, want the first chain entry's notBefore %v", entry.CreationTime, inter.NotBefore)
	}

	second, err := EncodeBundle(in)
	if err != nil {
		t.Fatalf("EncodeBundle (second): %v", err)
	}
	if !bytes.Equal(out, second) {
		t.Fatalf("two chain-only truststore encodes differ: %d bytes vs %d bytes", len(out), len(second))
	}
}

func TestEncodeJKSRejectsBadInput(t *testing.T) {
	t.Parallel()
	leaf, key, _ := testLeaf(t)
	for label, in := range map[string]BundleInput{
		"no password":    {Format: FormatJKS, Certificate: leaf, PrivateKey: key, FriendlyName: "a"},
		"short password": {Format: FormatJKS, Certificate: leaf, PrivateKey: key, Password: "12345", FriendlyName: "a"},
	} {
		if _, err := EncodeBundle(in); err == nil {
			t.Errorf("EncodeBundle(jks, %s) returned nil error, want an error", label)
		}
	}

	// "key without cert" gets its own assertion, on the message rather than
	// merely on error-ness: encodeJKS used to let creationTime's generic
	// nothing-to-derive-a-timestamp-from branch fire first for this input,
	// which shipped the wrong (and, per its own comment, supposedly
	// unreachable) error instead of the specific one naming the actual
	// problem. Asserting the substring pins the branch order so that
	// regression cannot come back silently.
	if _, err := EncodeBundle(BundleInput{
		Format: FormatJKS, PrivateKey: key, Password: testPassword, FriendlyName: "a",
	}); err == nil {
		t.Error("EncodeBundle(jks, key without cert) returned nil error, want an error")
	} else if !strings.Contains(err.Error(), "pairs the key with one specific certificate") {
		// This substring is unique to the specific "private key requires a
		// certificate" error. The generic creationTime fallback error also
		// contains the words "requires a certificate" (as part of "requires a
		// certificate or a chain entry"), so asserting on that shorter phrase
		// would not have caught the regression this test exists to guard
		// against: encodeJKS used to let that generic branch fire first for
		// this exact input.
		t.Errorf("EncodeBundle(jks, key without cert) error = %q, want the specific key-requires-a-certificate message", err.Error())
	}

	other, err := GenerateKey(KeyParams{Algorithm: AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, PrivateKey: other,
		Password: testPassword, FriendlyName: "a",
	}); err == nil {
		t.Error("EncodeBundle(jks) accepted a private key that does not match the certificate")
	}
}

func TestEncodeJKSIsReadableByKeytool(t *testing.T) {
	t.Parallel()
	requireKeytool(t, true)
	leaf, key, ca := testLeaf(t)
	out, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: leaf, PrivateKey: key,
		Chain: []*x509.Certificate{ca}, Password: testPassword, FriendlyName: "nick-ipad",
	})
	if err != nil {
		t.Fatalf("EncodeBundle: %v", err)
	}
	text := keytoolList(t, out, testPassword)
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "nick-ipad") {
		t.Errorf("keytool -list does not show the alias:\n%s", text)
	}
	if !strings.Contains(lower, "privatekeyentry") {
		t.Errorf("keytool -list does not report a PrivateKeyEntry:\n%s", text)
	}
}

// TestEncodeJKSTrustStoreAliasesAreCaseInsensitivelyDistinct mirrors Task 12's
// TestEncodePKCS12TrustStoreAliasesAreCaseInsensitivelyDistinct. The hazard is
// strictly worse here: keystore-go lowercases aliases with its own
// convertAlias and a duplicate silently overwrites the previous entry rather
// than merely merging with it, at the moment the colliding alias is set. If
// trustStoreAliases's case-insensitive dedup were skipped or re-derived
// incorrectly, the keystore would come out of encodeJKS already missing a
// trust anchor. keytool -list, run over the actual encoded bytes, is what
// Task 12's parallel test structure treats as the assertion of record here.
func TestEncodeJKSTrustStoreAliasesAreCaseInsensitivelyDistinct(t *testing.T) {
	t.Parallel()
	requireKeytool(t, true)
	upper, _ := testCA(t, nil, nil, "Root")
	lower, _ := testCA(t, nil, nil, "root")

	out, err := EncodeBundle(BundleInput{
		Format: FormatJKS, Certificate: upper, Chain: []*x509.Certificate{lower},
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

// TestEncodeJKSTrustStoreIsDeterministic checks the property WithOrderedAliases
// and the fixed creationTime exist for: a truststore built from the same input
// twice is byte-for-byte identical, so the Kubernetes Secret it lands in does
// not churn on every apply. Unlike the keyed path, nothing here draws from a
// random source, so no Rand is needed to make this hold.
func TestEncodeJKSTrustStoreIsDeterministic(t *testing.T) {
	t.Parallel()
	leaf, _, ca := testLeaf(t)
	in := BundleInput{
		Format: FormatJKS, Certificate: leaf, Chain: []*x509.Certificate{ca},
		Password: testPassword, FriendlyName: "homelab",
	}

	first, err := EncodeBundle(in)
	if err != nil {
		t.Fatalf("EncodeBundle (first): %v", err)
	}
	second, err := EncodeBundle(in)
	if err != nil {
		t.Fatalf("EncodeBundle (second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("two truststore encodes of identical input differ: %d bytes vs %d bytes", len(first), len(second))
	}
}

// TestEncodeJKSKeyedBundleIsDeterministicWithPinnedRand is the valuable half
// of the determinism story. keystore-go's Sun key protector draws a fresh
// random 20-byte salt from its random source on every SetPrivateKeyEntry --
// the same way a PKCS#12 keystore is freshly salted on every encode -- so the
// keyed path can never be byte-identical across two encodes in production,
// and encodeJKS does not claim otherwise. But with in.Rand pinned to a
// deterministic reader (mirroring what encodePKCS12 already supports via
// WithRand), two encodes must still be byte-identical. If they were not, that
// would mean something else in the path is nondeterministic -- a stray
// time.Now(), map iteration order leaking into the output, and so on -- which
// this test exists to catch.
func TestEncodeJKSKeyedBundleIsDeterministicWithPinnedRand(t *testing.T) {
	t.Parallel()
	leaf, key, ca := testLeaf(t)
	salt := bytes.Repeat([]byte{0x42}, 64) // more than the 20-byte salt keyprotector.go reads
	in := BundleInput{
		Format: FormatJKS, Certificate: leaf, PrivateKey: key,
		Chain: []*x509.Certificate{ca}, Password: testPassword, FriendlyName: "nick-ipad",
	}

	in.Rand = bytes.NewReader(salt)
	first, err := EncodeBundle(in)
	if err != nil {
		t.Fatalf("EncodeBundle (first): %v", err)
	}
	in.Rand = bytes.NewReader(salt)
	second, err := EncodeBundle(in)
	if err != nil {
		t.Fatalf("EncodeBundle (second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("two keyed encodes with the same pinned rand differ: %d bytes vs %d bytes", len(first), len(second))
	}
}
