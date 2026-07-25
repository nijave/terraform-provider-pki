// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"bytes"
	"crypto/x509"
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
	if _, err := EncodeBundle(BundleInput{Format: "pkcs11"}); err == nil {
		t.Error("EncodeBundle accepted an unknown format")
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
