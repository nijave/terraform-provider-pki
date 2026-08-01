// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

// TestPKIErrorPathOverRealGenerateKeyFailures is the test that makes the mapping
// safe to depend on. The coupling it guards is textual -- internal/pki names the
// attribute in prose and this layer reads it back -- so the errors here are the
// real ones, produced by calling pki.GenerateKey, not strings copied out of it.
// A reworded message that no longer names its attribute silently degrades to the
// fallback path in production, and fails loudly here.
//
// Every parameter-validation branch of GenerateKey is covered, including the two
// the schema's OneOf validators keep unreachable from configuration, because
// nothing but this test keeps them mapped.
func TestPKIErrorPathOverRealGenerateKeyFailures(t *testing.T) {
	t.Parallel()

	fallback := path.Root("algorithm")
	tests := map[string]struct {
		params   pki.KeyParams
		wantPath path.Path
	}{
		"ecdsa_curve on an RSA key": {
			params:   pki.KeyParams{Algorithm: pki.AlgorithmRSA, ECDSACurve: "P256"},
			wantPath: path.Root("ecdsa_curve"),
		},
		"rsa_bits on an ECDSA key": {
			params:   pki.KeyParams{Algorithm: pki.AlgorithmECDSA, RSABits: 2048},
			wantPath: path.Root("rsa_bits"),
		},
		"rsa_bits on an Ed25519 key": {
			params:   pki.KeyParams{Algorithm: pki.AlgorithmED25519, RSABits: 2048},
			wantPath: path.Root("rsa_bits"),
		},
		"ecdsa_curve on an Ed25519 key": {
			params:   pki.KeyParams{Algorithm: pki.AlgorithmED25519, ECDSACurve: "P256"},
			wantPath: path.Root("ecdsa_curve"),
		},
		"an RSA modulus below the floor": {
			params:   pki.KeyParams{Algorithm: pki.AlgorithmRSA, RSABits: 1024},
			wantPath: path.Root("rsa_bits"),
		},
		// "unknown key algorithm" names only algorithm, which is also the
		// fallback; the case is here so a future message that stops naming it is
		// noticed.
		"an unknown algorithm": {
			params:   pki.KeyParams{Algorithm: "DSA"},
			wantPath: path.Root("algorithm"),
		},
		// "unknown ecdsa curve" spells the attribute in prose, with a space.
		// Resolving it is what the prose spelling in pkiErrorPath is for, and
		// without it this would land on the fallback instead.
		"an unknown curve": {
			params:   pki.KeyParams{Algorithm: pki.AlgorithmECDSA, ECDSACurve: "P999"},
			wantPath: path.Root("ecdsa_curve"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := pki.GenerateKey(tt.params)
			if err == nil {
				t.Fatalf("pki.GenerateKey(%+v) succeeded; the case no longer exercises a failure", tt.params)
			}
			if got := pkiErrorPath(err, fallback, privateKeyErrorAttributes); !got.Equal(tt.wantPath) {
				t.Errorf("%q\nresolved to %s, want %s", err, got, tt.wantPath)
			}
		})
	}
}

// TestPKIErrorPathResolutionRules covers the parts of the resolution the real
// messages do not currently reach: the fallback, the earliest-mention rule when
// two candidates appear in one message, and the longer-name tiebreak.
func TestPKIErrorPathResolutionRules(t *testing.T) {
	t.Parallel()

	fallback := path.Root("algorithm")
	candidates := rootPKIErrorAttributes("algorithm", "rsa_bits", "ecdsa_curve")

	tests := map[string]struct {
		err      error
		wantPath path.Path
	}{
		"a message naming nothing falls back": {
			err:      errors.New("entropy source unavailable"),
			wantPath: fallback,
		},
		"the earliest of two names wins": {
			err:      errors.New("ecdsa_curve is not valid for algorithm RSA"),
			wantPath: path.Root("ecdsa_curve"),
		},
		"the earliest wins in either order": {
			err:      errors.New("algorithm RSA does not accept ecdsa_curve"),
			wantPath: fallback,
		},
		"a nil error falls back": {
			wantPath: fallback,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := pkiErrorPath(tt.err, fallback, candidates); !got.Equal(tt.wantPath) {
				t.Errorf("resolved to %s, want %s", got, tt.wantPath)
			}
		})
	}

	// The longer name wins a tie at the same offset, so a candidate list holding
	// one name that prefixes another cannot resolve to the shorter one.
	prefixing := []pkiErrorAttribute{
		{name: "rsa", path: path.Root("rsa")},
		{name: "rsa_bits", path: path.Root("rsa_bits")},
	}
	err := errors.New("rsa_bits 1024 is invalid")
	if got := pkiErrorPath(err, fallback, prefixing); !got.Equal(path.Root("rsa_bits")) {
		t.Errorf("resolved to %s, want rsa_bits", got)
	}
}

// TestAddPKIErrorCarriesThePath pins what the call sites actually depend on: the
// diagnostic is an attribute error, not a resource-level one, and it keeps
// internal/pki's message as the detail.
func TestAddPKIErrorCarriesThePath(t *testing.T) {
	t.Parallel()

	_, err := pki.GenerateKey(pki.KeyParams{Algorithm: pki.AlgorithmRSA, ECDSACurve: "P256"})
	if err == nil {
		t.Fatal("pki.GenerateKey accepted an ecdsa_curve on an RSA key")
	}

	var diags diag.Diagnostics
	addPKIError(&diags, err, "Unable to generate private key", path.Root("algorithm"), privateKeyErrorAttributes)

	if len(diags.Errors()) != 1 {
		t.Fatalf("addPKIError produced %d errors, want 1: %v", len(diags.Errors()), diags.Errors())
	}
	got := diags.Errors()[0]
	withPath, ok := got.(diag.DiagnosticWithPath)
	if !ok {
		t.Fatalf("the diagnostic is a %T, which renders against the whole resource block", got)
	}
	if want := path.Root("ecdsa_curve"); !withPath.Path().Equal(want) {
		t.Errorf("the diagnostic is attached to %s, want %s", withPath.Path(), want)
	}
	if got.Summary() != "Unable to generate private key" {
		t.Errorf("summary = %q", got.Summary())
	}
	if got.Detail() != err.Error() {
		t.Errorf("detail = %q, want internal/pki's message %q", got.Detail(), err.Error())
	}
}
