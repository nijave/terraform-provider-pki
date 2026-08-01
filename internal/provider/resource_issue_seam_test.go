// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

// discardState is a stateOut stub for the issue() unit tests. issue() mutates
// the model in place before calling Set, so the tests read the results off the
// model pointer they passed in; Set only needs to satisfy the interface.
type discardState struct{}

func (discardState) Set(_ context.Context, _ interface{}) diag.Diagnostics { return nil }

// seamTestCA issues a throwaway self-signed CA (with crlSign, so it also passes
// CheckCRLSigner) and returns its certificate and private key as PEM. It backs
// the issue()-seam unit tests, which need a signer but not a full acceptance
// harness.
func seamTestCA(t *testing.T) (certPEM, keyPEM string) {
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
	cert, err := pki.CreateCertificate(pki.CertTemplate{
		Subject:          pki.NamedSubject{CommonName: "seam-test-ca"}.Expand(),
		Serial:           serial,
		NotBefore:        now,
		NotAfter:         now.Add(24 * time.Hour),
		BasicConstraints: &pki.BasicConstraints{CA: true, Critical: true},
		KeyUsage:         pki.DefaultCAKeyUsagePtr(),
	}, pki.PublicKeyOf(key), nil, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyBytes, err := pki.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM: %v", err)
	}
	return string(cert), string(keyBytes)
}

// leafPublicKeyPEM generates a fresh key and returns its PKIX public key PEM,
// the public_key_pem a leaf certificate certifies.
func leafPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := pki.GenerateKey(pki.KeyParams{Algorithm: pki.AlgorithmECDSA})
	if err != nil {
		t.Fatalf("GenerateKey (leaf): %v", err)
	}
	pubPEM, err := pki.EncodePublicKeyPEM(pki.PublicKeyOf(key))
	if err != nil {
		t.Fatalf("EncodePublicKeyPEM: %v", err)
	}
	return string(pubPEM)
}

// TestCertificateIssueUsesInjectedClock exercises the now seam on
// certificateResource.issue: the certificate's notBefore must be exactly the
// injected instant (truncated to a second, as DER UTCTime requires), proving the
// clock is a genuine parameter rather than an internal time.Now() call. Both
// production callers pass time.Now(); this is the one place the seam is pinned.
func TestCertificateIssueUsesInjectedClock(t *testing.T) {
	t.Parallel()
	caCert, caKey := seamTestCA(t)
	subject := subjectFromPKI(pki.NamedSubject{CommonName: "seam-leaf"}.Expand())

	plan := certificateResourceModel{
		CACertificatePEM: types.StringValue(caCert),
		CAPrivateKeyPEM:  types.StringValue(caKey),
		PublicKeyPEM:     types.StringValue(leafPublicKeyPEM(t)),
		Subject:          &subject,
		Validity:         types.StringValue("8760h"),
	}

	fixedNow := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	var diags diag.Diagnostics
	(&certificateResource{}).issue(context.Background(), &plan, types.StringNull(), fixedNow, &diags, discardState{})
	if diags.HasError() {
		t.Fatalf("issue reported errors: %v", diags)
	}

	wantNotBefore := fixedNow.Format(time.RFC3339)
	if got := plan.NotBefore.ValueString(); got != wantNotBefore {
		t.Errorf("not_before = %q, want the injected clock %q", got, wantNotBefore)
	}
	// notAfter is notBefore + validity, which confirms the window is anchored on
	// the injected clock rather than the wall clock.
	wantNotAfter := fixedNow.Add(8760 * time.Hour).Format(time.RFC3339)
	if got := plan.NotAfter.ValueString(); got != wantNotAfter {
		t.Errorf("not_after = %q, want %q", got, wantNotAfter)
	}
}

// TestCRLIssueUsesInjectedClock is the CRL analogue: thisUpdate is the injected
// instant (truncated), and nextUpdate is thisUpdate + next_update. An omitted
// revoked_at also defaults to the injected clock, which is the anti-churn default
// the resource relies on.
func TestCRLIssueUsesInjectedClock(t *testing.T) {
	t.Parallel()
	caCert, caKey := seamTestCA(t)

	plan := crlResourceModel{
		CACertificatePEM: types.StringValue(caCert),
		CAPrivateKeyPEM:  types.StringValue(caKey),
		NextUpdate:       types.StringValue("168h"),
		Revoked: []revokedEntryModel{
			{SerialNumber: types.StringValue("2001")},
		},
	}

	fixedNow := time.Date(2030, 6, 7, 8, 9, 10, 0, time.UTC)
	var diags diag.Diagnostics
	(&crlResource{}).issue(context.Background(), &plan, 1, fixedNow, &diags, discardState{})
	if diags.HasError() {
		t.Fatalf("issue reported errors: %v", diags)
	}

	wantThisUpdate := fixedNow.Format(time.RFC3339)
	if got := plan.ThisUpdate.ValueString(); got != wantThisUpdate {
		t.Errorf("this_update = %q, want the injected clock %q", got, wantThisUpdate)
	}
	wantNextUpdate := fixedNow.Add(168 * time.Hour).Format(time.RFC3339)
	if got := plan.NextUpdateTime.ValueString(); got != wantNextUpdate {
		t.Errorf("next_update_time = %q, want %q", got, wantNextUpdate)
	}
	// An omitted revoked_at is filled from the injected clock (thisUpdate).
	if got := plan.Revoked[0].RevokedAt.ValueString(); got != wantThisUpdate {
		t.Errorf("defaulted revoked_at = %q, want the injected clock %q", got, wantThisUpdate)
	}
}

// TestCRLIssueRejectsDuplicateSerialAtAttributePath pins what the provider-side
// duplicate-serial check adds over pki.CreateCRL's own rejection: the two
// produce the same "already present in this CRL" phrase, so the acceptance
// test's ExpectError pattern would pass with either, but only the provider check
// anchors the diagnostic to the specific revoked[i].serial_number attribute — an
// AddAttributeError the library layer cannot emit. This test fails if the
// provider check is removed (the surviving error is a bare, path-less
// AddError from CreateCRL). It also proves the surface-form collision: "2001"
// and "0x2001" are the same serial and must be rejected as a pair.
func TestCRLIssueRejectsDuplicateSerialAtAttributePath(t *testing.T) {
	t.Parallel()
	caCert, caKey := seamTestCA(t)

	plan := crlResourceModel{
		CACertificatePEM: types.StringValue(caCert),
		CAPrivateKeyPEM:  types.StringValue(caKey),
		NextUpdate:       types.StringValue("168h"),
		Revoked: []revokedEntryModel{
			{SerialNumber: types.StringValue("2001")},
			// The same serial in a different surface form; it collides after
			// normalization.
			{SerialNumber: types.StringValue("0x2001")},
		},
	}

	fixedNow := time.Date(2030, 6, 7, 8, 9, 10, 0, time.UTC)
	var diags diag.Diagnostics
	(&crlResource{}).issue(context.Background(), &plan, 1, fixedNow, &diags, discardState{})

	if !diags.HasError() {
		t.Fatal("issue accepted a duplicate serial (0x2001 collides with 2001 after normalization)")
	}
	got := diags.Errors()[0]
	if got.Summary() != "Duplicate serial number" {
		t.Errorf("summary = %q, want %q", got.Summary(), "Duplicate serial number")
	}
	withPath, ok := got.(diag.DiagnosticWithPath)
	if !ok {
		t.Fatal("the duplicate-serial diagnostic carries no attribute path; the provider-side check (not pki.CreateCRL) is what anchors it, and it appears to have been removed")
	}
	want := path.Root("revoked").AtListIndex(1).AtName("serial_number")
	if !withPath.Path().Equal(want) {
		t.Errorf("diagnostic attached to %s, want %s", withPath.Path(), want)
	}
}
