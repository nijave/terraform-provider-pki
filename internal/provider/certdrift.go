// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"
	"crypto"
	"crypto/x509"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

// modifyCertificatePlan decides whether a certificate must be reissued.
//
// Terraform's default is to plan an update whenever any configured value
// differs from state. For certificates that default is wrong in an expensive
// direction: the CA key arrives from a rotating Bitwarden Secret, durations can
// be rewritten ("175320h" and "7305d" are the same window), and a subject can be
// spelled in two forms that encode to identical DER. Under the default, each of
// those reissues every certificate — and with 20-year certificates installed on
// phones and tablets, a reissue means a manual re-enrollment per device.
//
// So the plan is suppressed unless the desired certificate genuinely differs in
// content from the one in state, as pki.CompareCertificate defines content.
// Inputs that cannot be derived from a certificate — ca_private_key_pem,
// private_key_pem, csr_pem — are excluded from the comparison entirely
// (overlay B); ca_certificate_pem is matched against the issued cert's issuer
// rather than treated as an input diff.
//
// The one thing that overrides all of this is the early-renewal window: once
// inside it, the plan is left in place so the certificate is reissued (overlay
// C). A silent reissue of a device certificate should never be a surprise in a
// plan, so the diagnostic on drift and on early-renewal is a warning, never a
// quiet let-the-update-happen (overlay E).
//
// The build callback assembles the desired pki.CertTemplate from the PLAN,
// along with the desired public key and the CA certificate. It is parameterless
// because each resource captures its own plan/state via closure; the desired
// NotBefore comes from STATE (not time.Now), and NotAfter is
// stateNotBefore.Add(validity), which is what makes a rewritten-but-equivalent
// duration compare equal (overlay B). copyComputed is called only when the
// comparison finds no drift, so the resource can copy every Computed attribute
// from state into the plan — turning an update into a genuine no-op (overlay D).
func modifyCertificatePlan(
	ctx context.Context,
	req resource.ModifyPlanRequest,
	resp *resource.ModifyPlanResponse,
	build func() (pki.CertTemplate, crypto.PublicKey, *x509.Certificate, diag.Diagnostics),
	copyComputed func(),
) {
	// 1. Create (no prior state to compare against) and destroy (Plan.Raw is
	// null and dereferencing it would panic). Both guards are required.
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	// 2. Pull the issued certificate from STATE. It is the only source of
	// truth for "what does the current cert say" — reading it from plan would
	// compare the cert to itself.
	stateCertPEM := types.String{}
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("certificate_pem"), &stateCertPEM)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if stateCertPEM.IsNull() || stateCertPEM.IsUnknown() || stateCertPEM.ValueString() == "" {
		// Nothing to compare against (e.g. a mid-import state). Let the plan
		// stand rather than forcing a comparison the inputs cannot support.
		return
	}
	stateCert, err := pki.ParseCertificatePEM([]byte(stateCertPEM.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse stored certificate",
			"The certificate in state could not be parsed: "+err.Error())
		return
	}

	// 3. Build the desired template from the plan. The closure captures the
	// resource's typed model and stateNotBefore.
	desired, pub, caCert, diags := build()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// 4. Compare. pki.CompareCertificate already compares encoded DN bytes
	// (overlay A: trust the library; do not add a block-shape diff here),
	// verifies the signature against the CA cert, and diffs extensions per OID.
	drift, err := pki.CompareCertificate(pki.CompareInput{
		Desired:          desired,
		DesiredPublicKey: pub,
		Actual:           stateCert,
		CA:               caCert,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to compare certificate to state", err.Error())
		return
	}

	// 6 (checked before 5 because it overrides everything — overlay C).
	// Recompute ready_for_renewal against the configured early_renewal window
	// in the PLAN, since that is what the next apply will use. time.Now is the
	// one clock this resource reads; it is also what Read uses, so the two
	// paths agree on "are we inside the window yet".
	planEarlyRenewal := types.String{}
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("early_renewal"), &planEarlyRenewal)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var earlyDur time.Duration
	if !planEarlyRenewal.IsNull() && !planEarlyRenewal.IsUnknown() {
		earlyDur, diags = parseDurationAttr(planEarlyRenewal, path.Root("early_renewal"))
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	ready, err := pki.CompareValidity(stateCert, earlyDur, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute readiness for renewal", err.Error())
		return
	}
	if ready {
		// Inside the early-renewal window: leave the plan in place so the
		// reissue fires. This is the one case where a content-identical
		// certificate still reissues, on purpose.
		//
		// The framework's proposed plan after a config-only refresh carries
		// state forward for every Computed attr, so without intervention the
		// plan would equal state and Core would call it a Noop — the opposite
		// of what the early-renewal window exists to do. Marking the
		// certificate_pem (and the rest of the cert-derived Computed attrs)
		// Unknown forces a diff against state and surfaces the Update that the
		// reissue requires.
		forceReissuePlan(ctx, req, resp)
		resp.Diagnostics.AddWarning(
			"Certificate scheduled for reissue (early-renewal window)",
			"The certificate is inside its early_renewal window of not_after and will be "+
				"reissued on apply. This override is independent of the drift comparison: "+
				"even a byte-identical certificate reissues once the window is reached.",
		)
		return
	}

	if len(drift) == 0 {
		// 4. No drift: copy every Computed attribute from state into plan so
		// the plan is a genuine no-op. Without this, computed attrs left
		// unknown would surface as a diff and the resource would plan an
		// update for content identical to state (overlay D).
		copyComputed()
		return
	}

	// 5. Drift: leave the plan in place AND warn (overlay E). Drift.String
	// already names the field and both sides, so a plan reader sees *why* the
	// cert is being reissued.
	entries := make([]string, 0, len(drift))
	for _, d := range drift {
		entries = append(entries, d.String())
	}
	resp.Diagnostics.AddWarning(
		"Certificate scheduled for reissue (content drift)",
		"The desired content differs from the certificate in state, so it will be "+
			"reissued on apply:\n  - "+strings.Join(entries, "\n  -"),
	)
}

// stateNotBefore parses the not_before attribute from state as an RFC 3339
// timestamp. It is the desired NotBefore for the comparison: using time.Now
// here would make every plan drift on the validity window, because the new
// now would always be later than the moment the cert was issued (overlay B).
// The boolean is false when state has no parseable not_before; the caller
// treats that as "nothing to compare" and lets the plan stand.
func stateNotBefore(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) (time.Time, bool) {
	v := types.String{}
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("not_before"), &v)...)
	if resp.Diagnostics.HasError() {
		return time.Time{}, false
	}
	if v.IsNull() || v.IsUnknown() || v.ValueString() == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse stored not_before",
			"The not_before timestamp in state could not be parsed as RFC 3339: "+err.Error())
		return time.Time{}, false
	}
	return t, true
}

// forceReissuePlan marks every cert-derived Computed attribute Unknown in the
// plan so Terraform Core sees a diff against state and proposes an Update. It
// is the lever the early-renewal override uses to make a content-identical
// certificate reissue: copyComputed would instead suppress the diff (Noop),
// which is the right answer for the no-drift case but the wrong answer inside
// the renewal window.
//
// The list is the same set of attrs that lost UseStateForUnknown in this task
// (overlay D), plus ready_for_renewal which never carried it. serial_number is
// omitted: it is Optional+Computed and a config-set value must reach the plan
// verbatim or Core rejects the plan as inconsistent with config; resolveSerial
// in Update preserves it anyway.
//
// certificate_chain_pem (pki_certificate_authority only) is also omitted: it is
// Computed, so when certificate_pem is marked Unknown here Core plans an Update,
// and Update recomputes the chain alongside every other cert-derived Computed
// attr. The CA resource's copyComputed carries state's chain value forward on
// the no-drift path.
func forceReissuePlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	for _, p := range []path.Path{
		path.Root("certificate_pem"),
		path.Root("not_before"),
		path.Root("not_after"),
		path.Root("subject_key_id"),
		path.Root("authority_key_id"),
		path.Root("signature_algorithm"),
		path.Root("id"),
	} {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, p, types.StringUnknown())...)
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("ready_for_renewal"), types.BoolUnknown())...)
}
