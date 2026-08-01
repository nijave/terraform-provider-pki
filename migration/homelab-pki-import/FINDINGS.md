# homelab-pki import validation — findings

Ran against the real `homelab-pki` namespace's CA and 5 device certs, per
`docs/superpowers/specs/2026-08-01-homelab-pki-import-validation-design.md`.

Every result below was independently re-confirmed by a reviewer actually
re-running the relevant `tofu plan`/`apply`/`openssl` command against the
real fetched material — not just accepted from the implementing task's own
report.

## Results

- [x] CA import: zero plan diff — yes. First plan after import showed a real
      diff (not a no-op): the sample HCL omitted `basic_constraints` and
      `key_usage`, and this provider's `ImportState` always populates those
      blocks from the certificate's actual extensions, so the omitted blocks
      in config planned as `null` — a genuine block-shape mismatch (root
      cause in `internal/provider/resource_certificate_authority.go`,
      `ImportState`/`ModifyPlan`'s `copyComputed` guard), not a semantic
      no-op, and would have forced a reissue on apply. Fixed by declaring
      both blocks explicitly in `ca.tf` with the real cert's actual values
      (`basic_constraints { ca = true; critical = true }`,
      `key_usage { critical = true; usages = ["keyCertSign", "crlSign"] }`).
      After that fix, `tofu plan` reported "No changes." A `diff` of
      `tofu output -raw ca_certificate_pem` against the source
      `fetched-secrets/pki-ca.crt` PEM produced no output (exit 0) —
      byte-identical. No RDN-order or serial-casing correction was needed for
      the CA itself (the brief's given subject `OU=apps, O=homelab` and
      serial matched the decoded certificate exactly).

- [x] All 5 device imports: zero plan diff — yes, all 5 (kara-iphone,
      nick-desktop, nick-ipad, nick-xps, pixel7), across all 11 resulting
      resources (1 CA + 5 x (private_key + certificate)). The same
      `basic_constraints` block-shape issue found in the CA task was
      anticipated and fixed proactively for kara-iphone
      (`basic_constraints { ca = false; critical = true }` declared before
      ever running plan/import), so it did not need rediscovery on any
      device. The remaining 4 devices (highest risk: 4 near-identical HCL
      blocks) were cross-checked field-by-field against both the reference
      table and the real decoded certificates (serial, CN, SAN, DN) with
      zero copy-paste errors found.

- [x] Fresh cert issuance (`migration-test`) against the imported CA — pass.
      Issued via plain `tofu apply` (not import) against the already-imported
      CA, serial `9000`. `openssl verify -CAfile fetched-secrets/pki-ca.crt
      migration-test.crt` returned `OK`. Subject, issuer, serial, SAN, key
      usage, and EKU all matched the expected values exactly.

- [x] CRL validates via `openssl verify -crl_check` against a real leaf cert
      (the OU-order bug fix) — pass. This is the most important result of
      the whole plan. Production's current CRL (cfssl-generated) encodes its
      issuer with the CA's DN attributes in the wrong order
      (`O=homelab, OU=apps`) versus the CA's actual subject
      (`OU=apps, O=homelab`), which makes `openssl verify -crl_check` fail
      with "unable to get certificate CRL" against every real leaf cert
      today. This provider's `pki_crl` resource copies the issuer
      byte-for-byte from the CA's actual encoded subject: `openssl crl -in
      crl.pem -noout -issuer` and `openssl x509 ... -subject` both printed
      `OU=apps, O=homelab`, and the match was confirmed at the DER/ASN.1
      level (not just the human-readable string, which could coincidentally
      match) — a byte-level check, not merely a display-order check.
      `openssl verify -CAfile fetched-secrets/pki-ca.crt -crl_check -CRLfile
      crl.pem fetched-secrets/nick-desktop.crt` returned `OK` — the exact
      command that fails in production today, now succeeding against real
      cluster-fetched material.

- [x] Revoking `migration-test`'s serial and regenerating correctly causes
      `openssl verify` to report it revoked, without affecting other certs —
      pass. Added `revoked { serial_number = "9000"; reason =
      "cessationOfOperation" }` to `pki_crl.ca` and re-applied. `pki_crl.ca`
      was updated in place (CRL number incremented `1` -> `2`; "Modifying...
      / Modifications complete", no destroy/create), not replaced.
      `openssl verify -crl_check` against `migration-test.crt` now fails
      specifically with `error 23 at 0 depth lookup: certificate revoked`
      (not a generic parse/format failure). All 5 real devices (kara-iphone,
      nick-desktop, nick-ipad, nick-xps, pixel7) remained `OK` against the
      same regenerated CRL — the revocation did not leak to unrelated
      certs.

## Issues found

No provider bugs were found. Every result above passed. The only issues
found were two pieces of import-config diagnostic friction, both root-caused
to real, correct, non-buggy provider behavior (Terraform's own block-shape
semantics for `SingleNestedBlock`), not implementation defects:

1. **`basic_constraints`/`key_usage` must be declared explicitly in config
   after import, even when their values equal the resource's own defaults.**
   Resource: `pki_certificate_authority` (also applies to `pki_certificate`,
   e.g. kara-iphone's `basic_constraints { ca = false; critical = true }`).
   Expected (per the original sample HCL, which omitted these blocks):
   omitting a block whose values equal the resource default should plan as a
   no-op. Actual: `ImportState` always populates these blocks from the
   certificate's real X.509 extensions; an omitted block in config plans as
   `null`, which is a block-shape mismatch against imported state, not a
   semantic no-op — Terraform Core requires a `SingleNestedBlock` to be
   config-driven, so it cannot silently treat "absent in config" as
   "equal to defaults." `ModifyPlan`'s `copyComputed` guard
   (`reflect.DeepEqual` on the block) correctly detects the mismatch and
   forces the plan to show a change (which, if applied, would reissue the
   certificate/CA with a fresh `not_before`, breaking byte-identity with the
   real material). Root-caused in
   `internal/provider/resource_certificate_authority.go` and
   `internal/provider/resource_certificate.go`. Fix applied: declare both
   blocks explicitly in the resource config with the real certificate's
   actual extension values, read off `openssl x509 -text` output, for every
   imported CA/certificate. Not a bug to fix in the provider — this is
   correct, documented block semantics; a follow-on task adopting this
   provider for the real cutover should just always declare
   `basic_constraints`/`key_usage` explicitly for any imported resource,
   rather than relying on defaults matching.

2. **`private_key_pem` shows as a pending `+` (null -> configured) on the
   very first plan immediately after importing a CA or certificate.**
   Resource: `pki_certificate_authority` (and per-device `pki_private_key`).
   This is expected, documented resource behavior, not a bug — the schema
   description states the private key cannot be recovered from a
   certificate alone, so after import the configuration must supply
   `private_key_pem`, and the first plan shows it being set. Confirmed this
   does not reissue anything: the resource's `id` was identical before and
   after the settling `apply`, and no other certificate-derived attribute
   (`certificate_pem`, `not_before`, `signature_algorithm`, etc.) changed.
   One `tofu apply` clears it, and the following `tofu plan` is a genuine
   "No changes."

Two purely cosmetic items were also noted, deferred as non-blocking:

- `devices.tf` and `new-cert.tf` have a `tofu fmt`-style misalignment
  (`public_key_pem` indented one space too many) — no functional impact.
- `verify.sh`'s revocation guard checks `openssl verify`'s exit code but
  does not additionally `grep` for the literal "certificate revoked" text,
  so in principle a different failure mode would also satisfy the guard
  (though the script's visible output does distinguish the two to a human
  reader, and in this run the output was in fact "certificate revoked",
  error 23). Matches the task brief as written; optional hardening for a
  follow-on task.

## Conclusion

`terraform-provider-pki` is validated as ready for the cluster-cutover spec.
All 5 of the plan's success criteria passed against real homelab-pki
material (the CA, all 5 real device certs, a freshly issued cert, and CRL
generation/revocation), and every pass was independently re-verified by a
reviewer re-running the actual commands rather than trusting the
implementer's report. No provider bugs were found. Most importantly, the
provider's CRL generation was proven — down to the DER/ASN.1 level, and via
the exact `openssl verify -crl_check` invocation used in production today —
to fix the known production CRL issuer-RDN-ordering bug that currently
breaks CRL validation against every real leaf certificate in the
`homelab-pki` namespace. The only action item for a follow-on cutover task
is procedural, not a code fix: always declare `basic_constraints` and
`key_usage` explicitly (with values read off the real certificate) when
importing existing CAs/certificates, since this provider's `ImportState`
always populates those blocks from the certificate's actual extensions and
an omitted block is a genuine block-shape mismatch, not a no-op.
