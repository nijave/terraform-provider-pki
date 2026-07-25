// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"encoding/asn1"
	"os/exec"
	"testing"
)

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
