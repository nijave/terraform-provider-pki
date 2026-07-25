// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"os/exec"
	"testing"
)

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
