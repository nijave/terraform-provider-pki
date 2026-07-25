// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// NormalizeSerial reduces a hex serial to the canonical form the homelab
// reconciler uses (reconcile/plan.py norm_serial): trimmed, lowercased, with
// any "0x" prefix and leading zeros removed, and with the empty result mapped
// to "0".
//
// This is deliberately total rather than validating: it mirrors a Python
// function that never rejected input, and the Kubernetes Secret names already
// in the cluster are pki-<name>-<serial> using exactly this form. Use
// ParseSerial when the input needs to be rejected as invalid.
func NormalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// ParseSerial parses a hex serial number, tolerating the same surface forms
// NormalizeSerial accepts, and rejecting anything that is not hex. An empty or
// all-zero input parses to zero.
func ParseSerial(s string) (*big.Int, error) {
	norm := NormalizeSerial(s)
	// Validate that norm contains only valid hex digits (no minus signs or other chars)
	for _, c := range norm {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, fmt.Errorf("invalid serial number %q: want a hexadecimal string, optionally prefixed with 0x", s)
		}
	}
	n, ok := new(big.Int).SetString(norm, 16)
	if !ok {
		return nil, fmt.Errorf("invalid serial number %q: want a hexadecimal string, optionally prefixed with 0x", s)
	}
	return n, nil
}

// FormatSerial renders a serial as lowercase hex with no "0x" prefix and no
// leading zeros. FormatSerial(ParseSerial(x)) equals NormalizeSerial(x) for
// every x ParseSerial accepts.
func FormatSerial(n *big.Int) string {
	return n.Text(16)
}

// RandomSerial draws a random positive 128-bit serial.
//
// 128 bits is the CA/Browser Forum's floor for unpredictability and is what
// hashicorp/tls uses. The value is generated once at create time and then held
// in state; it is never recomputed on a later plan, because a changed serial
// means a replaced certificate and, for the 20-year certs on the devices in
// question, a manual re-enrollment.
func RandomSerial() (*big.Int, error) {
	// 1 << 128 as the exclusive upper bound, then add 1 so zero is impossible.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	limit.Sub(limit, big.NewInt(1))
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generating a random serial number: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}
