// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"math/big"
	"testing"
)

// TestNormalizeSerialMatchesPlanPy pins the behavior of reconcile/plan.py's
// norm_serial: strip, lower, drop an "0x" prefix, drop leading zeros, and map
// the empty result to "0". Cluster Secret names are pki-<name>-<serial> using
// this exact form, so a change here renames live objects.
func TestNormalizeSerialMatchesPlanPy(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"2001":       "2001",
		"2ABC":       "2abc",
		"0x2abc":     "2abc",
		"0X2ABC":     "2abc",
		"  2abc  ":   "2abc",
		"\t2abc\n":   "2abc",
		"0002abc":    "2abc",
		"0x0002abc":  "2abc",
		"0":          "0",
		"0000":       "0",
		"0x0":        "0",
		"0x":         "0",
		"":           "0",
		"   ":        "0",
		"ffffffffff": "ffffffffff",
	} {
		if got := NormalizeSerial(in); got != want {
			t.Errorf("NormalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseSerial(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]int64{
		"2001":     0x2001,
		"0x2001":   0x2001,
		"0002001":  0x2001,
		"  2001  ": 0x2001,
		"0":        0,
		"":         0,
		"deadbeef": 0xdeadbeef,
		"DEADBEEF": 0xdeadbeef,
	} {
		got, err := ParseSerial(in)
		if err != nil {
			t.Errorf("ParseSerial(%q): %v", in, err)
			continue
		}
		if got.Int64() != want {
			t.Errorf("ParseSerial(%q) = %d, want %d", in, got.Int64(), want)
		}
	}
	for _, bad := range []string{"nope", "0xzz", "12g4", "-1", "1.0", "0x 1"} {
		if _, err := ParseSerial(bad); err == nil {
			t.Errorf("ParseSerial(%q) returned nil error, want an error", bad)
		}
	}
}

func TestParseSerialHandlesValuesBeyondInt64(t *testing.T) {
	t.Parallel()
	// A random 128-bit serial does not fit in an int64; big.Int is not
	// decoration here.
	const in = "0102030405060708090a0b0c0d0e0f10"
	got, err := ParseSerial(in)
	if err != nil {
		t.Fatalf("ParseSerial: %v", err)
	}
	if got.BitLen() != 121 {
		t.Fatalf("BitLen = %d, want 121", got.BitLen())
	}
	if FormatSerial(got) != NormalizeSerial(in) {
		t.Fatalf("FormatSerial round-trip = %q, want %q", FormatSerial(got), NormalizeSerial(in))
	}
}

func TestFormatSerial(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{0x2001, "2001"},
		{0xdeadbeef, "deadbeef"},
	} {
		if got := FormatSerial(big.NewInt(tc.in)); got != tc.want {
			t.Errorf("FormatSerial(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestFormatSerialIsNormalizeSerialFixedPoint is the property that keeps the
// two functions consistent: formatting a parsed serial must produce the same
// string normalization produces, or state would churn between the two paths.
func TestFormatSerialIsNormalizeSerialFixedPoint(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"2001", "0x0002ABC", "0", "", "deadbeef", "0102030405060708090a0b0c0d0e0f10"} {
		n, err := ParseSerial(in)
		if err != nil {
			t.Fatalf("ParseSerial(%q): %v", in, err)
		}
		if got, want := FormatSerial(n), NormalizeSerial(in); got != want {
			t.Errorf("input %q: FormatSerial(ParseSerial(x)) = %q but NormalizeSerial(x) = %q", in, got, want)
		}
	}
}

func TestRandomSerial(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		n, err := RandomSerial()
		if err != nil {
			t.Fatalf("RandomSerial: %v", err)
		}
		if n.Sign() <= 0 {
			t.Fatalf("RandomSerial returned %v; RFC 5280 requires a positive serial", n)
		}
		if n.BitLen() > 128 {
			t.Fatalf("RandomSerial returned a %d-bit value, want at most 128", n.BitLen())
		}
		s := FormatSerial(n)
		if seen[s] {
			t.Fatalf("RandomSerial returned duplicate %q within 32 draws", s)
		}
		seen[s] = true
	}
}
