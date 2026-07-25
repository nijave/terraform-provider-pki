// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	t.Parallel()
	const day = 24 * time.Hour
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"175320h", 175320 * time.Hour}, // pastes in unchanged from cfssl/ca-config.json
		{"20y", 20 * 365 * day},         // calendar-naive by definition
		{"1y", 365 * day},
		{"90d", 90 * day},
		{"1d", day},
		{"720h", 720 * time.Hour},
		{"90m", 90 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"1s", time.Second},
	} {
		got, err := ParseDuration(tc.in)
		if err != nil {
			t.Errorf("ParseDuration(%q) returned error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestParseDurationEquivalences pins the exact calendar-naive definitions, so a
// later "improvement" to real calendar math fails loudly instead of silently
// shifting every certificate's notAfter.
func TestParseDurationEquivalences(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{
		{"1y", "8760h"},
		{"1y", "365d"},
		{"1d", "24h"},
		{"20y", "175200h"}, // note: NOT 175320h; cfssl's value is 20y plus 5 days
	} {
		a, err := ParseDuration(pair[0])
		if err != nil {
			t.Fatalf("ParseDuration(%q): %v", pair[0], err)
		}
		b, err := ParseDuration(pair[1])
		if err != nil {
			t.Fatalf("ParseDuration(%q): %v", pair[1], err)
		}
		if a != b {
			t.Errorf("ParseDuration(%q) = %v but ParseDuration(%q) = %v; want equal", pair[0], a, pair[1], b)
		}
	}
}

func TestParseDurationRejectsGarbage(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",         // empty
		"   ",      // whitespace only
		"forever",  // not a duration
		"20 y",     // internal space
		"1y6m",     // mixed year and Go duration syntax is not supported
		"1d12h",    // mixed day and Go duration syntax is not supported
		"-720h",    // negative
		"0h",       // zero
		"0d",       // zero
		"1.5y",     // fractional years
		"y",        // suffix with no number
		"d",        // suffix with no number
		"175320",   // no unit
		"175320hh", // doubled unit
		"1Y",       // uppercase suffix is not accepted
	} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) returned nil error, want an error", bad)
		}
	}
}
