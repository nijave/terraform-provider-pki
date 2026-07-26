// SPDX-License-Identifier: GPL-3.0-or-later

package pki

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

// day is the fixed length this package assigns to "d" and, multiplied by 365,
// to "y". Both suffixes are calendar-naive: no leap years, no DST, no month
// arithmetic. That is a documented property of the provider's validity
// attribute, not an approximation to be fixed later.
const day = 24 * time.Hour

// suffixPattern matches a whole-string count plus a "d" or "y" suffix. The
// anchors matter: they are what reject "1y6m" and "1d12h", which would
// otherwise be silently truncated.
var suffixPattern = regexp.MustCompile(`^([0-9]+)([dy])$`)

// ParseDuration parses a positive duration written either in Go's time.Duration
// syntax or as an integer count with a "d" (day) or "y" (365-day year) suffix.
//
// The "d" and "y" extensions exist because certificate lifetimes are naturally
// written in days and years, and Go's syntax stops at hours. Go durations pass
// straight through, so "175320h" from a cfssl signing profile parses unchanged.
//
// Zero and negative durations are rejected: every caller uses the result as a
// certificate or CRL lifetime, and neither is meaningful at or below zero. So
// is a count too large for time.Duration's int64 nanoseconds, which tops out at
// 292y or 106751d; the alternative is a silently wrapped, far shorter lifetime.
func ParseDuration(s string) (time.Duration, error) {
	if m := suffixPattern.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		unit := day
		if m[2] == "y" {
			unit = 365 * day
		}
		// time.Duration is an int64 count of nanoseconds, so the multiplication
		// below can overflow -- and unlike time.ParseDuration, which reports
		// overflow, a wrapped product is a perfectly plausible-looking duration.
		// "600y" wrapped to 15 years and "213504d" to 25 minutes, either of which
		// would issue a certificate with a lifetime nobody asked for and no
		// diagnostic anywhere. The ceiling is checked before multiplying rather
		// than inferred from the result, so the error can name it: 292y or
		// 106751d.
		if max := int64(math.MaxInt64) / int64(unit); int64(n) > max {
			return 0, fmt.Errorf("invalid duration %q: too large to represent; the maximum is %d%s", s, max, m[2])
		}
		d := time.Duration(n) * unit
		if d <= 0 {
			return 0, fmt.Errorf("invalid duration %q: must be positive", s)
		}
		return d, nil
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: want a Go duration such as \"175320h\" or a count with a \"d\" or \"y\" suffix such as \"90d\" or \"20y\"", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid duration %q: must be positive", s)
	}
	return d, nil
}
