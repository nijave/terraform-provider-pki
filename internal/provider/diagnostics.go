// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// This file is the provider side of a boundary internal/pki sets out in its own
// doc.go: some of its error messages deliberately name provider schema
// attributes -- "rsa_bits", "ecdsa_curve", "password_wo", "pkcs12_encoding" --
// even though nothing in that package knows what a Terraform attribute is,
// because an error naming the attribute the operator has to edit beats one that
// leaves this layer guessing. That package's stated migration path, if it ever
// gains a second consumer, is structured error types carrying the failing
// concept; until then the name in the message *is* the structure.
//
// So this reads the name back out and turns it into a path, once, instead of
// each resource re-deriving which attribute is at fault from the inputs it just
// sent. pki_private_key's Create did the latter: a switch over the KeyParams it
// had built, restating internal/pki's validation rules in different words. Two
// copies of one rule is a bug waiting for the rules to diverge, and Tasks 8 and 9
// have more cross-field validation than this one, not less.

// pkiErrorAttribute pairs the attribute name internal/pki writes in a message
// with the place that attribute lives in the calling resource's schema. The two
// differ as soon as an attribute is nested: internal/pki says "password_wo", and
// the resource decides whether that is a root attribute or one inside a block.
type pkiErrorAttribute struct {
	name string
	path path.Path
}

// rootPKIErrorAttributes is the shorthand for the common case, where each name
// internal/pki writes is a root attribute spelled identically.
func rootPKIErrorAttributes(names ...string) []pkiErrorAttribute {
	out := make([]pkiErrorAttribute, 0, len(names))
	for _, name := range names {
		out = append(out, pkiErrorAttribute{name: name, path: path.Root(name)})
	}
	return out
}

// pkiErrorPath resolves err to the attribute path its message names, or to
// fallback when it names none of the candidates.
//
// Two rules make the resolution deterministic:
//
// The earliest mention wins. internal/pki's messages lead with the offending
// field and mention the others as context -- "ecdsa_curve is not valid for
// algorithm RSA" names both, and it is ecdsa_curve that has to go. A longer name
// beats a shorter one starting at the same offset, so a candidate list holding
// both "rsa_bits" and a hypothetical "bits" cannot resolve to the wrong one.
//
// A name is matched in both its attribute spelling and its prose spelling, with
// underscores as spaces. internal/pki writes "unknown ecdsa curve %q" in one
// place and "ecdsa_curve is not valid for %s" in another, and both are about
// ecdsa_curve.
//
// A message naming nothing lands on fallback, so fallback should be the
// attribute most likely to be at fault rather than the resource root: a
// diagnostic with no path renders against the whole resource block, which is the
// outcome this file exists to avoid.
func pkiErrorPath(err error, fallback path.Path, candidates []pkiErrorAttribute) path.Path {
	if err == nil {
		return fallback
	}
	message := err.Error()

	best := fallback
	bestIndex := -1
	bestLength := 0
	for _, candidate := range candidates {
		index := -1
		for _, spelling := range []string{candidate.name, strings.ReplaceAll(candidate.name, "_", " ")} {
			at := strings.Index(message, spelling)
			if at >= 0 && (index < 0 || at < index) {
				index = at
			}
		}
		if index < 0 {
			continue
		}
		if bestIndex < 0 || index < bestIndex || (index == bestIndex && len(candidate.name) > bestLength) {
			best, bestIndex, bestLength = candidate.path, index, len(candidate.name)
		}
	}
	return best
}

// addPKIError appends err as an attribute error on whichever candidate attribute
// its message names. The detail is internal/pki's message verbatim, because it
// already says which value is wrong and why.
func addPKIError(diags *diag.Diagnostics, err error, summary string, fallback path.Path, candidates []pkiErrorAttribute) {
	diags.AddAttributeError(pkiErrorPath(err, fallback, candidates), summary, err.Error())
}
