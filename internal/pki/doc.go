// SPDX-License-Identifier: GPL-3.0-or-later

// Package pki implements the X.509 primitives behind terraform-provider-pki.
//
// It imports no Terraform packages. Every cryptographic decision lives here so
// it can be tested without a Terraform harness, and the provider's framework
// layer stays a mechanical translation between Terraform values and these
// types.
//
// Some error messages here name provider schema attributes -- "password_wo",
// "pkcs12_encoding" -- even though nothing in this package knows what a
// Terraform attribute is. That is deliberate, and the boundary is narrower than
// it looks. The rule Task 16's test enforces is that no Terraform package may be
// linked in: it exists for dependency hygiene and because Terraform CLI is
// BUSL-1.1, not to make this package portable. This is an internal package with
// exactly one consumer, so an error that names the attribute the operator has to
// edit is strictly more useful than one that makes the framework layer guess.
//
// The cost is that renaming an attribute in the provider means grepping here.
// If this package ever gains a second consumer, the migration is structured
// error types carrying the failing concept, which the framework layer maps to a
// path -- not stripping the names and leaving diagnostics that cannot say what
// to fix.
//
// Certificate fields are built explicitly and supplied through
// x509.Certificate.RawSubject and x509.Certificate.ExtraExtensions rather than
// through the convenience fields on x509.Certificate, because reproducing an
// existing certificate byte-for-byte is a requirement of the provider's import
// support.
package pki
