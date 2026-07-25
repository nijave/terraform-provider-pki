// SPDX-License-Identifier: GPL-3.0-or-later

// Package pki implements the X.509 primitives behind terraform-provider-pki.
//
// It imports no Terraform packages. Every cryptographic decision lives here so
// it can be tested without a Terraform harness, and the provider's framework
// layer stays a mechanical translation between Terraform values and these
// types.
//
// Certificate fields are built explicitly and supplied through
// x509.Certificate.RawSubject and x509.Certificate.ExtraExtensions rather than
// through the convenience fields on x509.Certificate, because reproducing an
// existing certificate byte-for-byte is a requirement of the provider's import
// support.
package pki
