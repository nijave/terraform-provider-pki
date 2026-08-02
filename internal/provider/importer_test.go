// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPEM = "-----BEGIN CERTIFICATE-----\nMIIBAg==\n-----END CERTIFICATE-----\n"

func TestResolveImportIDFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "tls.crt")
	if err := os.WriteFile(path, []byte(testPEM), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	got, err := resolveImportID("file://"+path, true)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the file's contents", got)
	}
}

func TestResolveImportIDPEM(t *testing.T) {
	t.Parallel()
	got, err := resolveImportID("pem://"+testPEM, true)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the inline PEM", got)
	}
}

func TestResolveImportIDBase64(t *testing.T) {
	t.Parallel()
	encoded := base64.StdEncoding.EncodeToString([]byte(testPEM))
	got, err := resolveImportID("base64://"+encoded, true)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the decoded PEM", got)
	}
	// Unpadded base64 is what a shell pipeline is most likely to produce, so
	// accept it too.
	if _, err := resolveImportID("base64://"+strings.TrimRight(encoded, "="), true); err != nil {
		t.Errorf("resolveImportID rejected unpadded base64: %v", err)
	}
}

func TestResolveImportIDRejectsBadInput(t *testing.T) {
	t.Parallel()
	for label, id := range map[string]string{
		"empty":           "",
		"no scheme":       "/tmp/tls.crt",
		"unknown scheme":  "https://example.com/tls.crt",
		"vault scheme":    "vault://secret/tls.crt",
		"empty file path": "file://",
		"missing file":    "file:///nonexistent/definitely/not/here.crt",
		"empty pem":       "pem://",
		"bad base64":      "base64://!!!!",
		"empty base64":    "base64://",
	} {
		if _, err := resolveImportID(id, true); err == nil {
			t.Errorf("resolveImportID(%s) returned nil error, want an error", label)
		}
	}
}

// TestResolveImportIDErrorNamesTheSchemes is what makes a mistyped import ID
// self-correcting: hashicorp/tls supports no import at all, so a user has no
// prior expectation of the format and the error is the only documentation they
// will see at that moment.
func TestResolveImportIDErrorNamesTheSchemes(t *testing.T) {
	t.Parallel()
	_, err := resolveImportID("/tmp/tls.crt", true)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"file://", "pem://", "base64://"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// TestResolveImportIDInlineDisallowed covers allowInline=false, used only by
// pki_private_key's ImportState: pem:// and base64:// must be rejected
// (OpenTofu/Terraform prints an import ID in full, unconditionally, before
// this provider ever runs -- inline schemes would put a private key itself
// into that output), while file:// -- the one scheme whose id string is never
// the key itself -- must keep working exactly as it does when inline is
// allowed.
func TestResolveImportIDInlineDisallowed(t *testing.T) {
	t.Parallel()

	for _, scheme := range []string{"pem://", "base64://"} {
		scheme := scheme
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			_, err := resolveImportID(scheme+"whatever", false)
			if err == nil {
				t.Fatalf("resolveImportID(%q, allowInline=false) returned nil error, want an error", scheme+"whatever")
			}
			if !strings.Contains(err.Error(), scheme) {
				t.Errorf("error %q does not name the rejected scheme %q", err.Error(), scheme)
			}
			if !strings.Contains(err.Error(), "file://") {
				t.Errorf("error %q does not point at file:// as the alternative", err.Error())
			}
		})
	}

	t.Run("file:// still works", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "tls.key")
		if err := os.WriteFile(path, []byte(testPEM), 0o600); err != nil {
			t.Fatalf("writing the fixture: %v", err)
		}
		got, err := resolveImportID("file://"+path, false)
		if err != nil {
			t.Fatalf("resolveImportID: %v", err)
		}
		if string(got) != testPEM {
			t.Fatalf("got %q, want the file's contents", got)
		}
	})
}

// TestResolveImportIDInlineDisallowedErrorDoesNotEchoPayload guards the
// rejection path itself: a private key resource rejecting pem://<key> or
// base64://<key> must not turn around and put the key into the rejection
// message -- that would just move the leak from the import log line into a
// diagnostic that reaches the same console and CI logs.
func TestResolveImportIDInlineDisallowedErrorDoesNotEchoPayload(t *testing.T) {
	t.Parallel()
	const secret = "c3VwZXJzZWNyZXRrZXltYXRlcmlhbA"

	for _, id := range []string{"pem://" + secret, "base64://" + secret} {
		id := id
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			_, err := resolveImportID(id, false)
			if err == nil {
				t.Fatalf("expected an error for %q", id)
			}
			msg := err.Error()
			const minRunLength = 8
			for length := minRunLength; length <= len(secret); length++ {
				if run := secret[:length]; strings.Contains(msg, run) {
					t.Fatalf("error message echoes %d bytes of the payload (%q): %q", length, run, msg)
				}
			}
		})
	}
}

// TestResolveImportIDErrorDoesNotEchoContents matters because a private key can
// be imported inline with pem:// or base64://, and a diagnostic is printed to
// the console and to CI logs.
//
// It covers every malformed shape that reaches the fallback "no recognized
// scheme" branch, not just the well-formed-scheme case (base64:// followed by
// bad base64): a one-slash typo of a real scheme, and a bare payload pasted
// with no scheme at all, both fall through to that branch too, and a helper
// that only special-cased strings containing "://" would print a prefix of
// the payload for exactly these shapes.
//
// It checks for any recognizable run of the payload, not just the whole
// string, because a helper that truncates its output never echoes the whole
// secret -- only a leading slice of it -- so a whole-string match would miss
// the leak entirely.
func TestResolveImportIDErrorDoesNotEchoContents(t *testing.T) {
	t.Parallel()
	const secret = "c3VwZXJzZWNyZXRrZXltYXRlcmlhbA"

	cases := map[string]string{
		"well-formed scheme, bad base64 payload": "base64://" + secret + "!!!",
		"one-slash typo of base64 scheme":        "base64:/" + secret,
		"one-slash typo of pem scheme":           "pem:/" + secret,
		"no scheme at all":                       secret,
		"unrecognized but well-formed scheme":    "nonsense://" + secret,
	}

	for label, id := range cases {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			_, err := resolveImportID(id, true)
			if err == nil {
				t.Fatalf("expected an error for %q", id)
			}
			msg := err.Error()
			// A leak that truncates its output would not contain the whole
			// secret, so scan increasing-length prefixes of it rather than
			// looking for an exact match on the entire string.
			const minRunLength = 8
			for length := minRunLength; length <= len(secret); length++ {
				if run := secret[:length]; strings.Contains(msg, run) {
					t.Fatalf("error message echoes %d bytes of the payload (%q): %q", length, run, msg)
				}
			}
		})
	}
}
