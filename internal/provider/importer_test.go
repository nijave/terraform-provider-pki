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
	got, err := resolveImportID("file://" + path)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the file's contents", got)
	}
}

func TestResolveImportIDPEM(t *testing.T) {
	t.Parallel()
	got, err := resolveImportID("pem://" + testPEM)
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
	got, err := resolveImportID("base64://" + encoded)
	if err != nil {
		t.Fatalf("resolveImportID: %v", err)
	}
	if string(got) != testPEM {
		t.Fatalf("got %q, want the decoded PEM", got)
	}
	// Unpadded base64 is what a shell pipeline is most likely to produce, so
	// accept it too.
	if _, err := resolveImportID("base64://" + strings.TrimRight(encoded, "=")); err != nil {
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
		if _, err := resolveImportID(id); err == nil {
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
	_, err := resolveImportID("/tmp/tls.crt")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"file://", "pem://", "base64://"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
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
			_, err := resolveImportID(id)
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
