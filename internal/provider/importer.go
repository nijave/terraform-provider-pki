// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// resolveImportID turns a scheme-prefixed import ID into PEM bytes.
//
// Terraform import IDs are a single string, and PEM is multi-line, so the
// scheme prefix is how one string can carry either a location or the material
// itself:
//
//	file://<path>       read from disk
//	pem://<pem>         inline PEM
//	base64://<base64>   base64-encoded PEM, for shell pipelines
//
// hashicorp/tls supports no import at all, so there is no prior convention to
// match and the error message has to teach the format.
func resolveImportID(id string) ([]byte, error) {
	const usage = `want an ID of the form "file://<path>", "pem://<pem>", or "base64://<base64-encoded pem>"`

	switch {
	case strings.HasPrefix(id, "file://"):
		path := strings.TrimPrefix(id, "file://")
		if path == "" {
			return nil, fmt.Errorf("import ID has an empty file path; %s", usage)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			// err already names the path and not the contents.
			return nil, fmt.Errorf("reading the import source: %w", err)
		}
		if len(content) == 0 {
			return nil, fmt.Errorf("import source %q is empty", path)
		}
		return content, nil

	case strings.HasPrefix(id, "pem://"):
		content := strings.TrimPrefix(id, "pem://")
		if strings.TrimSpace(content) == "" {
			return nil, fmt.Errorf("import ID has an empty pem:// payload; %s", usage)
		}
		return []byte(content), nil

	case strings.HasPrefix(id, "base64://"):
		payload := strings.TrimPrefix(id, "base64://")
		if payload == "" {
			return nil, fmt.Errorf("import ID has an empty base64:// payload; %s", usage)
		}
		// Accept both padded and unpadded input; a shell pipeline commonly
		// strips padding. Never include the payload in an error: it may be key
		// material, and diagnostics reach the console and CI logs.
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(payload)
		}
		if err != nil {
			return nil, fmt.Errorf("the base64:// payload is not valid base64")
		}
		if len(decoded) == 0 {
			return nil, fmt.Errorf("the base64:// payload decoded to nothing")
		}
		return decoded, nil

	case id == "":
		return nil, fmt.Errorf("import ID is empty; %s", usage)

	default:
		return nil, fmt.Errorf("import ID %q has no recognized scheme; %s", firstSegment(id), usage)
	}
}

// firstSegment returns a short, safe prefix of an ID for use in an error
// message: enough to identify a typo, never enough to leak a payload.
func firstSegment(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[:i+3]
	}
	if len(id) > 16 {
		return id[:16] + "..."
	}
	return id
}
