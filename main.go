// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/nijave/terraform-provider-pki/internal/provider"
)

// Documentation is generated from the tools module, which keeps tfplugindocs'
// dependency graph out of this module's go.sum. There is deliberately no
// //go:generate directive here: `go generate ./...` at the repo root does not
// descend into a nested module, so the directive would either be a no-op or
// duplicate the tools module's work. `make docs` is the entry point, and CI
// runs it followed by a git diff.

var (
	// version and commit are set by goreleaser's ldflags.
	version = "dev"
	commit  = ""
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	_ = commit // recorded in the binary for support purposes

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// The OpenTofu registry is the primary distribution channel (spec
		// section 12). This address only affects dev overrides and the
		// reattach output in debug mode; the same binary serves either
		// registry.
		Address: "registry.opentofu.org/nijave/pki",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
