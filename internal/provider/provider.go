// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure pkiProvider satisfies the interfaces the framework dispatches on. If a
// method signature drifts, this fails at compile time rather than at plan time.
var (
	_ provider.Provider              = (*pkiProvider)(nil)
	_ provider.ProviderWithFunctions = (*pkiProvider)(nil)
)

// pkiProvider manages a private X.509 certificate authority entirely
// in-process.
type pkiProvider struct {
	// version is injected by main.go from goreleaser's ldflags.
	version string
}

// New returns a provider factory for the given version string.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &pkiProvider{version: version}
	}
}

func (p *pkiProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pki"
	resp.Version = p.version
}

// Schema declares no attributes.
//
// There is no endpoint, no credentials, and no client to configure: every
// resource is self-contained and CA material is passed per-resource as PEM
// strings. That is what lets the externally-owned CA -- delivered from
// Bitwarden via ExternalSecret -- be consumed without a CA resource in the
// graph at all.
func (p *pkiProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage a private X.509 certificate authority in-process. " +
			"No external CA service, no `openssl` binary, no `cfssl` binary.",
	}
}

// Configure is a no-op. There is no client to build and nothing to validate,
// so no ResourceData or DataSourceData is passed down; every resource reads its
// inputs from its own configuration.
func (p *pkiProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *pkiProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *pkiProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *pkiProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{}
}
