// SPDX-License-Identifier: GPL-3.0-or-later

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/function"

	"github.com/nijave/terraform-provider-pki/internal/pki"
)

var (
	_ function.Function = (*oidFunction)(nil)
	_ function.Function = (*oidNameFunction)(nil)
)

type oidFunction struct{}

func NewOIDFunction() function.Function { return &oidFunction{} }

func (f *oidFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	// The bare name; OpenTofu renders the call as provider::pki::oid(...).
	resp.Name = "oid"
}

func (f *oidFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Look up the dotted OID for a well-known name.",
		MarkdownDescription: "Returns the dotted object identifier for a well-known DN attribute, " +
			"extension, or extended key usage name -- for example `oid(\"displayName\")` returns " +
			"`2.16.840.1.113730.3.1.241`.\n\n" +
			"Errors on an unknown name rather than returning an empty string, so a typo fails at plan " +
			"time instead of silently omitting a DN attribute.\n\n" +
			"Use the `pki_oids` data source when you need to iterate over the table.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "name",
				MarkdownDescription: "A well-known name such as `commonName`, `displayName`, `subjectAltName`, or `clientAuth`.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *oidFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var name string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &name))
	if resp.Error != nil {
		return
	}
	oid, err := pki.OIDByName(name)
	if err != nil {
		// Argument index 0 points the error at the offending expression.
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, err.Error()))
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, oid))
}

type oidNameFunction struct{}

func NewOIDNameFunction() function.Function { return &oidNameFunction{} }

func (f *oidNameFunction) Metadata(_ context.Context, _ function.MetadataRequest, resp *function.MetadataResponse) {
	// The bare name; OpenTofu renders the call as provider::pki::oid_name(...).
	resp.Name = "oid_name"
}

func (f *oidNameFunction) Definition(_ context.Context, _ function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Look up the well-known name for a dotted OID.",
		MarkdownDescription: "Returns the friendly name for a dotted object identifier that is a well-known " +
			"DN attribute, extension, or extended key usage -- for example `oid_name(\"2.5.4.4\")` returns " +
			"`surname`.\n\n" +
			"Errors on an unknown OID rather than returning an empty string, so a typo fails at plan time " +
			"instead of silently omitting a DN attribute.\n\n" +
			"Use the `pki_oids` data source when you need to iterate over the table.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "oid",
				MarkdownDescription: "A dotted OID such as `2.5.4.3` or `2.5.29.17`.",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *oidNameFunction) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var oid string
	resp.Error = function.ConcatFuncErrors(resp.Error, req.Arguments.Get(ctx, &oid))
	if resp.Error != nil {
		return
	}
	name, err := pki.NameByOID(oid)
	if err != nil {
		// Argument index 0 points the error at the offending expression.
		resp.Error = function.ConcatFuncErrors(resp.Error, function.NewArgumentFuncError(0, err.Error()))
		return
	}
	resp.Error = function.ConcatFuncErrors(resp.Error, resp.Result.Set(ctx, name))
}
