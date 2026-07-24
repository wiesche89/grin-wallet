// Copyright 2024 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! proc-macro crate to generate OpenAPI documentation for specified functions

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

mod openapi_fn;

use proc_macro::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::{Attribute, Expr, ItemFn, Lit, Meta};

use openapi_fn::{OpenAPIFn, OpenAPIFnAttr};

struct CommentAttributes(Vec<String>);

impl From<&[Attribute]> for CommentAttributes {
	fn from(attrs: &[Attribute]) -> Self {
		let comments = attrs
			.iter()
			.filter_map(|attr| match &attr.meta {
				Meta::NameValue(meta) if meta.path.is_ident("doc") => match &meta.value {
					Expr::Lit(expr) => match &expr.lit {
						Lit::Str(comment) => Some(comment.value()),
						_ => None,
					},
					_ => None,
				},
				_ => None,
			})
			.collect();

		Self(comments)
	}
}

/// Generate OpenAPI operation metadata from a function and its Rustdoc comments.
///
/// The annotated function remains unchanged. A sibling string constant named
/// `<FUNCTION_NAME>_OPENAPI` is generated containing an OpenAPI 3 Operation
/// Object in JSON format.
#[proc_macro_attribute]
pub fn derive_openapi_fn(input: TokenStream, item: TokenStream) -> TokenStream {
	let fn_attribute = syn::parse_macro_input!(input as OpenAPIFnAttr);
	let ast_fn = match syn::parse::<ItemFn>(item) {
		Ok(ast_fn) => ast_fn,
		Err(error) => return error.into_compile_error().into_token_stream().into(),
	};
	let openapi_fn = OpenAPIFn::new(fn_attribute, &ast_fn.sig.ident)
		.doc_comments(CommentAttributes::from(ast_fn.attrs.as_slice()).0);
	let operation_json = openapi_fn.operation_json();
	let operation_json = syn::LitStr::new(&operation_json, ast_fn.sig.ident.span());
	let openapi_const = format_ident!(
		"{}_OPENAPI",
		ast_fn.sig.ident.to_string().to_uppercase(),
		span = ast_fn.sig.ident.span()
	);
	let visibility = &ast_fn.vis;

	quote! {
		#ast_fn

		#[doc(hidden)]
		#visibility const #openapi_const: &str = #operation_json;
	}
	.into()
}
