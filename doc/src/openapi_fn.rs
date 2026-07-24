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

//! Definitions to generate OpenAPI documentation for specified functions

use proc_macro2::Ident;
use serde_json::{json, Value};
use syn::parse::{Parse, ParseStream};

#[derive(Default, Debug)]
pub(crate) struct OpenAPIFnAttr;

pub(crate) struct OpenAPIFn {
	fn_ident: Ident,
	doc_comments: Vec<String>,
}

impl OpenAPIFn {
	pub(crate) fn new(_openapi_fn_attr: OpenAPIFnAttr, fn_ident: &Ident) -> Self {
		OpenAPIFn {
			fn_ident: fn_ident.clone(),
			doc_comments: Vec::new(),
		}
	}

	pub(crate) fn doc_comments(mut self, doc_comments: Vec<String>) -> Self {
		self.doc_comments = doc_comments;
		self
	}

	pub(crate) fn operation_json(&self) -> String {
		let description = normalized_doc_comments(&self.doc_comments);
		let mut operation = json!({
			"operationId": self.fn_ident.to_string(),
			"responses": {
				"200": {
					"description": "Successful response"
				}
			}
		});

		if !description.is_empty() {
			let operation = operation
				.as_object_mut()
				.expect("the generated OpenAPI operation is an object");
			operation.insert(
				"summary".to_owned(),
				Value::String(first_paragraph(&description)),
			);
			operation.insert("description".to_owned(), Value::String(description));
		}

		serde_json::to_string(&operation).expect("the generated OpenAPI operation is serializable")
	}
}

impl Parse for OpenAPIFnAttr {
	fn parse(input: ParseStream) -> syn::Result<Self> {
		if input.is_empty() {
			Ok(Self)
		} else {
			Err(input.error("derive_openapi_fn does not accept arguments yet"))
		}
	}
}

fn normalized_doc_comments(comments: &[String]) -> String {
	let comments = comments
		.iter()
		.map(|comment| comment.trim())
		.collect::<Vec<_>>();
	let first = comments
		.iter()
		.position(|comment| !comment.is_empty())
		.unwrap_or(comments.len());
	let last = comments
		.iter()
		.rposition(|comment| !comment.is_empty())
		.map(|position| position + 1)
		.unwrap_or(first);

	comments[first..last].join("\n")
}

fn first_paragraph(description: &str) -> String {
	description
		.lines()
		.take_while(|line| !line.is_empty())
		.collect::<Vec<_>>()
		.join(" ")
}

#[cfg(test)]
mod tests {
	use super::{first_paragraph, normalized_doc_comments};

	#[test]
	fn normalizes_doc_comments() {
		let comments = vec![
			" ".to_owned(),
			" Returns wallet information. ".to_owned(),
			"".to_owned(),
			" # Returns ".to_owned(),
			" The current wallet summary. ".to_owned(),
			"".to_owned(),
		];

		assert_eq!(
			normalized_doc_comments(&comments),
			"Returns wallet information.\n\n# Returns\nThe current wallet summary."
		);
	}

	#[test]
	fn uses_first_paragraph_as_summary() {
		assert_eq!(
			first_paragraph("Returns wallet information.\nWith additional context.\n\n# Returns"),
			"Returns wallet information. With additional context."
		);
	}
}
