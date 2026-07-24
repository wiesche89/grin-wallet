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

use grin_wallet_doc::derive_openapi_fn;
use serde_json::{json, Map, Value};

#[derive_openapi_fn]
/// Returns the versions supported by the wallet.
pub fn check_version() {}

#[derive_openapi_fn]
/// Returns a summary of the wallet balance.
pub fn retrieve_summary_info() {}

fn main() {
	let owner_methods = jsonrpc_methods(&[CHECK_VERSION_OPENAPI, RETRIEVE_SUMMARY_INFO_OPENAPI]);
	let document = json!({
		"openapi": "3.0.0",
		"info": {
			"title": "Grin Wallet API",
			"version": env!("CARGO_PKG_VERSION")
		},
		"paths": {
			"/v3/owner": {
				"post": {
					"operationId": "ownerRpc",
					"description": "Grin Wallet Owner JSON-RPC endpoint.",
					"requestBody": {
						"required": true,
						"content": {
							"application/json": {
								"schema": {
									"type": "object"
								}
							}
						}
					},
					"responses": {
						"200": {
							"description": "JSON-RPC response"
						}
					},
					"x-jsonrpc-methods": owner_methods
				}
			}
		}
	});

	println!(
		"{}",
		serde_json::to_string_pretty(&document).expect("OpenAPI document is serializable")
	);
}

fn jsonrpc_methods(operations: &[&str]) -> Map<String, Value> {
	operations
		.iter()
		.map(|operation| {
			let operation: Value =
				serde_json::from_str(operation).expect("valid OpenAPI operation JSON");
			let operation_id = operation["operationId"]
				.as_str()
				.expect("OpenAPI operation has an operationId")
				.to_owned();
			(operation_id, operation)
		})
		.collect()
}
