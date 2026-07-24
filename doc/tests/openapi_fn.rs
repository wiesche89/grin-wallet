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
use serde_json::Value;

#[derive_openapi_fn]
/// Returns wallet information.
///
/// # Returns
/// The current wallet summary.
fn wallet_info() -> &'static str {
	"wallet info"
}

#[test]
fn preserves_the_annotated_function() {
	assert_eq!(wallet_info(), "wallet info");
}

#[test]
fn generates_an_openapi_operation_from_rustdoc() {
	let operation: Value =
		serde_json::from_str(WALLET_INFO_OPENAPI).expect("valid OpenAPI operation JSON");

	assert_eq!(operation["operationId"], "wallet_info");
	assert_eq!(operation["summary"], "Returns wallet information.");
	assert_eq!(
		operation["description"],
		"Returns wallet information.\n\n# Returns\nThe current wallet summary."
	);
	assert_eq!(
		operation["responses"]["200"]["description"],
		"Successful response"
	);
}
