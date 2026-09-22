// Copyright 2026 The Grin Developers
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

use easy_jsonrpc_mw::Handler;
use grin_wallet_libwallet as libwallet;
use libwallet::Slate;

pub fn rpc<T: serde::de::DeserializeOwned>(
	api: &(dyn grin_wallet_api::OwnerRpc + 'static),
	mask: Option<&grin_util::secp::SecretKey>,
	method: &str,
	mut params: serde_json::Value,
) -> Result<T, libwallet::Error> {
	params["token"] = serde_json::to_value(grin_wallet_api::Token {
		keychain_mask: mask.cloned(),
	})
	.unwrap();
	let response = api
		.handle_request(serde_json::json!({
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params
		}))
		.as_option()
		.expect("RPC response");
	assert!(response.get("error").is_none(), "{response}");
	assert!(response["result"].get("Err").is_none(), "{response}");
	serde_json::from_value(response["result"]["Ok"].clone())
		.map_err(|e| libwallet::Error::GenericError(e.to_string()))
}

pub fn foreign(
	api: &(dyn grin_wallet_api::ForeignRpc + 'static),
	method: &str,
	params: serde_json::Value,
) -> Slate {
	let response = api
		.handle_request(serde_json::json!({
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params
		}))
		.as_option()
		.unwrap();
	assert!(response.get("error").is_none(), "{response}");
	assert!(response["result"].get("Err").is_none(), "{response}");
	let wire: libwallet::VersionedSlate =
		serde_json::from_value(response["result"]["Ok"].clone()).unwrap();
	Slate::from(wire)
}

pub fn swap(
	api: &(dyn grin_wallet_api::OwnerRpc + 'static),
	mask: Option<&grin_util::secp::SecretKey>,
	request: grin_wallet_api::swap::Request,
) -> Result<grin_wallet_api::swap::Reply, libwallet::Error> {
	rpc(api, mask, "swap", serde_json::json!({"request": request}))
}
