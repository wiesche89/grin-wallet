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

pub fn bitcoin(args: &[&str]) -> serde_json::Value {
	let output = std::process::Command::new(std::env::var("GRIN_SWAP_CLI").unwrap())
		.arg(format!(
			"-datadir={}",
			std::env::var("GRIN_SWAP_DATADIR").unwrap()
		))
		.arg("-regtest")
		.arg(format!(
			"-rpcport={}",
			std::env::var("GRIN_SWAP_PORT").unwrap()
		))
		.arg("-rpcwallet=swap")
		.args(args)
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
		serde_json::Value::String(String::from_utf8(output.stdout).unwrap().trim().to_owned())
	})
}
