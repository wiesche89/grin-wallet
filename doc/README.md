# Grin Wallet OpenAPI macros

`grin_wallet_doc` provides procedural macros for deriving OpenAPI metadata from
wallet API functions and their Rustdoc comments.

The initial `derive_openapi_fn` attribute preserves the annotated function and
generates a sibling `<FUNCTION_NAME>_OPENAPI` string constant containing an
OpenAPI 3 Operation Object in JSON format.

```rust
use grin_wallet_doc::derive_openapi_fn;

#[derive_openapi_fn]
/// Returns wallet information.
fn wallet_info() {}

let operation = WALLET_INFO_OPENAPI;
```

The generated operation metadata is intentionally independent of an HTTP path.
Grin's Owner and Foreign APIs use JSON-RPC, where several methods share the same
HTTP endpoint. A later aggregation step can combine these operation objects into
the appropriate JSON-RPC request and response schemas.

## Generate an OpenAPI document

The `generate_openapi` example combines multiple generated operation objects
under Grin's shared JSON-RPC endpoint and prints a complete OpenAPI 3 document:

```sh
cargo run -p grin_wallet_doc --example generate_openapi
```

Redirect stdout to create a file:

```sh
cargo run --quiet -p grin_wallet_doc --example generate_openapi > openapi.json
```

JSON-RPC methods share a single HTTP `POST` operation and are listed in the
`x-jsonrpc-methods` extension. This avoids documenting method-specific URLs that
the wallet server does not actually provide.
