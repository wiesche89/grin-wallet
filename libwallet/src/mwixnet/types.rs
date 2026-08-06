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

//! Types related to mwixnet requests required by rest of lib crate apis
//! Should rexport all needed types here

use super::onion::comsig_serde;
use grin_core::libtx::secp_ser::string_or_u64;
use grin_core::ser::{Readable, Reader, Writeable, Writer};
use grin_util::secp::key::SecretKey;
use grin_util::secp::pedersen::Commitment;
use grin_util::ToHex;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey, StaticSecret};

pub use super::onion::{onion::Onion, ComSignature, Hop};

/// A legacy swap request.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct LegacySwapReq {
	/// Com signature
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
	/// Onion
	pub onion: Onion,
}

/// A route-bound swap request.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RouteSwapReq {
	/// MWixnet protocol version.
	pub version: u32,
	/// MWixnet message type.
	#[serde(rename = "type")]
	pub msg_type: mwixnet_protocol::MwixnetType,
	/// Random wallet request identifier.
	pub wallet_request_id: mwixnet_protocol::Hash,
	/// Selected route identifier.
	pub route_id: mwixnet_protocol::Hash,
	/// Selected route manifest sequence.
	#[serde(with = "string_or_u64")]
	pub manifest_sequence: u64,
	/// Last block height at which the server may accept the request.
	#[serde(with = "string_or_u64")]
	pub expires_at_height: u64,
	/// Onion payload for the selected route.
	pub onion: Onion,
	/// Canonical hash of the onion payload.
	pub onion_hash: mwixnet_protocol::Hash,
	/// Commitment signature over the route request hash.
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
}

/// A legacy or route-bound swap request.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum SwapReq {
	/// Route-bound request.
	Route(RouteSwapReq),
	/// Legacy request.
	Legacy(LegacySwapReq),
}

/// Result of creating a route-bound MWixnet request.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MwixnetRouteReqCreationResult {
	/// Request to submit to the route entry server.
	#[serde(flatten)]
	pub request: RouteSwapReq,
	/// Transaction log ID associated with the output lock.
	pub tx_id: u32,
	/// Route entry server onion address.
	pub swap_onion_address: mwixnet_protocol::OnionAddress,
}

/// Local state of a route-bound MWixnet request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WalletMwixnetRequestStatus {
	/// Accepted locally and ready for submission.
	Accepted,
	/// Assigned to a server batch.
	Batched,
	/// Transaction is being posted.
	Posting,
	/// Transaction was posted.
	Posted,
	/// Transaction is confirmed.
	Confirmed,
	/// Request was rejected.
	Rejected,
	/// Request was cancelled.
	Cancelled,
	/// Request expired.
	Expired,
	/// A reclaim transaction is pending.
	ReclaimPending,
	/// Both spends have been observed.
	ConflictObserved,
	/// The reclaim transaction is confirmed.
	ReclaimConfirmed,
	/// The MWixnet transaction is confirmed after a conflict.
	ConflictConfirmed,
}

/// Status returned by a route entry server.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SwapSubmissionStatus {
	/// Request was accepted.
	Accepted,
	/// Request was assigned to a batch.
	Batched,
	/// Transaction is being posted.
	Posting,
	/// Transaction was posted.
	Posted,
	/// Transaction is confirmed.
	Confirmed,
	/// Request was rejected.
	Rejected,
	/// Request was cancelled.
	Cancelled,
	/// Request expired.
	Expired,
}

/// Unsigned idempotent response from the route entry server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapSubmission {
	/// Route identifier.
	pub route_id: mwixnet_protocol::Hash,
	/// Wallet request identifier.
	pub wallet_request_id: mwixnet_protocol::Hash,
	/// Hash of the stored request.
	pub swap_req_hash: mwixnet_protocol::Hash,
	/// Current server state.
	pub status: SwapSubmissionStatus,
	/// Kernel excess once a transaction has been built.
	pub kernel_excess: Option<String>,
}

/// Commitment-signed cancellation request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelSwapReq {
	/// MWixnet protocol version.
	pub version: u32,
	/// MWixnet message type.
	#[serde(rename = "type")]
	pub msg_type: mwixnet_protocol::MwixnetType,
	/// Selected route identifier.
	pub route_id: mwixnet_protocol::Hash,
	/// Selected route manifest sequence.
	#[serde(with = "string_or_u64")]
	pub manifest_sequence: u64,
	/// Original wallet request identifier.
	pub wallet_request_id: mwixnet_protocol::Hash,
	/// Hash of the original swap request.
	pub swap_req_hash: mwixnet_protocol::Hash,
	/// Input controlled by the commitment signature.
	#[serde(with = "commitment_serde")]
	pub input_commitment: Commitment,
	/// Request creation time.
	#[serde(with = "string_or_u64")]
	pub created_at: u64,
	/// Commitment signature over the cancellation hash.
	#[serde(with = "comsig_serde")]
	pub comsig: ComSignature,
}

struct CancelSwapReqPayload<'a> {
	route_id: &'a mwixnet_protocol::Hash,
	manifest_sequence: u64,
	wallet_request_id: &'a mwixnet_protocol::Hash,
	swap_req_hash: &'a mwixnet_protocol::Hash,
	input_commitment: &'a Commitment,
	created_at: u64,
}

impl Writeable for CancelSwapReqPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		self.route_id.write(writer)?;
		writer.write_u64(self.manifest_sequence)?;
		self.wallet_request_id.write(writer)?;
		self.swap_req_hash.write(writer)?;
		self.input_commitment.write(writer)?;
		writer.write_u64(self.created_at)
	}
}

impl CancelSwapReq {
	/// Return the hash to sign for the given cancellation fields.
	pub fn signing_hash(
		route_id: &mwixnet_protocol::Hash,
		manifest_sequence: u64,
		wallet_request_id: &mwixnet_protocol::Hash,
		swap_req_hash: &mwixnet_protocol::Hash,
		input_commitment: &Commitment,
		created_at: u64,
	) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(
			mwixnet_protocol::MwixnetType::CancelSwapReq,
			&CancelSwapReqPayload {
				route_id,
				manifest_sequence,
				wallet_request_id,
				swap_req_hash,
				input_commitment,
				created_at,
			},
		)
	}

	/// Return the hash signed by the input commitment.
	pub fn hash(&self) -> mwixnet_protocol::Hash {
		Self::signing_hash(
			&self.route_id,
			self.manifest_sequence,
			&self.wallet_request_id,
			&self.swap_req_hash,
			&self.input_commitment,
			self.created_at,
		)
	}
}

/// Status carried by a signed cancellation acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CancelStatus {
	/// The request was cancelled before batching.
	Cancelled,
}

/// Signed cancellation acknowledgement from the swap server.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelAck {
	/// MWixnet protocol version.
	pub version: u32,
	/// MWixnet message type.
	#[serde(rename = "type")]
	pub msg_type: mwixnet_protocol::MwixnetType,
	/// Selected route identifier.
	pub route_id: mwixnet_protocol::Hash,
	/// Selected route manifest sequence.
	#[serde(with = "string_or_u64")]
	pub manifest_sequence: u64,
	/// Original wallet request identifier.
	pub wallet_request_id: mwixnet_protocol::Hash,
	/// Hash of the cancellation request.
	pub cancel_swap_req_hash: mwixnet_protocol::Hash,
	/// Cancelled input commitment.
	#[serde(with = "commitment_serde")]
	pub input_commitment: Commitment,
	/// Signed cancellation status.
	pub status: CancelStatus,
	/// Time at which the server persisted the tombstone.
	#[serde(with = "string_or_u64")]
	pub tombstone_created_at: u64,
	/// Identity of the route entry server.
	pub swap_identity: mwixnet_protocol::PublicKey,
	/// Signature by the route entry server.
	pub swap_signature: mwixnet_protocol::Signature,
}

struct CancelAckPayload<'a>(&'a CancelAck);

impl Writeable for CancelAckPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		self.0.route_id.write(writer)?;
		writer.write_u64(self.0.manifest_sequence)?;
		self.0.wallet_request_id.write(writer)?;
		self.0.cancel_swap_req_hash.write(writer)?;
		self.0.input_commitment.write(writer)?;
		writer.write_u8(0)?;
		writer.write_u64(self.0.tombstone_created_at)?;
		self.0.swap_identity.write(writer)
	}
}

impl CancelAck {
	/// Return the hash signed by the route entry server.
	pub fn hash(&self) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(
			mwixnet_protocol::MwixnetType::CancelAck,
			&CancelAckPayload(self),
		)
	}

	/// Verify the acknowledgement and bind it to a cancellation request.
	pub fn validate(
		&self,
		request: &CancelSwapReq,
		swap_identity: mwixnet_protocol::PublicKey,
	) -> Result<(), String> {
		if self.version != mwixnet_protocol::MWIXNET_PROTOCOL_VERSION
			|| self.msg_type != mwixnet_protocol::MwixnetType::CancelAck
			|| self.route_id != request.route_id
			|| self.manifest_sequence != request.manifest_sequence
			|| self.wallet_request_id != request.wallet_request_id
			|| self.cancel_swap_req_hash != request.hash()
			|| self.input_commitment != request.input_commitment
			|| self.status != CancelStatus::Cancelled
			|| self.swap_identity != swap_identity
		{
			return Err("MWixnet cancellation acknowledgement does not match".into());
		}
		mwixnet_protocol::verify_signature(self.hash(), self.swap_identity, self.swap_signature)
			.map_err(|_| "invalid MWixnet cancellation acknowledgement signature".into())
	}
}

/// Persisted wallet state for a route-bound MWixnet request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletMwixnetRequest {
	/// Full byte-stable request used for retries.
	pub request: RouteSwapReq,
	/// Wallet transaction log ID.
	pub tx_id: Option<u32>,
	/// Input commitment in hexadecimal form.
	pub input_commitment: String,
	/// Entry server onion address.
	pub swap_onion_address: mwixnet_protocol::OnionAddress,
	/// Current local request state.
	pub status: WalletMwixnetRequestStatus,
	/// Maximum fee permitted for a recovery self-spend.
	#[serde(default = "default_reclaim_max_fee")]
	pub reclaim_max_fee: u64,
	/// Confirmation depth selected when the request was created.
	#[serde(default = "default_confirmation_depth")]
	pub confirmation_depth: u64,
	/// Kernel excess returned by the server, when known.
	pub kernel_excess: Option<String>,
	/// Byte-stable cancellation request used for retries.
	#[serde(default)]
	pub cancel_request: Option<CancelSwapReq>,
	/// Verified signed acknowledgement received from the swap server.
	#[serde(default)]
	pub cancel_ack: Option<CancelAck>,
	/// Fully built reclaim transaction used for retries.
	#[serde(default)]
	pub reclaim_tx: Option<grin_core::core::Transaction>,
	/// Wallet transaction log entry for the reclaim transaction.
	#[serde(default)]
	pub reclaim_tx_id: Option<u32>,
	/// Height at which a competing spend was first observed.
	#[serde(default)]
	pub conflict_observed_height: Option<u64>,
}

fn default_reclaim_max_fee() -> u64 {
	1_000_000_000
}

fn default_confirmation_depth() -> u64 {
	10
}

/// Public owner-API view of a persisted MWixnet request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletMwixnetRequestInfo {
	/// Random wallet request identifier.
	pub wallet_request_id: mwixnet_protocol::Hash,
	/// Selected route identifier.
	pub route_id: mwixnet_protocol::Hash,
	/// Wallet transaction log ID.
	pub tx_id: Option<u32>,
	/// Input commitment in hexadecimal form.
	pub input_commitment: String,
	/// Hash of the signed swap request.
	pub swap_req_hash: mwixnet_protocol::Hash,
	/// Current local request state.
	pub status: WalletMwixnetRequestStatus,
	/// Last block at which the server may accept the request.
	#[serde(with = "string_or_u64")]
	pub expires_at_height: u64,
	/// Kernel excess returned by the server, when known.
	pub kernel_excess: Option<String>,
}

impl From<&WalletMwixnetRequest> for WalletMwixnetRequestInfo {
	fn from(request: &WalletMwixnetRequest) -> Self {
		Self {
			wallet_request_id: request.request.wallet_request_id,
			route_id: request.request.route_id,
			tx_id: request.tx_id,
			input_commitment: request.input_commitment.clone(),
			swap_req_hash: request.request.hash(),
			status: request.status,
			expires_at_height: request.request.expires_at_height,
			kernel_excess: request.kernel_excess.clone(),
		}
	}
}

mod commitment_serde {
	use super::*;
	use serde::de::Error;

	pub fn serialize<S>(value: &Commitment, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&value.to_hex())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Commitment, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		let bytes = grin_util::from_hex(&value).map_err(D::Error::custom)?;
		if bytes.len() != 33 {
			return Err(D::Error::custom("invalid commitment length"));
		}
		Ok(Commitment::from_vec(bytes))
	}
}

impl Writeable for WalletMwixnetRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		writer.write_bytes(
			&serde_json::to_vec(self).map_err(|_| grin_core::ser::Error::CorruptedData)?,
		)
	}
}

impl Readable for WalletMwixnetRequest {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, grin_core::ser::Error> {
		let bytes = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&bytes).map_err(|_| grin_core::ser::Error::CorruptedData)
	}
}

struct RouteSwapReqPayload<'a> {
	wallet_request_id: &'a mwixnet_protocol::Hash,
	route_id: &'a mwixnet_protocol::Hash,
	manifest_sequence: u64,
	expires_at_height: u64,
	onion_hash: &'a mwixnet_protocol::Hash,
}

impl Writeable for RouteSwapReqPayload<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		self.wallet_request_id.write(writer)?;
		self.route_id.write(writer)?;
		writer.write_u64(self.manifest_sequence)?;
		writer.write_u64(self.expires_at_height)?;
		self.onion_hash.write(writer)
	}
}

impl RouteSwapReq {
	/// Return the hash to sign for the given route request fields.
	pub fn signing_hash(
		wallet_request_id: &mwixnet_protocol::Hash,
		route_id: &mwixnet_protocol::Hash,
		manifest_sequence: u64,
		expires_at_height: u64,
		onion_hash: &mwixnet_protocol::Hash,
	) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(
			mwixnet_protocol::MwixnetType::SwapReq,
			&RouteSwapReqPayload {
				wallet_request_id,
				route_id,
				manifest_sequence,
				expires_at_height,
				onion_hash,
			},
		)
	}

	/// Calculate the canonical onion hash.
	pub fn onion_hash(onion: &Onion) -> mwixnet_protocol::Hash {
		mwixnet_protocol::hash(mwixnet_protocol::MwixnetType::SwapReqOnion, onion)
	}

	/// Calculate the commitment-signed request hash.
	pub fn hash(&self) -> mwixnet_protocol::Hash {
		Self::signing_hash(
			&self.wallet_request_id,
			&self.route_id,
			self.manifest_sequence,
			self.expires_at_height,
			&self.onion_hash,
		)
	}

	/// Verify the structural fields, onion binding and commitment signature.
	pub fn validate(&self) -> Result<(), String> {
		if self.version != mwixnet_protocol::MWIXNET_PROTOCOL_VERSION
			|| self.msg_type != mwixnet_protocol::MwixnetType::SwapReq
			|| self.onion_hash != Self::onion_hash(&self.onion)
		{
			return Err("invalid route-bound MWixnet request".into());
		}
		self.comsig
			.verify(&self.onion.commit, &self.hash().0.to_vec())
			.map_err(|_| "invalid MWixnet request commitment signature".into())
	}
}

impl SwapReq {
	/// Return the request onion.
	pub fn onion(&self) -> &Onion {
		match self {
			Self::Route(request) => &request.onion,
			Self::Legacy(request) => &request.onion,
		}
	}

	/// Return the request commitment signature.
	pub fn comsig(&self) -> &ComSignature {
		match self {
			Self::Route(request) => &request.comsig,
			Self::Legacy(request) => &request.comsig,
		}
	}
}

/// Result of creating an mwixnet request.
#[derive(Serialize, Deserialize, Debug)]
pub struct MwixnetReqCreationResult {
	/// Request to submit to the first mwixnet server.
	#[serde(flatten)]
	pub request: SwapReq,
	/// Transaction log ID when the wallet output was locked.
	pub tx_id: Option<u32>,
}

/// Public X25519 key of an mwixnet server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MwixnetServerPublicKey([u8; 32]);

impl MwixnetServerPublicKey {
	/// Derive the public key published by an mwixnet server.
	pub fn from_secret(key: &SecretKey) -> Self {
		let key = PublicKey::from(&StaticSecret::from(key.0));
		Self(key.to_bytes())
	}

	/// Parse a public key from hexadecimal representation.
	pub fn from_hex(value: &str) -> Result<Self, String> {
		let bytes = grin_util::from_hex(value).map_err(|e| e.to_string())?;
		let bytes: [u8; 32] = bytes
			.try_into()
			.map_err(|_| "mwixnet server public key must be 32 bytes".to_string())?;
		Ok(Self(bytes))
	}

	/// Return the public key bytes.
	pub fn to_bytes(self) -> [u8; 32] {
		self.0
	}

	/// Return the hexadecimal representation.
	pub fn to_hex(self) -> String {
		self.0.to_hex()
	}
}

impl Serialize for MwixnetServerPublicKey {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_hex())
	}
}

impl<'de> Deserialize<'de> for MwixnetServerPublicKey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = String::deserialize(deserializer)?;
		Self::from_hex(&value).map_err(D::Error::custom)
	}
}

/// mwixnetRequest Creation Params
#[derive(Serialize, Deserialize, Debug)]
pub struct MixnetReqCreationParams {
	/// Ordered public keys of 1 to [`super::MAX_MWIXNET_HOPS`] participating servers
	pub server_keys: Vec<MwixnetServerPublicKey>,
	/// Fees per hop
	#[serde(with = "string_or_u64")]
	pub fee_per_hop: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// MWixnet route as evaluated by the wallet.
pub struct WalletRoute {
	/// Stable route identifier.
	pub route_id: mwixnet_protocol::Hash,
	/// Sequence of the active route manifest.
	#[serde(with = "string_or_u64")]
	pub manifest_sequence: u64,
	/// Latest signed route state.
	pub status: mwixnet_protocol::RouteState,
	/// Whether the route passed the wallet checks.
	pub usable: bool,
	/// Reason why the route is not usable.
	pub unusable_reason: Option<String>,
	/// Number of servers in the route.
	pub hop_count: u8,
	/// Fee charged by each server.
	#[serde(with = "string_or_u64")]
	pub fee_per_hop: u64,
	/// Total fee charged by the route.
	#[serde(with = "string_or_u64")]
	pub total_fee: u64,
	/// Time of the latest successful health check.
	#[serde(with = "string_or_u64")]
	pub last_verified: u64,
	/// Earliest expiry of the verified route records.
	#[serde(with = "string_or_u64")]
	pub valid_until: u64,
}

impl WalletRoute {
	/// Return an unusable route when signed relay records make a Tor query unnecessary.
	pub fn from_terminal_relay(
		announcement: &mwixnet_protocol::RouteAnnouncement,
		status: Option<&mwixnet_protocol::RouteStatus>,
		revocations: &[mwixnet_protocol::RouteRevocation],
		now: u64,
	) -> Result<Option<Self>, String> {
		announcement
			.validate(now)
			.map_err(|error| error.to_string())?;
		if let Some(status) = status {
			status.validate(now).map_err(|error| error.to_string())?;
		}
		for revocation in revocations {
			revocation
				.validate(now)
				.map_err(|error| error.to_string())?;
		}

		let matching_status = status.filter(|status| {
			status.route_id == announcement.route_id
				&& status.manifest_sequence == announcement.manifest_sequence
				&& status.manifest_hash == announcement.manifest_hash
				&& status.swap_identity == announcement.swap_identity
				&& status.sequence > announcement.sequence
				&& status.last_verified == announcement.last_verified
				&& status.valid_until <= announcement.valid_until
		});
		let revoked = revocations.iter().any(|revocation| {
			revocation.route_id == announcement.route_id
				&& revocation.manifest_sequence == announcement.manifest_sequence
				&& revocation.manifest_hash == announcement.manifest_hash
				&& announcement
					.participant_identities
					.contains(&revocation.participant_identity)
		});
		let status = if revoked {
			mwixnet_protocol::RouteState::Revoked
		} else if let Some(status) = matching_status {
			status.status
		} else {
			return Ok(None);
		};
		if !matches!(
			status,
			mwixnet_protocol::RouteState::Unavailable
				| mwixnet_protocol::RouteState::Draining
				| mwixnet_protocol::RouteState::Expired
				| mwixnet_protocol::RouteState::Revoked
		) {
			return Ok(None);
		}

		Ok(Some(Self {
			route_id: announcement.route_id,
			manifest_sequence: announcement.manifest_sequence,
			status,
			usable: false,
			unusable_reason: Some(format!("route is {:?}", status)),
			hop_count: announcement.hop_count,
			fee_per_hop: announcement.fee_per_hop,
			total_fee: announcement
				.fee_per_hop
				.saturating_mul(announcement.hop_count as u64),
			last_verified: announcement.last_verified,
			valid_until: matching_status
				.map(|status| status.valid_until)
				.unwrap_or(announcement.valid_until),
		}))
	}
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Route records fetched from the node and the entry server.
pub struct VerifiedMwixnetRoute {
	/// Signed route announcement received from the node.
	pub announcement: mwixnet_protocol::RouteAnnouncement,
	/// Route manifest received from the entry server.
	pub manifest: mwixnet_protocol::RouteManifest,
	/// Current offer from the entry swap server.
	pub swap_offer: mwixnet_protocol::SwapOffer,
	/// Current end-to-end route health proof.
	pub health: mwixnet_protocol::RouteHealthProof,
	/// Latest route status received after the announcement.
	#[serde(default)]
	pub status: Option<mwixnet_protocol::RouteStatus>,
	/// Latest revocations received for this manifest.
	#[serde(default)]
	pub revocations: Vec<mwixnet_protocol::RouteRevocation>,
}

impl VerifiedMwixnetRoute {
	/// Verify all records and their cross-record bindings.
	pub fn validate(&self, now: u64) -> Result<(), String> {
		self.announcement
			.validate(now)
			.map_err(|error| error.to_string())?;
		self.manifest
			.validate(now)
			.map_err(|error| error.to_string())?;
		self.swap_offer
			.validate(now)
			.map_err(|error| error.to_string())?;
		self.health
			.validate(&self.manifest, now)
			.map_err(|error| error.to_string())?;
		let first = self
			.manifest
			.ordered_hops
			.first()
			.ok_or_else(|| "route has no swap server".to_string())?;
		if self.announcement.route_id != self.manifest.route_id
			|| self.announcement.manifest_sequence != self.manifest.manifest_sequence
			|| self.announcement.manifest_hash != self.manifest.hash()
			|| self.announcement.health_hash != self.health.certificate.hash()
			|| self.announcement.swap_identity != self.manifest.swap_identity
			|| self.announcement.entry_onion != first.onion_address
			|| self.announcement.hop_count as usize != self.manifest.ordered_hops.len()
			|| self.announcement.fee_per_hop != self.manifest.fee_per_hop
			|| self.announcement.last_verified != self.health.certificate.verified_at
			|| self.announcement.valid_until > self.health.certificate.expires_at
			|| self.swap_offer.identity_public_key != first.identity_public_key
			|| self.swap_offer.onion_address != first.onion_address
			|| self.swap_offer.onion_public_key != first.onion_public_key
			|| self.manifest.fee_per_hop < self.swap_offer.minimum_fee
		{
			return Err("MWixnet route records do not match".to_string());
		}
		self.manifest
			.fee_per_hop
			.checked_mul(self.manifest.ordered_hops.len() as u64)
			.ok_or_else(|| "MWixnet route fee overflow".to_string())?;
		let participants = self
			.manifest
			.ordered_hops
			.iter()
			.map(|hop| hop.identity_public_key)
			.collect::<Vec<_>>();
		if self.announcement.participant_identities != participants {
			return Err("MWixnet route participant list does not match".to_string());
		}
		if let Some(status) = &self.status {
			status.validate(now).map_err(|error| error.to_string())?;
			if status.route_id != self.manifest.route_id
				|| status.manifest_sequence != self.manifest.manifest_sequence
				|| status.manifest_hash != self.manifest.hash()
				|| status.swap_identity != self.manifest.swap_identity
				|| status.sequence <= self.announcement.sequence
				|| status.last_verified != self.announcement.last_verified
				|| status.valid_until > self.announcement.valid_until
			{
				return Err("MWixnet route status does not match".to_string());
			}
		}
		for revocation in &self.revocations {
			revocation
				.validate(now)
				.map_err(|error| error.to_string())?;
			if revocation.route_id != self.manifest.route_id
				|| revocation.manifest_sequence != self.manifest.manifest_sequence
				|| revocation.manifest_hash != self.manifest.hash()
				|| !self.manifest.acceptances.iter().any(|acceptance| {
					acceptance.participant_identity == revocation.participant_identity
				}) {
				return Err("MWixnet route revocation does not match".to_string());
			}
		}
		Ok(())
	}

	/// Convert the verified records to the wallet-facing route summary.
	pub fn wallet_route(&self) -> WalletRoute {
		let hop_count = self.manifest.ordered_hops.len() as u8;
		let mut route = WalletRoute {
			route_id: self.manifest.route_id,
			manifest_sequence: self.manifest.manifest_sequence,
			status: self.announcement.status,
			usable: true,
			unusable_reason: None,
			hop_count,
			fee_per_hop: self.manifest.fee_per_hop,
			total_fee: self.manifest.fee_per_hop.saturating_mul(hop_count as u64),
			last_verified: self.health.certificate.verified_at,
			valid_until: self
				.manifest
				.valid_until
				.min(self.health.certificate.expires_at),
		};
		if let Some(status) = &self.status {
			route.status = status.status;
			route.valid_until = route.valid_until.min(status.valid_until);
		}
		if !self.revocations.is_empty() {
			route.status = mwixnet_protocol::RouteState::Revoked;
		}
		if !matches!(
			route.status,
			mwixnet_protocol::RouteState::Healthy | mwixnet_protocol::RouteState::Degraded
		) {
			route.usable = false;
			route.unusable_reason = Some(format!("route is {:?}", route.status));
		}
		route
	}
}

impl Writeable for VerifiedMwixnetRoute {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_core::ser::Error> {
		writer.write_bytes(
			&serde_json::to_vec(self).map_err(|_| grin_core::ser::Error::CorruptedData)?,
		)
	}
}

impl Readable for VerifiedMwixnetRoute {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, grin_core::ser::Error> {
		let bytes = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&bytes).map_err(|_| grin_core::ser::Error::CorruptedData)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mwixnet::onion::crypto::secp;
	use ed25519_dalek::{Signer, SigningKey};
	use grin_core::ser::{self, ProtocolVersion};
	use grin_util::secp::Secp256k1;
	use serde::Deserialize;

	#[derive(Deserialize)]
	struct DiscoveryVector<T> {
		value: T,
		binary: String,
		hash: String,
	}

	#[derive(Deserialize)]
	struct DiscoveryVectors {
		announcement: DiscoveryVector<mwixnet_protocol::RouteAnnouncement>,
		status: DiscoveryVector<mwixnet_protocol::RouteStatus>,
		revocation: DiscoveryVector<mwixnet_protocol::RouteRevocation>,
	}

	#[derive(Deserialize)]
	struct BinaryVector<T> {
		value: T,
		binary: String,
	}

	#[derive(Deserialize)]
	struct RouteVector {
		manifest: DiscoveryVector<mwixnet_protocol::RouteManifest>,
	}

	#[derive(Deserialize)]
	struct HealthVector {
		proof: BinaryVector<mwixnet_protocol::RouteHealthProof>,
	}

	#[derive(Deserialize)]
	struct RouteHealthVectors {
		route: RouteVector,
		health: HealthVector,
	}

	#[derive(Deserialize)]
	struct SignedVector<T> {
		value: T,
		signed_payload_binary: String,
		hash: String,
	}

	#[derive(Deserialize)]
	struct SwapVector {
		value: RouteSwapReq,
		onion_binary: String,
		onion_hash: String,
		signed_payload_binary: String,
		hash: String,
	}

	#[derive(Deserialize)]
	struct SwapVectors {
		swap: SwapVector,
		cancel: SignedVector<CancelSwapReq>,
		ack: SignedVector<CancelAck>,
	}

	fn route_request() -> RouteSwapReq {
		let secp = Secp256k1::new();
		let blind = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let amount = 42;
		let onion = Onion {
			ephemeral_pubkey: PublicKey::from([0; 32]),
			commit: secp::commit(amount, &blind).unwrap(),
			enc_payloads: Vec::new(),
		};
		let mut request = RouteSwapReq {
			version: mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
			msg_type: mwixnet_protocol::MwixnetType::SwapReq,
			wallet_request_id: mwixnet_protocol::Hash([2; 32]),
			route_id: mwixnet_protocol::Hash([3; 32]),
			manifest_sequence: 4,
			expires_at_height: 100,
			onion_hash: RouteSwapReq::onion_hash(&onion),
			onion,
			comsig: ComSignature::sign(amount, &blind, &Vec::new(), false).unwrap(),
		};
		request.comsig =
			ComSignature::sign(amount, &blind, &request.hash().0.to_vec(), false).unwrap();
		request
	}

	#[test]
	fn wallet_route_serializes_u64_values_as_strings() {
		let route = WalletRoute {
			route_id: mwixnet_protocol::Hash([1; 32]),
			manifest_sequence: u64::MAX,
			status: mwixnet_protocol::RouteState::Healthy,
			usable: true,
			unusable_reason: None,
			hop_count: 2,
			fee_per_hop: 12_500_000,
			total_fee: 25_000_000,
			last_verified: 1_800_000_000,
			valid_until: 1_800_000_900,
		};
		let value = serde_json::to_value(&route).unwrap();
		assert_eq!(value["manifest_sequence"], u64::MAX.to_string());
		assert_eq!(value["fee_per_hop"], "12500000");
		assert_eq!(value["total_fee"], "25000000");
		assert_eq!(value["last_verified"], "1800000000");
		assert_eq!(value["valid_until"], "1800000900");
		assert_eq!(serde_json::from_value::<WalletRoute>(value).unwrap(), route);
	}

	#[test]
	fn route_request_is_bound_and_strict() {
		let request = route_request();
		request.validate().unwrap();
		let mut json = serde_json::to_value(&request).unwrap();
		json.as_object_mut()
			.unwrap()
			.insert("unknown".into(), serde_json::Value::Bool(true));
		assert!(serde_json::from_value::<RouteSwapReq>(json).is_err());

		let mut invalid = request;
		invalid.expires_at_height += 1;
		assert!(invalid.validate().is_err());

		let mut legacy = serde_json::to_value(LegacySwapReq {
			onion: invalid.onion,
			comsig: invalid.comsig,
		})
		.unwrap();
		legacy
			.as_object_mut()
			.unwrap()
			.insert("route_id".into(), serde_json::json!(vec![0; 32]));
		assert!(serde_json::from_value::<SwapReq>(legacy).is_err());
	}

	#[test]
	fn cancel_ack_is_bound_to_request() {
		let route_request = route_request();
		let mut request = CancelSwapReq {
			version: mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
			msg_type: mwixnet_protocol::MwixnetType::CancelSwapReq,
			route_id: route_request.route_id,
			manifest_sequence: route_request.manifest_sequence,
			wallet_request_id: route_request.wallet_request_id,
			swap_req_hash: route_request.hash(),
			input_commitment: route_request.onion.commit,
			created_at: 1_800_000_000,
			comsig: route_request.comsig.clone(),
		};
		let secp = Secp256k1::new();
		let blind = SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		request.comsig = ComSignature::sign(42, &blind, &request.hash().0.to_vec(), false).unwrap();
		let key = SigningKey::from_bytes(&[7; 32]);
		let identity = mwixnet_protocol::PublicKey(key.verifying_key().to_bytes());
		let mut ack = CancelAck {
			version: mwixnet_protocol::MWIXNET_PROTOCOL_VERSION,
			msg_type: mwixnet_protocol::MwixnetType::CancelAck,
			route_id: request.route_id,
			manifest_sequence: request.manifest_sequence,
			wallet_request_id: request.wallet_request_id,
			cancel_swap_req_hash: request.hash(),
			input_commitment: request.input_commitment,
			status: CancelStatus::Cancelled,
			tombstone_created_at: 1_800_000_001,
			swap_identity: identity,
			swap_signature: mwixnet_protocol::Signature([0; 64]),
		};
		ack.swap_signature =
			mwixnet_protocol::Signature(key.sign(ack.hash().as_bytes()).to_bytes());
		ack.validate(&request, identity).unwrap();
		ack.wallet_request_id.0[0] ^= 1;
		assert!(ack.validate(&request, identity).is_err());
	}

	#[test]
	fn swap_vectors_match() {
		let vectors: SwapVectors =
			serde_json::from_str(include_str!("../../tests/swap_vectors.json")).unwrap();
		let swap = vectors.swap.value;
		let cancel = vectors.cancel.value;
		let ack = vectors.ack.value;
		assert_eq!(
			vectors.swap.onion_binary,
			ser::ser_vec(&swap.onion, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(
			vectors.swap.onion_hash,
			RouteSwapReq::onion_hash(&swap.onion).0.to_hex()
		);
		assert_eq!(
			vectors.swap.signed_payload_binary,
			ser::ser_vec(
				&RouteSwapReqPayload {
					wallet_request_id: &swap.wallet_request_id,
					route_id: &swap.route_id,
					manifest_sequence: swap.manifest_sequence,
					expires_at_height: swap.expires_at_height,
					onion_hash: &swap.onion_hash,
				},
				ProtocolVersion::local(),
			)
			.unwrap()
			.to_hex()
		);
		assert_eq!(vectors.swap.hash, swap.hash().0.to_hex());
		swap.validate().unwrap();
		assert_eq!(
			vectors.cancel.signed_payload_binary,
			ser::ser_vec(
				&CancelSwapReqPayload {
					route_id: &cancel.route_id,
					manifest_sequence: cancel.manifest_sequence,
					wallet_request_id: &cancel.wallet_request_id,
					swap_req_hash: &cancel.swap_req_hash,
					input_commitment: &cancel.input_commitment,
					created_at: cancel.created_at,
				},
				ProtocolVersion::local(),
			)
			.unwrap()
			.to_hex()
		);
		assert_eq!(vectors.cancel.hash, cancel.hash().0.to_hex());
		cancel
			.comsig
			.verify(&cancel.input_commitment, &cancel.hash().0.to_vec())
			.unwrap();
		assert_eq!(
			vectors.ack.signed_payload_binary,
			ser::ser_vec(&CancelAckPayload(&ack), ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.ack.hash, ack.hash().0.to_hex());
		ack.validate(&cancel, ack.swap_identity).unwrap();

		let mut conflicting = cancel;
		conflicting.created_at += 1;
		assert_ne!(vectors.cancel.hash, conflicting.hash().0.to_hex());
	}

	#[test]
	fn discovery_vectors_match() {
		let vectors: DiscoveryVectors =
			serde_json::from_str(include_str!("../../tests/mwixnet_vectors.json")).unwrap();
		let announcement = vectors.announcement.value;
		let status = vectors.status.value;
		let revocation = vectors.revocation.value;
		assert_eq!(
			vectors.announcement.binary,
			ser::ser_vec(&announcement, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.announcement.hash, announcement.hash().0.to_hex());
		assert_eq!(
			vectors.status.binary,
			ser::ser_vec(&status, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.status.hash, status.hash().0.to_hex());
		assert_eq!(
			vectors.revocation.binary,
			ser::ser_vec(&revocation, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.revocation.hash, revocation.hash().0.to_hex());
	}

	#[test]
	fn terminal_relay_route_does_not_require_server_records() {
		let vectors: DiscoveryVectors =
			serde_json::from_str(include_str!("../../tests/mwixnet_vectors.json")).unwrap();
		let announcement = vectors.announcement.value;
		let mut status = vectors.status.value;
		assert!(
			WalletRoute::from_terminal_relay(&announcement, Some(&status), &[], 1_800_000_000,)
				.unwrap()
				.is_none()
		);

		let key = SigningKey::from_bytes(&[7; 32]);
		for terminal in [
			mwixnet_protocol::RouteState::Unavailable,
			mwixnet_protocol::RouteState::Draining,
			mwixnet_protocol::RouteState::Expired,
		] {
			status.status = terminal;
			status.signature =
				mwixnet_protocol::Signature(key.sign(status.hash().as_bytes()).to_bytes());
			let route =
				WalletRoute::from_terminal_relay(&announcement, Some(&status), &[], 1_800_000_000)
					.unwrap()
					.unwrap();
			assert_eq!(route.status, terminal);
			assert!(!route.usable);
		}

		let route = WalletRoute::from_terminal_relay(
			&announcement,
			None,
			&[vectors.revocation.value],
			1_800_000_000,
		)
		.unwrap()
		.unwrap();
		assert_eq!(route.status, mwixnet_protocol::RouteState::Revoked);
		assert!(!route.usable);
	}

	#[test]
	fn route_health_vectors_match() {
		let vectors: RouteHealthVectors =
			serde_json::from_str(include_str!("../../tests/route_health_vectors.json")).unwrap();
		let manifest = vectors.route.manifest.value;
		let proof = vectors.health.proof.value;
		manifest.validate(1_800_000_000).unwrap();
		proof.validate(&manifest, 1_800_000_300).unwrap();
		assert_eq!(
			vectors.route.manifest.binary,
			ser::ser_vec(&manifest, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
		assert_eq!(vectors.route.manifest.hash, manifest.hash().0.to_hex());
		assert_eq!(
			vectors.health.proof.binary,
			ser::ser_vec(&proof, ProtocolVersion::local())
				.unwrap()
				.to_hex()
		);
	}
}
