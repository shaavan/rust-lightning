// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and methods for constructing [`BlindedPath`]s to send a message over.
//!
//! [`BlindedPath`]: crate::blinded_path::BlindedPath

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::ln::channelmanager::PaymentId;
#[allow(unused_imports)]
use crate::prelude::*;

use crate::blinded_path::{BlindedHop, BlindedPath, IntroductionNode, NextMessageHop, NodeIdLookUp};
use crate::blinded_path::utils;
use crate::io;
use crate::io::Cursor;
use crate::ln::onion_utils;
use crate::onion_message::packet::ControlTlvs;
use crate::sign::{NodeSigner, Recipient};
use crate::crypto::streams::ChaChaPolyReadAdapter;
use crate::util::ser::{FixedLengthReader, LengthReadableArgs, Writeable, Writer};

use core::mem;
use core::ops::Deref;

/// An intermediate node, and possibly a short channel id leading to the next node.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ForwardNode {
	/// This node's pubkey.
	pub node_id: PublicKey,
	/// The channel between `node_id` and the next hop. If set, the constructed [`BlindedHop`]'s
	/// `encrypted_payload` will use this instead of the next [`ForwardNode::node_id`] for a more
	/// compact representation.
	pub short_channel_id: Option<u64>,
}

/// TLVs to encode in an intermediate onion message packet's hop data. When provided in a blinded
/// route, they are encoded into [`BlindedHop::encrypted_payload`].
pub(crate) struct ForwardTlvs {
	/// The next hop in the onion message's path.
	pub(crate) next_hop: NextMessageHop,
	/// Senders to a blinded path use this value to concatenate the route they find to the
	/// introduction node with the blinded path.
	pub(crate) next_blinding_override: Option<PublicKey>,
}

/// Similar to [`ForwardTlvs`], but these TLVs are for the final node.
pub(crate) struct ReceiveTlvs {
	/// If `path_id` is `Some`, it is used to identify the blinded path that this onion message is
	/// sending to. This is useful for receivers to check that said blinded path is being used in
	/// the right context.
	pub(crate) path_id: Option<[u8; 32]>,
	pub recipient_data: RecipientData,
}

/// Represents additional data appended along with the sent reply path.
///
/// This data can be utilized by the final recipient for further processing
/// upon receiving it back.
#[derive(Clone, Debug)]
pub enum RecipientData {
    /// Payment ID of the outbound BOLT12 payment.
    Offers(OffersData),
    /// Custom data represented as a vector of bytes.
    Custom(Vec<u8>),
}

impl RecipientData {
    /// Creates a new, empty RecipientData instance of the Offers variant.
    pub fn offers(payment_id: PaymentId) -> Self {
        RecipientData::Offers(OffersData::new(payment_id))
    }

    /// Creates a new, empty RecipientData instance of the Custom variant.
    pub fn custom(data: Vec<u8>) -> Self {
        RecipientData::Custom(data)
    }
}

/// RecipientData for Offers Messages
#[derive(Clone, Debug)]
pub struct OffersData {
	/// Represents the local ID of the outbound payment this message belongs to.
	pub payment_id: Option<PaymentId>
}

impl OffersData {
	/// Create a new OffersData struct with a payment_id
	pub fn new(payment_id: PaymentId) -> Self {
		OffersData {
			payment_id: Some(payment_id)
		}
	}
}

impl Writeable for ForwardTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let (next_node_id, short_channel_id) = match self.next_hop {
			NextMessageHop::NodeId(pubkey) => (Some(pubkey), None),
			NextMessageHop::ShortChannelId(scid) => (None, Some(scid)),
		};
		// TODO: write padding
		encode_tlv_stream!(writer, {
			(2, short_channel_id, option),
			(4, next_node_id, option),
			(8, self.next_blinding_override, option)
		});
		Ok(())
	}
}

impl Writeable for ReceiveTlvs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		// TODO: write padding
		let mut payment_id = None;
		let mut custom_data = &Vec::new();

		match &self.recipient_data {
			RecipientData::Offers(data) => {
				let OffersData { payment_id: id } = data;
				payment_id = *id;
			}
			RecipientData::Custom(data) => {
				custom_data = data;
			}
		}

		encode_tlv_stream!(writer, {
			(6, self.path_id, option),
			(65537, payment_id, option),
			(65539, *custom_data, optional_vec),
		});
		Ok(())
	}
}

/// Construct blinded onion message hops for the given `intermediate_nodes` and `recipient_node_id`.
pub(super) fn blinded_hops<T: secp256k1::Signing + secp256k1::Verification>(
	secp_ctx: &Secp256k1<T>, intermediate_nodes: &[ForwardNode], recipient_node_id: PublicKey,
	session_priv: &SecretKey
) -> Result<Vec<BlindedHop>, secp256k1::Error> {
	let pks = intermediate_nodes.iter().map(|node| &node.node_id)
		.chain(core::iter::once(&recipient_node_id));
	let tlvs = pks.clone()
		.skip(1) // The first node's TLVs contains the next node's pubkey
		.zip(intermediate_nodes.iter().map(|node| node.short_channel_id))
		.map(|(pubkey, scid)| match scid {
			Some(scid) => NextMessageHop::ShortChannelId(scid),
			None => NextMessageHop::NodeId(*pubkey),
		})
		.map(|next_hop| ControlTlvs::Forward(ForwardTlvs { next_hop, next_blinding_override: None }))
		.chain(core::iter::once(ControlTlvs::Receive(ReceiveTlvs { path_id: None, recipient_data: RecipientData::custom(Vec::new()) })));

	utils::construct_blinded_hops(secp_ctx, pks, tlvs, session_priv)
}

// Advance the blinded onion message path by one hop, so make the second hop into the new
// introduction node.
pub(crate) fn advance_path_by_one<NS: Deref, NL: Deref, T>(
	path: &mut BlindedPath, node_signer: &NS, node_id_lookup: &NL, secp_ctx: &Secp256k1<T>
) -> Result<(), ()>
where
	NS::Target: NodeSigner,
	NL::Target: NodeIdLookUp,
	T: secp256k1::Signing + secp256k1::Verification,
{
	let control_tlvs_ss = node_signer.ecdh(Recipient::Node, &path.blinding_point, None)?;
	let rho = onion_utils::gen_rho_from_shared_secret(&control_tlvs_ss.secret_bytes());
	let encrypted_control_tlvs = path.blinded_hops.remove(0).encrypted_payload;
	let mut s = Cursor::new(&encrypted_control_tlvs);
	let mut reader = FixedLengthReader::new(&mut s, encrypted_control_tlvs.len() as u64);
	match ChaChaPolyReadAdapter::read(&mut reader, rho) {
		Ok(ChaChaPolyReadAdapter {
			readable: ControlTlvs::Forward(ForwardTlvs { next_hop, next_blinding_override })
		}) => {
			let next_node_id = match next_hop {
				NextMessageHop::NodeId(pubkey) => pubkey,
				NextMessageHop::ShortChannelId(scid) => match node_id_lookup.next_node_id(scid) {
					Some(pubkey) => pubkey,
					None => return Err(()),
				},
			};
			let mut new_blinding_point = match next_blinding_override {
				Some(blinding_point) => blinding_point,
				None => {
					onion_utils::next_hop_pubkey(secp_ctx, path.blinding_point,
						control_tlvs_ss.as_ref()).map_err(|_| ())?
				}
			};
			mem::swap(&mut path.blinding_point, &mut new_blinding_point);
			path.introduction_node = IntroductionNode::NodeId(next_node_id);
			Ok(())
		},
		_ => Err(())
	}
}
