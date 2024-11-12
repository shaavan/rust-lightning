// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use core::ops::Deref;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::blinded_path::NodeIdLookUp;
use crate::ln::channelmanager::{AChannelManager, OffersMessageCommons};
use crate::ln::inbound_payment;
use crate::onion_message::messenger::{MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;

use crate::routing::router::Router;
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::sync::Mutex;
use crate::util::logger::Logger;


pub struct OffersMessageFlow<ES: Deref, OMC: Deref, MR: Deref, R: Deref, NS: Deref, NL: Deref, L: Deref>
where
    ES::Target: EntropySource,
    OMC::Target: OffersMessageCommons + AChannelManager + Sized,
    MR::Target: MessageRouter,
    R::Target: Router,
    NS::Target: NodeSigner,
    NL::Target: NodeIdLookUp,
    L::Target: Logger,
{
	secp_ctx: Secp256k1<secp256k1::All>,
	inbound_payment_key: inbound_payment::ExpandedKey,

	node_signer: NS,
	entropy_source: ES,

	our_network_pubkey: PublicKey,

	/// Contains function shared between OffersMessageHandler, and ChannelManager.
	commons: OMC,

	lookup: NL,

	message_router: MR,
	router: R,

    #[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pub logger: L,
}

impl<ES: Deref, OMC: Deref, MR: Deref, R: Deref, NS: Deref, NL: Deref, L: Deref> OffersMessageFlow<ES, OMC, MR, R, NS, NL, L>
where
    ES::Target: EntropySource,
    OMC::Target: OffersMessageCommons + AChannelManager + Sized,
    MR::Target: MessageRouter,
    R::Target: Router,
    NS::Target: NodeSigner,
    NL::Target: NodeIdLookUp,
    L::Target: Logger,
{
	pub fn new(entropy_source: ES, commons: OMC, message_router: MR, router: R, node_signer: NS, lookup: NL, logger: L) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		let inbound_pmt_key_material = node_signer.get_inbound_payment_key_material();
		let expanded_inbound_key = inbound_payment::ExpandedKey::new(&inbound_pmt_key_material);
		Self {
			secp_ctx,
			inbound_payment_key: expanded_inbound_key,
			
			our_network_pubkey: node_signer.get_node_id(Recipient::Node).unwrap(),

			commons,
			lookup,
			message_router,
			router,

			pending_offers_messages: Mutex::new(Vec::new()),

			node_signer,
			entropy_source,

			logger,
		}
	}

	fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}
}