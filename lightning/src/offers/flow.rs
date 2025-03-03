// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling Bolt12 messages and payments.

use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{Secp256k1, PublicKey};
use bitcoin::{secp256k1, Network};
use crate::ln::inbound_payment;
use crate::sign::EntropySource;
use crate::onion_message::messenger::{MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::sync::Mutex;

use core::ops::Deref;
use core::sync::atomic::AtomicUsize;

#[cfg(feature = "dnssec")]
use crate::onion_message::dns_resolution::DNSResolverMessage;

pub struct OffersMessageFlow<ES: Deref, MR: Deref>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
{
    chain_hash: ChainHash,
    message_router: MR,

    our_network_pubkey: PublicKey,
    highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

    secp_ctx: Secp256k1<secp256k1::All>,
	entropy_source: ES,

	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

    #[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<ES: Deref, MR: Deref> OffersMessageFlow<ES, MR>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
        network: Network, message_router: MR, our_network_pubkey: PublicKey,
        current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
        entropy_source: ES,

	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			chain_hash: ChainHash::using_genesis_block(network),
            message_router,

            our_network_pubkey,
            highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
            inbound_payment_key,

            secp_ctx,
            entropy_source,

            pending_offers_messages: Mutex::new(Vec::new()),
            pending_async_payments_messages: Mutex::new(Vec::new()),
            #[cfg(feature = "dnssec")]
			pending_dns_onion_messages: Mutex::new(Vec::new()),
		}
	}

	/// Gets the node_id held by this OffersMessageFlow
	pub fn get_our_node_id(&self) -> PublicKey {
		self.our_network_pubkey
	}
}