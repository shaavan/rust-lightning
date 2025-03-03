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
use types::payment::PaymentHash;
use crate::blinded_path::message::{BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext};
use crate::blinded_path::payment::BlindedPaymentPath;
use crate::ln::channelmanager::{PaymentId, MAX_SHORT_LIVED_RELATIVE_EXPIRY};
use crate::ln::inbound_payment;
use crate::onion_message::dns_resolution::{DNSSECQuery, HumanReadableName};
use crate::sign::EntropySource;
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, InvoiceBuilder};
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestBuilder};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::messenger::{MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::sync::Mutex;

use core::ops::Deref;
use core::sync::atomic::AtomicUsize;
use core::time::Duration;

#[cfg(feature = "dnssec")]
use crate::onion_message::dns_resolution::DNSResolverMessage;

pub trait Flow {
    fn create_offer_builder(&self, nonce: Nonce) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError>;

    fn create_refund_builder(&self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId, nonce: Nonce) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError>;

    fn create_invoice_request_builder(
        &self, offer: &'static Offer, nonce: Nonce, quantity: Option<u64>, amount_msats: Option<u64>,
        payer_note: Option<String>, human_readable_name: Option<HumanReadableName>, payment_id: PaymentId
    ) -> Result<InvoiceRequestBuilder<secp256k1::All>, Bolt12SemanticError>;

    fn create_invoice_builder(
        &self, refund: &'static Refund, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash
    ) -> Result<InvoiceBuilder<DerivedSigningPubkey>, Bolt12SemanticError>;

    fn create_blinded_paths(&self, peers: Vec<MessageForwardNode>, context: MessageContext) -> Result<Vec<BlindedMessagePath>, ()>;

    fn create_compact_blinded_paths(&self, peers: Vec<MessageForwardNode>, context: OffersContext) -> Result<Vec<BlindedMessagePath>, ()>;

    fn create_blinded_paths_using_absolute_expiry(&self, peers: Vec<MessageForwardNode>, context: OffersContext, absolute_expiry: Option<Duration>) -> Result<Vec<BlindedMessagePath>, ()>;

    fn enqueue_invoice_request(
		&self, invoice_request: InvoiceRequest, reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError>;

    fn enqueue_invoice(
        &self, invoice: Bolt12Invoice, paths: &[BlindedMessagePath], reply_paths: Vec<BlindedMessagePath>
    ) -> Result<(), Bolt12SemanticError>;

    fn enqueue_dns_onion_message(
        &self, message: DNSSECQuery, reply_paths: Vec<BlindedMessagePath>
    ) -> Result<(), Bolt12SemanticError>;
}

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