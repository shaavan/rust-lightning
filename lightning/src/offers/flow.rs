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


use core::ops::Deref;
use core::time::Duration;
use core::sync::atomic::{AtomicUsize, Ordering};

use bitcoin::block::Header;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::blinded_path::message::{AsyncPaymentsContext, BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext};
use crate::blinded_path::payment::{BlindedPaymentPath, PaymentConstraints, PaymentContext, UnauthenticatedReceiveTlvs};
use crate::chain::{self, BestBlock};
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::chain::transaction::TransactionData;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{ChainParameters, PaymentId, CLTV_FAR_FAR_AWAY, MAX_SHORT_LIVED_RELATIVE_EXPIRY};
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, InvoiceBuilder};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestBuilder, VerifiedInvoiceRequest};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::routing::router::Router;
use crate::sign::NodeSigner;
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::sign::EntropySource;
use crate::sync::{Mutex, RwLock};
use crate::ln::inbound_payment;

#[cfg(async_payments)]
use crate::offers::static_invoice::{StaticInvoice, StaticInvoiceBuilder};

#[cfg(feature = "dnssec")]
use {
	crate::blinded_path::message::DNSResolverContext,
	crate::onion_message::dns_resolution::{DNSResolverMessage, DNSSECQuery},
};

pub trait Flow: chain::Listen {
	fn verify_invoice_request(&self, invoice_request: InvoiceRequest, context: Option<OffersContext>) -> Result<VerifiedInvoiceRequest, ()>;

	fn verify_bolt12_invoice(&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>) -> Result<PaymentId, ()>;

	#[cfg(async_payments)]
	fn verify_async_context(&self, context: AsyncPaymentsContext) -> Result<Option<PaymentId>, ()>;

	fn create_offer_builder(
		&self, absolute_expiry: Option<Duration>, nonce: Option<Nonce>, peers: Vec<MessageForwardNode>,
	) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError>;

	fn create_refund_builder(
		&self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId, peers: Vec<MessageForwardNode>,
	) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError>;

	fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, human_readable_name: Option<HumanReadableName>,
		payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError>;

	#[cfg(async_payments)]
	fn create_static_invoice_builder<'a>(
		&'a self, offer: &'a Offer, offer_nonce: Nonce, relative_expiry: Option<Duration>, usable_channels: Vec<ChannelDetails>, peers: Vec<MessageForwardNode>
	) -> Result<StaticInvoiceBuilder<'a>, Bolt12SemanticError>;

	fn create_invoice_builder_from_refund<'a>(
		&'a self, refund: &'a Refund, payment_hash: PaymentHash, payment_secret: PaymentSecret, usable_channels: Vec<ChannelDetails>,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError>;

	fn create_invoice_from_invoice_request<NS: Deref>(
		&self, signer: &NS, invoice_request: VerifiedInvoiceRequest, amount_msats: u64, payment_hash: PaymentHash, payment_secret: PaymentSecret, usable_channels: Vec<ChannelDetails>
	) -> Result<Bolt12Invoice, InvoiceError>
	where
		NS::Target: NodeSigner;

	fn enqueue_invoice_request(
		&self, invoice_request: InvoiceRequest, payment_id: PaymentId, nonce: Option<Nonce>, peers: Vec<MessageForwardNode>
	) -> Result<(), Bolt12SemanticError>;

	fn enqueue_invoice(
		&self, invoice: Bolt12Invoice, refund: &Refund, payment_hash: PaymentHash, peers: Vec<MessageForwardNode>
	) -> Result<(), Bolt12SemanticError>;

	#[cfg(async_payments)]
	fn enqueue_async_payment_messages(
		&self, invoice: &StaticInvoice, payment_id: PaymentId, peers: Vec<MessageForwardNode>
	) -> Result<(), Bolt12SemanticError>;

	#[cfg(feature = "dnssec")]
	fn enqueue_dns_onion_message(
		&self, message: DNSSECQuery, context: DNSResolverContext, dns_resolvers: Vec<Destination>,
		peers: Vec<MessageForwardNode>
	) -> Result<(), Bolt12SemanticError>;

	fn get_and_clear_pending_offers_messages(
		&self,
	) -> Vec<(OffersMessage, MessageSendInstructions)>;

	fn get_and_clear_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)>;

	#[cfg(feature = "dnssec")]
	fn get_and_clear_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)>;
}


pub struct OffersMessageFlow<ES: Deref, MR: Deref, R: Deref>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	chain_hash: ChainHash,
	best_block: RwLock<BestBlock>,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	entropy_source: ES,

	message_router: MR,
	router: R,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<ES: Deref, MR: Deref, R: Deref> OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		params: ChainParameters, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		entropy_source: ES, message_router: MR, router: R,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			chain_hash: ChainHash::using_genesis_block(params.network),
			best_block: RwLock::new(params.best_block),

			our_network_pubkey,
			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
			inbound_payment_key,

			secp_ctx,
			entropy_source,

			message_router,
			router,

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

	fn duration_since_epoch(&self) -> Duration {
		#[cfg(not(feature = "std"))]
		let now = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
		#[cfg(feature = "std")]
		let now = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");
		now
	}

	fn best_block_updated(&self, header: &Header) {
		macro_rules! max_time {
			($timestamp: expr) => {
				loop {
					// Update $timestamp to be the max of its current value and the block
					// timestamp. This should keep us close to the current time without relying on
					// having an explicit local time source.
					// Just in case we end up in a race, we loop until we either successfully
					// update $timestamp or decide we don't need to.
					let old_serial = $timestamp.load(Ordering::Acquire);
					if old_serial >= header.time as usize { break; }
					if $timestamp.compare_exchange(old_serial, header.time as usize, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
						break;
					}
				}
			}
		}

		max_time!(self.highest_seen_timestamp);
	}
}

impl<ES: Deref, MR: Deref, R: Deref> OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	/// Creates a collection of blinded paths by delegating to [`MessageRouter`] based on
	/// the path's intended lifetime.
	///
	/// Whether or not the path is compact depends on whether the path is short-lived or long-lived,
	/// respectively, based on the given `absolute_expiry` as seconds since the Unix epoch. See
	/// [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`].
	fn create_blinded_paths_using_absolute_expiry(
		&self, context: OffersContext, absolute_expiry: Option<Duration>, peers: Vec<MessageForwardNode>
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let now = self.duration_since_epoch();
		let max_short_lived_absolute_expiry = now.saturating_add(MAX_SHORT_LIVED_RELATIVE_EXPIRY);

		if absolute_expiry.unwrap_or(Duration::MAX) <= max_short_lived_absolute_expiry {
			self.create_compact_blinded_paths(peers, context)
		} else {
			self.create_blinded_paths(peers, MessageContext::Offers(context))
		}
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_blinded_paths(&self, peers: Vec<MessageForwardNode>, context: MessageContext) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = peers
			.into_iter()
			.map(|node| node.node_id)
			.collect();

		self.message_router
			.create_blinded_paths(recipient, context, peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_compact_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_compact_blinded_paths(&self, peers: Vec<MessageForwardNode>, context: OffersContext) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = peers;

		self.message_router
			.create_compact_blinded_paths(recipient, MessageContext::Offers(context), peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	fn create_blinded_payment_paths(
		&self, usable_channels: Vec<ChannelDetails>, amount_msats: Option<u64>, payment_secret: PaymentSecret,
		payment_context: PaymentContext, relative_expiry_seconds: u32
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let first_hops = usable_channels;
		let payee_node_id = self.get_our_node_id();

		// Assume shorter than usual block times to avoid spuriously failing payments too early.
		const SECONDS_PER_BLOCK: u32 = 9 * 60;
		let relative_expiry_blocks = relative_expiry_seconds / SECONDS_PER_BLOCK;
		let max_cltv_expiry = core::cmp::max(relative_expiry_blocks, CLTV_FAR_FAR_AWAY)
			.saturating_add(LATENCY_GRACE_PERIOD_BLOCKS)
			.saturating_add(self.best_block.read().unwrap().height);

		let payee_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret,
			payment_constraints: PaymentConstraints {
				max_cltv_expiry,
				htlc_minimum_msat: 1,
			},
			payment_context,
		};
		let nonce = Nonce::from_entropy_source(entropy);
		let payee_tlvs = payee_tlvs.authenticate(nonce, expanded_key);

		self.router.create_blinded_payment_paths(
			payee_node_id, first_hops, payee_tlvs, amount_msats, secp_ctx
		)
	}
}

impl<ES: Deref, MR: Deref, R: Deref> chain::Listen for OffersMessageFlow<ES, MR, R>
where
	ES::Target: EntropySource,
	MR::Target: MessageRouter,
	R::Target: Router,
{
	fn filtered_block_connected(&self, header: &Header, _txdata: &TransactionData, _height: u32) {
		self.best_block_updated(header);
	}

	fn block_disconnected(&self, _header: &Header, _height: u32) {}
}
