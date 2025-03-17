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


use core::time::Duration;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::ops::Deref;

use bitcoin::block::Header;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use bitcoin::network::Network;

use crate::blinded_path::message::{AsyncPaymentsContext, BlindedMessagePath, OffersContext};
use crate::blinded_path::payment::{BlindedPaymentPath, PaymentContext};
use crate::chain;
use crate::chain::transaction::TransactionData;
use crate::ln::channelmanager::PaymentId;
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, InvoiceBuilder};
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestBuilder, VerifiedInvoiceRequest};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::onion_message::messenger::{Destination, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::types::payment::{PaymentHash, PaymentSecret};
use crate::sign::EntropySource;
use crate::sync::Mutex;
use crate::ln::inbound_payment;

#[cfg(async_payments)]
use {
	crate::blinded_path::message::MessageContext,
	crate::blinded_path::payment::AsyncBolt12OfferContext,
	crate::offers::offer::Amount,
	crate::offers::signer,
	crate::offers::static_invoice::{DEFAULT_RELATIVE_EXPIRY as STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY, StaticInvoice, StaticInvoiceBuilder},
	crate::onion_message::async_payments::AsyncPaymentsMessage,
};

#[cfg(feature = "dnssec")]
use crate::onion_message::dns_resolution::{DNSResolverMessage, DNSSECQuery};

pub trait Flow: chain::Listen {
	fn verify_invoice_request(&self, invoice_request: InvoiceRequest, context: Option<OffersContext>) -> Result<VerifiedInvoiceRequest, ()>;

	fn verify_bolt12_invoice(&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>) -> Result<PaymentId, ()>;

	#[cfg(async_payments)]
	fn verify_async_context(&self, context: AsyncPaymentsContext) -> Result<Option<PaymentId>, ()>;

	fn create_offer_builder<F>(
		&self, absolute_expiry: Option<Duration>, paths: F,
	) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError>
	where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>;

	fn create_refund_builder<F>(
		&self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId, paths: F,
	) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError>
	where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>;

	fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, human_readable_name: Option<HumanReadableName>,
		payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError>;

	#[cfg(async_payments)]
	fn create_static_invoice_builder<'a, F1, F2>(
		&'a self, offer: &'a Offer, offer_nonce: Nonce, relative_expiry: Option<Duration>, payment_paths: F1, receive_paths: F2
	) -> Result<StaticInvoiceBuilder<'a>, Bolt12SemanticError>
	where
		F1: Fn(Option<u64>, PaymentSecret, PaymentContext, u32) -> Result<Vec<BlindedPaymentPath>, ()>,
		F2: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>;

	fn create_invoice_builder_from_refund<'a, F>(
		&'a self, refund: &'a Refund, payment_hash: PaymentHash, payment_secret: PaymentSecret, payment_paths: F,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError>
	where
		F: Fn(PaymentContext) -> Result<Vec<BlindedPaymentPath>, ()>;

	fn create_invoice_builder_from_invoice_request<'a, F>(
		&'a self, invoice_request: VerifiedInvoiceRequest, payment_hash: PaymentHash, payment_secret: PaymentSecret, payment_paths: F,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError>
	where
		F: Fn(PaymentContext) -> Result<Vec<BlindedPaymentPath>, ()>;

	fn enqueue_invoice_request<F>(
		&self, invoice_request: InvoiceRequest, nonce: Option<Nonce>, reply_paths: F,
	) -> Result<(), Bolt12SemanticError>
	where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>;

	fn enqueue_invoice<F>(
		&self, invoice: Bolt12Invoice, refund: &Refund, reply_paths: F,
	) -> Result<(), Bolt12SemanticError>
	where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>;

   #[cfg(async_payments)]
   fn enqueue_async_payment_messages<F>(
		&self, invoice: Bolt12Invoice, reply_paths: F,
   ) -> Result<(), Bolt12SemanticError>
   where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>;

	#[cfg(feature = "dnssec")]
	fn enqueue_dns_onion_message<F>(
		&self, message: DNSSECQuery, dns_resolvers: Vec<Destination>,
		reply_paths: F,
	) -> Result<(), Bolt12SemanticError>
	where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>;

	fn get_and_clear_pending_offers_messages(
		&self,
	) -> Vec<(OffersMessage, MessageSendInstructions)>;

	#[cfg(async_payments)]
	fn get_and_clear_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)>;

	#[cfg(feature = "dnssec")]
	fn get_and_clear_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)>;
}


pub struct OffersMessageFlow<ES: Deref>
where
	ES::Target: EntropySource,
{
	chain_hash: ChainHash,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	entropy_source: ES,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
}

impl<ES: Deref> OffersMessageFlow<ES>
where
	ES::Target: EntropySource,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		network: Network, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		entropy_source: ES,
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			chain_hash: ChainHash::using_genesis_block(network),

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

impl<ES: Deref> chain::Listen for OffersMessageFlow<ES>
where
	ES::Target: EntropySource,
{
	fn filtered_block_connected(&self, header: &Header, _txdata: &TransactionData, _height: u32) {
		self.best_block_updated(header);
	}

	fn block_disconnected(&self, _header: &Header, _height: u32) {}
}

impl<ES: Deref> Flow for OffersMessageFlow<ES>
where
	ES::Target: EntropySource,
{
	fn verify_invoice_request(&self, invoice_request: InvoiceRequest, context: Option<OffersContext>) -> Result<VerifiedInvoiceRequest, ()> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		let nonce = match context {
			None if invoice_request.metadata().is_some() => None,
			Some(OffersContext::InvoiceRequest { nonce }) => Some(nonce),
			_ => return Err(()),
		};

		let invoice_request = match nonce {
			Some(nonce) => match invoice_request.verify_using_recipient_data(
				nonce, expanded_key, secp_ctx,
			) {
				Ok(invoice_request) => invoice_request,
				Err(()) => return Err(()),
			},
			None => match invoice_request.verify_using_metadata(expanded_key, secp_ctx) {
				Ok(invoice_request) => invoice_request,
				Err(()) => return Err(()),
			},
		};

		Ok(invoice_request)
	}

	fn verify_bolt12_invoice(&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>) -> Result<PaymentId, ()> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		match context {
			None if invoice.is_for_refund_without_paths() => {
				invoice.verify_using_metadata(expanded_key, secp_ctx)
			},
			Some(&OffersContext::OutboundPayment { payment_id, nonce, .. }) => {
				invoice.verify_using_payer_data(payment_id, nonce, expanded_key, secp_ctx)
			},
			_ => Err(()),
		}
	}

	#[cfg(async_payments)]
	fn verify_async_context(&self, context: AsyncPaymentsContext) -> Result<Option<PaymentId>, ()> {
		match context {
			AsyncPaymentsContext::InboundPayment { nonce, hmac, path_absolute_expiry } => {
				signer::verify_held_htlc_available_context(nonce, hmac, &self.inbound_payment_key)?;
	
				if self.duration_since_epoch() > path_absolute_expiry {
					return Err(())
				}
				Ok(None)
			}
			AsyncPaymentsContext::OutboundPayment { payment_id, hmac, nonce } => {
				payment_id.verify_for_async_payment(hmac, nonce, &self.inbound_payment_key)?;
				Ok(Some(payment_id))
			}
		}
	}

	fn create_offer_builder<F>(
		&self, absolute_expiry: Option<Duration>, paths: F,
	) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError>
	where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>
	{
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::InvoiceRequest { nonce };

		let path = paths(context)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = OfferBuilder::deriving_signing_pubkey(node_id, expanded_key, nonce, secp_ctx)
			.chain_hash(self.chain_hash)
			.path(path);

		let builder = match absolute_expiry {
			None => builder,
			Some(absolute_expiry) => builder.absolute_expiry(absolute_expiry),
		};

		Ok(builder)
	}

	fn create_refund_builder<F>(
		&self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId, paths: F,
	) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError>
	where
		F: Fn(OffersContext) -> Result<Vec<BlindedMessagePath>, ()>
	{
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::OutboundPayment { payment_id, nonce, hmac: None };

		let path = paths(context)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = RefundBuilder::deriving_signing_pubkey(
			node_id, expanded_key, nonce, secp_ctx, amount_msats, payment_id
		)?
			.chain_hash(self.chain_hash)
			.absolute_expiry(absolute_expiry)
			.path(path);

		Ok(builder)
	}

	fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, human_readable_name: Option<HumanReadableName>,
		payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let builder: InvoiceRequestBuilder<secp256k1::All> = offer
			.request_invoice(expanded_key, nonce, secp_ctx, payment_id)?
			.into();
		let builder = builder.chain_hash(self.chain_hash)?;

		let builder = match quantity {
			None => builder,
			Some(quantity) => builder.quantity(quantity)?,
		};
		let builder = match amount_msats {
			None => builder,
			Some(amount_msats) => builder.amount_msats(amount_msats)?,
		};
		let builder = match payer_note {
			None => builder,
			Some(payer_note) => builder.payer_note(payer_note),
		};
		let builder = match human_readable_name {
			None => builder,
			Some(hrn) => builder.sourced_from_human_readable_name(hrn),
		};

		Ok(builder)
	}

	#[cfg(async_payments)]
	fn create_static_invoice_builder<'a, F1, F2>(
		&'a self, offer: &'a Offer, offer_nonce: Nonce, relative_expiry: Option<Duration>, payment_paths: F1, receive_paths: F2
	) -> Result<StaticInvoiceBuilder<'a>, Bolt12SemanticError>
	where
		F1: Fn(Option<u64>, PaymentSecret, PaymentContext, u32) -> Result<Vec<BlindedPaymentPath>, ()>,
		F2: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let payment_context = PaymentContext::AsyncBolt12Offer(
			AsyncBolt12OfferContext { offer_nonce }
		);
		let amount_msat = offer.amount().and_then(|amount| {
			match amount {
				Amount::Bitcoin { amount_msats } => Some(amount_msats),
				Amount::Currency { .. } => None
			}
		});

		let relative_expiry = relative_expiry.unwrap_or(STATIC_INVOICE_DEFAULT_RELATIVE_EXPIRY);
		let relative_expiry_secs: u32 = relative_expiry.as_secs().try_into().unwrap_or(u32::MAX);

		let created_at = self.duration_since_epoch();
		let payment_secret = inbound_payment::create_for_spontaneous_payment(
			&self.inbound_payment_key, amount_msat, relative_expiry_secs, created_at.as_secs(), None
		).map_err(|()| Bolt12SemanticError::InvalidAmount)?;

		let payment_paths = payment_paths(amount_msat, payment_secret, payment_context, relative_expiry_secs)
			.map_err(|()| Bolt12SemanticError::MissingPaths)?;

		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = signer::hmac_for_held_htlc_available_context(nonce, expanded_key);
		let path_absolute_expiry = Duration::from_secs(
			inbound_payment::calculate_absolute_expiry(created_at.as_secs(), relative_expiry_secs)
		);

		let context = MessageContext::AsyncPayments(
			AsyncPaymentsContext::InboundPayment { nonce, hmac, path_absolute_expiry }
		);

		let async_receive_message_paths = receive_paths(context)
			.map_err(|()| Bolt12SemanticError::MissingPaths)?;

		StaticInvoiceBuilder::for_offer_using_derived_keys(
			offer, payment_paths, async_receive_message_paths, created_at, expanded_key,
			offer_nonce, secp_ctx
		).map(|inv| inv.allow_mpp().relative_expiry(relative_expiry_secs))
	}


}