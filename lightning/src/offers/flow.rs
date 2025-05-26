// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling BOLT12 messages and payments.

use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use bitcoin::block::Header;
use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::{self, PublicKey, Secp256k1};

use crate::blinded_path::message::{
	BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext,
};
use crate::blinded_path::payment::{
	BlindedPaymentPath, Bolt12OfferContext, Bolt12RefundContext, PaymentConstraints,
	PaymentContext, UnauthenticatedReceiveTlvs,
};
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;

#[allow(unused_imports)]
use crate::prelude::*;

use crate::chain::BestBlock;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::{
	Verification, {PaymentId, CLTV_FAR_FAR_AWAY, MAX_SHORT_LIVED_RELATIVE_EXPIRY},
};
use crate::ln::inbound_payment;
use crate::offers::invoice::{
	Bolt12Invoice, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY
};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{
	InvoiceRequest, InvoiceRequestBuilder, VerifiedInvoiceRequest,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{Amount, DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::onion_message::packet::OnionMessageContents;
use crate::routing::router::Router;
use crate::sign::{EntropySource, NodeSigner};
use crate::sync::{Mutex, RwLock};
use crate::types::payment::{PaymentHash, PaymentSecret};

#[cfg(async_payments)]
use {
	crate::blinded_path::message::AsyncPaymentsContext,
	crate::blinded_path::payment::AsyncBolt12OfferContext,
	crate::offers::signer,
	crate::offers::static_invoice::{StaticInvoice, StaticInvoiceBuilder},
	crate::onion_message::async_payments::HeldHtlcAvailable,
};

#[cfg(feature = "dnssec")]
use {
	crate::blinded_path::message::DNSResolverContext,
	crate::onion_message::dns_resolution::{DNSResolverMessage, DNSSECQuery, OMNameResolver},
};

/// The UserConfig to determine the level of event generation and manual handling user wants.
/// Set during Flow initialisation
pub struct UserConfigs {
	/// Represent config parameter, and behavior to be followed when invoice request is received.
	invoice_request_configs: InvoiceRequestConfigs,
	/// Represent config parameter, and behavior to be followed when bolt12invoice is received.
	invoice_configs: Bolt12InvoiceConfigs,
}

impl Default for UserConfigs {
	fn default() -> Self {
		UserConfigs {
			invoice_request_configs: InvoiceRequestConfigs::NeverTrigger,
			invoice_configs: Bolt12InvoiceConfigs::NeverTrigger,
		}
	}
}

/// Different level of config parameter to represents when [`OfferEvents::InvoiceRequestReceived`]
/// will be triggered.
pub enum InvoiceRequestConfigs {
	/// Always trigger.
	AlwaysTrigger,
	/// Trigger only if the corresponding offer is in currency.
	TriggerIfOfferInCurrency,
	/// Never trigger
	NeverTrigger,
}

/// Different level of config parameter to represents when [`OfferEvents::Bolt12InvoiceReceived`]
/// will be triggered.
pub enum Bolt12InvoiceConfigs {
	/// Always trigger.
	AlwaysTrigger,
	/// Trigger only if invoice corresponds to offer and the offer is in currency.
	TriggerIfOfferInCurrency,
	/// Trigger only if invoice corresponds to offer and the offer is in currency,
	/// and the corresponding IR amount is also no set.
	TriggerIfOfferInCurrencyAndNoIRAmount,
	/// Never trigger
	NeverTrigger,
}

/// Represents the nature of InvoiceRequest and the corresponding Offer's amount is set.
pub enum IREventAmount {
	/// Only the Offer amount is set, and the InvoiceRequest amount is not specified.
	OfferOnly { offer_amount: Amount },
	/// Only the InvoiceRequest amount is set, and the Offer amount is not specified.
	InvoiceRequestOnly { invoice_request_amount_msats: u64 },
	/// Both the InvoiceRequest amount and Offer amount are set.
	InvoiceRequestAndOfferAmount {
		invoice_request_amount_msats: u64,
		offer_amount: Amount,
	},
}

/// Contains OfferEvents that can optionally triggered for manual
/// handling by user based on appropriate user_config.
pub enum OfferEvents {
	/// Notifies that an [`InvoiceRequest`] was received
	InvoiceRequestReceived {
		invoice_request: VerifiedInvoiceRequest,
		amount: IREventAmount,
	},

	/// Notified that an [`Bolt12Invoice`] was received
	Bolt12InvoiceReceived {
		invoice: Bolt12Invoice,
		payment_id: PaymentId,
		invoice_amount: u64,
		amount_source: Bolt12InvoiceAmountSource,
	},
}

/// Contains [`OfferEvents::Bolt12InvoiceReceived`] data specific
/// to [`Bolt12Invoice`] corresponds to Offer or Refund.
pub enum Bolt12InvoiceAmountSource {
	ForOffer { amount: IREventAmount },
	ForRefund { refund_amount: u64 },
}

/// A BOLT12 offers code and flow utility provider, which facilitates
/// BOLT12 builder generation and onion message handling.
///
/// [`OffersMessageFlow`] is parameterized by a [`MessageRouter`], which is responsible
/// for finding message paths when initiating and retrying onion messages.
pub struct OffersMessageFlow<MR: Deref>
where
	MR::Target: MessageRouter,
{
	chain_hash: ChainHash,
	best_block: RwLock<BestBlock>,

	our_network_pubkey: PublicKey,
	highest_seen_timestamp: AtomicUsize,
	inbound_payment_key: inbound_payment::ExpandedKey,

	secp_ctx: Secp256k1<secp256k1::All>,
	message_router: MR,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

	pending_offers_events: Mutex<Vec<OfferEvents>>,

	pending_async_payments_messages: Mutex<Vec<(AsyncPaymentsMessage, MessageSendInstructions)>>,

	#[cfg(feature = "dnssec")]
	pub(crate) hrn_resolver: OMNameResolver,
	#[cfg(feature = "dnssec")]
	pending_dns_onion_messages: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,

	user_configs: UserConfigs,
}

impl<MR: Deref> OffersMessageFlow<MR>
where
	MR::Target: MessageRouter,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(
		chain_hash: ChainHash, best_block: BestBlock, our_network_pubkey: PublicKey,
		current_timestamp: u32, inbound_payment_key: inbound_payment::ExpandedKey,
		secp_ctx: Secp256k1<secp256k1::All>, message_router: MR,
	) -> Self {
		Self {
			chain_hash,
			best_block: RwLock::new(best_block),

			our_network_pubkey,
			highest_seen_timestamp: AtomicUsize::new(current_timestamp as usize),
			inbound_payment_key,

			secp_ctx,
			message_router,

			pending_offers_messages: Mutex::new(Vec::new()),
			pending_offers_events: Mutex::new(Vec::new()),
			pending_async_payments_messages: Mutex::new(Vec::new()),

			#[cfg(feature = "dnssec")]
			hrn_resolver: OMNameResolver::new(current_timestamp, best_block.height),
			#[cfg(feature = "dnssec")]
			pending_dns_onion_messages: Mutex::new(Vec::new()),

			user_configs: UserConfigs::default(),
		}
	}

	/// Gets the node_id held by this [`OffersMessageFlow`]`
	fn get_our_node_id(&self) -> PublicKey {
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

	/// Notifies the [`OffersMessageFlow`] that a new block has been observed.
	///
	/// This allows the flow to keep in sync with the latest block timestamp,
	/// which may be used for time-sensitive operations.
	///
	/// Must be called whenever a new chain tip becomes available. May be skipped
	/// for intermediary blocks.
	pub fn best_block_updated(&self, header: &Header, _height: u32) {
		let timestamp = &self.highest_seen_timestamp;
		let block_time = header.time as usize;

		loop {
			// Update timestamp to be the max of its current value and the block
			// timestamp. This should keep us close to the current time without relying on
			// having an explicit local time source.
			// Just in case we end up in a race, we loop until we either successfully
			// update timestamp or decide we don't need to.
			let old_serial = timestamp.load(Ordering::Acquire);
			if old_serial >= block_time {
				break;
			}
			if timestamp
				.compare_exchange(old_serial, block_time, Ordering::AcqRel, Ordering::Relaxed)
				.is_ok()
			{
				break;
			}
		}

		#[cfg(feature = "dnssec")]
		{
			let updated_time = timestamp.load(Ordering::Acquire) as u32;
			self.hrn_resolver.new_best_block(_height, updated_time);
		}
	}
}

/// Defines the maximum number of [`OffersMessage`] including different reply paths to be sent
/// along different paths.
/// Sending multiple requests increases the chances of successful delivery in case some
/// paths are unavailable. However, only one invoice for a given [`PaymentId`] will be paid,
/// even if multiple invoices are received.
const OFFERS_MESSAGE_REQUEST_LIMIT: usize = 10;

impl<MR: Deref> OffersMessageFlow<MR>
where
	MR::Target: MessageRouter,
{
	/// Creates a collection of blinded paths by delegating to [`MessageRouter`] based on
	/// the path's intended lifetime.
	///
	/// Whether or not the path is compact depends on whether the path is short-lived or long-lived,
	/// respectively, based on the given `absolute_expiry` as seconds since the Unix epoch. See
	/// [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`].
	fn create_blinded_paths_using_absolute_expiry(
		&self, context: OffersContext, absolute_expiry: Option<Duration>,
		peers: Vec<MessageForwardNode>,
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
	fn create_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: MessageContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		let peers = peers.into_iter().map(|node| node.node_id).collect();
		self.message_router
			.create_blinded_paths(recipient, context, peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_compact_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_compact_blinded_paths(
		&self, peers: Vec<MessageForwardNode>, context: OffersContext,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		self.message_router
			.create_compact_blinded_paths(
				recipient,
				MessageContext::Offers(context),
				peers,
				secp_ctx,
			)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	fn create_blinded_payment_paths<ES: Deref, R: Deref>(
		&self, router: &R, entropy_source: ES, usable_channels: Vec<ChannelDetails>,
		amount_msats: Option<u64>, payment_secret: PaymentSecret, payment_context: PaymentContext,
		relative_expiry_seconds: u32,
	) -> Result<Vec<BlindedPaymentPath>, ()>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let payee_node_id = self.get_our_node_id();

		// Assume shorter than usual block times to avoid spuriously failing payments too early.
		const SECONDS_PER_BLOCK: u32 = 9 * 60;
		let relative_expiry_blocks = relative_expiry_seconds / SECONDS_PER_BLOCK;
		let max_cltv_expiry = core::cmp::max(relative_expiry_blocks, CLTV_FAR_FAR_AWAY)
			.saturating_add(LATENCY_GRACE_PERIOD_BLOCKS)
			.saturating_add(self.best_block.read().unwrap().height);

		let payee_tlvs = UnauthenticatedReceiveTlvs {
			payment_secret,
			payment_constraints: PaymentConstraints { max_cltv_expiry, htlc_minimum_msat: 1 },
			payment_context,
		};
		let nonce = Nonce::from_entropy_source(entropy);
		let payee_tlvs = payee_tlvs.authenticate(nonce, expanded_key);

		router.create_blinded_payment_paths(
			payee_node_id,
			usable_channels,
			payee_tlvs,
			amount_msats,
			secp_ctx,
		)
	}

	#[cfg(all(test, async_payments))]
	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	pub(crate) fn test_create_blinded_payment_paths<ES: Deref, R: Deref>(
		&self, router: &R, entropy_source: ES, usable_channels: Vec<ChannelDetails>,
		amount_msats: Option<u64>, payment_secret: PaymentSecret, payment_context: PaymentContext,
		relative_expiry_seconds: u32,
	) -> Result<Vec<BlindedPaymentPath>, ()>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		self.create_blinded_payment_paths(
			router,
			entropy_source,
			usable_channels,
			amount_msats,
			payment_secret,
			payment_context,
			relative_expiry_seconds,
		)
	}
}

fn enqueue_onion_message_with_reply_paths<T: OnionMessageContents + Clone>(
	message: T, message_paths: &[BlindedMessagePath], reply_paths: Vec<BlindedMessagePath>,
	queue: &mut Vec<(T, MessageSendInstructions)>,
) {
	reply_paths
		.iter()
		.flat_map(|reply_path| message_paths.iter().map(move |path| (path, reply_path)))
		.take(OFFERS_MESSAGE_REQUEST_LIMIT)
		.for_each(|(path, reply_path)| {
			let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
				destination: Destination::BlindedPath(path.clone()),
				reply_path: reply_path.clone(),
			};
			queue.push((message.clone(), instructions));
		});
}

impl<MR: Deref> OffersMessageFlow<MR>
where
	MR::Target: MessageRouter,
{
	pub fn should_trigger_invoice_request_event(&self, invoice_request: &VerifiedInvoiceRequest) -> bool {
		match self.user_configs.invoice_request_configs {
			InvoiceRequestConfigs::AlwaysTrigger => true,
			InvoiceRequestConfigs::TriggerIfOfferInCurrency => {
				matches!(invoice_request.inner.get_offer_amount(), Some(Amount::Currency { .. }))
			}
			InvoiceRequestConfigs::NeverTrigger => false,
		}
	}

	pub fn should_trigger_invoice_event(&self, invoice: &Bolt12Invoice) -> bool {
		let configs = &self.user_configs.invoice_configs;

		match configs {
			Bolt12InvoiceConfigs::AlwaysTrigger => true,
			Bolt12InvoiceConfigs::TriggerIfOfferInCurrency => {
				matches!(invoice.get_offer_amount(), Ok(Some(Amount::Currency { .. })))
			}
			Bolt12InvoiceConfigs::TriggerIfOfferInCurrencyAndNoIRAmount => {
				matches!(invoice.get_offer_amount(), Ok(Some(Amount::Currency { .. })))
					&& invoice.get_precursor_amount().is_none()
			}
			Bolt12InvoiceConfigs::NeverTrigger => false,
		}
	}

	/// Verifies an [`InvoiceRequest`] using the provided [`OffersContext`] or the invoice request's own metadata.
	///
	/// - If an [`OffersContext::InvoiceRequest`] with a `nonce` is provided, verification is performed using recipient context data.
	/// - If no context is provided but the [`InvoiceRequest`] contains [`Offer`] metadata, verification is performed using that metadata.
	/// - If neither is available, verification fails.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - Both [`OffersContext`] and [`InvoiceRequest`] metadata are absent or invalid.
	/// - The verification process (via recipient context data or metadata) fails.
	pub fn verify_invoice_request(
		&self, invoice_request: InvoiceRequest, context: Option<OffersContext>,
	) -> Result<VerifiedInvoiceRequest, ()> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		let nonce = match context {
			None if invoice_request.metadata().is_some() => None,
			Some(OffersContext::InvoiceRequest { nonce }) => Some(nonce),
			_ => return Err(()),
		};

		let invoice_request = match nonce {
			Some(nonce) => {
				invoice_request.verify_using_recipient_data(nonce, expanded_key, secp_ctx)
			},
			None => invoice_request.verify_using_metadata(expanded_key, secp_ctx),
		}?;

		Ok(invoice_request)
	}

	/// Verifies a [`Bolt12Invoice`] using the provided [`OffersContext`] or the invoice's payer metadata,
	/// returning the corresponding [`PaymentId`] if successful.
	///
	/// - If an [`OffersContext::OutboundPayment`] with a `nonce` is provided, verification is performed
	///   using this to form the payer metadata.
	/// - If no context is provided and the invoice corresponds to a [`Refund`] without blinded paths,
	///   verification is performed using the [`Bolt12Invoice::payer_metadata`].
	/// - If neither condition is met, verification fails.
	pub fn verify_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>,
	) -> Result<PaymentId, ()> {
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

	/// Verifies the provided [`AsyncPaymentsContext`] for an inbound [`HeldHtlcAvailable`] message.
	///
	/// The context is verified using the `nonce` and `hmac` values, and ensures that the context
	/// has not expired based on `path_absolute_expiry`.
	///
	/// # Errors
	///
	/// Returns `Err(())` if:
	/// - The HMAC verification fails for inbound context.
	/// - The inbound payment context has expired.
	#[cfg(async_payments)]
	pub fn verify_inbound_async_payment_context(
		&self, context: AsyncPaymentsContext,
	) -> Result<(), ()> {
		match context {
			AsyncPaymentsContext::InboundPayment { nonce, hmac, path_absolute_expiry } => {
				signer::verify_held_htlc_available_context(nonce, hmac, &self.inbound_payment_key)?;

				if self.duration_since_epoch() > path_absolute_expiry {
					return Err(());
				}
				Ok(())
			},
			_ => Err(()),
		}
	}

	/// Verifies the provided [`AsyncPaymentsContext`] for an inbound [`ReleaseHeldHtlc`] message.
	///
	/// The context is verified using the `nonce` and `hmac` values, and if valid,
	/// returns the associated [`PaymentId`].
	///
	/// # Errors
	///
	/// Returns `Err(())` if:
	/// - The HMAC verification fails for outbound context.
	///
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	#[cfg(async_payments)]
	pub fn verify_outbound_async_payment_context(
		&self, context: AsyncPaymentsContext,
	) -> Result<PaymentId, ()> {
		match context {
			AsyncPaymentsContext::OutboundPayment { payment_id, hmac, nonce } => {
				payment_id.verify_for_async_payment(hmac, nonce, &self.inbound_payment_key)?;
				Ok(payment_id)
			},
			_ => Err(()),
		}
	}

	/// This function runs user_configs checks on the invoice_request, and make sure whether
	/// the invoice_request is to be handled synchornously or asynchornously (in which case
	/// the correspoonding OfferEvent will be enquqed).
	pub fn synchornously_handle_invoice_request(&self, invoice_request: VerifiedInvoiceRequest) -> Result<Option<VerifiedInvoiceRequest>, ()>
	{
		if self.should_trigger_invoice_request_event(&invoice_request) {
			let amount = match (invoice_request.inner.amount_msats(), invoice_request.inner.get_offer_amount()) {
				(Some(ir_amount), Some(offer_amount)) => IREventAmount::InvoiceRequestAndOfferAmount {
					invoice_request_amount_msats: ir_amount,
					offer_amount,
				},
				(Some(ir_amount), None) => IREventAmount::InvoiceRequestOnly {
					invoice_request_amount_msats: ir_amount,
				},
				(None, Some(offer_amount)) => IREventAmount::OfferOnly { offer_amount },
				(None, None) => {
					// This is an error case, we should not have an invoice_request without
					// either amount set.
					return Err(());
				}
			};

			let event = OfferEvents::InvoiceRequestReceived {
				invoice_request,
				amount,
			};

			// Enqueue the event for later processing.
			self.enqueue_offers_event(event)?;

			Ok(None)
		} else {
			// If the user_config is set to never trigger, we just return the invoice_request
			// without any further processing.
			Ok(Some(invoice_request))
		}
	}

	pub fn synchornously_handle_invoice(&self, invoice: Bolt12Invoice, payment_id: PaymentId) -> Result<Option<Bolt12Invoice>, ()> {
		if self.should_trigger_invoice_event(&invoice) {
			let precurseor_amount = invoice.get_precursor_amount();
			let offer_amount = invoice.get_offer_amount();

			let amount_source = match offer_amount {
				Ok(offer_amt) => match (precurseor_amount, offer_amt) {
					(Some(pre_amt), Some(amt)) => Bolt12InvoiceAmountSource::ForOffer {
						amount: IREventAmount::InvoiceRequestAndOfferAmount {
							invoice_request_amount_msats: pre_amt,
							offer_amount: amt,
						},
					},
					(Some(pre_amt), None) => Bolt12InvoiceAmountSource::ForOffer {
						amount: IREventAmount::InvoiceRequestOnly {
							invoice_request_amount_msats: pre_amt,
						},
					},
					(None, Some(amt)) => Bolt12InvoiceAmountSource::ForOffer {
						amount: IREventAmount::OfferOnly { offer_amount: amt },
					},
					(None, None) => {
						// This is an error case, we should not have an invoice without
						// either amount set.
						return Err(());
					}
				},
				Err(_) => {
					// If the invoice does not have an offer amount, it is likely a refund.
					// We can still process it, but we won't have an offer amount.
					Bolt12InvoiceAmountSource::ForRefund {
						refund_amount: precurseor_amount.expect("precursor_amount must be Some for refund"),
					}
				}
			};

			let invoice_amount = invoice.amount_msats();
			let event = OfferEvents::Bolt12InvoiceReceived {
				invoice,
				payment_id,
				invoice_amount,
				amount_source,
			};

			// Enqueue the event for later processing.
			self.enqueue_offers_event(event)?;

			Ok(None)
		} else {
			// If the user_config is set to never trigger, we just return the invoice
			// without any further processing.
			Ok(Some(invoice))
		}
	}

	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by the
	/// [`OffersMessageFlow`], and any corresponding [`InvoiceRequest`] can be verified using
	/// [`Self::verify_invoice_request`]. The offer will expire at `absolute_expiry` if `Some`,
	/// or will not expire if `None`.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] to construct a [`BlindedMessagePath`] for the offer based on the given
	/// `absolute_expiry` according to [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]. See those docs for
	/// privacy implications, as well as those of the parameterized [`Router`], which implements
	/// [`MessageRouter`].
	///
	/// Also uses a derived signing pubkey in the offer for recipient privacy.
	///
	/// # Limitations
	///
	/// If [`DefaultMessageRouter`] is used to parameterize the [`OffersMessageFlow`], a direct
	/// connection to the introduction node in the responding [`InvoiceRequest`]'s reply path is required.
	/// See the [`DefaultMessageRouter`] documentation for more details.
	///
	/// # Errors
	///
	/// Returns an error if the parameterized [`Router`] is unable to create a blinded path for the offer.
	///
	/// [`DefaultMessageRouter`]: crate::onion_message::messenger::DefaultMessageRouter
	pub fn create_offer_builder<ES: Deref>(
		&self, entropy_source: ES, absolute_expiry: Option<Duration>,
		peers: Vec<MessageForwardNode>,
	) -> Result<OfferBuilder<DerivedMetadata, secp256k1::All>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::InvoiceRequest { nonce };

		let path = self
			.create_blinded_paths_using_absolute_expiry(context, absolute_expiry, peers)
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

	/// Create an offer for receiving async payments as an often-offline recipient.
	///
	/// Because we may be offline when the payer attempts to request an invoice, you MUST:
	/// 1. Provide at least 1 [`BlindedMessagePath`] terminating at an always-online node that will
	///    serve the [`StaticInvoice`] created from this offer on our behalf.
	/// 2. Use [`Self::create_static_invoice_builder`] to create a [`StaticInvoice`] from this
	///    [`Offer`] plus the returned [`Nonce`], and provide the static invoice to the
	///    aforementioned always-online node.
	#[cfg(async_payments)]
	pub fn create_async_receive_offer_builder<ES: Deref>(
		&self, entropy_source: ES, message_paths_to_always_online_node: Vec<BlindedMessagePath>,
	) -> Result<(OfferBuilder<DerivedMetadata, secp256k1::All>, Nonce), Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		if message_paths_to_always_online_node.is_empty() {
			return Err(Bolt12SemanticError::MissingPaths);
		}

		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let mut builder =
			OfferBuilder::deriving_signing_pubkey(node_id, expanded_key, nonce, secp_ctx)
				.chain_hash(self.chain_hash);

		for path in message_paths_to_always_online_node {
			builder = builder.path(path);
		}

		Ok((builder.into(), nonce))
	}

	/// Creates a [`RefundBuilder`] such that the [`Refund`] it builds is recognized by the
	/// [`OffersMessageFlow`], and any corresponding [`Bolt12Invoice`] received for the refund
	/// can be verified using [`Self::verify_bolt12_invoice`].
	///
	/// The builder will have the provided expiration set. Any changes to the expiration on the
	/// returned builder will not be honored by [`OffersMessageFlow`]. For non-`std`, the highest seen
	/// block time minus two hours is used for the current time when determining if the refund has
	/// expired.
	///
	/// To refund can be revoked by the user prior to receiving the invoice.
	/// If abandoned, or if an invoice is not received before expiration, the payment will fail
	/// with an [`Event::PaymentFailed`].
	///
	/// If `max_total_routing_fee_msat` is not specified, the default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] to construct a [`BlindedMessagePath`] for the refund based on the given
	/// `absolute_expiry` according to [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]. See those docs for
	/// privacy implications.
	///
	/// Also uses a derived payer id in the refund for payer privacy.
	///
	/// # Errors
	///
	/// Returns an error if:
	/// - A duplicate `payment_id` is provided, given the caveats in the aforementioned link.
	/// - `amount_msats` is invalid, or
	/// - The parameterized [`Router`] is unable to create a blinded path for the refund.
	///
	/// [`Event::PaymentFailed`]: crate::events::Event::PaymentFailed
	/// [`RouteParameters::from_payment_params_and_value`]: crate::routing::router::RouteParameters::from_payment_params_and_value
	pub fn create_refund_builder<ES: Deref>(
		&self, entropy_source: ES, amount_msats: u64, absolute_expiry: Duration,
		payment_id: PaymentId, peers: Vec<MessageForwardNode>,
	) -> Result<RefundBuilder<secp256k1::All>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		let node_id = self.get_our_node_id();
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::OutboundPayment { payment_id, nonce, hmac: None };

		let path = self
			.create_blinded_paths_using_absolute_expiry(context, Some(absolute_expiry), peers)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = RefundBuilder::deriving_signing_pubkey(
			node_id,
			expanded_key,
			nonce,
			secp_ctx,
			amount_msats,
			payment_id,
		)?
		.chain_hash(self.chain_hash)
		.absolute_expiry(absolute_expiry)
		.path(path);

		Ok(builder)
	}

	/// Creates an [`InvoiceRequestBuilder`] such that the [`InvoiceRequest`] it builds is recognized
	/// by the [`OffersMessageFlow`], and any corresponding [`Bolt12Invoice`] received in response
	/// can be verified using [`Self::verify_bolt12_invoice`].
	///
	/// # Nonce
	/// The nonce is used to create a unique [`InvoiceRequest::payer_metadata`] for the invoice request.
	/// These will be used to verify the corresponding [`Bolt12Invoice`] when it is received.
	pub fn create_invoice_request_builder<'a>(
		&'a self, offer: &'a Offer, nonce: Nonce, payment_id: PaymentId,
	) -> Result<InvoiceRequestBuilder<'a, 'a, secp256k1::All>, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let builder: InvoiceRequestBuilder<secp256k1::All> =
			offer.request_invoice(expanded_key, nonce, secp_ctx, payment_id)?.into();
		let builder = builder.chain_hash(self.chain_hash)?;

		Ok(builder)
	}

	/// Creates a [`StaticInvoiceBuilder`] from the corresponding [`Offer`] and [`Nonce`] that were
	/// created via [`Self::create_async_receive_offer_builder`].
	#[cfg(async_payments)]
	pub fn create_static_invoice_builder<'a, ES: Deref, R: Deref>(
		&self, router: &R, entropy_source: ES, offer: &'a Offer, offer_nonce: Nonce,
		payment_secret: PaymentSecret, relative_expiry_secs: u32,
		usable_channels: Vec<ChannelDetails>, peers: Vec<MessageForwardNode>,
	) -> Result<StaticInvoiceBuilder<'a>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;
		let secp_ctx = &self.secp_ctx;

		let payment_context =
			PaymentContext::AsyncBolt12Offer(AsyncBolt12OfferContext { offer_nonce });

		let amount_msat = offer.amount().and_then(|amount| match amount {
			Amount::Bitcoin { amount_msats } => Some(amount_msats),
			Amount::Currency { .. } => None,
		});

		let created_at = self.duration_since_epoch();

		let payment_paths = self
			.create_blinded_payment_paths(
				router,
				entropy,
				usable_channels,
				amount_msat,
				payment_secret,
				payment_context,
				relative_expiry_secs,
			)
			.map_err(|()| Bolt12SemanticError::MissingPaths)?;

		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = signer::hmac_for_held_htlc_available_context(nonce, expanded_key);
		let path_absolute_expiry = Duration::from_secs(inbound_payment::calculate_absolute_expiry(
			created_at.as_secs(),
			relative_expiry_secs,
		));

		let context = MessageContext::AsyncPayments(AsyncPaymentsContext::InboundPayment {
			nonce,
			hmac,
			path_absolute_expiry,
		});

		let async_receive_message_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|()| Bolt12SemanticError::MissingPaths)?;

		StaticInvoiceBuilder::for_offer_using_derived_keys(
			offer,
			payment_paths,
			async_receive_message_paths,
			created_at,
			expanded_key,
			offer_nonce,
			secp_ctx,
		)
		.map(|inv| inv.allow_mpp().relative_expiry(relative_expiry_secs))
	}

	/// Creates an [`InvoiceBuilder`] using the provided [`Refund`].
	///
	/// This method is used when a node wishes to construct an [`InvoiceBuilder`]
	/// in response to a [`Refund`] request as part of a BOLT 12 flow.
	///
	/// Returns an `InvoiceBuilder` configured with:
	/// - Blinded payment paths created using the parameterized [`Router`], with the provided
	///   `payment_secret` included in the path payloads.
	/// - The given `payment_hash` and `payment_secret`, enabling secure claim verification.
	///
	/// Returns an error if the refund targets a different chain or if no valid
	/// blinded path can be constructed.
	pub fn create_invoice_builder_from_refund<'a, ES: Deref, R: Deref>(
		&'a self, router: &R, entropy_source: ES, refund: &'a Refund, payment_hash: PaymentHash,
		payment_secret: PaymentSecret, usable_channels: Vec<ChannelDetails>,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError>
	where
		ES::Target: EntropySource,
		R::Target: Router,
	{
		if refund.chain() != self.chain_hash {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;

		let amount_msats = refund.amount_msats();
		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
		let payment_paths = self
			.create_blinded_payment_paths(
				router,
				entropy,
				usable_channels,
				Some(amount_msats),
				payment_secret,
				payment_context,
				relative_expiry,
			)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		#[cfg(feature = "std")]
		let builder = refund.respond_using_derived_keys(
			payment_paths,
			payment_hash,
			expanded_key,
			entropy,
		)?;

		#[cfg(not(feature = "std"))]
		let created_at = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);
		#[cfg(not(feature = "std"))]
		let builder = refund.respond_using_derived_keys_no_std(
			payment_paths,
			payment_hash,
			created_at,
			expanded_key,
			entropy,
		)?;

		Ok(builder.into())
	}

	/// Creates a response for the provided [`VerifiedInvoiceRequest`].
	///
	/// A response can be either an [`OffersMessage::Invoice`] with additional [`MessageContext`],
	/// or an [`OffersMessage::InvoiceError`], depending on the [`InvoiceRequest`].
	///
	/// An [`OffersMessage::InvoiceError`] will be generated if:
	/// - We fail to generate valid payment paths to include in the [`Bolt12Invoice`].
	/// - We fail to generate a valid signed [`Bolt12Invoice`] for the [`InvoiceRequest`].
	pub fn create_response_for_invoice_request<ES: Deref, NS: Deref, R: Deref>(
		&self, signer: &NS, router: &R, entropy_source: ES,
		invoice_request: VerifiedInvoiceRequest, amount_msats: u64, payment_hash: PaymentHash,
		payment_secret: PaymentSecret, usable_channels: Vec<ChannelDetails>,
	) -> (OffersMessage, Option<MessageContext>)
	where
		ES::Target: EntropySource,
		NS::Target: NodeSigner,
		R::Target: Router,
	{
		let entropy = &*entropy_source;
		let expanded_key = &self.inbound_payment_key;
		let secp_ctx = &self.secp_ctx;

		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		let context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
			offer_id: invoice_request.offer_id,
			invoice_request: invoice_request.fields(),
		});

		let payment_paths = match self.create_blinded_payment_paths(
			router,
			entropy,
			usable_channels,
			Some(amount_msats),
			payment_secret,
			context,
			relative_expiry,
		) {
			Ok(paths) => paths,
			Err(_) => {
				let error = InvoiceError::from(Bolt12SemanticError::MissingPaths);
				return (OffersMessage::InvoiceError(error.into()), None);
			},
		};

		#[cfg(not(feature = "std"))]
		let created_at = Duration::from_secs(self.highest_seen_timestamp.load(Ordering::Acquire) as u64);

		let response = if invoice_request.keys.is_some() {
			#[cfg(feature = "std")]
			let builder = invoice_request.respond_using_derived_keys(payment_paths, payment_hash);
			#[cfg(not(feature = "std"))]
			let builder = invoice_request.respond_using_derived_keys_no_std(
				payment_paths,
				payment_hash,
				created_at,
			);
			builder
				.map(InvoiceBuilder::<DerivedSigningPubkey>::from)
				.and_then(|builder| builder.allow_mpp().build_and_sign(secp_ctx))
				.map_err(InvoiceError::from)
		} else {
			#[cfg(feature = "std")]
			let builder = invoice_request.respond_with(payment_paths, payment_hash);
			#[cfg(not(feature = "std"))]
			let builder = invoice_request.respond_with_no_std(payment_paths, payment_hash, created_at);
			builder
				.map(InvoiceBuilder::<ExplicitSigningPubkey>::from)
				.and_then(|builder| builder.allow_mpp().build())
				.map_err(InvoiceError::from)
				.and_then(|invoice| {
					#[cfg(c_bindings)]
					let mut invoice = invoice;
					invoice
						.sign(|invoice: &UnsignedBolt12Invoice| signer.sign_bolt12_invoice(invoice))
						.map_err(InvoiceError::from)
				})
		};

		match response {
			Ok(invoice) => {
				let nonce = Nonce::from_entropy_source(entropy);
				let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
				let context = MessageContext::Offers(OffersContext::InboundPayment {
					payment_hash,
					nonce,
					hmac,
				});

				(OffersMessage::Invoice(invoice), Some(context))
			},
			Err(error) => (OffersMessage::InvoiceError(error.into()), None),
		}
	}

	/// Enqueues the created [`InvoiceRequest`] to be sent to the counterparty.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to create a unique [`MessageContext`] for the
	/// blinded paths sent to the counterparty. This allows them to respond with an invoice,
	/// over those blinded paths, which can be verified against the intended outbound payment,
	/// ensuring the invoice corresponds to a payment we actually want to make.
	///
	/// # Nonce
	/// The nonce is used to create a unique [`MessageContext`] for the reply paths.
	/// These will be used to verify the corresponding [`Bolt12Invoice`] when it is received.
	///
	/// Note: The provided [`Nonce`] MUST be the same as the [`Nonce`] used for creating the
	/// [`InvoiceRequest`] to ensure correct verification of the corresponding [`Bolt12Invoice`].
	///
	/// See [`OffersMessageFlow::create_invoice_request_builder`] for more details.
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate
	/// valid reply paths for the counterparty to send back the corresponding [`Bolt12Invoice`]
	/// or [`InvoiceError`].
	///
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	pub fn enqueue_invoice_request(
		&self, invoice_request: InvoiceRequest, payment_id: PaymentId, nonce: Nonce,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;

		let hmac = payment_id.hmac_for_offer_payment(nonce, expanded_key);
		let context = MessageContext::Offers(OffersContext::OutboundPayment {
			payment_id,
			nonce,
			hmac: Some(hmac),
		});
		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
		if !invoice_request.paths().is_empty() {
			let message = OffersMessage::InvoiceRequest(invoice_request.clone());
			enqueue_onion_message_with_reply_paths(
				message,
				invoice_request.paths(),
				reply_paths,
				&mut pending_offers_messages,
			);
		} else if let Some(node_id) = invoice_request.issuer_signing_pubkey() {
			for reply_path in reply_paths {
				let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
					destination: Destination::Node(node_id),
					reply_path,
				};
				let message = OffersMessage::InvoiceRequest(invoice_request.clone());
				pending_offers_messages.push((message, instructions));
			}
		} else {
			debug_assert!(false);
			return Err(Bolt12SemanticError::MissingIssuerSigningPubkey);
		}

		Ok(())
	}

	/// Enqueues the created [`Bolt12Invoice`] corresponding to a [`Refund`] to be sent
	/// to the counterparty.
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate valid
	/// reply paths for the counterparty to send back the corresponding [`InvoiceError`] if we fail
	/// to create blinded reply paths
	///
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	pub fn enqueue_invoice<ES: Deref>(
		&self, entropy_source: ES, invoice: Bolt12Invoice, refund: &Refund,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;

		let payment_hash = invoice.payment_hash();

		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);

		let context =
			MessageContext::Offers(OffersContext::InboundPayment { payment_hash, nonce, hmac });

		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();

		if refund.paths().is_empty() {
			for reply_path in reply_paths {
				let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
					destination: Destination::Node(refund.payer_signing_pubkey()),
					reply_path,
				};
				let message = OffersMessage::Invoice(invoice.clone());
				pending_offers_messages.push((message, instructions));
			}
		} else {
			let message = OffersMessage::Invoice(invoice);
			enqueue_onion_message_with_reply_paths(
				message,
				refund.paths(),
				reply_paths,
				&mut pending_offers_messages,
			);
		}

		Ok(())
	}

	/// Enqueues `held_htlc_available` onion messages to be sent to the payee via the reply paths
	/// contained within the provided [`StaticInvoice`].
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate valid
	/// reply paths for the recipient to send back the corresponding [`ReleaseHeldHtlc`] onion message.
	///
	/// [`ReleaseHeldHtlc`]: crate::onion_message::async_payments::ReleaseHeldHtlc
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	#[cfg(async_payments)]
	pub fn enqueue_held_htlc_available<ES: Deref>(
		&self, entropy_source: ES, invoice: &StaticInvoice, payment_id: PaymentId,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError>
	where
		ES::Target: EntropySource,
	{
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*entropy_source;

		let nonce = Nonce::from_entropy_source(entropy);
		let hmac = payment_id.hmac_for_async_payment(nonce, expanded_key);
		let context = MessageContext::AsyncPayments(AsyncPaymentsContext::OutboundPayment {
			payment_id,
			nonce,
			hmac,
		});

		let reply_paths = self
			.create_blinded_paths(peers, context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let mut pending_async_payments_messages =
			self.pending_async_payments_messages.lock().unwrap();

		let message = AsyncPaymentsMessage::HeldHtlcAvailable(HeldHtlcAvailable {});
		enqueue_onion_message_with_reply_paths(
			message,
			invoice.message_paths(),
			reply_paths,
			&mut pending_async_payments_messages,
		);

		Ok(())
	}

	/// Enqueues the created [`DNSSECQuery`] to be sent to the counterparty.
	///
	/// # Peers
	///
	/// The user must provide a list of [`MessageForwardNode`] that will be used to generate
	/// valid reply paths for the counterparty to send back the corresponding response for
	/// the [`DNSSECQuery`] message.
	///
	/// [`supports_onion_messages`]: crate::types::features::Features::supports_onion_messages
	#[cfg(feature = "dnssec")]
	pub fn enqueue_dns_onion_message(
		&self, message: DNSSECQuery, context: DNSResolverContext, dns_resolvers: Vec<Destination>,
		peers: Vec<MessageForwardNode>,
	) -> Result<(), Bolt12SemanticError> {
		let reply_paths = self
			.create_blinded_paths(peers, MessageContext::DNSResolver(context))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let message_params = dns_resolvers
			.iter()
			.flat_map(|destination| reply_paths.iter().map(move |path| (path, destination)))
			.take(OFFERS_MESSAGE_REQUEST_LIMIT);
		for (reply_path, destination) in message_params {
			self.pending_dns_onion_messages.lock().unwrap().push((
				DNSResolverMessage::DNSSECQuery(message.clone()),
				MessageSendInstructions::WithSpecifiedReplyPath {
					destination: destination.clone(),
					reply_path: reply_path.clone(),
				},
			));
		}

		Ok(())
	}

	pub fn enqueue_offers_event(
		&self, event: OfferEvents
	) -> Result<(), ()> {
		let mut pending_offers_events = self.pending_offers_events.lock().unwrap();
		pending_offers_events.push(event);
		Ok(())
	}

	/// Gets the enqueued [`OffersMessage`] with their corresponding [`MessageSendInstructions`].
	pub fn release_pending_offers_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}

	/// Gets the enqueued [`AsyncPaymentsMessage`] with their corresponding [`MessageSendInstructions`].
	pub fn release_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_async_payments_messages.lock().unwrap())
	}

	/// Gets the enqueued [`DNSResolverMessage`] with their corresponding [`MessageSendInstructions`].
	#[cfg(feature = "dnssec")]
	pub fn release_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_dns_onion_messages.lock().unwrap())
	}

	pub fn get_and_clear_pending_offers_events(
		&self,
	) -> Vec<OfferEvents> {
		core::mem::take(&mut self.pending_offers_events.lock().unwrap())
	}
}
