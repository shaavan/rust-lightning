// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use core::ops::Deref;
use core::time::Duration;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1};
use lightning_invoice::PaymentSecret;

use crate::blinded_path::NodeIdLookUp;
use crate::blinded_path::message::{BlindedMessagePath, MessageContext, OffersContext};
use crate::blinded_path::payment::{BlindedPaymentPath, Bolt12OfferContext, Bolt12RefundContext, PaymentConstraints, PaymentContext, ReceiveTlvs};
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::events::{Event, PaymentFailureReason};
use crate::ln::channelmanager::{AChannelManager, Bolt12PaymentError, CLTV_FAR_FAR_AWAY, MAX_SHORT_LIVED_RELATIVE_EXPIRY, OffersMessageCommons, PaymentId, PersistenceNotifierGuard, Retry, Verification};
use crate::ln::inbound_payment;
use crate::ln::outbound_payment::{RetryableInvoiceRequest, StaleExpiration};
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};

use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{DerivedPayerSigningPubkey, InvoiceRequest, InvoiceRequestBuilder};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};

use crate::routing::router::Router;
use crate::sign::{EntropySource, NodeSigner, Recipient};
use crate::sync::Mutex;
use crate::util::logger::{Logger, WithContext};

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

	/// Pays the [`Bolt12Invoice`] associated with the `payment_id` encoded in its `payer_metadata`.
	///
	/// The invoice's `payer_metadata` is used to authenticate that the invoice was indeed requested
	/// before attempting a payment. [`Bolt12PaymentError::UnexpectedInvoice`] is returned if this
	/// fails or if the encoded `payment_id` is not recognized. The latter may happen once the
	/// payment is no longer tracked because the payment was attempted after:
	/// - an invoice for the `payment_id` was already paid,
	/// - one full [timer tick] has elapsed since initially requesting the invoice when paying an
	///   offer, or
	/// - the refund corresponding to the invoice has already expired.
	///
	/// To retry the payment, request another invoice using a new `payment_id`.
	///
	/// Attempting to pay the same invoice twice while the first payment is still pending will
	/// result in a [`Bolt12PaymentError::DuplicateInvoice`].
	///
	/// Otherwise, either [`Event::PaymentSent`] or [`Event::PaymentFailed`] are used to indicate
	/// whether or not the payment was successful.
	///
	/// [timer tick]: Self::timer_tick_occurred
	pub fn send_payment_for_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>,
	) -> Result<(), Bolt12PaymentError> {
		match self.verify_bolt12_invoice(invoice, context) {
			Ok(payment_id) => self.send_payment_for_verified_bolt12_invoice(invoice, payment_id),
			Err(()) => Err(Bolt12PaymentError::UnexpectedInvoice),
		}
	}

	fn verify_bolt12_invoice(
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

	fn send_payment_for_verified_bolt12_invoice(&self, invoice: &Bolt12Invoice, payment_id: PaymentId) -> Result<(), Bolt12PaymentError> {
		let best_block_height = self.commons.get_best_block().height;
		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&*self.commons);
		let features = self.commons.bolt12_invoice_features();
		self.commons.get_pending_outbound_payments()
			.send_payment_for_bolt12_invoice(
				invoice, payment_id, &self.router, self.commons.list_usable_channels(), features,
				|| self.commons.compute_inflight_htlcs(), &self.entropy_source, &self.node_signer, &self.lookup,
				&self.secp_ctx, best_block_height, &self.logger, &self.commons.get_pending_events(),
				|args| self.commons.send_payment_along_path(args)
			)
	}

}

macro_rules! create_offer_builder { ($self: ident, $builder: ty) => {
	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by the
	/// [`ChannelManager`] when handling [`InvoiceRequest`] messages for the offer. The offer's
	/// expiration will be `absolute_expiry` if `Some`, otherwise it will not expire.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] to construct a [`BlindedMessagePath`] for the offer based on the given
	/// `absolute_expiry` according to [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]. See those docs for
	/// privacy implications as well as those of the parameterized [`Router`], which implements
	/// [`MessageRouter`].
	///
	/// Also, uses a derived signing pubkey in the offer for recipient privacy.
	///
	/// # Limitations
	///
	/// Requires a direct connection to the introduction node in the responding [`InvoiceRequest`]'s
	/// reply path.
	///
	/// # Errors
	///
	/// Errors if the parameterized [`Router`] is unable to create a blinded path for the offer.
	///
	/// [`Offer`]: crate::offers::offer::Offer
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	pub fn create_offer_builder(
		&$self, absolute_expiry: Option<Duration>
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.get_our_node_id();
		let expanded_key = &$self.inbound_payment_key;
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::InvoiceRequest { nonce };
		let path = $self.create_blinded_paths_using_absolute_expiry(context, absolute_expiry)
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;
		let builder = OfferBuilder::deriving_signing_pubkey(node_id, expanded_key, nonce, secp_ctx)
			.chain_hash($self.commons.get_chain_hash())
			.path(path);

		let builder = match absolute_expiry {
			None => builder,
			Some(absolute_expiry) => builder.absolute_expiry(absolute_expiry),
		};

		Ok(builder.into())
	}
} }

macro_rules! create_refund_builder { ($self: ident, $builder: ty) => {
	/// Creates a [`RefundBuilder`] such that the [`Refund`] it builds is recognized by the
	/// [`ChannelManager`] when handling [`Bolt12Invoice`] messages for the refund.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the refund.
	/// See [Avoiding Duplicate Payments] for other requirements once the payment has been sent.
	///
	/// The builder will have the provided expiration set. Any changes to the expiration on the
	/// returned builder will not be honored by [`ChannelManager`]. For non-`std`, the highest seen
	/// block time minus two hours is used for the current time when determining if the refund has
	/// expired.
	///
	/// To revoke the refund, use [`ChannelManager::abandon_payment`] prior to receiving the
	/// invoice. If abandoned, or an invoice isn't received before expiration, the payment will fail
	/// with an [`Event::PaymentFailed`].
	///
	/// If `max_total_routing_fee_msat` is not specified, The default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// # Privacy
	///
	/// Uses [`MessageRouter`] to construct a [`BlindedMessagePath`] for the refund based on the given
	/// `absolute_expiry` according to [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]. See those docs for
	/// privacy implications as well as those of the parameterized [`Router`], which implements
	/// [`MessageRouter`].
	///
	/// Also, uses a derived payer id in the refund for payer privacy.
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in the responding
	/// [`Bolt12Invoice::payment_paths`].
	///
	/// # Errors
	///
	/// Errors if:
	/// - a duplicate `payment_id` is provided given the caveats in the aforementioned link,
	/// - `amount_msats` is invalid, or
	/// - the parameterized [`Router`] is unable to create a blinded path for the refund.
	///
	/// [`Refund`]: crate::offers::refund::Refund
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn create_refund_builder(
		&$self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId,
		retry_strategy: Retry, max_total_routing_fee_msat: Option<u64>
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.get_our_node_id();
		let expanded_key = &$self.inbound_payment_key;
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::OutboundPayment { payment_id, nonce, hmac: None };
		let path = $self.create_blinded_paths_using_absolute_expiry(context, Some(absolute_expiry))
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = RefundBuilder::deriving_signing_pubkey(
			node_id, expanded_key, nonce, secp_ctx, amount_msats, payment_id
		)?
			.chain_hash($self.commons.get_chain_hash())
			.absolute_expiry(absolute_expiry)
			.path(path);

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&*$self.commons);
		let expiration = StaleExpiration::AbsoluteTimeout(absolute_expiry);
		$self.commons.get_pending_outbound_payments()
			.add_new_awaiting_invoice(
				payment_id, expiration, retry_strategy, max_total_routing_fee_msat, None,
			)
			.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		Ok(builder.into())
	}
} }

/// Defines the maximum number of [`OffersMessage`] including different reply paths to be sent
/// along different paths.
/// Sending multiple requests increases the chances of successful delivery in case some
/// paths are unavailable. However, only one invoice for a given [`PaymentId`] will be paid,
/// even if multiple invoices are received.
const OFFERS_MESSAGE_REQUEST_LIMIT: usize = 10;

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
	#[cfg(not(c_bindings))]
	create_offer_builder!(self, OfferBuilder<DerivedMetadata, secp256k1::All>);
	#[cfg(not(c_bindings))]
	create_refund_builder!(self, RefundBuilder<secp256k1::All>);

	#[cfg(c_bindings)]
	create_offer_builder!(self, OfferWithDerivedMetadataBuilder);
	#[cfg(c_bindings)]
	create_refund_builder!(self, RefundMaybeWithDerivedMetadataBuilder);
	/// Pays for an [`Offer`] using the given parameters by creating an [`InvoiceRequest`] and
	/// enqueuing it to be sent via an onion message. [`ChannelManager`] will pay the actual
	/// [`Bolt12Invoice`] once it is received.
	///
	/// Uses [`InvoiceRequestBuilder`] such that the [`InvoiceRequest`] it builds is recognized by
	/// the [`ChannelManager`] when handling a [`Bolt12Invoice`] message in response to the request.
	/// The optional parameters are used in the builder, if `Some`:
	/// - `quantity` for [`InvoiceRequest::quantity`] which must be set if
	///   [`Offer::expects_quantity`] is `true`.
	/// - `amount_msats` if overpaying what is required for the given `quantity` is desired, and
	/// - `payer_note` for [`InvoiceRequest::payer_note`].
	///
	/// If `max_total_routing_fee_msat` is not specified, The default from
	/// [`RouteParameters::from_payment_params_and_value`] is applied.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the request
	/// when received. See [Avoiding Duplicate Payments] for other requirements once the payment has
	/// been sent.
	///
	/// To revoke the request, use [`ChannelManager::abandon_payment`] prior to receiving the
	/// invoice. If abandoned, or an invoice isn't received in a reasonable amount of time, the
	/// payment will fail with an [`Event::PaymentFailed`].
	///
	/// # Privacy
	///
	/// For payer privacy, uses a derived payer id and uses [`MessageRouter::create_blinded_paths`]
	/// to construct a [`BlindedMessagePath`] for the reply path. For further privacy implications, see the
	/// docs of the parameterized [`Router`], which implements [`MessageRouter`].
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in [`Offer::paths`] or to
	/// [`Offer::issuer_signing_pubkey`], if empty. A similar restriction applies to the responding
	/// [`Bolt12Invoice::payment_paths`].
	///
	/// # Errors
	///
	/// Errors if:
	/// - a duplicate `payment_id` is provided given the caveats in the aforementioned link,
	/// - the provided parameters are invalid for the offer,
	/// - the offer is for an unsupported chain, or
	/// - the parameterized [`Router`] is unable to create a blinded reply path for the invoice
	///   request.
	///
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`InvoiceRequest::quantity`]: crate::offers::invoice_request::InvoiceRequest::quantity
	/// [`InvoiceRequest::payer_note`]: crate::offers::invoice_request::InvoiceRequest::payer_note
	/// [`InvoiceRequestBuilder`]: crate::offers::invoice_request::InvoiceRequestBuilder
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn pay_for_offer(
		&self, offer: &Offer, quantity: Option<u64>, amount_msats: Option<u64>,
		payer_note: Option<String>, payment_id: PaymentId, retry_strategy: Retry,
		max_total_routing_fee_msat: Option<u64>
	) -> Result<(), Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let builder: InvoiceRequestBuilder<DerivedPayerSigningPubkey, secp256k1::All> = offer
			.request_invoice_deriving_signing_pubkey(expanded_key, nonce, secp_ctx, payment_id)?
			.into();
		let builder = builder.chain_hash(self.commons.get_chain_hash())?;

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
		let invoice_request = builder.build_and_sign()?;

		let hmac = payment_id.hmac_for_offer_payment(nonce, expanded_key);
		let context = MessageContext::Offers(
			OffersContext::OutboundPayment { payment_id, nonce, hmac: Some(hmac) }
		);
		let reply_paths = self.create_blinded_paths(context)
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&*self.commons);

		let expiration = StaleExpiration::TimerTicks(1);
		let retryable_invoice_request = RetryableInvoiceRequest {
			invoice_request: invoice_request.clone(),
			nonce,
		};
		self.commons.get_pending_outbound_payments()
			.add_new_awaiting_invoice(
				payment_id, expiration, retry_strategy, max_total_routing_fee_msat,
				Some(retryable_invoice_request)
			)
			.map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		self.enqueue_invoice_request(invoice_request, reply_paths)
	}

    /// Creates a [`Bolt12Invoice`] for a [`Refund`] and enqueues it to be sent via an onion
	/// message.
	///
	/// The resulting invoice uses a [`PaymentHash`] recognized by the [`ChannelManager`] and a
	/// [`BlindedPaymentPath`] containing the [`PaymentSecret`] needed to reconstruct the
	/// corresponding [`PaymentPreimage`]. It is returned purely for informational purposes.
	///
	/// # Limitations
	///
	/// Requires a direct connection to an introduction node in [`Refund::paths`] or to
	/// [`Refund::payer_signing_pubkey`], if empty. This request is best effort; an invoice will be
	/// sent to each node meeting the aforementioned criteria, but there's no guarantee that they
	/// will be received and no retries will be made.
	///
	/// # Errors
	///
	/// Errors if:
	/// - the refund is for an unsupported chain, or
	/// - the parameterized [`Router`] is unable to create a blinded payment path or reply path for
	///   the invoice.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn request_refund_payment(
		&self, refund: &Refund
	) -> Result<Bolt12Invoice, Bolt12SemanticError> {
		let expanded_key = &self.inbound_payment_key;
		let entropy = &*self.entropy_source;
		let secp_ctx = &self.secp_ctx;

		let amount_msats = refund.amount_msats();
		let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;

		if refund.chain() != self.commons.get_chain_hash() {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		let _persistence_guard = PersistenceNotifierGuard::notify_on_drop(&*self.commons);

		match self.commons.create_inbound_payment(Some(amount_msats), relative_expiry, None) {
			Ok((payment_hash, payment_secret)) => {
				let payment_context = PaymentContext::Bolt12Refund(Bolt12RefundContext {});
				let payment_paths = self.create_blinded_payment_paths(
					amount_msats, payment_secret, payment_context
				)
					.map_err(|_| Bolt12SemanticError::MissingPaths)?;

				#[cfg(feature = "std")]
				let builder = refund.respond_using_derived_keys(
					payment_paths, payment_hash, expanded_key, entropy
				)?;
				#[cfg(not(feature = "std"))]
				let created_at = Duration::from_secs(
					self.highest_seen_timestamp.load(Ordering::Acquire) as u64
				);
				#[cfg(not(feature = "std"))]
				let builder = refund.respond_using_derived_keys_no_std(
					payment_paths, payment_hash, created_at, expanded_key, entropy
				)?;
				let builder: InvoiceBuilder<DerivedSigningPubkey> = builder.into();
				let invoice = builder.allow_mpp().build_and_sign(secp_ctx)?;

				let nonce = Nonce::from_entropy_source(entropy);
				let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
				let context = MessageContext::Offers(OffersContext::InboundPayment {
					payment_hash: invoice.payment_hash(), nonce, hmac
				});
				let reply_paths = self.create_blinded_paths(context)
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
					reply_paths
						.iter()
						.flat_map(|reply_path| refund.paths().iter().map(move |path| (path, reply_path)))
						.take(OFFERS_MESSAGE_REQUEST_LIMIT)
						.for_each(|(path, reply_path)| {
							let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
								destination: Destination::BlindedPath(path.clone()),
								reply_path: reply_path.clone(),
							};
							let message = OffersMessage::Invoice(invoice.clone());
							pending_offers_messages.push((message, instructions));
						});
				}

				Ok(invoice)
			},
			Err(()) => Err(Bolt12SemanticError::InvalidAmount),
		}
	}

    fn enqueue_invoice_request(
		&self,
		invoice_request: InvoiceRequest,
		reply_paths: Vec<BlindedMessagePath>,
	) -> Result<(), Bolt12SemanticError> {
		let mut pending_offers_messages = self.pending_offers_messages.lock().unwrap();
		if !invoice_request.paths().is_empty() {
			reply_paths
				.iter()
				.flat_map(|reply_path| invoice_request.paths().iter().map(move |path| (path, reply_path)))
				.take(OFFERS_MESSAGE_REQUEST_LIMIT)
				.for_each(|(path, reply_path)| {
					let instructions = MessageSendInstructions::WithSpecifiedReplyPath {
						destination: Destination::BlindedPath(path.clone()),
						reply_path: reply_path.clone(),
					};
					let message = OffersMessage::InvoiceRequest(invoice_request.clone());
					pending_offers_messages.push((message, instructions));
				});
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
	/// Creates multi-hop blinded payment paths for the given `amount_msats` by delegating to
	/// [`Router::create_blinded_payment_paths`].
	fn create_blinded_payment_paths(
		&self, amount_msats: u64, payment_secret: PaymentSecret, payment_context: PaymentContext
	) -> Result<Vec<BlindedPaymentPath>, ()> {
		let secp_ctx = &self.secp_ctx;

		let first_hops = self.commons.list_usable_channels();
		let payee_node_id = self.get_our_node_id();
		let max_cltv_expiry = self.commons.get_best_block().height + CLTV_FAR_FAR_AWAY
			+ LATENCY_GRACE_PERIOD_BLOCKS;
		let payee_tlvs = ReceiveTlvs {
			payment_secret,
			payment_constraints: PaymentConstraints {
				max_cltv_expiry,
				htlc_minimum_msat: 1,
			},
			payment_context,
		};
		self.router.create_blinded_payment_paths(
			payee_node_id, first_hops, payee_tlvs, amount_msats, secp_ctx
		)
	}

	/// Creates a collection of blinded paths by delegating to [`MessageRouter`] based on
	/// the path's intended lifetime.
	///
	/// Whether or not the path is compact depends on whether the path is short-lived or long-lived,
	/// respectively, based on the given `absolute_expiry` as seconds since the Unix epoch. See
	/// [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`].
	fn create_blinded_paths_using_absolute_expiry(
		&self, context: OffersContext, absolute_expiry: Option<Duration>,
	) -> Result<Vec<BlindedMessagePath>, ()> {
		let now = self.duration_since_epoch();
		let max_short_lived_absolute_expiry = now.saturating_add(MAX_SHORT_LIVED_RELATIVE_EXPIRY);

		if absolute_expiry.unwrap_or(Duration::MAX) <= max_short_lived_absolute_expiry {
			self.create_compact_blinded_paths(context)
		} else {
			self.create_blinded_paths(MessageContext::Offers(context))
		}
	}

	pub(crate) fn duration_since_epoch(&self) -> Duration {
		#[cfg(not(feature = "std"))]
		let now = Duration::from_secs(
			self.highest_seen_timestamp.load(Ordering::Acquire) as u64
		);
		#[cfg(feature = "std")]
		let now = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		now
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_blinded_paths(&self, context: MessageContext) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		// let peers = self.per_peer_state.read().unwrap()
		// 	.iter()
		// 	.map(|(node_id, peer_state)| (node_id, peer_state.lock().unwrap()))
		// 	.filter(|(_, peer)| peer.is_connected)
		// 	.filter(|(_, peer)| peer.latest_features.supports_onion_messages())
		// 	.map(|(node_id, _)| *node_id)
		// 	.collect::<Vec<_>>();

		let peers = self.commons.get_peers_for_blinded_path()
			.into_iter()
			.map(|node| node.node_id)
			.collect::<Vec<_>>();


		self.message_router
			.create_blinded_paths(recipient, context, peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

	/// Creates a collection of blinded paths by delegating to
	/// [`MessageRouter::create_compact_blinded_paths`].
	///
	/// Errors if the `MessageRouter` errors.
	fn create_compact_blinded_paths(&self, context: OffersContext) -> Result<Vec<BlindedMessagePath>, ()> {
		let recipient = self.get_our_node_id();
		let secp_ctx = &self.secp_ctx;

		// let peers = self.per_peer_state.read().unwrap()
		// 	.iter()
		// 	.map(|(node_id, peer_state)| (node_id, peer_state.lock().unwrap()))
		// 	.filter(|(_, peer)| peer.is_connected)
		// 	.filter(|(_, peer)| peer.latest_features.supports_onion_messages())
		// 	.map(|(node_id, peer)| MessageForwardNode {
		// 		node_id: *node_id,
		// 		short_channel_id: peer.channel_by_id
		// 			.iter()
		// 			.filter(|(_, channel)| channel.context().is_usable())
		// 			.min_by_key(|(_, channel)| channel.context().channel_creation_height)
		// 			.and_then(|(_, channel)| channel.context().get_short_channel_id()),
		// 	})
		// 	.collect::<Vec<_>>();

		let peers = self.commons.get_peers_for_blinded_path();

		self.message_router
			.create_compact_blinded_paths(recipient, MessageContext::Offers(context), peers, secp_ctx)
			.and_then(|paths| (!paths.is_empty()).then(|| paths).ok_or(()))
	}

}

impl<ES: Deref, OMC: Deref, MR: Deref, R: Deref, NS: Deref, NL: Deref, L: Deref> OffersMessageHandler for OffersMessageFlow<ES, OMC, MR, R, NS, NL, L>
where
    ES::Target: EntropySource,
    OMC::Target: OffersMessageCommons + AChannelManager + Sized,
    MR::Target: MessageRouter,
    R::Target: Router,
    NS::Target: NodeSigner,
    NL::Target: NodeIdLookUp,
    L::Target: Logger,
{
    fn handle_message(
		&self, message: OffersMessage, context: Option<OffersContext>, responder: Option<Responder>,
	) -> Option<(OffersMessage, ResponseInstruction)> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = &self.inbound_payment_key;

		macro_rules! handle_pay_invoice_res {
			($res: expr, $invoice: expr, $logger: expr) => {{
				let error = match $res {
					Err(Bolt12PaymentError::UnknownRequiredFeatures) => {
						log_trace!(
							$logger, "Invoice requires unknown features: {:?}",
							$invoice.invoice_features()
						);
						InvoiceError::from(Bolt12SemanticError::UnknownRequiredFeatures)
					},
					Err(Bolt12PaymentError::SendingFailed(e)) => {
						log_trace!($logger, "Failed paying invoice: {:?}", e);
						InvoiceError::from_string(format!("{:?}", e))
					},
					#[cfg(async_payments)]
					Err(Bolt12PaymentError::BlindedPathCreationFailed) => {
						let err_msg = "Failed to create a blinded path back to ourselves";
						log_trace!($logger, "{}", err_msg);
						InvoiceError::from_string(err_msg.to_string())
					},
					Err(Bolt12PaymentError::UnexpectedInvoice)
						| Err(Bolt12PaymentError::DuplicateInvoice)
						| Ok(()) => return None,
				};

				match responder {
					Some(responder) => return Some((OffersMessage::InvoiceError(error), responder.respond())),
					None => {
						log_trace!($logger, "No reply path to send error: {:?}", error);
						return None
					},
				}
			}}
		}

		match message {
			OffersMessage::InvoiceRequest(invoice_request) => {
				let responder = match responder {
					Some(responder) => responder,
					None => return None,
				};

				let nonce = match context {
					None if invoice_request.metadata().is_some() => None,
					Some(OffersContext::InvoiceRequest { nonce }) => Some(nonce),
					_ => return None,
				};

				let invoice_request = match nonce {
					Some(nonce) => match invoice_request.verify_using_recipient_data(
						nonce, expanded_key, secp_ctx,
					) {
						Ok(invoice_request) => invoice_request,
						Err(()) => return None,
					},
					None => match invoice_request.verify_using_metadata(expanded_key, secp_ctx) {
						Ok(invoice_request) => invoice_request,
						Err(()) => return None,
					},
				};

				let amount_msats = match InvoiceBuilder::<DerivedSigningPubkey>::amount_msats(
					&invoice_request.inner
				) {
					Ok(amount_msats) => amount_msats,
					Err(error) => return Some((OffersMessage::InvoiceError(error.into()), responder.respond())),
				};

				let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;
				let (payment_hash, payment_secret) = match self.commons.create_inbound_payment(
					Some(amount_msats), relative_expiry, None
				) {
					Ok((payment_hash, payment_secret)) => (payment_hash, payment_secret),
					Err(()) => {
						let error = Bolt12SemanticError::InvalidAmount;
						return Some((OffersMessage::InvoiceError(error.into()), responder.respond()));
					},
				};

				let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
					offer_id: invoice_request.offer_id,
					invoice_request: invoice_request.fields(),
				});
				let payment_paths = match self.create_blinded_payment_paths(
					amount_msats, payment_secret, payment_context
				) {
					Ok(payment_paths) => payment_paths,
					Err(()) => {
						let error = Bolt12SemanticError::MissingPaths;
						return Some((OffersMessage::InvoiceError(error.into()), responder.respond()));
					},
				};

				#[cfg(not(feature = "std"))]
				let created_at = Duration::from_secs(
					self.highest_seen_timestamp.load(Ordering::Acquire) as u64
				);

				let response = if invoice_request.keys.is_some() {
					#[cfg(feature = "std")]
					let builder = invoice_request.respond_using_derived_keys(
						payment_paths, payment_hash
					);
					#[cfg(not(feature = "std"))]
					let builder = invoice_request.respond_using_derived_keys_no_std(
						payment_paths, payment_hash, created_at
					);
					builder
						.map(InvoiceBuilder::<DerivedSigningPubkey>::from)
						.and_then(|builder| builder.allow_mpp().build_and_sign(secp_ctx))
						.map_err(InvoiceError::from)
				} else {
					#[cfg(feature = "std")]
					let builder = invoice_request.respond_with(payment_paths, payment_hash);
					#[cfg(not(feature = "std"))]
					let builder = invoice_request.respond_with_no_std(
						payment_paths, payment_hash, created_at
					);
					builder
						.map(InvoiceBuilder::<ExplicitSigningPubkey>::from)
						.and_then(|builder| builder.allow_mpp().build())
						.map_err(InvoiceError::from)
						.and_then(|invoice| {
							#[cfg(c_bindings)]
							let mut invoice = invoice;
							invoice
								.sign(|invoice: &UnsignedBolt12Invoice|
									self.node_signer.sign_bolt12_invoice(invoice)
								)
								.map_err(InvoiceError::from)
						})
				};

				match response {
					Ok(invoice) => {
						let nonce = Nonce::from_entropy_source(&*self.entropy_source);
						let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
						let context = MessageContext::Offers(OffersContext::InboundPayment { payment_hash, nonce, hmac });
						Some((OffersMessage::Invoice(invoice), responder.respond_with_reply_path(context)))
					},
					Err(error) => Some((OffersMessage::InvoiceError(error.into()), responder.respond())),
				}
			},
			OffersMessage::Invoice(invoice) => {
				let payment_id = match self.verify_bolt12_invoice(&invoice, context.as_ref()) {
					Ok(payment_id) => payment_id,
					Err(()) => return None,
				};

				let logger = WithContext::from(
					&self.logger, None, None, Some(invoice.payment_hash()),
				);

				if self.commons.get_current_default_configuration()
					.manually_handle_bolt12_invoices {
						let event = Event::InvoiceReceived {
							payment_id, invoice, context, responder,
						};
						self.commons.add_new_pending_event((event, None));
						return None;
				}

				let res = self.send_payment_for_verified_bolt12_invoice(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, logger);
			},
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(invoice) => {
				let payment_id = match context {
					Some(OffersContext::OutboundPayment { payment_id, nonce, hmac: Some(hmac) }) => {
						if payment_id.verify_for_offer_payment(hmac, nonce, expanded_key).is_err() {
							return None
						}
						payment_id
					},
					_ => return None
				};
				let res = self.initiate_async_payment(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, self.logger);
			},
			OffersMessage::InvoiceError(invoice_error) => {
				let payment_hash = match context {
					Some(OffersContext::InboundPayment { payment_hash, nonce, hmac }) => {
						match payment_hash.verify_for_offer_payment(hmac, nonce, expanded_key) {
							Ok(_) => Some(payment_hash),
							Err(_) => None,
						}
					},
					_ => None,
				};

				let logger = WithContext::from(&self.logger, None, None, payment_hash);
				log_trace!(logger, "Received invoice_error: {}", invoice_error);

				match context {
					Some(OffersContext::OutboundPayment { payment_id, nonce, hmac: Some(hmac) }) => {
						if let Ok(()) = payment_id.verify_for_offer_payment(hmac, nonce, expanded_key) {
							self.commons.abandon_payment_with_reason(
								payment_id, PaymentFailureReason::InvoiceRequestRejected,
							);
						}
					},
					_ => {},
				}

				None
			},
		}
	}

	fn message_received(&self) {
		for (payment_id, retryable_invoice_request) in self.commons
			.get_pending_outbound_payments()
			.release_invoice_requests_awaiting_invoice()
		{
			let RetryableInvoiceRequest { invoice_request, nonce } = retryable_invoice_request;
			let hmac = payment_id.hmac_for_offer_payment(nonce, &self.inbound_payment_key);
			let context = MessageContext::Offers(OffersContext::OutboundPayment {
				payment_id,
				nonce,
				hmac: Some(hmac)
			});
			match self.create_blinded_paths(context) {
				Ok(reply_paths) => match self.enqueue_invoice_request(invoice_request, reply_paths) {
					Ok(_) => {}
					Err(_) => {
						log_warn!(self.logger,
							"Retry failed for an invoice request with payment_id: {}",
							payment_id
						);
					}
				},
				Err(_) => {
					log_warn!(self.logger,
						"Retry failed for an invoice request with payment_id: {}. \
							Reason: router could not find a blinded path to include as the reply path",
						payment_id
					);
				}
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}
}