// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for dealing with OffersMessage

use alloc::vec::Vec;
use core::ops::Deref;
use core::time::Duration;

use bitcoin::secp256k1::{self, Secp256k1};

use crate::blinded_path::message::{MessageContext, OffersContext};
use crate::blinded_path::payment::{Bolt12OfferContext, PaymentContext};
use crate::events::{Event, PaymentFailureReason};
use crate::ln::channelmanager::{
	Bolt12PaymentError, OffersMessageCommons, PaymentId, Verification,
};
use crate::ln::outbound_payment::{Retry, RetryableInvoiceRequest, StaleExpiration};
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};

use crate::offers::invoice::{
	DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice,
	DEFAULT_RELATIVE_EXPIRY,
};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::RefundBuilder;

use crate::sign::EntropySource;
use crate::util::logger::{Logger, WithContext};

#[cfg(c_bindings)]
use {
	crate::offers::offer::OfferWithDerivedMetadataBuilder,
	crate::offers::refund::RefundMaybeWithDerivedMetadataBuilder,
};

/// A trivial trait which describes any [`OffersMessageFlow`].
///
/// This is not exported to bindings users as general cover traits aren't useful in other
/// languages.
pub trait AnOffersMessageFlow {
    /// A type implementing [`EntropySource`].
    type EntropySource: EntropySource + ?Sized;
    /// A type that may be dereferenced to [`Self::EntropySource`].
    type ES: Deref<Target = Self::EntropySource>;

    /// A type implementing [`OffersMessageCommons`].
    type OffersMessageCommons: OffersMessageCommons + ?Sized;
    /// A type that may be dereferenced to [`Self::OffersMessageCommons`].
    type OMC: Deref<Target = Self::OffersMessageCommons>;

    /// A type implementing [`Logger`].
    type Logger: Logger + ?Sized;
    /// A type that may be dereferenced to [`Self::Logger`].
    type L: Deref<Target = Self::Logger>;

    /// Returns a reference to the actual [`OffersMessageFlow`] object.
    fn get_omf(&self) -> &OffersMessageFlow<Self::ES, Self::OMC, Self::L>;
}

impl<ES: Deref, OMC: Deref, L: Deref> AnOffersMessageFlow
    for OffersMessageFlow<ES, OMC, L>
where
    ES::Target: EntropySource,
    OMC::Target: OffersMessageCommons,
    L::Target: Logger,
{
    type EntropySource = ES::Target;
    type ES = ES;

    type OffersMessageCommons = OMC::Target;
    type OMC = OMC;

    type Logger = L::Target;
    type L = L;

    fn get_omf(&self) -> &OffersMessageFlow<ES, OMC, L> {
        self
    }
}

/// ## BOLT 12 Offers
///
/// The [`offers`] module is useful for creating BOLT 12 offers. An [`Offer`] is a precursor to a
/// [`Bolt12Invoice`], which must first be requested by the payer. The interchange of these messages
/// as defined in the specification is handled by [`OffersMessageFlow`] and its implementation of
/// [`OffersMessageHandler`]. However, this only works with an [`Offer`] created using a builder
/// returned by [`create_offer_builder`]. With this approach, BOLT 12 offers and invoices are
/// stateless just as BOLT 11 invoices are.
///
/// ```
/// # use lightning::events::{Event, EventsProvider, PaymentPurpose};
/// # use lightning::ln::channelmanager::AChannelManager;
/// # use lightning::offers::flow::AnOffersMessageFlow;
/// # use lightning::offers::parse::Bolt12SemanticError;
///
/// #
/// # fn example<T: AnOffersMessageFlow, U: AChannelManager>(offers_flow: T, channel_manager: U) -> Result<(), Bolt12SemanticError> {
/// # let offers_flow = offers_flow.get_omf();
/// # let channel_manager = channel_manager.get_cm();
/// # let absolute_expiry = None;
/// # let offer = offers_flow
///     .create_offer_builder(absolute_expiry)?
/// # ;
/// # // Needed for compiling for c_bindings
/// # let builder: lightning::offers::offer::OfferBuilder<_, _> = offer.into();
/// # let offer = builder
///     .description("coffee".to_string())
///     .amount_msats(10_000_000)
///     .build()?;
/// let bech32_offer = offer.to_string();
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentClaimable { payment_hash, purpose, .. } => match purpose {
///             PaymentPurpose::Bolt12OfferPayment { payment_preimage: Some(payment_preimage), .. } => {
///                 println!("Claiming payment {}", payment_hash);
///                 channel_manager.claim_funds(payment_preimage);
///             },
///             PaymentPurpose::Bolt12OfferPayment { payment_preimage: None, .. } => {
///                 println!("Unknown payment hash: {}", payment_hash);
///             }
/// #           _ => {},
///         },
///         Event::PaymentClaimed { payment_hash, amount_msat, .. } => {
///             println!("Claimed {} msats", amount_msat);
///         },
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # Ok(())
/// # }
/// ```
///
/// A [`Refund`] is a request for an invoice to be paid. Like *paying* for an [`Offer`], *creating*
/// a [`Refund`] involves maintaining state since it represents a future outbound payment.
/// Therefore, use [`create_refund_builder`] when creating one, otherwise [`OffersMessageFlow`] will
/// refuse to pay any corresponding [`Bolt12Invoice`] that it receives.
///
/// ```
/// # use core::time::Duration;
/// # use lightning::events::{Event, EventsProvider};
/// # use lightning::ln::channelmanager::{AChannelManager, PaymentId, RecentPaymentDetails, Retry};
/// # use lightning::offers::flow::AnOffersMessageFlow;
/// # use lightning::offers::parse::Bolt12SemanticError;
/// #
/// # fn example<T: AnOffersMessageFlow, U: AChannelManager>(
/// #     offers_flow: T, channel_manager: U, amount_msats: u64, absolute_expiry: Duration, retry: Retry,
/// #     max_total_routing_fee_msat: Option<u64>
/// # ) -> Result<(), Bolt12SemanticError> {
/// # let offers_flow = offers_flow.get_omf();
/// # let channel_manager = channel_manager.get_cm();
/// # let payment_id = PaymentId([42; 32]);
/// # let refund = offers_flow
///     .create_refund_builder(
///         amount_msats, absolute_expiry, payment_id, retry, max_total_routing_fee_msat
///     )?
/// # ;
/// # // Needed for compiling for c_bindings
/// # let builder: lightning::offers::refund::RefundBuilder<_> = refund.into();
/// # let refund = builder
///     .description("coffee".to_string())
///     .payer_note("refund for order 1234".to_string())
///     .build()?;
/// let bech32_refund = refund.to_string();
///
/// // First the payment will be waiting on an invoice
/// let expected_payment_id = payment_id;
/// assert!(
///     channel_manager.list_recent_payments().iter().find(|details| matches!(
///         details,
///         RecentPaymentDetails::AwaitingInvoice { payment_id: expected_payment_id }
///     )).is_some()
/// );
///
/// // Once the invoice is received, a payment will be sent
/// assert!(
///     channel_manager.list_recent_payments().iter().find(|details| matches!(
///         details,
///         RecentPaymentDetails::Pending { payment_id: expected_payment_id, ..  }
///     )).is_some()
/// );
///
/// // On the event processing thread
/// channel_manager.process_pending_events(&|event| {
///     match event {
///         Event::PaymentSent { payment_id: Some(payment_id), .. } => println!("Paid {}", payment_id),
///         Event::PaymentFailed { payment_id, .. } => println!("Failed paying {}", payment_id),
///         // ...
///     #     _ => {},
///     }
///     Ok(())
/// });
/// # Ok(())
/// # }
/// ```
///
/// [`Bolt12Invoice`]: crate::offers::invoice
/// [`create_offer_builder`]: Self::create_offer_builder
/// [`create_refund_builder`]: Self::[`create_refund_builder`]
/// [`Offer`]: crate::offers::offer
/// [`offers`]: crate::offers
pub struct OffersMessageFlow<ES: Deref, OMC: Deref, L: Deref>
where
    ES::Target: EntropySource,
    OMC::Target: OffersMessageCommons,
    L::Target: Logger,
{
    secp_ctx: Secp256k1<secp256k1::All>,

    entropy_source: ES,

    /// Contains functions shared between OffersMessageHandler and ChannelManager.
    commons: OMC,

    /// The Logger for use in the OffersMessageFlow and which may be used to log
    /// information during deserialization.
    pub logger: L,
}


impl<ES: Deref, OMC: Deref, L: Deref> OffersMessageFlow<ES, OMC, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	L::Target: Logger,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(entropy_source: ES, commons: OMC, logger: L) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());

		Self {
			secp_ctx,
			entropy_source,
			commons,
			logger,
		}
	}
}

impl<ES: Deref, OMC: Deref, L: Deref> OffersMessageHandler
	for OffersMessageFlow<ES, OMC, L>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	L::Target: Logger,
{
	fn handle_message(
		&self, message: OffersMessage, context: Option<OffersContext>, responder: Option<Responder>,
	) -> Option<(OffersMessage, ResponseInstruction)> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = self.commons.get_expanded_key();

		macro_rules! handle_pay_invoice_res {
			($res: expr, $invoice: expr, $logger: expr) => {{
				let error = match $res {
					Err(Bolt12PaymentError::UnknownRequiredFeatures) => {
						log_trace!(
							$logger,
							"Invoice requires unknown features: {:?}",
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
					Some(responder) => {
						return Some((OffersMessage::InvoiceError(error), responder.respond()))
					},
					None => {
						log_trace!($logger, "No reply path to send error: {:?}", error);
						return None;
					},
				}
			}};
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
						nonce,
						expanded_key,
						secp_ctx,
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
					&invoice_request.inner,
				) {
					Ok(amount_msats) => amount_msats,
					Err(error) => {
						return Some((
							OffersMessage::InvoiceError(error.into()),
							responder.respond(),
						))
					},
				};

				let relative_expiry = DEFAULT_RELATIVE_EXPIRY.as_secs() as u32;
				let (payment_hash, payment_secret) = match self.commons.create_inbound_payment(
					Some(amount_msats),
					relative_expiry,
					None,
				) {
					Ok((payment_hash, payment_secret)) => (payment_hash, payment_secret),
					Err(()) => {
						let error = Bolt12SemanticError::InvalidAmount;
						return Some((
							OffersMessage::InvoiceError(error.into()),
							responder.respond(),
						));
					},
				};

				let payment_context = PaymentContext::Bolt12Offer(Bolt12OfferContext {
					offer_id: invoice_request.offer_id,
					invoice_request: invoice_request.fields(),
				});
				let payment_paths = match self.commons.create_blinded_payment_paths(
					amount_msats,
					payment_secret,
					payment_context,
				) {
					Ok(payment_paths) => payment_paths,
					Err(()) => {
						let error = Bolt12SemanticError::MissingPaths;
						return Some((
							OffersMessage::InvoiceError(error.into()),
							responder.respond(),
						));
					},
				};

				#[cfg(not(feature = "std"))]
				let created_at = self.commons.get_current_blocktime();

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
								.sign(|invoice: &UnsignedBolt12Invoice| {
									self.commons.sign_bolt12_invoice(invoice)
								})
								.map_err(InvoiceError::from)
						})
				};

				match response {
					Ok(invoice) => {
						let nonce = Nonce::from_entropy_source(&*self.entropy_source);
						let hmac = payment_hash.hmac_for_offer_payment(nonce, expanded_key);
						let context = MessageContext::Offers(OffersContext::InboundPayment {
							payment_hash,
							nonce,
							hmac,
						});
						Some((
							OffersMessage::Invoice(invoice),
							responder.respond_with_reply_path(context),
						))
					},
					Err(error) => {
						Some((OffersMessage::InvoiceError(error.into()), responder.respond()))
					},
				}
			},
			OffersMessage::Invoice(invoice) => {
				let payment_id =
					match self.commons.verify_bolt12_invoice(&invoice, context.as_ref()) {
						Ok(payment_id) => payment_id,
						Err(()) => return None,
					};

				let logger =
					WithContext::from(&self.logger, None, None, Some(invoice.payment_hash()));

				if self.commons.get_current_default_configuration().manually_handle_bolt12_invoices
				{
					let event = Event::InvoiceReceived { payment_id, invoice, context, responder };
					self.commons.add_new_pending_event((event, None));
					return None;
				}

				let res =
					self.commons.send_payment_for_verified_bolt12_invoice(&invoice, payment_id);
				handle_pay_invoice_res!(res, invoice, logger);
			},
			#[cfg(async_payments)]
			OffersMessage::StaticInvoice(invoice) => {
				let payment_id = match context {
					Some(OffersContext::OutboundPayment {
						payment_id,
						nonce,
						hmac: Some(hmac),
					}) => {
						if payment_id.verify_for_offer_payment(hmac, nonce, expanded_key).is_err() {
							return None;
						}
						payment_id
					},
					_ => return None,
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
					Some(OffersContext::OutboundPayment {
						payment_id,
						nonce,
						hmac: Some(hmac),
					}) => {
						if let Ok(()) =
							payment_id.verify_for_offer_payment(hmac, nonce, expanded_key)
						{
							self.commons.abandon_payment_with_reason(
								payment_id,
								PaymentFailureReason::InvoiceRequestRejected,
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
		for (payment_id, retryable_invoice_request) in
			self.commons.release_invoice_requests_awaiting_invoice()
		{
			let RetryableInvoiceRequest { invoice_request, nonce } = retryable_invoice_request;
			let hmac = payment_id.hmac_for_offer_payment(nonce, self.commons.get_expanded_key());
			let context = MessageContext::Offers(OffersContext::OutboundPayment {
				payment_id,
				nonce,
				hmac: Some(hmac),
			});
			match self.commons.create_blinded_paths(context) {
				Ok(reply_paths) => {
					match self.commons.enqueue_invoice_request(invoice_request, reply_paths) {
						Ok(_) => {},
						Err(_) => {
							log_warn!(
								self.logger,
								"Retry failed for an invoice request with payment_id: {}",
								payment_id
							);
						},
					}
				},
				Err(_) => {
					log_warn!(
						self.logger,
						"Retry failed for an invoice request with payment_id: {}. \
							Reason: router could not find a blinded path to include as the reply path",
						payment_id
					);
				},
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.commons.get_pending_offers_messages())
	}
}

macro_rules! create_offer_builder { ($self: ident, $builder: ty) => {
	/// Creates an [`OfferBuilder`] such that the [`Offer`] it builds is recognized by the
	/// [`OffersMessageFlow`] when handling [`InvoiceRequest`] messages for the offer. The offer's
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
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
	/// [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]: crate::ln::channelmanager::MAX_SHORT_LIVED_RELATIVE_EXPIRY
	/// [`MessageRouter`]: crate::onion_message::messenger::MessageRouter
	/// [`Offer`]: crate::offers::offer
	/// [`Router`]: crate::routing::router::Router
	pub fn create_offer_builder(
		&$self, absolute_expiry: Option<Duration>
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.commons.get_our_node_id();
		let expanded_key = &$self.commons.get_expanded_key();
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::InvoiceRequest { nonce };
		let path = $self.commons.create_blinded_paths_using_absolute_expiry(context, absolute_expiry)
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
	/// [`OffersMessageFlow`] when handling [`Bolt12Invoice`] messages for the refund.
	///
	/// # Payment
	///
	/// The provided `payment_id` is used to ensure that only one invoice is paid for the refund.
	/// See [Avoiding Duplicate Payments] for other requirements once the payment has been sent.
	///
	/// The builder will have the provided expiration set. Any changes to the expiration on the
	/// returned builder will not be honored by [`OffersMessageFlow`]. For non-`std`, the highest seen
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
	/// [`BlindedMessagePath`]: crate::blinded_path::message::BlindedMessagePath
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	/// [`Bolt12Invoice::payment_paths`]: crate::offers::invoice::Bolt12Invoice::payment_paths
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	/// [`MAX_SHORT_LIVED_RELATIVE_EXPIRY`]: crate::ln::channelmanager::MAX_SHORT_LIVED_RELATIVE_EXPIRY
	/// [`MessageRouter`]: crate::onion_message::messenger::MessageRouter
	/// [`RouteParameters::from_payment_params_and_value`]: crate::routing::router::RouteParameters::from_payment_params_and_value
	/// [`Router`]: crate::routing::router::Router
	/// [Avoiding Duplicate Payments]: #avoiding-duplicate-payments
	pub fn create_refund_builder(
		&$self, amount_msats: u64, absolute_expiry: Duration, payment_id: PaymentId,
		retry_strategy: Retry, max_total_routing_fee_msat: Option<u64>
	) -> Result<$builder, Bolt12SemanticError> {
		let node_id = $self.commons.get_our_node_id();
		let expanded_key = &$self.commons.get_expanded_key();
		let entropy = &*$self.entropy_source;
		let secp_ctx = &$self.secp_ctx;

		let nonce = Nonce::from_entropy_source(entropy);
		let context = OffersContext::OutboundPayment { payment_id, nonce, hmac: None };
		let path = $self.commons.create_blinded_paths_using_absolute_expiry(context, Some(absolute_expiry))
			.and_then(|paths| paths.into_iter().next().ok_or(()))
			.map_err(|_| Bolt12SemanticError::MissingPaths)?;

		let builder = RefundBuilder::deriving_signing_pubkey(
			node_id, expanded_key, nonce, secp_ctx, amount_msats, payment_id
		)?
			.chain_hash($self.commons.get_chain_hash())
			.absolute_expiry(absolute_expiry)
			.path(path);

		let expiration = StaleExpiration::AbsoluteTimeout(absolute_expiry);

		$self.commons.add_new_awaiting_invoice(
			payment_id, expiration, retry_strategy, max_total_routing_fee_msat, None
		).map_err(|_| Bolt12SemanticError::DuplicatePaymentId)?;

		Ok(builder.into())
	}
} }

impl<ES: Deref, OMC: Deref, L: Deref> OffersMessageFlow<ES, OMC, L>
where
    ES::Target: EntropySource,
    OMC::Target: OffersMessageCommons,
    L::Target: Logger,
{
	#[cfg(not(c_bindings))]
	create_offer_builder!(self, OfferBuilder<DerivedMetadata, secp256k1::All>);
	#[cfg(c_bindings)]
	create_offer_builder!(self, OfferWithDerivedMetadataBuilder);

	#[cfg(not(c_bindings))]
	create_refund_builder!(self, RefundBuilder<secp256k1::All>);

	#[cfg(c_bindings)]
	create_refund_builder!(self, RefundMaybeWithDerivedMetadataBuilder);
}
