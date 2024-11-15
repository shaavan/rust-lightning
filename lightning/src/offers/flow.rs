// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Provides data structures and functions for creating and managing Offers messages,
//! facilitating communication, and handling Bolt12 invoice payments.

use alloc::vec::Vec;
use core::ops::Deref;

use bitcoin::secp256k1::{self, Secp256k1};

use crate::blinded_path::message::{MessageContext, OffersContext};
use crate::blinded_path::payment::{Bolt12OfferContext, PaymentContext};
use crate::events::{Event, PaymentFailureReason};
use crate::ln::channelmanager::{Bolt12PaymentError, OffersMessageCommons, Verification};
use crate::ln::outbound_payment::RetryableInvoiceRequest;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};

use crate::offers::invoice::{
	DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice,
	DEFAULT_RELATIVE_EXPIRY,
};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::nonce::Nonce;
use crate::offers::parse::Bolt12SemanticError;

use crate::sign::EntropySource;
use crate::util::logger::{Logger, WithContext};

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

impl<ES: Deref, OMC: Deref, L: Deref> AnOffersMessageFlow for OffersMessageFlow<ES, OMC, L>
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

/// Facilitates the handling, communication, and management of Offers messages within a Lightning
/// node, enabling the creation, verification, and resolution of BOLT 12 invoices and related
/// payment flows.
///
/// The `OffersMessageFlow` struct integrates several components to manage the lifecycle of Offers
/// messages, ensuring robust communication and payment handling:
/// - [`EntropySource`] to provide cryptographic randomness essential for Offers message handling.
/// - [`Logger`] for detailed operational logging of Offers-related activity.
/// - [`OffersMessageCommons`] for core operations shared across Offers messages, such as metadata
///   verification and signature handling.
/// - MessageRouter for routing Offers messages to their appropriate destinations within the
///   Lightning network.
/// - Manages [`OffersMessage`] for creating and processing Offers-related messages.
/// - Handles [`DNSResolverMessage`] for resolving human-readable names in Offers messages
///   (when the `dnssec` feature is enabled).
///
/// Key Features:
/// - Supports creating BOLT 12 Offers, invoice requests, and refunds.
/// - Integrates with the Lightning node's broader message and payment infrastructure.
/// - Handles cryptographic operations and message validation to ensure compliance with BOLT 12.
/// - Supports DNS resolution for human-readable names (when enabled with `dnssec` feature).
///
/// This struct is essential for enabling BOLT12 payment workflows in the Lightning network,
/// providing the foundational mechanisms for Offers and related message exchanges.
///
/// [`DNSResolverMessage`]: crate::onion_message::dns_resolution::DNSResolverMessage
pub struct OffersMessageFlow<ES: Deref, OMC: Deref, L: Deref>
where
	ES::Target: EntropySource,
	OMC::Target: OffersMessageCommons,
	L::Target: Logger,
{
	secp_ctx: Secp256k1<secp256k1::All>,

	entropy_source: ES,

	/// Contains function shared between OffersMessageHandler, and ChannelManager.
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

		Self { secp_ctx, commons, entropy_source, logger }
	}
}

impl<ES: Deref, OMC: Deref, L: Deref> OffersMessageHandler for OffersMessageFlow<ES, OMC, L>
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
