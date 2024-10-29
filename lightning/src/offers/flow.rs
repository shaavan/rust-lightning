// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use core::ops::Deref;
use std::sync::Mutex;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1;

use crate::blinded_path::message::{MessageContext, OffersContext};
use crate::blinded_path::payment::{Bolt12OfferContext, PaymentContext};
use crate::events::PaymentFailureReason;
use crate::ln::channelmanager::{Bolt12PaymentError, NewTrait, PaymentId, Verification};
use crate::offers::invoice::{DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::nonce::Nonce;
use crate::offers::parse::Bolt12SemanticError;
use crate::onion_message::messenger::{MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};
use crate::sign::{EntropySource, NodeSigner};
use crate::util::logger::{Logger, WithContext};

use super::invoice::Bolt12Invoice;

// This would contain a bunch of things to allow separating Bolt12Invoice creation from ChannelManager
pub struct OffersMessageFlow<NT: Deref, ES: Deref, NS: Deref, L: Deref>
where 
    NT::Target: NewTrait,
    ES::Target: EntropySource,
    NS::Target: NodeSigner,
    L::Target: Logger,
{
    // secp_ctx for handle_message
    secp_ctx: Secp256k1<secp256k1::All>,

	#[cfg(not(any(test, feature = "_test_utils")))]
	pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,
	#[cfg(any(test, feature = "_test_utils"))]
	pub(crate) pending_offers_messages: Mutex<Vec<(OffersMessage, MessageSendInstructions)>>,

    channel_manager: NT,

    entropy_source: ES,
    node_signer: NS,

    logger: L,
}

impl<NT: Deref, ES: Deref, NS: Deref, L: Deref> OffersMessageFlow<NT, ES, NS, L>
where
    NT::Target: NewTrait,
    ES::Target: EntropySource,
    NS::Target: NodeSigner,
    L::Target: Logger,
{
	pub fn new(
		channel_manager: NT, entropy_source: ES, node_signer: NS, logger: L
	) -> Self {
		let mut secp_ctx = Secp256k1::new();
		secp_ctx.seeded_randomize(&entropy_source.get_secure_random_bytes());
		OffersMessageFlow {
			secp_ctx,
			pending_offers_messages: Mutex::new(Vec::new()),
			channel_manager,
			entropy_source,
			node_signer,
			logger,
		}
	}

    fn verify_bolt12_invoice(
		&self, invoice: &Bolt12Invoice, context: Option<&OffersContext>,
	) -> Result<PaymentId, ()> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = self.channel_manager.inbound_payment_key();

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
}

// OffersMessageFlow would implement OffersMessageHandler
// To implement it, it would need the function that currently channelmanager implements.
// So we would move those functions into a trait, and make channelmanager implement it, and parametrise OffersMessageFlow
// on the trait, and hence the ChannelManager.
impl<NT: Deref, ES: Deref, NS: Deref, L: Deref> OffersMessageHandler for OffersMessageFlow<NT, ES, NS, L>
where
    NT::Target: NewTrait,
    ES::Target: EntropySource,
    NS::Target: NodeSigner,
    L::Target: Logger,
{
    fn handle_message(
		&self, message: OffersMessage, context: Option<OffersContext>, responder: Option<Responder>,
	) -> Option<(OffersMessage, ResponseInstruction)> {
		let secp_ctx = &self.secp_ctx;
		let expanded_key = self.channel_manager.inbound_payment_key();

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
				let (payment_hash, payment_secret) = match self.channel_manager.create_inbound_payment(
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
				let payment_paths = match self.channel_manager.create_blinded_payment_paths(
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

				let res = self.channel_manager.send_payment_for_verified_bolt12_invoice(&invoice, payment_id);
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
							self.channel_manager.abandon_payment_with_reason(
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

    fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
		core::mem::take(&mut self.pending_offers_messages.lock().unwrap())
	}
}