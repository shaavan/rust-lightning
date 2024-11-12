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
use lightning_invoice::PaymentSecret;

use crate::blinded_path::NodeIdLookUp;
use crate::blinded_path::message::{BlindedMessagePath, MessageContext, OffersContext};
use crate::blinded_path::payment::{BlindedPaymentPath, Bolt12OfferContext, PaymentConstraints, PaymentContext, ReceiveTlvs};
use crate::chain::channelmonitor::LATENCY_GRACE_PERIOD_BLOCKS;
use crate::events::{Event, PaymentFailureReason};
use crate::ln::channelmanager::{AChannelManager, Bolt12PaymentError, OffersMessageCommons, PaymentId, PersistenceNotifierGuard, Verification, CLTV_FAR_FAR_AWAY, OFFERS_MESSAGE_REQUEST_LIMIT};
use crate::ln::inbound_payment;
use crate::ln::outbound_payment::RetryableInvoiceRequest;
use crate::onion_message::messenger::{Destination, MessageRouter, MessageSendInstructions, Responder, ResponseInstruction};
use crate::onion_message::offers::{OffersMessage, OffersMessageHandler};

use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, ExplicitSigningPubkey, InvoiceBuilder, UnsignedBolt12Invoice, DEFAULT_RELATIVE_EXPIRY};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::InvoiceRequest;
use crate::offers::nonce::Nonce;
use crate::offers::parse::Bolt12SemanticError;

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