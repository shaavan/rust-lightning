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

use bitcoin::secp256k1;

use crate::blinded_path::message::{AsyncPaymentsContext, BlindedMessagePath, OffersContext};
use crate::blinded_path::payment::{BlindedPaymentPath, PaymentContext};
use crate::chain;
use crate::ln::channelmanager::PaymentId;
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, InvoiceBuilder};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestBuilder, VerifiedInvoiceRequest};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::onion_message::messenger::{Destination, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::sign::NodeSigner;
use crate::types::payment::{PaymentHash, PaymentSecret};

#[cfg(async_payments)]
use {
	crate::blinded_path::message::MessageContext,
	crate::offers::static_invoice::StaticInvoiceBuilder,
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
		&'a self, refund: &'a Refund, payment_hash: PaymentHash, payment_paths: F,
	) -> Result<InvoiceBuilder<'a, DerivedSigningPubkey>, Bolt12SemanticError>
	where
		F: Fn(PaymentContext) -> Result<Vec<BlindedPaymentPath>, ()>;

	fn create_invoice_from_invoice_request<NS: Deref, F>(
		self, signer: NS, invoice_request: VerifiedInvoiceRequest, payment_hash: PaymentHash, payment_paths: F,
	) -> Result<Bolt12Invoice, InvoiceError>
	where
		NS::Target: NodeSigner,
		F: Fn(PaymentContext) -> Result<Vec<BlindedPaymentPath>, ()>;

	fn enqueue_invoice_request<F>(
		&self, invoice_request: InvoiceRequest, payment_id: PaymentId, nonce: Option<Nonce>, reply_paths: F,
	) -> Result<(), Bolt12SemanticError>
	where
		F: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>;

	fn enqueue_invoice<F>(
		&self, invoice: Bolt12Invoice, refund: &Refund, payment_hash: PaymentHash, reply_paths: F,
	) -> Result<(), Bolt12SemanticError>
	where
		F: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>;

   #[cfg(async_payments)]
   fn enqueue_async_payment_messages<F>(
		 &self, invoice: Bolt12Invoice, payment_id: PaymentId, reply_paths: F,
	) -> Result<(), Bolt12SemanticError>
	where
		 F: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>;

	#[cfg(feature = "dnssec")]
	fn enqueue_dns_onion_message<F>(
		&self, message: DNSSECQuery, context: DNSResolverMessage, dns_resolvers: Vec<Destination>,
		reply_paths: F,
	) -> Result<(), Bolt12SemanticError>
	where
		F: Fn(MessageContext) -> Result<Vec<BlindedMessagePath>, ()>;

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