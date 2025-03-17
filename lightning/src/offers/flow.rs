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

use crate::blinded_path::message::{AsyncPaymentsContext, MessageForwardNode, OffersContext};
use crate::chain;
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::PaymentId;
use crate::offers::invoice::{Bolt12Invoice, DerivedSigningPubkey, InvoiceBuilder};
use crate::offers::invoice_error::InvoiceError;
use crate::offers::invoice_request::{InvoiceRequest, InvoiceRequestBuilder, VerifiedInvoiceRequest};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{DerivedMetadata, Offer, OfferBuilder};
use crate::offers::parse::Bolt12SemanticError;
use crate::offers::refund::{Refund, RefundBuilder};
use crate::onion_message::async_payments::AsyncPaymentsMessage;
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::onion_message::messenger::{Destination, MessageSendInstructions};
use crate::onion_message::offers::OffersMessage;
use crate::sign::NodeSigner;
use crate::types::payment::{PaymentHash, PaymentSecret};

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

	#[cfg(async_payments)]
	fn get_and_clear_pending_async_messages(
		&self,
	) -> Vec<(AsyncPaymentsMessage, MessageSendInstructions)>;

	#[cfg(feature = "dnssec")]
	fn get_and_clear_pending_dns_messages(
		&self,
	) -> Vec<(DNSResolverMessage, MessageSendInstructions)>;
}