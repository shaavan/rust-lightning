// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for `invoice_request` messages.
//!
//! An [`InvoiceRequest`] can be built from a parsed [`Offer`] as an "offer to be paid". It is
//! typically constructed by a customer and sent to the merchant who had published the corresponding
//! offer. The recipient of the request responds with a [`Bolt12Invoice`].
//!
//! For an "offer for money" (e.g., refund, ATM withdrawal), where an offer doesn't exist as a
//! precursor, see [`Refund`].
//!
//! [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
//! [`Refund`]: crate::offers::refund::Refund
//!
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::network::Network;
//! use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
//! use lightning::ln::channelmanager::PaymentId;
//! use lightning::ln::inbound_payment::ExpandedKey;
//! use lightning::types::features::OfferFeatures;
//! use lightning::offers::invoice_request::UnsignedInvoiceRequest;
//! # use lightning::offers::nonce::Nonce;
//! use lightning::offers::offer::Offer;
//! # use lightning::sign::EntropySource;
//! use lightning::util::ser::Writeable;
//!
//! # struct FixedEntropy;
//! # impl EntropySource for FixedEntropy {
//! #     fn get_secure_random_bytes(&self) -> [u8; 32] {
//! #         [42; 32]
//! #     }
//! # }
//! # fn parse() -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let expanded_key = ExpandedKey::new([42; 32]);
//! # let entropy = FixedEntropy {};
//! # let nonce = Nonce::from_entropy_source(&entropy);
//! let secp_ctx = Secp256k1::new();
//! let payment_id = PaymentId([1; 32]);
//! let mut buffer = Vec::new();
//!
//! # use lightning::offers::invoice_request::InvoiceRequestBuilder;
//! # <InvoiceRequestBuilder<_>>::from(
//! "lno1qcp4256ypq"
//!     .parse::<Offer>()?
//!     .request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)?
//! # )
//!     .chain(Network::Testnet)?
//!     .amount_msats(1000)?
//!     .quantity(5)?
//!     .payer_note("foo".to_string())
//!     .build_and_sign()?
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use crate::blinded_path::message::BlindedMessagePath;
use crate::blinded_path::payment::BlindedPaymentPath;
use crate::io;
use crate::ln::channelmanager::PaymentId;
use crate::ln::inbound_payment::{ExpandedKey, IV_LEN};
use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
use crate::offers::invoice::{
	self, DerivedSigningPubkey, ExplicitSigningPubkey, SigningPubkeyStrategy,
};
use crate::offers::merkle::{
	self, SignError, SignFn, SignatureTlvStream, SignatureTlvStreamRef, TaggedHash, TlvStream,
};
use crate::offers::nonce::Nonce;
use crate::offers::offer::{
	Amount, ExperimentalOfferTlvStream, ExperimentalOfferTlvStreamRef, Offer, OfferContents,
	OfferId, OfferTlvStream, OfferTlvStreamRef, EXPERIMENTAL_OFFER_TYPES, OFFER_TYPES,
};
use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError, ParsedMessage};
use crate::offers::payer::{PayerContents, PayerTlvStream, PayerTlvStreamRef};
use crate::offers::recurrence;
use crate::offers::signer::{self, Metadata, MetadataMaterial};
use crate::onion_message::dns_resolution::HumanReadableName;
use crate::types::features::InvoiceRequestFeatures;
use crate::types::payment::PaymentHash;
use crate::types::string::{PrintableString, UntrustedString};
use crate::util::ser::{
	CursorReadable, HighZeroBytesDroppedBigSize, LengthLimitedRead, LengthReadable, Readable,
	WithoutLength, Writeable, Writer,
};
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{self, Keypair, PublicKey, Secp256k1};

use core::time::Duration;

#[cfg(not(c_bindings))]
use crate::offers::invoice::InvoiceBuilder;
#[cfg(c_bindings)]
use crate::offers::invoice::{
	InvoiceWithDerivedSigningPubkeyBuilder, InvoiceWithExplicitSigningPubkeyBuilder,
};

#[allow(unused_imports)]
use crate::prelude::*;

/// Tag for the hash function used when signing an [`InvoiceRequest`]'s merkle root.
pub const SIGNATURE_TAG: &'static str = concat!("lightning", "invoice_request", "signature");

pub(super) const IV_BYTES: &[u8; IV_LEN] = b"LDK Invreq ~~~~~";

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// This is not exported to bindings users as builder patterns don't map outside of move semantics.
///
/// [module-level documentation]: self
pub struct InvoiceRequestBuilder<'a, 'b, T: secp256k1::Signing> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContentsWithoutPayerSigningPubkey,
	payer_signing_pubkey: Option<PublicKey>,
	secp_ctx: Option<&'b Secp256k1<T>>,
}

/// Builds an [`InvoiceRequest`] from an [`Offer`] for the "offer to be paid" flow.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: self
#[cfg(c_bindings)]
pub struct InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b> {
	offer: &'a Offer,
	invoice_request: InvoiceRequestContentsWithoutPayerSigningPubkey,
	payer_signing_pubkey: Option<PublicKey>,
	secp_ctx: Option<&'b Secp256k1<secp256k1::All>>,
}

macro_rules! invoice_request_derived_payer_signing_pubkey_builder_methods {
	(
	$self: ident, $self_type: ty, $secp_context: ty
) => {
		#[cfg_attr(c_bindings, allow(dead_code))]
		pub(super) fn deriving_signing_pubkey(
			offer: &'a Offer, expanded_key: &ExpandedKey, nonce: Nonce,
			secp_ctx: &'b Secp256k1<$secp_context>, payment_id: PaymentId,
		) -> Self {
			let payment_id = Some(payment_id);
			let derivation_material = MetadataMaterial::new(nonce, expanded_key, payment_id);
			let metadata = Metadata::DerivedSigningPubkey(derivation_material);
			Self {
				offer,
				invoice_request: Self::create_contents(offer, metadata),
				payer_signing_pubkey: None,
				secp_ctx: Some(secp_ctx),
			}
		}

		/// Derives per-request metadata while retaining the supplied payer signing pubkey.
		///
		/// Use a fresh nonce and payment id for each request; the signing pubkey may remain stable
		/// across a recurrence without reusing payment metadata.
		pub(crate) fn deriving_metadata_with_payer_signing_pubkey(
			offer: &'a Offer, expanded_key: &ExpandedKey, nonce: Nonce, payment_id: PaymentId,
			payer_signing_pubkey: PublicKey,
		) -> Self {
			let payment_id = Some(payment_id);
			let derivation_material = MetadataMaterial::new(nonce, expanded_key, payment_id);
			let metadata = Metadata::Derived(derivation_material);
			Self {
				offer,
				invoice_request: Self::create_contents(offer, metadata),
				payer_signing_pubkey: Some(payer_signing_pubkey),
				secp_ctx: None,
			}
		}

		/// Builds an unsigned request with derived metadata and a supplied payer signing pubkey.
		pub(crate) fn build(
			$self: $self_type,
		) -> Result<UnsignedInvoiceRequest, Bolt12SemanticError> {
			let (unsigned_invoice_request, keys, secp_ctx) = $self.build_with_checks()?;
			debug_assert!(keys.is_none());
			debug_assert!(secp_ctx.is_none());

			Ok(unsigned_invoice_request)
		}

		/// Builds a signed [`InvoiceRequest`] after checking for valid semantics.
		pub fn build_and_sign($self: $self_type) -> Result<InvoiceRequest, Bolt12SemanticError> {
			let (unsigned_invoice_request, keys, secp_ctx) = $self.build_with_checks()?;
			#[cfg(c_bindings)]
			let mut unsigned_invoice_request = unsigned_invoice_request;
			debug_assert!(keys.is_some());

			let secp_ctx = secp_ctx.unwrap();
			let keys = keys.unwrap();
			let invoice_request = unsigned_invoice_request
				.sign(|message: &UnsignedInvoiceRequest| {
					Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
				})
				.unwrap();
			Ok(invoice_request)
		}

		/// Builds a request and signs it with the keys matching the supplied payer signing pubkey.
		///
		/// Metadata is derived per request while the signing keys remain scoped to the caller.
		/// Returns [`Bolt12SemanticError::InvalidSigningPubkey`] if the supplied keys cannot sign
		/// for the request's payer signing pubkey.
		pub(crate) fn build_and_sign_with_keys(
			$self: $self_type, keys: &Keypair, secp_ctx: &Secp256k1<$secp_context>,
		) -> Result<InvoiceRequest, Bolt12SemanticError> {
			let unsigned_invoice_request = $self.build()?;
			#[cfg(c_bindings)]
			let mut unsigned_invoice_request = unsigned_invoice_request;

			unsigned_invoice_request
				.sign(|message: &UnsignedInvoiceRequest| {
					Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), keys))
				})
				.map_err(|_| Bolt12SemanticError::InvalidSigningPubkey)
		}
	};
}

/// Returns the recurrence terms if a joining discount applies to this request.
///
/// Only the first payment can receive a joining discount. Follow-up requests and cancellations
/// do not qualify.
pub(super) fn joining_discount_terms(
	offer: &OfferContents, request: Option<&recurrence::RequestFields>,
) -> Option<recurrence::Recurrence> {
	let terms = offer.recurrence()?;
	let request = request?;
	if request.counter != 0 || request.cancel {
		return None;
	}

	match terms.anchor {
		recurrence::Anchor::Fixed { proportional: true, .. } => Some(terms),
		_ => None,
	}
}

/// Checks request amounts without requiring an invoice creation time.
///
/// A joining discount depends on the invoice's creation time. Check the amount's range here and
/// defer its minimum to invoice creation; ordinary requests retain the full-period minimum.
fn check_request_amount(
	offer: &OfferContents, amount: Option<u64>, quantity: Option<u64>,
	request: Option<&recurrence::RequestFields>,
) -> Result<(), Bolt12SemanticError> {
	if joining_discount_terms(offer, request).is_some() {
		match offer.amount() {
			Some(Amount::Bitcoin { amount_msats }) => {
				amount_msats
					.checked_mul(quantity.unwrap_or(1))
					.ok_or(Bolt12SemanticError::InvalidAmount)?;
			},
			Some(Amount::Currency { .. }) => return Err(Bolt12SemanticError::UnsupportedCurrency),
			None => return Err(Bolt12SemanticError::MissingAmount),
		}
		if amount.map_or(false, |amount| amount > MAX_VALUE_MSAT) {
			return Err(Bolt12SemanticError::InvalidAmount);
		}
		Ok(())
	} else {
		offer.check_amount_msats_for_quantity(amount, quantity)
	}
}

/// Validates the request's amount and quantity against the offer.
///
/// Cancellation requests may omit either field. Supplied values are still validated.
/// Other requests must include each field required by the offer. Joining discounts are checked
/// against the invoice creation time when an invoice is built or parsed.
fn check_amount_and_quantity(
	offer: &OfferContents, amount: Option<u64>, quantity: Option<u64>,
	request: Option<&recurrence::RequestFields>,
) -> Result<(), Bolt12SemanticError> {
	let is_cancellation = request.map_or(false, |request| request.cancel);

	if !is_cancellation {
		if offer.amount().is_none() && amount.is_none() {
			return Err(Bolt12SemanticError::MissingAmount);
		}
		offer.check_quantity(quantity)?;
		return check_request_amount(offer, amount, quantity, request);
	}

	if quantity.is_some() {
		offer.check_quantity(quantity)?;
	}
	if amount.is_some() {
		// An omitted cancellation quantity has a multiplier of one. Supplying it here also
		// ensures the amount is checked when the offer normally requires an explicit quantity.
		offer.check_amount_msats_for_quantity(amount, Some(quantity.unwrap_or(1)))?;
	}
	Ok(())
}

macro_rules! invoice_request_builder_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr, $secp_context: ty $(, $self_mut: tt)?
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	fn create_contents(offer: &Offer, metadata: Metadata) -> InvoiceRequestContentsWithoutPayerSigningPubkey {
		let offer = offer.contents.clone();

		InvoiceRequestContentsWithoutPayerSigningPubkey {
			payer: PayerContents(metadata), offer, chain: None, amount_msats: None,
			features: InvoiceRequestFeatures::empty(), quantity: None, payer_note: None,
			offer_from_hrn: None, request_recurrence: None,
			#[cfg(test)]
			experimental_bar: None,
		}
	}

	/// Sets the [`InvoiceRequest::chain`] of the given [`Network`] for paying an invoice. If not
	/// called, [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported
	/// by the offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub fn chain($self: $self_type, network: Network) -> Result<$return_type, Bolt12SemanticError> {
		$self.chain_hash(ChainHash::using_genesis_block(network))
	}

	/// Sets the [`InvoiceRequest::chain`] for paying an invoice. If not called, the chain hash of
	/// [`Network::Bitcoin`] is assumed. Errors if the chain for `network` is not supported by the
	/// offer.
	///
	/// Successive calls to this method will override the previous setting.
	pub(crate) fn chain_hash($($self_mut)* $self: $self_type, chain: ChainHash) -> Result<$return_type, Bolt12SemanticError> {
		if !$self.offer.supports_chain(chain) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		$self.invoice_request.chain = Some(chain);
		Ok($return_value)
	}

	/// Sets the [`InvoiceRequest::amount_msats`] for paying an invoice. Errors if `amount_msats` is
	/// not at least the expected invoice amount (i.e., [`Offer::amount`] times [`quantity`]).
	/// For an initial request with proportional pricing, the minimum is checked when the invoice's
	/// creation time is known; this method only checks the amount's range.
	///
	/// Successive calls to this method will override the previous setting.
	///
	/// [`quantity`]: Self::quantity
	pub fn amount_msats($($self_mut)* $self: $self_type, amount_msats: u64) -> Result<$return_type, Bolt12SemanticError> {
		check_request_amount(
			&$self.invoice_request.offer, Some(amount_msats), $self.invoice_request.quantity,
			$self.invoice_request.request_recurrence.as_ref(),
		)?;
		$self.invoice_request.amount_msats = Some(amount_msats);
		Ok($return_value)
	}

	/// Sets [`InvoiceRequest::quantity`] of items. If not set, `1` is assumed. Errors if `quantity`
	/// does not conform to [`Offer::is_valid_quantity`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn quantity($($self_mut)* $self: $self_type, quantity: u64) -> Result<$return_type, Bolt12SemanticError> {
		$self.invoice_request.offer.check_quantity(Some(quantity))?;
		$self.invoice_request.quantity = Some(quantity);
		Ok($return_value)
	}

	/// Sets the [`InvoiceRequest::payer_note`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn payer_note($($self_mut)* $self: $self_type, payer_note: String) -> $return_type {
		$self.invoice_request.payer_note = Some(payer_note);
		$return_value
	}

	/// Sets the [`InvoiceRequest::offer_from_hrn`].
	///
	/// Successive calls to this method will override the previous setting.
	pub fn sourced_from_human_readable_name($($self_mut)* $self: $self_type, hrn: HumanReadableName) -> $return_type {
		$self.invoice_request.offer_from_hrn = Some(hrn);
		$return_value
	}

	/// Sets recurrence fields for a recurring offer invoice request.
	///
	/// Rejects previous state or cancellation on the first request. Compatibility with the
	/// offer's recurrence requirement, anchor, and limit is checked when the request is built.
	pub(crate) fn recurrence(
		$($self_mut)* $self: $self_type, counter: u32, start: Option<u32>,
		prev_state: Option<Vec<u8>>, cancel: bool,
	) -> Result<$return_type, Bolt12SemanticError> {
		$self.invoice_request.request_recurrence =
			recurrence::RequestFields::from_tlv_fields(Some(counter), start, prev_state, cancel.then_some(()))
				.map_err(|_| Bolt12SemanticError::InvalidRecurrence)?;
		Ok($return_value)
	}

	fn build_with_checks($($self_mut)* $self: $self_type) -> Result<
		(UnsignedInvoiceRequest, Option<Keypair>, Option<&'b Secp256k1<$secp_context>>),
		Bolt12SemanticError
	> {
		#[cfg(feature = "std")] {
			// Offer expiry prevents new payments from starting, but allows recurring payments to continue.
			let is_initial_request = $self.invoice_request.request_recurrence.as_ref()
				.map_or(true, |request| request.counter == 0);
			if is_initial_request && $self.offer.is_expired() {
				return Err(Bolt12SemanticError::AlreadyExpired);
			}
		}

		let chain = $self.invoice_request.chain();
		if !$self.offer.supports_chain(chain) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		if chain == $self.offer.implied_chain() {
			$self.invoice_request.chain = None;
		}

		// Ensure built invoice requests use the same recurrence form and limit checks as parsed
		// invoice requests, including explicit-basetime start handling and period-index overflow.
		recurrence::RequestFields::validate_for_offer(
			$self.offer.recurrence(),
			$self.invoice_request.request_recurrence.as_ref(),
		)?;

		check_amount_and_quantity(
			&$self.invoice_request.offer,
			$self.invoice_request.amount_msats,
			$self.invoice_request.quantity,
			$self.invoice_request.request_recurrence.as_ref(),
		)?;

		Ok($self.build_without_checks())
	}

	fn build_without_checks($($self_mut)* $self: $self_type) ->
		(UnsignedInvoiceRequest, Option<Keypair>, Option<&'b Secp256k1<$secp_context>>)
	{
		// Create the metadata for stateless verification of a Bolt12Invoice.
		let mut keys = None;
		let secp_ctx = $self.secp_ctx.clone();
		if $self.invoice_request.payer.0.has_derivation_material() {
			let mut metadata = core::mem::take(&mut $self.invoice_request.payer.0);

			let mut tlv_stream = $self.invoice_request.as_tlv_stream();
			debug_assert!(tlv_stream.2.payer_id.is_none());
			tlv_stream.0.metadata = None;
			if !metadata.derives_payer_keys() {
				tlv_stream.2.payer_id = $self.payer_signing_pubkey.as_ref();
			}

			let (derived_metadata, derived_keys) =
				metadata.derive_from(IV_BYTES, tlv_stream, $self.secp_ctx);
			metadata = derived_metadata;
			keys = derived_keys;
			if let Some(keys) = keys {
				debug_assert!($self.payer_signing_pubkey.is_none());
				$self.payer_signing_pubkey = Some(keys.public_key());
			}

			$self.invoice_request.payer.0 = metadata;
		}

		debug_assert!($self.invoice_request.payer.0.as_bytes().is_some());
		debug_assert!($self.payer_signing_pubkey.is_some());
		let payer_signing_pubkey = $self.payer_signing_pubkey.unwrap();

		let invoice_request = InvoiceRequestContents {
			#[cfg(not(c_bindings))]
			inner: $self.invoice_request,
			#[cfg(c_bindings)]
			inner: $self.invoice_request.clone(),
			payer_signing_pubkey,
		};
		let unsigned_invoice_request = UnsignedInvoiceRequest::new($self.offer, invoice_request);

		(unsigned_invoice_request, keys, secp_ctx)
	}
} }

#[cfg(test)]
macro_rules! invoice_request_builder_test_methods { (
	$self: ident, $self_type: ty, $return_type: ty, $return_value: expr $(, $self_mut: tt)?
) => {
	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn payer_metadata($($self_mut)* $self: $self_type, metadata: Metadata) -> $return_type {
		$self.invoice_request.payer = PayerContents(metadata);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn chain_unchecked($($self_mut)* $self: $self_type, network: Network) -> $return_type {
		let chain = ChainHash::using_genesis_block(network);
		$self.invoice_request.chain = Some(chain);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn amount_msats_unchecked($($self_mut)* $self: $self_type, amount_msats: u64) -> $return_type {
		$self.invoice_request.amount_msats = Some(amount_msats);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn features_unchecked($($self_mut)* $self: $self_type, features: InvoiceRequestFeatures) -> $return_type {
		$self.invoice_request.features = features;
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	fn quantity_unchecked($($self_mut)* $self: $self_type, quantity: u64) -> $return_type {
		$self.invoice_request.quantity = Some(quantity);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn payer_signing_pubkey($($self_mut)* $self: $self_type, signing_pubkey: PublicKey) -> $return_type {
		$self.payer_signing_pubkey = Some(signing_pubkey);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn experimental_bar($($self_mut)* $self: $self_type, experimental_bar: u64) -> $return_type {
		$self.invoice_request.experimental_bar = Some(experimental_bar);
		$return_value
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn build_unchecked($self: $self_type) -> UnsignedInvoiceRequest {
		$self.build_without_checks().0
	}

	#[cfg_attr(c_bindings, allow(dead_code))]
	pub(super) fn build_unchecked_and_sign($self: $self_type) -> InvoiceRequest {
		let (unsigned_invoice_request, keys, secp_ctx) = $self.build_without_checks();
		#[cfg(c_bindings)]
		let mut unsigned_invoice_request = unsigned_invoice_request;
		debug_assert!(keys.is_some());

		let secp_ctx = secp_ctx.unwrap();
		let keys = keys.unwrap();
		unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest|
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			)
			.unwrap()
	}
} }

impl<'a, 'b, T: secp256k1::Signing> InvoiceRequestBuilder<'a, 'b, T> {
	invoice_request_derived_payer_signing_pubkey_builder_methods!(self, Self, T);
	invoice_request_builder_methods!(self, Self, Self, self, T, mut);

	#[cfg(test)]
	invoice_request_builder_test_methods!(self, Self, Self, self, mut);
}

#[cfg(all(c_bindings, not(test)))]
impl<'a, 'b> InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b> {
	invoice_request_derived_payer_signing_pubkey_builder_methods!(self, &mut Self, secp256k1::All);
	invoice_request_builder_methods!(self, &mut Self, (), (), secp256k1::All);
}

#[cfg(all(c_bindings, test))]
impl<'a, 'b> InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b> {
	invoice_request_derived_payer_signing_pubkey_builder_methods!(self, &mut Self, secp256k1::All);
	invoice_request_builder_methods!(self, &mut Self, &mut Self, self, secp256k1::All);
	invoice_request_builder_test_methods!(self, &mut Self, &mut Self, self);
}

#[cfg(c_bindings)]
impl<'a, 'b> From<InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b>>
	for InvoiceRequestBuilder<'a, 'b, secp256k1::All>
{
	fn from(builder: InvoiceRequestWithDerivedPayerSigningPubkeyBuilder<'a, 'b>) -> Self {
		let InvoiceRequestWithDerivedPayerSigningPubkeyBuilder {
			offer,
			invoice_request,
			payer_signing_pubkey,
			secp_ctx,
		} = builder;

		Self { offer, invoice_request, payer_signing_pubkey, secp_ctx }
	}
}

/// A semantically valid [`InvoiceRequest`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
#[derive(Clone)]
pub struct UnsignedInvoiceRequest {
	bytes: Vec<u8>,
	experimental_bytes: Vec<u8>,
	contents: InvoiceRequestContents,
	tagged_hash: TaggedHash,
}

/// A function for signing an [`UnsignedInvoiceRequest`].
pub trait SignInvoiceRequestFn {
	/// Signs a [`TaggedHash`] computed over the merkle root of `message`'s TLV stream.
	fn sign_invoice_request(&self, message: &UnsignedInvoiceRequest) -> Result<Signature, ()>;
}

impl<F> SignInvoiceRequestFn for F
where
	F: Fn(&UnsignedInvoiceRequest) -> Result<Signature, ()>,
{
	fn sign_invoice_request(&self, message: &UnsignedInvoiceRequest) -> Result<Signature, ()> {
		self(message)
	}
}

impl<F> SignFn<UnsignedInvoiceRequest> for F
where
	F: SignInvoiceRequestFn,
{
	fn sign(&self, message: &UnsignedInvoiceRequest) -> Result<Signature, ()> {
		self.sign_invoice_request(message)
	}
}

impl UnsignedInvoiceRequest {
	fn new(offer: &Offer, contents: InvoiceRequestContents) -> Self {
		// Use the offer bytes instead of the offer TLV stream as the offer may have contained
		// unknown TLV records, which are not stored in `OfferContents`.
		let (
			payer_tlv_stream,
			_offer_tlv_stream,
			invoice_request_tlv_stream,
			_experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
		) = contents.as_tlv_stream();

		const INVOICE_REQUEST_ALLOCATION_SIZE: usize = 512;
		let mut bytes = Vec::with_capacity(INVOICE_REQUEST_ALLOCATION_SIZE);

		payer_tlv_stream.write(&mut bytes).unwrap();

		for record in TlvStream::new(&offer.bytes).range(OFFER_TYPES) {
			record.write(&mut bytes).unwrap();
		}

		let remaining_bytes = &offer.bytes[bytes.len() - payer_tlv_stream.serialized_length()..];

		invoice_request_tlv_stream.write(&mut bytes).unwrap();

		const EXPERIMENTAL_TLV_ALLOCATION_SIZE: usize = 0;
		let mut experimental_bytes = Vec::with_capacity(EXPERIMENTAL_TLV_ALLOCATION_SIZE);

		let experimental_tlv_stream =
			TlvStream::new(remaining_bytes).range(EXPERIMENTAL_OFFER_TYPES);
		for record in experimental_tlv_stream {
			record.write(&mut experimental_bytes).unwrap();
		}

		experimental_invoice_request_tlv_stream.write(&mut experimental_bytes).unwrap();

		let tlv_stream = TlvStream::new(&bytes).chain(TlvStream::new(&experimental_bytes));
		let tagged_hash = TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		Self { bytes, experimental_bytes, contents, tagged_hash }
	}

	/// Returns the [`TaggedHash`] of the invoice to sign.
	pub fn tagged_hash(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

macro_rules! unsigned_invoice_request_sign_method { (
	$self: ident, $self_type: ty $(, $self_mut: tt)?
) => {
	/// Signs the [`TaggedHash`] of the invoice request using the given function.
	///
	/// Note: The hash computation may have included unknown, odd TLV records.
	pub fn sign<F: SignInvoiceRequestFn>(
		$($self_mut)* $self: $self_type, sign: F
	) -> Result<InvoiceRequest, SignError> {
		let pubkey = $self.contents.payer_signing_pubkey;
		let signature = merkle::sign_message(sign, &$self, pubkey)?;

		// Append the signature TLV record to the bytes.
		let signature_tlv_stream = SignatureTlvStreamRef {
			signature: Some(&signature),
		};
		signature_tlv_stream.write(&mut $self.bytes).unwrap();

		// Append the experimental bytes after the signature.
		$self.bytes.extend_from_slice(&$self.experimental_bytes);

		Ok(InvoiceRequest {
			#[cfg(not(c_bindings))]
			bytes: $self.bytes,
			#[cfg(c_bindings)]
			bytes: $self.bytes.clone(),
			#[cfg(not(c_bindings))]
			contents: $self.contents,
			#[cfg(c_bindings)]
			contents: $self.contents.clone(),
			signature,
		})
	}
} }

#[cfg(not(c_bindings))]
impl UnsignedInvoiceRequest {
	unsigned_invoice_request_sign_method!(self, Self, mut);
}

#[cfg(c_bindings)]
impl UnsignedInvoiceRequest {
	unsigned_invoice_request_sign_method!(self, &mut Self);
}

impl AsRef<TaggedHash> for UnsignedInvoiceRequest {
	fn as_ref(&self) -> &TaggedHash {
		&self.tagged_hash
	}
}

/// An `InvoiceRequest` is a request for a [`Bolt12Invoice`] formulated from an [`Offer`].
///
/// An offer may provide choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that its recipient can send an invoice for payment.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InvoiceRequest {
	pub(super) bytes: Vec<u8>,
	pub(super) contents: InvoiceRequestContents,
	signature: Signature,
}

#[cfg(not(test))]
impl PartialEq for InvoiceRequest {
	fn eq(&self, other: &Self) -> bool {
		self.bytes.eq(&other.bytes) && self.signature.eq(&other.signature)
	}
}

impl Eq for InvoiceRequest {}

/// An [`InvoiceRequest`] that has been verified by [`InvoiceRequest::verify_using_metadata`] or
/// [`InvoiceRequest::verify_using_recipient_data`] and exposes different ways to respond depending
/// on whether the signing keys were derived.
#[derive(Clone, Debug)]
pub struct VerifiedInvoiceRequest<S: SigningPubkeyStrategy> {
	/// The identifier of the [`Offer`] for which the [`InvoiceRequest`] was made.
	pub offer_id: OfferId,

	/// The verified request.
	pub(crate) inner: InvoiceRequest,

	/// Basetime recovered from the payer's previous state, if available.
	///
	/// Later requests with a first-invoice anchor need this to preserve the original schedule
	/// instead of starting a new schedule at the current invoice's creation time.
	pub(crate) recovered_basetime: Option<u64>,

	/// Keys for signing a [`Bolt12Invoice`] for the request.
	///
	#[cfg_attr(
		feature = "std",
		doc = "If `DerivedSigningPubkey`, must call [`respond_using_derived_keys`] when responding. Otherwise, call [`respond_with`]."
	)]
	#[cfg_attr(feature = "std", doc = "")]
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[cfg_attr(
		feature = "std",
		doc = "[`respond_using_derived_keys`]: Self::respond_using_derived_keys"
	)]
	#[cfg_attr(feature = "std", doc = "[`respond_with`]: Self::respond_with")]
	pub keys: S,
}

impl<S: SigningPubkeyStrategy> VerifiedInvoiceRequest<S> {
	/// Requires previous state to be present for automatic recurring follow-up handling.
	///
	/// Supplied state was authenticated during verification. Its presence is required here even
	/// for cancellation, while the payment-window checks apply only when issuing invoices.
	pub(crate) fn require_recurring_state(&self) -> Result<(), Bolt12SemanticError> {
		if let Some(request) = self.inner.request_recurrence() {
			if request.counter > 0 && request.prev_state.is_none() {
				return Err(Bolt12SemanticError::InvalidMetadata);
			}
		}
		Ok(())
	}

	/// Validates an automatic invoice response and returns its amount at `created_at`.
	///
	/// Requires previous state on follow-up requests, rejects cancellation, and checks the
	/// requested period's inclusive opening and exclusive closing bounds. `created_at` is the
	/// time being checked: the current time during verification, or the invoice's creation time
	/// when building a response. Recheck when building, since the request may have waited.
	pub(crate) fn validate_recurring_request(
		&self, created_at: Duration,
	) -> Result<u64, Bolt12SemanticError> {
		self.require_recurring_state()?;
		let request = match self.inner.request_recurrence() {
			Some(request) => request,
			None => return self.inner.invoice_amount_msats(created_at),
		};

		// Cancellation requests do not produce payable invoices.
		if request.cancel {
			return Err(Bolt12SemanticError::UnexpectedRecurrence);
		}

		let (terms, basetime) = self
			.recurrence_payment_context(created_at)?
			.ok_or(Bolt12SemanticError::InvalidRecurrence)?;
		let period_index = terms.period_index(request.counter, request.start)?;
		let (opening, closing) = terms
			.payment_window(basetime, period_index)
			.map_err(|_| Bolt12SemanticError::InvalidRecurrence)?;
		let now = created_at.as_secs();
		if now < opening || now >= closing {
			return Err(Bolt12SemanticError::InvalidRecurrence);
		}
		// A supplied amount may be below the full-period price only for the joining invoice.
		// Check its minimum now that the invoice creation time is available.
		self.inner.invoice_amount_msats(created_at)
	}

	/// Resolves the offer terms and basetime to include in an inbound payment context.
	///
	/// Use the invoice's creation time when a first-invoice anchor establishes period zero.
	/// Later requests with that anchor reuse the basetime recovered during verification. Fixed
	/// anchors use the offer's basetime. Returns `None` when the request does not use recurrence,
	/// including single payments for offers with optional recurrence.
	pub(crate) fn recurrence_payment_context(
		&self, created_at: Duration,
	) -> Result<Option<(recurrence::Recurrence, u64)>, Bolt12SemanticError> {
		let basetime = match self.inner.recurrence_basetime(created_at, self.recovered_basetime)? {
			Some(basetime) => basetime,
			None => return Ok(None),
		};
		let terms = self.inner.recurrence().ok_or(Bolt12SemanticError::InvalidRecurrence)?;
		Ok(Some((terms, basetime)))
	}

	/// Creates state for the payer to echo in the next recurring request.
	///
	/// Automatic recurring responses always include a token, so requests with a nonzero
	/// counter must supply previous state. Returns an error if recurrence or required
	/// state is missing, the basetime cannot be resolved, or the counter overflows.
	pub(crate) fn create_recurrence_next_state(
		&self, created_at: Duration, nonce: Nonce, key: &ExpandedKey,
	) -> Result<Vec<u8>, Bolt12SemanticError> {
		let request = match self.inner.request_recurrence() {
			Some(request) => request,
			None => return Err(Bolt12SemanticError::UnexpectedRecurrence),
		};

		self.require_recurring_state()?;

		let basetime = self
			.inner
			.recurrence_basetime(created_at, self.recovered_basetime)?
			.ok_or(Bolt12SemanticError::InvalidRecurrence)?;

		signer::create_recurrence_next_state(
			self.offer_id,
			self.inner.payer_signing_pubkey(),
			basetime,
			request.counter,
			request.start,
			nonce,
			key,
		)
		.map_err(|_| Bolt12SemanticError::InvalidRecurrence)
	}
}

/// Represents a [`VerifiedInvoiceRequest`], along with information about how the resulting
/// [`Bolt12Invoice`] should be signed.
///
/// The signing strategy determines whether the signing keys are:
/// - Derived either from the originating [`Offer`]’s metadata or recipient_data, or
/// - Explicitly provided.
///
/// This distinction is required to produce a valid, signed [`Bolt12Invoice`] from a verified request.
///
/// For more on key derivation strategies, see:
/// [`InvoiceRequest::verify_using_metadata`] and [`InvoiceRequest::verify_using_recipient_data`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
pub enum InvoiceRequestVerifiedFromOffer {
	/// A verified invoice request that uses signing keys derived from the originating [`Offer`]’s metadata or recipient_data.
	DerivedKeys(VerifiedInvoiceRequest<DerivedSigningPubkey>),
	/// A verified invoice request that requires explicitly provided signing keys to sign the resulting [`Bolt12Invoice`].
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	ExplicitKeys(VerifiedInvoiceRequest<ExplicitSigningPubkey>),
}

impl InvoiceRequestVerifiedFromOffer {
	/// Requires continuity state for automatic handling with either signing strategy.
	pub(crate) fn require_recurring_state(&self) -> Result<(), Bolt12SemanticError> {
		match self {
			Self::DerivedKeys(request) => request.require_recurring_state(),
			Self::ExplicitKeys(request) => request.require_recurring_state(),
		}
	}

	/// Validates an automatic invoice response and resolves its amount for either signing strategy.
	pub(crate) fn validate_recurring_request(
		&self, created_at: Duration,
	) -> Result<u64, Bolt12SemanticError> {
		match self {
			Self::DerivedKeys(request) => request.validate_recurring_request(created_at),
			Self::ExplicitKeys(request) => request.validate_recurring_request(created_at),
		}
	}

	/// Returns a reference to the underlying `InvoiceRequest`.
	pub(crate) fn inner(&self) -> &InvoiceRequest {
		match self {
			InvoiceRequestVerifiedFromOffer::DerivedKeys(req) => &req.inner,
			InvoiceRequestVerifiedFromOffer::ExplicitKeys(req) => &req.inner,
		}
	}

	/// Returns the `OfferId` of the offer this invoice request is for.
	pub fn offer_id(&self) -> OfferId {
		match self {
			InvoiceRequestVerifiedFromOffer::DerivedKeys(req) => req.offer_id,
			InvoiceRequestVerifiedFromOffer::ExplicitKeys(req) => req.offer_id,
		}
	}
}

/// The contents of an [`InvoiceRequest`], which may be shared with an [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct InvoiceRequestContents {
	pub(super) inner: InvoiceRequestContentsWithoutPayerSigningPubkey,
	payer_signing_pubkey: PublicKey,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct InvoiceRequestContentsWithoutPayerSigningPubkey {
	pub(super) payer: PayerContents,
	pub(super) offer: OfferContents,
	chain: Option<ChainHash>,
	amount_msats: Option<u64>,
	features: InvoiceRequestFeatures,
	quantity: Option<u64>,
	payer_note: Option<String>,
	offer_from_hrn: Option<HumanReadableName>,
	/// Recurrence fields for this invoice request.
	request_recurrence: Option<recurrence::RequestFields>,
	#[cfg(test)]
	experimental_bar: Option<u64>,
}

macro_rules! invoice_request_accessors { ($self: ident, $contents: expr) => {
	/// An unpredictable series of bytes, typically containing information about the derivation of
	/// [`payer_signing_pubkey`].
	///
	/// [`payer_signing_pubkey`]: Self::payer_signing_pubkey
	pub fn payer_metadata(&$self) -> &[u8] {
		$contents.metadata()
	}

	/// A chain from [`Offer::chains`] that the offer is valid for.
	pub fn chain(&$self) -> ChainHash {
		$contents.chain()
	}

	/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
	/// accounts for quantity and any joining discount.
	///
	/// Returns `None` if the initial request uses proportional pricing without an explicit amount,
	/// since its amount depends on the invoice's creation time.
	///
	/// [`chain`]: Self::chain
	pub fn amount_msats(&$self) -> Option<u64> {
		$contents.amount_msats()
	}

	/// Returns whether an amount was set in the request; otherwise, if [`amount_msats`] is `Some`
	/// then it was inferred from the [`Offer::amount`] and [`quantity`].
	///
	/// [`amount_msats`]: Self::amount_msats
	/// [`quantity`]: Self::quantity
	pub fn has_amount_msats(&$self) -> bool {
		$contents.has_amount_msats()
	}

	/// Features pertaining to requesting an invoice.
	pub fn invoice_request_features(&$self) -> &InvoiceRequestFeatures {
		&$contents.features()
	}

	/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
	pub fn quantity(&$self) -> Option<u64> {
		$contents.quantity()
	}

	/// A possibly transient pubkey used to sign the invoice request.
	pub fn payer_signing_pubkey(&$self) -> PublicKey {
		$contents.payer_signing_pubkey()
	}

	/// Returns this invoice request's recurrence fields, if present.
	pub fn request_recurrence(&$self) -> Option<&recurrence::RequestFields> {
		$contents.request_recurrence()
	}

	/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
	/// response.
	pub fn payer_note(&$self) -> Option<PrintableString<'_>> {
		$contents.payer_note()
	}

	/// If the [`Offer`] was sourced from a BIP 353 Human Readable Name, this should be set by the
	/// builder to indicate the original [`HumanReadableName`] which was resolved.
	pub fn offer_from_hrn(&$self) -> &Option<HumanReadableName> {
		$contents.offer_from_hrn()
	}
} }

impl UnsignedInvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);
}

macro_rules! invoice_request_respond_with_explicit_signing_pubkey_methods { (
	$self: ident, $contents: expr, $basetime: expr, $builder: ty
) => {
	/// Creates an [`InvoiceBuilder`] for the request with the given required fields and using the
	/// [`Duration`] since [`std::time::SystemTime::UNIX_EPOCH`] as the creation time.
	///
	/// See [`InvoiceRequest::respond_with_no_std`] for further details where the aforementioned
	/// creation time is used for the `created_at` parameter.
	///
	/// [`Duration`]: core::time::Duration
	#[cfg(feature = "std")]
	pub fn respond_with(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash
	) -> Result<$builder, Bolt12SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		$contents.respond_with_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the request with the given required fields.
	///
	/// Unless [`InvoiceBuilder::relative_expiry`] is set, the invoice will expire two hours after
	/// `created_at`, which is used to set [`Bolt12Invoice::created_at`].
	#[cfg_attr(feature = "std", doc = "Useful for non-`std` builds where [`std::time::SystemTime`] is not available.")]
	///
	/// The caller is expected to remember the preimage of `payment_hash` in order to claim a payment
	/// for the invoice.
	///
	/// The `payment_paths` parameter is useful for maintaining the payment recipient's privacy. It
	/// must contain one or more elements ordered from most-preferred to least-preferred, if there's
	/// a preference. Note, however, that any privacy is lost if a public node id was used for
	/// [`Offer::issuer_signing_pubkey`].
	///
	/// For recurring payments, callers constructing `payment_paths` should include the offer's
	/// recurrence terms and the invoice's recurrence basetime in the paths' [`Bolt12OfferContext`].
	/// This makes the timing information available when the payment is received. Use the same
	/// `created_at` when determining the basetime and constructing the invoice if the first invoice
	/// establishes the basetime. Leave both context fields absent for non-recurring payments,
	/// including single payments for offers with optional recurrence.
	///
	/// [`Bolt12OfferContext`]: crate::blinded_path::payment::Bolt12OfferContext
	///
	/// Errors if the request contains unknown required features.
	///
	/// # Note
	///
	/// If the originating [`Offer`] was created using [`OfferBuilder::deriving_signing_pubkey`],
	/// then first use [`InvoiceRequest::verify_using_metadata`] or
	/// [`InvoiceRequest::verify_using_recipient_data`] and then [`InvoiceRequestVerifiedFromOffer`] methods
	/// instead.
	///
	/// [`Bolt12Invoice::created_at`]: crate::offers::invoice::Bolt12Invoice::created_at
	/// [`OfferBuilder::deriving_signing_pubkey`]: crate::offers::offer::OfferBuilder::deriving_signing_pubkey
	pub fn respond_with_no_std(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<$builder, Bolt12SemanticError> {
		if $contents.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		let signing_pubkey = match $contents.contents.inner.offer.issuer_signing_pubkey() {
			Some(signing_pubkey) => signing_pubkey,
			None => return Err(Bolt12SemanticError::MissingIssuerSigningPubkey),
		};

		let recurrence_basetime = ($contents).recurrence_basetime(created_at, $basetime)?;

		<$builder>::for_offer(&$contents, payment_paths, created_at, recurrence_basetime, payment_hash, signing_pubkey)
	}

	#[cfg(test)]
	#[allow(dead_code)]
	pub(super) fn respond_with_no_std_using_signing_pubkey(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash,
		created_at: core::time::Duration, signing_pubkey: PublicKey
	) -> Result<$builder, Bolt12SemanticError> {
		debug_assert!($contents.contents.inner.offer.issuer_signing_pubkey().is_none());

		if $contents.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		let recurrence_basetime = ($contents).recurrence_basetime(created_at, $basetime)?;

		<$builder>::for_offer(&$contents, payment_paths, created_at, recurrence_basetime, payment_hash, signing_pubkey)
	}
} }

macro_rules! invoice_request_verify_method {
	($self: ident, $self_type: ty) => {
/// Verifies that the request was for an offer created using the given key by checking the
	/// metadata from the offer.
	///
	/// Returns the verified request which contains the derived keys needed to sign a
	/// [`Bolt12Invoice`] for the request if they could be extracted from the metadata.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[rustfmt::skip]
	pub fn verify_using_metadata<
		#[cfg(not(c_bindings))]
		T: secp256k1::Signing
	>(
		$self: $self_type, key: &ExpandedKey,
		#[cfg(not(c_bindings))]
		secp_ctx: &Secp256k1<T>,
		#[cfg(c_bindings)]
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<InvoiceRequestVerifiedFromOffer, ()> {
		let (offer_id, keys) =
			$self.contents.inner.offer.verify_using_metadata(&$self.bytes, key, secp_ctx)?;
		let inner = {
			#[cfg(not(c_bindings))]
			{ $self }
			#[cfg(c_bindings)]
			{ $self.clone() }
		};

		let recovered_basetime = inner.verify_recurrence_prev_state(offer_id, key)?;

		let verified = match keys {
			None => InvoiceRequestVerifiedFromOffer::ExplicitKeys(VerifiedInvoiceRequest {
				offer_id,
				inner,
				recovered_basetime,
				keys: ExplicitSigningPubkey {},
			}),
			Some(keys) => InvoiceRequestVerifiedFromOffer::DerivedKeys(VerifiedInvoiceRequest {
				offer_id,
				inner,
				recovered_basetime,
				keys: DerivedSigningPubkey(keys),
			}),
		};

		Ok(verified)
	}

/// Verifies that the request was for an offer created using the given key by checking a nonce
	/// included with the [`BlindedMessagePath`] for which the request was sent through.
	///
	/// Returns the verified request which contains the derived keys needed to sign a
	/// [`Bolt12Invoice`] for the request if they could be extracted from the metadata.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[rustfmt::skip]
	pub fn verify_using_recipient_data<
		#[cfg(not(c_bindings))]
		T: secp256k1::Signing
	>(
		$self: $self_type, nonce: Nonce, key: &ExpandedKey,
		#[cfg(not(c_bindings))]
		secp_ctx: &Secp256k1<T>,
		#[cfg(c_bindings)]
		secp_ctx: &Secp256k1<secp256k1::All>,
	) -> Result<InvoiceRequestVerifiedFromOffer, ()> {
		let (offer_id, keys) = $self.contents.inner.offer.verify_using_recipient_data(
			&$self.bytes, nonce, key, secp_ctx
		)?;

		let inner = {
			#[cfg(not(c_bindings))]
			{ $self }
			#[cfg(c_bindings)]
			{ $self.clone() }
		};

		let recovered_basetime = inner.verify_recurrence_prev_state(offer_id, key)?;

		let verified = match keys {
			None => InvoiceRequestVerifiedFromOffer::ExplicitKeys(VerifiedInvoiceRequest {
				offer_id,
				inner,
				recovered_basetime,
				keys: ExplicitSigningPubkey {},
			}),
			Some(keys) => InvoiceRequestVerifiedFromOffer::DerivedKeys(VerifiedInvoiceRequest {
				offer_id,
				inner,
				recovered_basetime,
				keys: DerivedSigningPubkey(keys),
			}),
		};

		Ok(verified)
	}
	};
}

#[cfg(not(c_bindings))]
impl InvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);
	invoice_request_respond_with_explicit_signing_pubkey_methods!(
		self,
		self,
		None,
		InvoiceBuilder<'_, ExplicitSigningPubkey>
	);
	invoice_request_verify_method!(self, Self);

	#[allow(unused)] // TODO: remove this once we remove the `async_payments` cfg flag
	pub(super) fn bytes(&self) -> &Vec<u8> {
		&self.bytes
	}
}

#[cfg(c_bindings)]
impl InvoiceRequest {
	offer_accessors!(self, self.contents.inner.offer);
	invoice_request_accessors!(self, self.contents);
	invoice_request_respond_with_explicit_signing_pubkey_methods!(
		self,
		self,
		None,
		InvoiceWithExplicitSigningPubkeyBuilder
	);
	invoice_request_verify_method!(self, &Self);

	#[allow(unused)] // TODO: remove this once we remove the `async_payments` cfg flag
	pub(super) fn bytes(&self) -> &Vec<u8> {
		&self.bytes
	}
}

impl InvoiceRequest {
	/// Resolves the amount to invoice at `created_at`, including any initial joining discount.
	///
	/// Use the same creation time for payment data, payment paths, and the invoice so their amounts
	/// agree. An explicit request amount is retained only if it covers the minimum at that time.
	pub(crate) fn invoice_amount_msats(
		&self, created_at: Duration,
	) -> Result<u64, Bolt12SemanticError> {
		invoice::resolve_amount_msats(&self.contents, created_at)
	}

	/// Verifies echoed recurrence state and recovers the basetime for subsequent invoices.
	///
	/// The token binds the request to the offer, payer, counter, and start offset without
	/// storing per-payer state. An absent token returns `Ok(None)`; it is not required when
	/// the previous invoice omitted next state. Verification permits replay of the same valid
	/// request and does not prove prior payment.
	fn verify_recurrence_prev_state(
		&self, offer_id: OfferId, key: &ExpandedKey,
	) -> Result<Option<u64>, ()> {
		let request = match self.contents.request_recurrence() {
			Some(request) => request,
			None => return Ok(None),
		};

		match request.prev_state.as_ref() {
			Some(prev_state) => signer::verify_recurrence_prev_state(
				prev_state,
				offer_id,
				self.contents.payer_signing_pubkey(),
				request.counter,
				request.start,
				key,
			)
			.map(Some),
			None => Ok(None),
		}
	}

	/// Returns no basetime for a non-recurring request, otherwise resolves its schedule anchor.
	pub(crate) fn recurrence_basetime(
		&self, created_at: Duration, recovered_basetime: Option<u64>,
	) -> Result<Option<u64>, Bolt12SemanticError> {
		let request = match self.request_recurrence() {
			None => return Ok(None),
			Some(request) => request,
		};
		let terms = self.recurrence().ok_or(Bolt12SemanticError::InvalidRecurrence)?;
		request.resolve_basetime(terms.anchor, created_at.as_secs(), recovered_basetime).map(Some)
	}

	/// Signature of the invoice request using [`payer_signing_pubkey`].
	///
	/// [`payer_signing_pubkey`]: Self::payer_signing_pubkey
	pub fn signature(&self) -> Signature {
		self.signature
	}

	pub(crate) fn as_tlv_stream(&self) -> FullInvoiceRequestTlvStreamRef<'_> {
		let (
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
		) = self.contents.as_tlv_stream();
		let signature_tlv_stream = SignatureTlvStreamRef { signature: Some(&self.signature) };
		(
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			signature_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
		)
	}
}

macro_rules! invoice_request_respond_with_derived_signing_pubkey_methods { (
	$self: ident, $contents: expr, $basetime: expr, $builder: ty
) => {
	/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
	/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
	/// the same [`ExpandedKey`] as the one used to create the offer.
	///
	/// See [`InvoiceRequest::respond_with`] for further details.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	#[cfg(feature = "std")]
	pub fn respond_using_derived_keys(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash
	) -> Result<$builder, Bolt12SemanticError> {
		let created_at = std::time::SystemTime::now()
			.duration_since(std::time::SystemTime::UNIX_EPOCH)
			.expect("SystemTime::now() should come after SystemTime::UNIX_EPOCH");

		$self.respond_using_derived_keys_no_std(payment_paths, payment_hash, created_at)
	}

	/// Creates an [`InvoiceBuilder`] for the request using the given required fields and that uses
	/// derived signing keys from the originating [`Offer`] to sign the [`Bolt12Invoice`]. Must use
	/// the same [`ExpandedKey`] as the one used to create the offer.
	///
	/// For recurring payments, include the offer's recurrence terms and invoice basetime in
	/// the payment paths' context, using the same `created_at` to resolve the basetime and build
	/// the invoice. See [`InvoiceRequest::respond_with_no_std`] for the context requirements.
	///
	/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
	pub fn respond_using_derived_keys_no_std(
		&$self, payment_paths: Vec<BlindedPaymentPath>, payment_hash: PaymentHash,
		created_at: core::time::Duration
	) -> Result<$builder, Bolt12SemanticError> {
		if $self.inner.invoice_request_features().requires_unknown_bits() {
			return Err(Bolt12SemanticError::UnknownRequiredFeatures);
		}

		let keys = $self.keys.0;

		match $contents.contents.inner.offer.issuer_signing_pubkey() {
			Some(signing_pubkey) => debug_assert_eq!(signing_pubkey, keys.public_key()),
			None => return Err(Bolt12SemanticError::MissingIssuerSigningPubkey),
		}

		let recurrence_basetime = ($contents).recurrence_basetime(created_at, $basetime)?;

		<$builder>::for_offer_using_keys(
			&$self.inner, payment_paths, created_at, recurrence_basetime, payment_hash, keys
		)
	}
} }

macro_rules! fields_accessor {
	($self:ident, $inner:expr) => {
		/// Fetch the [`PayerFields`] for this verified invoice.
		///
		/// These are fields which we expect to be useful when receiving a payment for this invoice
		/// request, and include the returned [`PayerFields`] in the
		/// [`PaymentContext::Bolt12Offer`].
		///
		/// [`PaymentContext::Bolt12Offer`]: crate::blinded_path::payment::PaymentContext::Bolt12Offer
		pub fn fields(&$self) -> PayerFields {
			let InvoiceRequestContents {
				payer_signing_pubkey,
				inner: InvoiceRequestContentsWithoutPayerSigningPubkey {
					quantity,
					payer_note,
					request_recurrence,
					..
				},
			} = &$inner;

			PayerFields {
				payer_signing_pubkey: *payer_signing_pubkey,
				quantity: *quantity,
				payer_note_truncated: payer_note
					.clone()
					// Truncate the payer note to `PAYER_NOTE_LIMIT` bytes, rounding
					// down to the nearest valid UTF-8 code point boundary.
					.map(|s| UntrustedString(string_truncate_safe(s, PAYER_NOTE_LIMIT))),
				human_readable_name: $self.offer_from_hrn().clone(),
				request_recurrence: request_recurrence.clone(),
			}
		}
	};
}

impl VerifiedInvoiceRequest<DerivedSigningPubkey> {
	offer_accessors!(self, self.inner.contents.inner.offer);
	invoice_request_accessors!(self, self.inner.contents);
	fields_accessor!(self, self.inner.contents);

	#[cfg(not(c_bindings))]
	invoice_request_respond_with_derived_signing_pubkey_methods!(
		self,
		self.inner,
		self.recovered_basetime,
		InvoiceBuilder<'_, DerivedSigningPubkey>
	);
	#[cfg(c_bindings)]
	invoice_request_respond_with_derived_signing_pubkey_methods!(
		self,
		self.inner,
		self.recovered_basetime,
		InvoiceWithDerivedSigningPubkeyBuilder
	);
}

impl VerifiedInvoiceRequest<ExplicitSigningPubkey> {
	offer_accessors!(self, self.inner.contents.inner.offer);
	invoice_request_accessors!(self, self.inner.contents);
	fields_accessor!(self, self.inner.contents);

	#[cfg(not(c_bindings))]
	invoice_request_respond_with_explicit_signing_pubkey_methods!(
		self,
		self.inner,
		self.recovered_basetime,
		InvoiceBuilder<'_, ExplicitSigningPubkey>
	);
	#[cfg(c_bindings)]
	invoice_request_respond_with_explicit_signing_pubkey_methods!(
		self,
		self.inner,
		self.recovered_basetime,
		InvoiceWithExplicitSigningPubkeyBuilder
	);
}

impl InvoiceRequestVerifiedFromOffer {
	offer_accessors!(self, self.inner().contents.inner.offer);
	invoice_request_accessors!(self, self.inner().contents);
	fields_accessor!(self, self.inner().contents);
}

/// `String::truncate(new_len)` panics if you split inside a UTF-8 code point,
/// which would leave the `String` containing invalid UTF-8. This function will
/// instead truncate the string to the next smaller code point boundary so the
/// truncated string always remains valid UTF-8.
///
/// This can still split a grapheme cluster, but that's probably fine.
/// We'd otherwise have to pull in the `unicode-segmentation` crate and its big
/// unicode tables to find the next smaller grapheme cluster boundary.
pub(super) fn string_truncate_safe(mut s: String, new_len: usize) -> String {
	// Finds the largest byte index `x` not exceeding byte index `index` where
	// `s.is_char_boundary(x)` is true.
	// TODO(phlip9): remove when `std::str::floor_char_boundary` stabilizes.
	let truncated_len = if new_len >= s.len() {
		s.len()
	} else {
		(0..=new_len).rev().find(|idx| s.is_char_boundary(*idx)).unwrap_or(0)
	};
	s.truncate(truncated_len);
	s
}

impl InvoiceRequestContents {
	pub(super) fn metadata(&self) -> &[u8] {
		self.inner.metadata()
	}

	pub(super) fn chain(&self) -> ChainHash {
		self.inner.chain()
	}

	pub(super) fn amount_msats(&self) -> Option<u64> {
		if let Some(amount_msats) = self.inner.amount_msats() {
			return Some(amount_msats);
		}

		// The first payment is discounted for time already elapsed in the period. Without the
		// invoice's creation time, we cannot tell how much time remains or calculate the price.
		if joining_discount_terms(&self.inner.offer, self.request_recurrence()).is_some() {
			return None;
		}

		match self.inner.offer.amount() {
			Some(Amount::Bitcoin { amount_msats }) => {
				Some(amount_msats.saturating_mul(self.quantity().unwrap_or(1)))
			},
			Some(Amount::Currency { .. }) => None,
			None => {
				debug_assert!(false);
				None
			},
		}
	}

	pub(super) fn has_amount_msats(&self) -> bool {
		self.inner.amount_msats().is_some()
	}

	pub(super) fn features(&self) -> &InvoiceRequestFeatures {
		&self.inner.features
	}

	pub(super) fn quantity(&self) -> Option<u64> {
		self.inner.quantity
	}

	pub(super) fn payer_signing_pubkey(&self) -> PublicKey {
		self.payer_signing_pubkey
	}

	pub(super) fn request_recurrence(&self) -> Option<&recurrence::RequestFields> {
		self.inner.request_recurrence.as_ref()
	}

	pub(super) fn payer_note(&self) -> Option<PrintableString<'_>> {
		self.inner.payer_note.as_ref().map(|payer_note| PrintableString(payer_note.as_str()))
	}

	pub(super) fn offer_from_hrn(&self) -> &Option<HumanReadableName> {
		&self.inner.offer_from_hrn
	}

	pub(super) fn as_tlv_stream(&self) -> PartialInvoiceRequestTlvStreamRef<'_> {
		let (payer, offer, mut invoice_request, experimental_offer, experimental_invoice_request) =
			self.inner.as_tlv_stream();
		invoice_request.payer_id = Some(&self.payer_signing_pubkey);
		(payer, offer, invoice_request, experimental_offer, experimental_invoice_request)
	}
}

impl InvoiceRequestContentsWithoutPayerSigningPubkey {
	pub(super) fn metadata(&self) -> &[u8] {
		self.payer.0.as_bytes().map(|bytes| bytes.as_slice()).unwrap_or(&[])
	}

	pub(super) fn chain(&self) -> ChainHash {
		self.chain.unwrap_or_else(|| self.offer.implied_chain())
	}

	pub(super) fn amount_msats(&self) -> Option<u64> {
		self.amount_msats
	}

	pub(super) fn as_tlv_stream(&self) -> PartialInvoiceRequestTlvStreamRef<'_> {
		let payer = PayerTlvStreamRef { metadata: self.payer.0.as_bytes() };

		let (offer, experimental_offer) = self.offer.as_tlv_stream();

		let features = {
			if self.features == InvoiceRequestFeatures::empty() {
				None
			} else {
				Some(&self.features)
			}
		};

		let (recurrence_counter, recurrence_start, recurrence_prev_state, recurrence_cancel) =
			match self.request_recurrence.as_ref() {
				None => (None, None, None, None),
				Some(rec) => rec.fields(),
			};

		let invoice_request = InvoiceRequestTlvStreamRef {
			chain: self.chain.as_ref(),
			amount: self.amount_msats,
			features,
			quantity: self.quantity,
			payer_id: None,
			payer_note: self.payer_note.as_ref(),
			offer_from_hrn: self.offer_from_hrn.as_ref(),
			paths: None,
			recurrence_counter,
			recurrence_start,
			recurrence_cancel,
			recurrence_prev_state,
		};

		let experimental_invoice_request = ExperimentalInvoiceRequestTlvStreamRef {
			#[cfg(test)]
			experimental_bar: self.experimental_bar,
		};

		(payer, offer, invoice_request, experimental_offer, experimental_invoice_request)
	}
}

impl Writeable for UnsignedInvoiceRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)?;
		WithoutLength(&self.experimental_bytes).write(writer)
	}
}

impl Writeable for InvoiceRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		WithoutLength(&self.bytes).write(writer)
	}
}

impl Writeable for InvoiceRequestContents {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.as_tlv_stream().write(writer)
	}
}

impl LengthReadable for InvoiceRequest {
	fn read_from_fixed_length_buffer<R: LengthLimitedRead>(r: &mut R) -> Result<Self, DecodeError> {
		let bytes: WithoutLength<Vec<u8>> = LengthReadable::read_from_fixed_length_buffer(r)?;
		Self::try_from(bytes.0).map_err(|e| match e {
			Bolt12ParseError::Decode(e) => e,
			_ => DecodeError::InvalidValue,
		})
	}
}

/// Valid type range for invoice_request TLV records.
pub(super) const INVOICE_REQUEST_TYPES: core::ops::Range<u64> = 80..160;

/// TLV record type for [`InvoiceRequest::payer_signing_pubkey`] and
/// [`Refund::payer_signing_pubkey`].
///
/// [`Refund::payer_signing_pubkey`]: crate::offers::refund::Refund::payer_signing_pubkey
pub(super) const INVOICE_REQUEST_PAYER_ID_TYPE: u64 = 88;

// This TLV stream is used for both InvoiceRequest and Refund, but not all TLV records are valid for
// InvoiceRequest as noted below.
tlv_stream!(InvoiceRequestTlvStream, InvoiceRequestTlvStreamRef<'a>, INVOICE_REQUEST_TYPES, {
	(80, chain: ChainHash),
	(82, amount: (u64, HighZeroBytesDroppedBigSize)),
	(84, features: (InvoiceRequestFeatures, WithoutLength)),
	(86, quantity: (u64, HighZeroBytesDroppedBigSize)),
	(INVOICE_REQUEST_PAYER_ID_TYPE, payer_id: PublicKey),
	(89, payer_note: (String, WithoutLength)),
	// Only used for Refund since the onion message of an InvoiceRequest has a reply path.
	(90, paths: (Vec<BlindedMessagePath>, WithoutLength)),
	(91, offer_from_hrn: HumanReadableName),
	(92, recurrence_counter: (u32, HighZeroBytesDroppedBigSize)),
	(93, recurrence_start: (u32, HighZeroBytesDroppedBigSize)),
	(94, recurrence_cancel: ()),
	(96, recurrence_prev_state: (Vec<u8>, WithoutLength)),
});

/// Valid type range for experimental invoice_request TLV records.
pub(super) const EXPERIMENTAL_INVOICE_REQUEST_TYPES: core::ops::Range<u64> =
	2_000_000_000..3_000_000_000;

#[cfg(not(test))]
tlv_stream!(
	ExperimentalInvoiceRequestTlvStream,
	ExperimentalInvoiceRequestTlvStreamRef,
	EXPERIMENTAL_INVOICE_REQUEST_TYPES,
	{
		// When adding experimental TLVs, update EXPERIMENTAL_TLV_ALLOCATION_SIZE accordingly in
		// UnsignedInvoiceRequest::new to avoid unnecessary allocations.
	}
);

#[cfg(test)]
tlv_stream!(
	ExperimentalInvoiceRequestTlvStream, ExperimentalInvoiceRequestTlvStreamRef,
	EXPERIMENTAL_INVOICE_REQUEST_TYPES, {
		(2_999_999_999, experimental_bar: (u64, HighZeroBytesDroppedBigSize)),
	}
);

type FullInvoiceRequestTlvStream = (
	PayerTlvStream,
	OfferTlvStream,
	InvoiceRequestTlvStream,
	SignatureTlvStream,
	ExperimentalOfferTlvStream,
	ExperimentalInvoiceRequestTlvStream,
);

type FullInvoiceRequestTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	SignatureTlvStreamRef<'a>,
	ExperimentalOfferTlvStreamRef,
	ExperimentalInvoiceRequestTlvStreamRef,
);

impl CursorReadable for FullInvoiceRequestTlvStream {
	fn read<R: AsRef<[u8]>>(r: &mut io::Cursor<R>) -> Result<Self, DecodeError> {
		let payer = CursorReadable::read(r)?;
		let offer = CursorReadable::read(r)?;
		let invoice_request = CursorReadable::read(r)?;
		let signature = CursorReadable::read(r)?;
		let experimental_offer = CursorReadable::read(r)?;
		let experimental_invoice_request = CursorReadable::read(r)?;

		Ok((
			payer,
			offer,
			invoice_request,
			signature,
			experimental_offer,
			experimental_invoice_request,
		))
	}
}

type PartialInvoiceRequestTlvStream = (
	PayerTlvStream,
	OfferTlvStream,
	InvoiceRequestTlvStream,
	ExperimentalOfferTlvStream,
	ExperimentalInvoiceRequestTlvStream,
);

type PartialInvoiceRequestTlvStreamRef<'a> = (
	PayerTlvStreamRef<'a>,
	OfferTlvStreamRef<'a>,
	InvoiceRequestTlvStreamRef<'a>,
	ExperimentalOfferTlvStreamRef,
	ExperimentalInvoiceRequestTlvStreamRef,
);

impl TryFrom<Vec<u8>> for UnsignedInvoiceRequest {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice_request = ParsedMessage::<PartialInvoiceRequestTlvStream>::try_from(bytes)?;
		let ParsedMessage { mut bytes, tlv_stream } = invoice_request;

		let contents = InvoiceRequestContents::try_from(tlv_stream)?;
		let tagged_hash = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);

		let offset = TlvStream::new(&bytes)
			.range(0..INVOICE_REQUEST_TYPES.end)
			.last()
			.map_or(0, |last_record| last_record.end);
		let experimental_bytes = bytes.split_off(offset);

		Ok(UnsignedInvoiceRequest { bytes, experimental_bytes, contents, tagged_hash })
	}
}

impl TryFrom<Vec<u8>> for InvoiceRequest {
	type Error = Bolt12ParseError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let invoice_request = ParsedMessage::<FullInvoiceRequestTlvStream>::try_from(bytes)?;
		let ParsedMessage { bytes, tlv_stream } = invoice_request;
		let (
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			SignatureTlvStream { signature },
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
		) = tlv_stream;
		let contents = InvoiceRequestContents::try_from((
			payer_tlv_stream,
			offer_tlv_stream,
			invoice_request_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
		))?;

		let signature = match signature {
			None => {
				return Err(Bolt12ParseError::InvalidSemantics(
					Bolt12SemanticError::MissingSignature,
				))
			},
			Some(signature) => signature,
		};
		let message = TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &bytes);
		merkle::verify_signature(&signature, &message, contents.payer_signing_pubkey)?;

		Ok(InvoiceRequest { bytes, contents, signature })
	}
}

impl TryFrom<PartialInvoiceRequestTlvStream> for InvoiceRequestContents {
	type Error = Bolt12SemanticError;

	fn try_from(tlv_stream: PartialInvoiceRequestTlvStream) -> Result<Self, Self::Error> {
		let (
			PayerTlvStream { metadata },
			offer_tlv_stream,
			InvoiceRequestTlvStream {
				chain,
				amount,
				features,
				quantity,
				payer_id,
				payer_note,
				paths,
				offer_from_hrn,
				recurrence_counter,
				recurrence_start,
				recurrence_cancel,
				recurrence_prev_state,
			},
			experimental_offer_tlv_stream,
			ExperimentalInvoiceRequestTlvStream {
				#[cfg(test)]
				experimental_bar,
			},
		) = tlv_stream;

		let payer = match metadata {
			None => return Err(Bolt12SemanticError::MissingPayerMetadata),
			Some(metadata) => PayerContents(Metadata::Bytes(metadata)),
		};
		let offer = OfferContents::try_from((offer_tlv_stream, experimental_offer_tlv_stream))?;

		if !offer.supports_chain(chain.unwrap_or_else(|| offer.implied_chain())) {
			return Err(Bolt12SemanticError::UnsupportedChain);
		}

		let features = features.unwrap_or_else(InvoiceRequestFeatures::empty);

		let payer_signing_pubkey = match payer_id {
			None => return Err(Bolt12SemanticError::MissingPayerSigningPubkey),
			Some(payer_id) => payer_id,
		};

		if paths.is_some() {
			return Err(Bolt12SemanticError::UnexpectedPaths);
		}

		let request_recurrence = recurrence::RequestFields::from_tlv_fields(
			recurrence_counter,
			recurrence_start,
			recurrence_prev_state,
			recurrence_cancel,
		)
		.map_err(|_| Bolt12SemanticError::InvalidRecurrence)?;

		recurrence::RequestFields::validate_for_offer(
			offer.recurrence(),
			request_recurrence.as_ref(),
		)?;

		check_amount_and_quantity(&offer, amount, quantity, request_recurrence.as_ref())?;

		let inner = InvoiceRequestContentsWithoutPayerSigningPubkey {
			payer,
			offer,
			chain,
			amount_msats: amount,
			features,
			quantity,
			payer_note,
			offer_from_hrn,
			request_recurrence,
			#[cfg(test)]
			experimental_bar,
		};

		Ok(InvoiceRequestContents { inner, payer_signing_pubkey })
	}
}

/// Payer-provided fields to include in a [`PaymentContext`], so a payment recipient can recover
/// them without needing to separately persist them.
///
/// These fields are sent in an [`InvoiceRequest`] message for [`PaymentContext::Bolt12Offer`], or
/// are known upfront by a [`Refund`] issuer for [`PaymentContext::Bolt12Refund`].
///
/// [`PaymentContext`]: crate::blinded_path::payment::PaymentContext
/// [`PaymentContext::Bolt12Offer`]: crate::blinded_path::payment::PaymentContext::Bolt12Offer
/// [`PaymentContext::Bolt12Refund`]: crate::blinded_path::payment::PaymentContext::Bolt12Refund
/// [`Refund`]: crate::offers::refund::Refund
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayerFields {
	/// A possibly transient pubkey used to sign the invoice request.
	pub payer_signing_pubkey: PublicKey,

	/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
	pub quantity: Option<u64>,

	/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
	/// response. Truncated to [`PAYER_NOTE_LIMIT`] characters.
	pub payer_note_truncated: Option<UntrustedString>,

	/// The Human Readable Name which the sender indicated they were paying to.
	pub human_readable_name: Option<HumanReadableName>,

	/// Recurrence fields copied from the invoice request, if present.
	///
	/// See [`recurrence::RequestFields`] for the fields and their meaning.
	pub request_recurrence: Option<recurrence::RequestFields>,
}

/// The maximum number of characters included in [`PayerFields::payer_note_truncated`].
#[cfg(not(fuzzing))]
pub const PAYER_NOTE_LIMIT: usize = 512;

/// The maximum number of characters included in [`PayerFields::payer_note_truncated`].
#[cfg(fuzzing)]
pub const PAYER_NOTE_LIMIT: usize = 8;

impl Writeable for PayerFields {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let (recurrence_counter, recurrence_start, recurrence_prev_state, recurrence_cancel) =
			match self.request_recurrence.as_ref() {
				None => (None, None, None, None),
				Some(rec) => rec.fields(),
			};

		write_tlv_fields!(writer, {
			(0, self.payer_signing_pubkey, required),
			(1, self.human_readable_name, option),
			(2, self.quantity.map(|v| HighZeroBytesDroppedBigSize(v)), option),
			(3, recurrence_counter.map(HighZeroBytesDroppedBigSize), option),
			(4, self.payer_note_truncated.as_ref().map(|s| WithoutLength(&s.0)), option),
			(5, recurrence_start.map(HighZeroBytesDroppedBigSize), option),
			(7, recurrence_cancel, option),
			(9, recurrence_prev_state.map(|prev_state| WithoutLength(prev_state)), option),
		});
		Ok(())
	}
}

impl Readable for PayerFields {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, payer_signing_pubkey, required),
			(1, human_readable_name, option),
			(2, quantity, (option, encoding: (u64, HighZeroBytesDroppedBigSize))),
			(3, recurrence_counter, (option, encoding: (u32, HighZeroBytesDroppedBigSize))),
			(4, payer_note_truncated, (option, encoding: (String, WithoutLength))),
			(5, recurrence_start, (option, encoding: (u32, HighZeroBytesDroppedBigSize))),
			(7, recurrence_cancel, option),
			(9, recurrence_prev_state, (option, encoding: (Vec<u8>, WithoutLength))),
		});

		let request_recurrence = recurrence::RequestFields::from_tlv_fields(
			recurrence_counter,
			recurrence_start,
			recurrence_prev_state,
			recurrence_cancel,
		)
		.map_err(|_| DecodeError::InvalidValue)?;

		Ok(PayerFields {
			payer_signing_pubkey: payer_signing_pubkey.0.unwrap(),
			quantity,
			payer_note_truncated: payer_note_truncated.map(|s| UntrustedString(s)),
			human_readable_name,
			request_recurrence,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{
		ExperimentalInvoiceRequestTlvStreamRef, InvoiceRequest, InvoiceRequestTlvStreamRef,
		PayerFields, UnsignedInvoiceRequest, EXPERIMENTAL_INVOICE_REQUEST_TYPES,
		INVOICE_REQUEST_TYPES, PAYER_NOTE_LIMIT, SIGNATURE_TAG,
	};

	use crate::ln::channelmanager::PaymentId;
	use crate::ln::inbound_payment::ExpandedKey;
	use crate::ln::msgs::{DecodeError, MAX_VALUE_MSAT};
	use crate::offers::invoice::{Bolt12Invoice, SIGNATURE_TAG as INVOICE_SIGNATURE_TAG};
	use crate::offers::invoice_request::string_truncate_safe;
	use crate::offers::merkle::{self, SignatureTlvStreamRef, TaggedHash, TlvStream};
	use crate::offers::nonce::Nonce;
	#[cfg(not(c_bindings))]
	use crate::offers::offer::OfferBuilder;
	#[cfg(c_bindings)]
	use crate::offers::offer::OfferWithExplicitMetadataBuilder as OfferBuilder;
	use crate::offers::offer::{
		Amount, CurrencyCode, ExperimentalOfferTlvStreamRef, OfferTlvStreamRef, Quantity,
	};
	use crate::offers::parse::{Bolt12ParseError, Bolt12SemanticError};
	use crate::offers::payer::PayerTlvStreamRef;
	use crate::offers::test_utils::*;
	use crate::types::features::{InvoiceRequestFeatures, OfferFeatures};
	use crate::types::string::{PrintableString, UntrustedString};
	use crate::util::ser::{BigSize, Readable, Writeable};
	use bitcoin::constants::ChainHash;
	use bitcoin::network::Network;
	use bitcoin::secp256k1::{self, Keypair, Secp256k1, SecretKey};
	use core::num::NonZeroU64;
	#[cfg(feature = "std")]
	use core::time::Duration;

	#[test]
	fn builds_invoice_request_with_defaults() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);
		let encrypted_payment_id = expanded_key.crypt_for_offer(payment_id.0, nonce);
		let mut payer_metadata = encrypted_payment_id.to_vec();
		payer_metadata.extend_from_slice(nonce.as_slice());

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		assert_eq!(invoice_request.bytes, buffer.as_slice());
		assert_eq!(invoice_request.payer_metadata(), payer_metadata.as_slice());
		assert_eq!(
			invoice_request.chains(),
			vec![ChainHash::using_genesis_block(Network::Bitcoin)]
		);
		assert_eq!(invoice_request.metadata(), None);
		assert_eq!(invoice_request.amount(), Some(Amount::Bitcoin { amount_msats: 1000 }));
		assert_eq!(invoice_request.description(), Some(PrintableString("")));
		assert_eq!(invoice_request.offer_features(), &OfferFeatures::empty());
		assert_eq!(invoice_request.absolute_expiry(), None);
		assert_eq!(invoice_request.paths(), &[]);
		assert_eq!(invoice_request.issuer(), None);
		assert_eq!(invoice_request.supported_quantity(), Quantity::One);
		assert_eq!(invoice_request.issuer_signing_pubkey(), Some(recipient_pubkey()));
		assert_eq!(invoice_request.chain(), ChainHash::using_genesis_block(Network::Bitcoin));
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(invoice_request.quantity(), None);
		assert_eq!(invoice_request.payer_note(), None);

		let message =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &invoice_request.bytes);
		assert!(merkle::verify_signature(
			&invoice_request.signature,
			&message,
			invoice_request.payer_signing_pubkey(),
		)
		.is_ok());

		assert_eq!(
			invoice_request.as_tlv_stream(),
			(
				PayerTlvStreamRef { metadata: Some(&payer_metadata) },
				OfferTlvStreamRef {
					chains: None,
					metadata: None,
					currency: None,
					amount: Some(1000),
					description: Some(&String::from("")),
					features: None,
					absolute_expiry: None,
					paths: None,
					issuer: None,
					quantity_max: None,
					issuer_id: Some(&recipient_pubkey()),
					recurrence_compulsory: None,
					recurrence_optional: None,
					recurrence_base: None,
					recurrence_paywindow: None,
					recurrence_limit: None,
				},
				InvoiceRequestTlvStreamRef {
					chain: None,
					amount: None,
					features: None,
					quantity: None,
					payer_id: Some(&invoice_request.payer_signing_pubkey()),
					payer_note: None,
					paths: None,
					offer_from_hrn: None,
					recurrence_counter: None,
					recurrence_start: None,
					recurrence_cancel: None,
					recurrence_prev_state: None,
				},
				SignatureTlvStreamRef { signature: Some(&invoice_request.signature()) },
				ExperimentalOfferTlvStreamRef { experimental_foo: None },
				ExperimentalInvoiceRequestTlvStreamRef { experimental_bar: None },
			),
		);

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice request: {:?}", e);
		}
	}

	#[cfg(feature = "std")]
	#[test]
	fn builds_invoice_request_from_offer_with_expiration() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let future_expiry = Duration::from_secs(u64::MAX);
		let past_expiry = Duration::from_secs(0);

		if let Err(e) = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(future_expiry)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
		{
			panic!("error building invoice_request: {:?}", e);
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.absolute_expiry(past_expiry)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::AlreadyExpired),
		}
	}

	#[test]
	fn builds_invoice_request_with_derived_payer_signing_pubkey() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let offer = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.experimental_foo(42)
			.build()
			.unwrap();
		let invoice_request = offer
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.experimental_bar(42)
			.build_and_sign()
			.unwrap();

		let invoice = invoice_request
			.respond_with_no_std(payment_paths(), payment_hash(), now())
			.unwrap()
			.experimental_baz(42)
			.build()
			.unwrap()
			.sign(recipient_sign)
			.unwrap();
		match invoice.verify_using_metadata(&expanded_key, &secp_ctx) {
			Ok(payment_id) => assert_eq!(payment_id, PaymentId([1; 32])),
			Err(()) => panic!("verification failed"),
		}

		// Fails verification with altered fields
		let (
			payer_tlv_stream,
			offer_tlv_stream,
			mut invoice_request_tlv_stream,
			mut invoice_tlv_stream,
			mut signature_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		) = invoice.as_tlv_stream();
		invoice_request_tlv_stream.amount = Some(2000);
		invoice_tlv_stream.amount = Some(2000);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let experimental_tlv_stream = (
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		);
		let mut bytes = Vec::new();
		(&tlv_stream, &experimental_tlv_stream).write(&mut bytes).unwrap();

		let message = TaggedHash::from_valid_tlv_stream_bytes(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = Vec::new();
		(tlv_stream, signature_tlv_stream, experimental_tlv_stream)
			.write(&mut encoded_invoice)
			.unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(invoice.verify_using_metadata(&expanded_key, &secp_ctx).is_err());

		// Fails verification with altered payer id
		let (
			payer_tlv_stream,
			offer_tlv_stream,
			mut invoice_request_tlv_stream,
			invoice_tlv_stream,
			mut signature_tlv_stream,
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		) = invoice.as_tlv_stream();
		let payer_id = pubkey(1);
		invoice_request_tlv_stream.payer_id = Some(&payer_id);

		let tlv_stream =
			(payer_tlv_stream, offer_tlv_stream, invoice_request_tlv_stream, invoice_tlv_stream);
		let experimental_tlv_stream = (
			experimental_offer_tlv_stream,
			experimental_invoice_request_tlv_stream,
			experimental_invoice_tlv_stream,
		);
		let mut bytes = Vec::new();
		(&tlv_stream, &experimental_tlv_stream).write(&mut bytes).unwrap();

		let message = TaggedHash::from_valid_tlv_stream_bytes(INVOICE_SIGNATURE_TAG, &bytes);
		let signature = merkle::sign_message(recipient_sign, &message, recipient_pubkey()).unwrap();
		signature_tlv_stream.signature = Some(&signature);

		let mut encoded_invoice = Vec::new();
		(tlv_stream, signature_tlv_stream, experimental_tlv_stream)
			.write(&mut encoded_invoice)
			.unwrap();

		let invoice = Bolt12Invoice::try_from(encoded_invoice).unwrap();
		assert!(invoice.verify_using_metadata(&expanded_key, &secp_ctx).is_err());
	}

	#[test]
	fn builds_invoice_request_with_chain() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mainnet = ChainHash::using_genesis_block(Network::Bitcoin);
		let testnet = ChainHash::using_genesis_block(Network::Testnet);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain(Network::Bitcoin)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), mainnet);
		assert_eq!(tlv_stream.chain, None);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain(Network::Testnet)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain(Network::Bitcoin)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), mainnet);
		assert_eq!(tlv_stream.chain, None);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Bitcoin)
			.chain(Network::Testnet)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain(Network::Bitcoin)
			.unwrap()
			.chain(Network::Testnet)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.chain(), testnet);
		assert_eq!(tlv_stream.chain, Some(&testnet));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain(Network::Bitcoin)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.chain(Network::Testnet)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnsupportedChain),
		}
	}

	#[test]
	fn builds_invoice_request_with_amount() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(1000)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert!(invoice_request.has_amount_msats());
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(tlv_stream.amount, Some(1000));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(1001)
			.unwrap()
			.amount_msats(1000)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert!(invoice_request.has_amount_msats());
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(tlv_stream.amount, Some(1000));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(1001)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert!(invoice_request.has_amount_msats());
		assert_eq!(invoice_request.amount_msats(), Some(1001));
		assert_eq!(tlv_stream.amount, Some(1001));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(999)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.quantity(2)
			.unwrap()
			.amount_msats(1000)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(MAX_VALUE_MSAT + 1)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(1000)
			.unwrap()
			.quantity(2)
			.unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InsufficientAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingAmount),
		}

		// An offer with amount_msats(0) must be rejected by the builder per BOLT 12.
		match OfferBuilder::new(recipient_pubkey()).amount_msats(0).build() {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.quantity(u64::MAX)
			.unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidAmount),
		}
	}

	#[test]
	fn builds_invoice_request_without_amount() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert!(!invoice_request.has_amount_msats());
		assert_eq!(invoice_request.amount_msats(), Some(1000));
		assert_eq!(tlv_stream.amount, None);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.quantity(2)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert!(!invoice_request.has_amount_msats());
		assert_eq!(invoice_request.amount_msats(), Some(2000));
		assert_eq!(tlv_stream.amount, None);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount(Amount::Currency {
				iso4217_code: CurrencyCode::new(*b"USD").unwrap(),
				amount: 10,
			})
			.build_unchecked()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked_and_sign();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert!(!invoice_request.has_amount_msats());
		assert_eq!(invoice_request.amount_msats(), None);
		assert_eq!(tlv_stream.amount, None);
	}

	#[test]
	fn builds_invoice_request_with_features() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::unknown());
		assert_eq!(tlv_stream.features, Some(&InvoiceRequestFeatures::unknown()));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.features_unchecked(InvoiceRequestFeatures::empty())
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.invoice_request_features(), &InvoiceRequestFeatures::empty());
		assert_eq!(tlv_stream.features, None);
	}

	#[test]
	fn builds_invoice_request_with_quantity() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.quantity(), None);
		assert_eq!(tlv_stream.quantity, None);

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(2_000)
			.unwrap()
			.quantity(2)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnexpectedQuantity),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(10_000)
			.unwrap()
			.quantity(10)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(10_000));
		assert_eq!(tlv_stream.amount, Some(10_000));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(11_000)
			.unwrap()
			.quantity(11)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidQuantity),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.quantity(0)
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::InvalidQuantity),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(2_000)
			.unwrap()
			.quantity(2)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.amount_msats(), Some(2_000));
		assert_eq!(tlv_stream.amount, Some(2_000));

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingQuantity),
		}

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(one))
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::MissingQuantity),
		}
	}

	#[test]
	fn builds_invoice_request_with_payer_note() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.payer_note("bar".into())
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.payer_note(), Some(PrintableString("bar")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("bar")));

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.payer_note("bar".into())
			.payer_note("baz".into())
			.build_and_sign()
			.unwrap();
		let (_, _, tlv_stream, _, _, _) = invoice_request.as_tlv_stream();
		assert_eq!(invoice_request.payer_note(), Some(PrintableString("baz")));
		assert_eq!(tlv_stream.payer_note, Some(&String::from("baz")));
	}

	#[test]
	fn fails_responding_with_unknown_required_features() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		match OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.features_unchecked(InvoiceRequestFeatures::unknown())
			.build_and_sign()
			.unwrap()
			.respond_with_no_std(payment_paths(), payment_hash(), now())
		{
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12SemanticError::UnknownRequiredFeatures),
		}
	}

	#[test]
	fn parses_invoice_request_with_metadata() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}
	}

	#[test]
	fn parses_invoice_request_with_chain() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain(Network::Bitcoin)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain_unchecked(Network::Testnet)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnsupportedChain)
			),
		}
	}

	#[test]
	fn parses_invoice_request_with_amount() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(1000)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingAmount)
			),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats_unchecked(999)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InsufficientAmount)
			),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.description("foo".to_string())
			.amount(Amount::Currency {
				iso4217_code: CurrencyCode::new(*b"USD").unwrap(),
				amount: 1000,
			})
			.build_unchecked()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnsupportedCurrency)
				);
			},
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.quantity(u64::MAX)
			.unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidAmount)
			),
		}
	}

	#[test]
	fn parses_invoice_request_with_quantity() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let one = NonZeroU64::new(1).unwrap();
		let ten = NonZeroU64::new(10).unwrap();

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::One)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(2_000)
			.unwrap()
			.quantity_unchecked(2)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::UnexpectedQuantity)
				);
			},
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(10_000)
			.unwrap()
			.quantity(10)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(ten))
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(11_000)
			.unwrap()
			.quantity_unchecked(11)
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::InvalidQuantity)
			),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.amount_msats(2_000)
			.unwrap()
			.quantity(2)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		if let Err(e) = InvoiceRequest::try_from(buffer) {
			panic!("error parsing invoice_request: {:?}", e);
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingQuantity)
			),
		}

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.supported_quantity(Quantity::Bounded(one))
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked_and_sign();

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingQuantity)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_metadata() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.0.metadata = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerMetadata)
				);
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_payer_signing_pubkey() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.2.payer_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingPayerSigningPubkey)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_issuer_id() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let unsigned_invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked();
		let mut tlv_stream = unsigned_invoice_request.contents.as_tlv_stream();
		tlv_stream.1.issuer_id = None;

		let mut buffer = Vec::new();
		tlv_stream.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSemantics(
						Bolt12SemanticError::MissingIssuerSigningPubkey
					)
				);
			},
		}
	}

	#[test]
	fn fails_parsing_invoice_request_without_signature() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mut buffer = Vec::new();
		OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_unchecked()
			.contents
			.write(&mut buffer)
			.unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSemantics(Bolt12SemanticError::MissingSignature)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_with_invalid_signature() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let mut invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();
		let last_signature_byte = invoice_request.bytes.last_mut().unwrap();
		*last_signature_byte = last_signature_byte.wrapping_add(1);

		let mut buffer = Vec::new();
		invoice_request.write(&mut buffer).unwrap();

		match InvoiceRequest::try_from(buffer) {
			Ok(_) => panic!("expected error"),
			Err(e) => {
				assert_eq!(
					e,
					Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature)
				);
			},
		}
	}

	#[test]
	fn parses_invoice_request_with_unknown_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let payment_id = PaymentId([1; 32]);

		const UNKNOWN_ODD_TYPE: u64 = INVOICE_REQUEST_TYPES.end - 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice_request.bytes);

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request.clone()) {
			Ok(invoice_request) => assert_eq!(invoice_request.bytes, encoded_invoice_request),
			Err(e) => panic!("error parsing invoice_request: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = INVOICE_REQUEST_TYPES.end - 2;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.bytes.extend_from_slice(&unknown_bytes);
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_valid_tlv_stream_bytes(SIGNATURE_TAG, &unsigned_invoice_request.bytes);

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}
	}

	#[test]
	fn parses_invoice_request_with_experimental_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let payment_id = PaymentId([1; 32]);

		const UNKNOWN_ODD_TYPE: u64 = EXPERIMENTAL_INVOICE_REQUEST_TYPES.start + 1;
		assert!(UNKNOWN_ODD_TYPE % 2 == 1);

		let secp_ctx = Secp256k1::new();
		let keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_ODD_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice_request.bytes)
			.chain(TlvStream::new(&unsigned_invoice_request.experimental_bytes));
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let mut encoded_invoice_request = Vec::new();
		unsigned_invoice_request.write(&mut encoded_invoice_request).unwrap();

		match UnsignedInvoiceRequest::try_from(encoded_invoice_request) {
			Ok(reparsed) => {
				assert_eq!(reparsed.tagged_hash, unsigned_invoice_request.tagged_hash)
			},
			Err(e) => panic!("error parsing invoice_request: {:?}", e),
		}

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request.clone()) {
			Ok(invoice_request) => assert_eq!(invoice_request.bytes, encoded_invoice_request),
			Err(e) => panic!("error parsing invoice_request: {:?}", e),
		}

		const UNKNOWN_EVEN_TYPE: u64 = EXPERIMENTAL_INVOICE_REQUEST_TYPES.start;
		assert!(UNKNOWN_EVEN_TYPE % 2 == 0);

		let (mut unsigned_invoice_request, payer_keys, _) = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_without_checks();

		let mut unknown_bytes = Vec::new();
		BigSize(UNKNOWN_EVEN_TYPE).write(&mut unknown_bytes).unwrap();
		BigSize(32).write(&mut unknown_bytes).unwrap();
		[42u8; 32].write(&mut unknown_bytes).unwrap();

		unsigned_invoice_request.experimental_bytes.extend_from_slice(&unknown_bytes);

		let tlv_stream = TlvStream::new(&unsigned_invoice_request.bytes)
			.chain(TlvStream::new(&unsigned_invoice_request.experimental_bytes));
		unsigned_invoice_request.tagged_hash =
			TaggedHash::from_tlv_stream(SIGNATURE_TAG, tlv_stream);

		let keys = payer_keys.unwrap();
		let invoice_request = unsigned_invoice_request
			.sign(|message: &UnsignedInvoiceRequest| {
				Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
			})
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::UnknownRequiredFeature)),
		}

		let invoice_request = OfferBuilder::new(keys.public_key())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();

		BigSize(UNKNOWN_ODD_TYPE).write(&mut encoded_invoice_request).unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::InvalidSignature(secp256k1::Error::IncorrectSignature)
			),
		}
	}

	#[test]
	fn fails_parsing_invoice_request_with_out_of_range_tlv_records() {
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		let invoice_request = OfferBuilder::new(recipient_pubkey())
			.amount_msats(1000)
			.build()
			.unwrap()
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.build_and_sign()
			.unwrap();

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();
		BigSize(1002).write(&mut encoded_invoice_request).unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}

		let mut encoded_invoice_request = Vec::new();
		invoice_request.write(&mut encoded_invoice_request).unwrap();
		BigSize(EXPERIMENTAL_INVOICE_REQUEST_TYPES.end)
			.write(&mut encoded_invoice_request)
			.unwrap();
		BigSize(32).write(&mut encoded_invoice_request).unwrap();
		[42u8; 32].write(&mut encoded_invoice_request).unwrap();

		match InvoiceRequest::try_from(encoded_invoice_request) {
			Ok(_) => panic!("expected error"),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}

	#[test]
	fn copies_verified_invoice_request_fields() {
		let node_id = recipient_pubkey();
		let expanded_key = ExpandedKey::new([42; 32]);
		let entropy = FixedEntropy {};
		let nonce = Nonce::from_entropy_source(&entropy);
		let secp_ctx = Secp256k1::new();
		let payment_id = PaymentId([1; 32]);

		#[cfg(c_bindings)]
		use crate::offers::offer::OfferWithDerivedMetadataBuilder as OfferBuilder;
		let offer = OfferBuilder::deriving_signing_pubkey(node_id, &expanded_key, nonce, &secp_ctx)
			.chain(Network::Testnet)
			.amount_msats(1000)
			.supported_quantity(Quantity::Unbounded)
			.build()
			.unwrap();
		assert_eq!(offer.issuer_signing_pubkey(), Some(node_id));

		// UTF-8 payer note that we can't naively `.truncate(PAYER_NOTE_LIMIT)`
		// because it would split a multi-byte UTF-8 code point.
		let payer_note = "❤️".repeat(86);
		assert_eq!(payer_note.len(), PAYER_NOTE_LIMIT + 4);
		let expected_payer_note = "❤️".repeat(85);

		let invoice_request = offer
			.request_invoice(&expanded_key, nonce, &secp_ctx, payment_id)
			.unwrap()
			.chain(Network::Testnet)
			.unwrap()
			.quantity(1)
			.unwrap()
			.payer_note(payer_note)
			.build_and_sign()
			.unwrap();
		match invoice_request.verify_using_metadata(&expanded_key, &secp_ctx) {
			Ok(invoice_request) => {
				let fields = invoice_request.fields();
				assert_eq!(invoice_request.offer_id(), offer.id());
				assert_eq!(
					fields,
					PayerFields {
						payer_signing_pubkey: invoice_request.payer_signing_pubkey(),
						quantity: Some(1),
						payer_note_truncated: Some(UntrustedString(expected_payer_note)),
						human_readable_name: None,
						request_recurrence: None,
					}
				);

				let mut buffer = Vec::new();
				fields.write(&mut buffer).unwrap();

				let deserialized_fields: PayerFields =
					Readable::read(&mut buffer.as_slice()).unwrap();
				assert_eq!(deserialized_fields, fields);
			},
			Err(_) => panic!("unexpected error"),
		}
	}

	#[test]
	fn test_string_truncate_safe() {
		// We'll correctly truncate to the nearest UTF-8 code point boundary:
		// ❤      variation-selector
		// e29da4 efb88f
		let s = String::from("❤️");
		assert_eq!(s.len(), 6);
		assert_eq!(s, string_truncate_safe(s.clone(), 7));
		assert_eq!(s, string_truncate_safe(s.clone(), 6));
		assert_eq!("❤", string_truncate_safe(s.clone(), 5));
		assert_eq!("❤", string_truncate_safe(s.clone(), 4));
		assert_eq!("❤", string_truncate_safe(s.clone(), 3));
		assert_eq!("", string_truncate_safe(s.clone(), 2));
		assert_eq!("", string_truncate_safe(s.clone(), 1));
		assert_eq!("", string_truncate_safe(s.clone(), 0));

		// Every byte in an ASCII string is also a full UTF-8 code point.
		let s = String::from("my ASCII string!");
		for new_len in 0..(s.len() + 5) {
			if new_len >= s.len() {
				assert_eq!(s, string_truncate_safe(s.clone(), new_len));
			} else {
				assert_eq!(s[..new_len], string_truncate_safe(s.clone(), new_len));
			}
		}
	}
}
