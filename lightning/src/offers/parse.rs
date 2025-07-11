// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Parsing and formatting for bech32 message encoding.

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::util::ser::CursorReadable;
use bech32::primitives::decode::CheckedHrpstringError;
use bitcoin::secp256k1;

#[allow(unused_imports)]
use crate::prelude::*;

#[cfg(not(fuzzing))]
pub(super) use sealed::Bech32Encode;

#[cfg(fuzzing)]
pub use sealed::Bech32Encode;

mod sealed {
	use super::Bolt12ParseError;
	use bech32::primitives::decode::CheckedHrpstring;
	use bech32::{encode_to_fmt, EncodeError, Hrp, NoChecksum};
	use core::fmt;

	#[allow(unused_imports)]
	use crate::prelude::*;

	/// Indicates a message can be encoded using bech32.
	pub trait Bech32Encode: AsRef<[u8]> + TryFrom<Vec<u8>, Error = Bolt12ParseError> {
		/// Human readable part of the message's bech32 encoding.
		const BECH32_HRP: &'static str;

		/// Parses a bech32-encoded message into a TLV stream.
		fn from_bech32_str(s: &str) -> Result<Self, Bolt12ParseError> {
			// Offer encoding may be split by '+' followed by optional whitespace.
			let encoded = match s.split('+').skip(1).next() {
				Some(_) => {
					for chunk in s.split('+') {
						let chunk = chunk.trim_start();
						if chunk.is_empty() || chunk.contains(char::is_whitespace) {
							return Err(Bolt12ParseError::InvalidContinuation);
						}
					}

					let s: String = s.chars().filter(|c| *c != '+' && !c.is_whitespace()).collect();
					Bech32String::Owned(s)
				},
				None => Bech32String::Borrowed(s),
			};

			let parsed = CheckedHrpstring::new::<NoChecksum>(encoded.as_ref())?;
			let hrp = parsed.hrp();
			// Compare the lowercase'd iter to allow for all-uppercase HRPs
			if hrp.lowercase_char_iter().ne(Self::BECH32_HRP.chars()) {
				return Err(Bolt12ParseError::InvalidBech32Hrp);
			}

			let data = parsed.byte_iter().collect::<Vec<u8>>();
			Self::try_from(data)
		}

		/// Formats the message using bech32-encoding.
		fn fmt_bech32_str(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
			encode_to_fmt::<NoChecksum, _>(f, Hrp::parse(Self::BECH32_HRP).unwrap(), self.as_ref())
				.map_err(|e| match e {
					EncodeError::Fmt(e) => e,
					_ => fmt::Error {},
				})
		}
	}

	// Used to avoid copying a bech32 string not containing the continuation character (+).
	enum Bech32String<'a> {
		Borrowed(&'a str),
		Owned(String),
	}

	impl<'a> AsRef<str> for Bech32String<'a> {
		fn as_ref(&self) -> &str {
			match self {
				Bech32String::Borrowed(s) => s,
				Bech32String::Owned(s) => s,
			}
		}
	}
}

/// A wrapper for reading a message as a TLV stream `T` from a byte sequence, while still
/// maintaining ownership of the bytes for later use.
pub(super) struct ParsedMessage<T: CursorReadable> {
	pub bytes: Vec<u8>,
	pub tlv_stream: T,
}

impl<T: CursorReadable> TryFrom<Vec<u8>> for ParsedMessage<T> {
	type Error = DecodeError;

	fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
		let mut cursor = io::Cursor::new(bytes);
		let tlv_stream: T = CursorReadable::read(&mut cursor)?;

		// Ensure that there are no more TLV records left to parse.
		if cursor.position() < cursor.get_ref().len() as u64 {
			return Err(DecodeError::InvalidValue);
		}

		let bytes = cursor.into_inner();
		Ok(Self { bytes, tlv_stream })
	}
}

/// Error when parsing a bech32 encoded message using [`str::parse`].
#[derive(Clone, Debug, PartialEq)]
pub enum Bolt12ParseError {
	/// The bech32 encoding does not conform to the BOLT 12 requirements for continuing messages
	/// across multiple parts (i.e., '+' followed by whitespace).
	InvalidContinuation,
	/// The bech32 encoding's human-readable part does not match what was expected for the message
	/// being parsed.
	InvalidBech32Hrp,
	/// The string could not be bech32 decoded.
	Bech32(CheckedHrpstringError),
	/// The bech32 decoded string could not be decoded as the expected message type.
	Decode(DecodeError),
	/// The parsed message has invalid semantics.
	InvalidSemantics(Bolt12SemanticError),
	/// The parsed message has an invalid signature.
	InvalidSignature(secp256k1::Error),
}

/// Error when interpreting a TLV stream as a specific type.
#[derive(Clone, Debug, PartialEq)]
pub enum Bolt12SemanticError {
	/// The current system time is past the offer or invoice's expiration.
	AlreadyExpired,
	/// The provided chain hash does not correspond to a supported chain.
	UnsupportedChain,
	/// A chain was provided but was not expected.
	UnexpectedChain,
	/// An amount was expected but was missing.
	MissingAmount,
	/// The amount exceeded the total bitcoin supply or didn't match an expected amount.
	InvalidAmount,
	/// The currency code did not contain valid ASCII uppercase letters.
	InvalidCurrencyCode,
	/// An amount was provided but was not sufficient in value.
	InsufficientAmount,
	/// An amount was provided but was not expected.
	UnexpectedAmount,
	/// A currency was provided that is not supported.
	UnsupportedCurrency,
	/// A feature was required but is unknown.
	UnknownRequiredFeatures,
	/// Features were provided but were not expected.
	UnexpectedFeatures,
	/// A required description was not provided.
	MissingDescription,
	/// An issuer's signing pubkey was not provided.
	MissingIssuerSigningPubkey,
	/// An issuer's signing pubkey was provided but was not expected.
	UnexpectedIssuerSigningPubkey,
	/// A quantity was expected but was missing.
	MissingQuantity,
	/// An unsupported quantity was provided.
	InvalidQuantity,
	/// A quantity or quantity bounds was provided but was not expected.
	UnexpectedQuantity,
	/// Metadata could not be used to verify the offers message.
	InvalidMetadata,
	/// Metadata was provided but was not expected.
	UnexpectedMetadata,
	/// Payer metadata was expected but was missing.
	MissingPayerMetadata,
	/// A payer signing pubkey was expected but was missing.
	MissingPayerSigningPubkey,
	/// The payment id for a refund or request is already in use.
	DuplicatePaymentId,
	/// Blinded paths were expected but were missing.
	MissingPaths,
	/// Blinded paths were provided but were not expected.
	UnexpectedPaths,
	/// The blinded payinfo given does not match the number of blinded path hops.
	InvalidPayInfo,
	/// An invoice creation time was expected but was missing.
	MissingCreationTime,
	/// An invoice payment hash was expected but was missing.
	MissingPaymentHash,
	/// An invoice payment hash was provided but was not expected.
	UnexpectedPaymentHash,
	/// A signing pubkey was not provided.
	MissingSigningPubkey,
	/// A signing pubkey was provided but a different one was expected.
	InvalidSigningPubkey,
	/// A signature was expected but was missing.
	MissingSignature,
	/// A Human Readable Name was provided but was not expected (i.e. was included in a
	/// [`Refund`]).
	///
	/// [`Refund`]: super::refund::Refund
	UnexpectedHumanReadableName,
}

impl From<CheckedHrpstringError> for Bolt12ParseError {
	fn from(error: CheckedHrpstringError) -> Self {
		Self::Bech32(error)
	}
}

impl From<DecodeError> for Bolt12ParseError {
	fn from(error: DecodeError) -> Self {
		Self::Decode(error)
	}
}

impl From<Bolt12SemanticError> for Bolt12ParseError {
	fn from(error: Bolt12SemanticError) -> Self {
		Self::InvalidSemantics(error)
	}
}

impl From<secp256k1::Error> for Bolt12ParseError {
	fn from(error: secp256k1::Error) -> Self {
		Self::InvalidSignature(error)
	}
}

#[cfg(test)]
mod bolt12_tests {
	use super::Bolt12ParseError;
	use crate::offers::offer::Offer;
	use bech32::primitives::decode::{CharError, CheckedHrpstringError, UncheckedHrpstringError};

	#[test]
	fn encodes_offer_as_bech32_without_checksum() {
		let encoded_offer = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
		let offer = dbg!(encoded_offer.parse::<Offer>().unwrap());
		let reencoded_offer = offer.to_string();
		dbg!(reencoded_offer.parse::<Offer>().unwrap());
		assert_eq!(reencoded_offer, encoded_offer);
	}

	#[test]
	fn parses_bech32_encoded_offers() {
		let offers = [
			// A complete string is valid
			"lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",

			// Uppercase is valid
			"LNO1PQPS7SJQPGTYZM3QV4UXZMTSD3JJQER9WD3HY6TSW35K7MSJZFPY7NZ5YQCNYGRFDEJ82UM5WF5K2UCKYYPWA3EYT44H6TXTXQUQH7LZ5DJGE4AFGFJN7K4RGRKUAG0JSD5XVXG",

			// + can join anywhere
			"l+no1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",

			// Multiple + can join
			"lno1pqps7sjqpgt+yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+5k7msjzfpy7nz5yqcn+ygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+5xvxg",

			// + can be followed by whitespace
			"lno1pqps7sjqpgt+ yzm3qv4uxzmtsd3jjqer9wd3hy6tsw3+  5k7msjzfpy7nz5yqcn+\nygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd+\r\n 5xvxg",
		];
		for encoded_offer in &offers {
			if let Err(e) = encoded_offer.parse::<Offer>() {
				panic!("Invalid offer ({:?}): {}", e, encoded_offer);
			}
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offers_with_invalid_continuations() {
		let offers = [
			// + must be surrounded by bech32 characters
			"lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg+",
			"lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg+ ",
			"+lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",
			"+ lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",
			"ln++o1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg",
		];
		for encoded_offer in &offers {
			match encoded_offer.parse::<Offer>() {
				Ok(_) => panic!("Valid offer: {}", encoded_offer),
				Err(e) => assert_eq!(e, Bolt12ParseError::InvalidContinuation),
			}
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offers_with_mixed_casing() {
		// We assert that mixed-case encoding fails to parse.
		let mixed_case_offer = "LnO1PqPs7sJqPgTyZm3qV4UxZmTsD3JjQeR9Wd3hY6TsW35k7mSjZfPy7nZ5YqCnYgRfDeJ82uM5Wf5k2uCkYyPwA3EyT44h6tXtXqUqH7Lz5dJgE4AfGfJn7k4rGrKuAg0jSd5xVxG";
		match mixed_case_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", mixed_case_offer),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::Bech32(CheckedHrpstringError::Parse(
					UncheckedHrpstringError::Char(CharError::MixedCase)
				))
			),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::Bolt12ParseError;
	use crate::ln::msgs::DecodeError;
	use crate::offers::offer::Offer;
	use bech32::primitives::decode::{CharError, CheckedHrpstringError, UncheckedHrpstringError};

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_hrp() {
		let encoded_offer = "lni1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxg";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, Bolt12ParseError::InvalidBech32Hrp),
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_bech32_data() {
		let encoded_offer = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxo";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(
				e,
				Bolt12ParseError::Bech32(CheckedHrpstringError::Parse(
					UncheckedHrpstringError::Char(CharError::InvalidChar('o'))
				))
			),
		}
	}

	#[test]
	fn fails_parsing_bech32_encoded_offer_with_invalid_tlv_data() {
		let encoded_offer = "lno1pqps7sjqpgtyzm3qv4uxzmtsd3jjqer9wd3hy6tsw35k7msjzfpy7nz5yqcnygrfdej82um5wf5k2uckyypwa3eyt44h6txtxquqh7lz5djge4afgfjn7k4rgrkuag0jsd5xvxgqqqqq";
		match encoded_offer.parse::<Offer>() {
			Ok(_) => panic!("Valid offer: {}", encoded_offer),
			Err(e) => assert_eq!(e, Bolt12ParseError::Decode(DecodeError::InvalidValue)),
		}
	}
}
