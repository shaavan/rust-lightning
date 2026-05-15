// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for currency conversion support.

use crate::offers::offer::CurrencyCode;
#[allow(unused_imports)]
use crate::prelude::*;

use core::cmp::Ordering;
use core::num::NonZeroU64;
use core::ops::Deref;

/// An exchange rate represented as `msats / minor_units`.
///
/// For example:
///
/// `ExchangeRate { msats: 123, minor_units: 1_000_000 }`
///
/// represents `123 millisatoshis per 1,000,000 minor currency units`.
///
/// Minor units are the smallest unit of an ISO 4217 currency.
///
/// For example:
/// - USD (exponent 2) uses cents (0.01 USD)
/// - JPY (exponent 0) uses yen
#[derive(Clone, Copy, Debug)]
pub struct ExchangeRate {
	/// The millisatoshi numerator of the exchange-rate ratio.
	pub msats: u64,

	/// The fiat minor-unit denominator of the exchange-rate ratio.
	pub minor_units: NonZeroU64,
}

impl ExchangeRate {
	/// Creates a new exchange rate represented as `msats / minor_units`.
	///
	/// Returns an error if `minor_units` is zero.
	pub fn new(msats: u64, minor_units: u64) -> Result<Self, ()> {
		Ok(Self { msats, minor_units: NonZeroU64::new(minor_units).ok_or(())? })
	}

	/// Converts the given fiat minor-unit amount to millisatoshis using this
	/// exchange rate.
	///
	/// The conversion is calculated as:
	///
	/// `fiat_minor_units * self.msats / self.minor_units`
	///
	/// Returns an error if the calculation overflows.
	pub(crate) fn convert_to_msats(&self, fiat_minor_units: u64) -> Result<u64, ()> {
		u128::from(fiat_minor_units)
			.checked_mul(u128::from(self.msats))
			.and_then(|amount| amount.checked_div(u128::from(self.minor_units.get())))
			.and_then(|amount| amount.try_into().ok())
			.ok_or(())
	}
}

impl PartialEq for ExchangeRate {
	fn eq(&self, other: &Self) -> bool {
		self.cmp(other) == Ordering::Equal
	}
}

impl Eq for ExchangeRate {}

impl PartialOrd for ExchangeRate {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for ExchangeRate {
	fn cmp(&self, other: &Self) -> Ordering {
		let lhs = u128::from(self.msats) * u128::from(other.minor_units.get());
		let rhs = u128::from(other.msats) * u128::from(self.minor_units.get());

		lhs.cmp(&rhs)
	}
}

/// A range of accepted exchange rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeRange {
	/// The minimum accepted exchange rate.
	minimum: ExchangeRate,

	/// The maximum accepted exchange rate.
	maximum: ExchangeRate,
}

impl ExchangeRange {
	/// Constructs a new range of accepted exchange rates.
	///
	/// Returns `Err(())` if `minimum` exceeds `maximum`.
	pub fn new(minimum: ExchangeRate, maximum: ExchangeRate) -> Result<Self, ()> {
		if minimum > maximum {
			return Err(());
		}

		Ok(Self { minimum, maximum })
	}

	/// Constructs a symmetric range around `exchange_rate` using `tolerance_percent`.
	///
	/// A tolerance of `5` accepts exchange rates in the range `[95%, 105%]`.
	///
	/// Returns `Err(())` if `tolerance_percent` is greater than or equal to 100,
	/// or if the calculation overflows.
	pub fn from_tolerance(
		exchange_rate: ExchangeRate, tolerance_percent: u8
	) -> Result<Self, ()> {
		if tolerance_percent >= 100 {
			return Err(());
		}

		let tolerance = u64::from(tolerance_percent);

		let minimum_msats = u128::from(exchange_rate.msats)
			.checked_mul(u128::from(100 - tolerance))
			.and_then(|v| v.checked_div(100))
			.and_then(|v| v.try_into().ok())
			.ok_or(())?;

		let maximum_msats = u128::from(exchange_rate.msats)
			.checked_mul(u128::from(100 + tolerance))
			.and_then(|v| v.checked_div(100))
			.and_then(|v| v.try_into().ok())
			.ok_or(())?;

		Self::new(
			ExchangeRate::new(minimum_msats, exchange_rate.minor_units.get())?,
			ExchangeRate::new(maximum_msats, exchange_rate.minor_units.get())?,
		)
	}

	/// Returns the minimum accepted exchange rate.
	pub fn minimum(&self) -> ExchangeRate {
		self.minimum
	}

	/// Returns the maximum accepted exchange rate.
	pub fn maximum(&self) -> ExchangeRate {
		self.maximum
	}
}

/// A trait for retrieving fiat-to-bitcoin conversion ranges.
///
/// The returned range defines the minimum and maximum accepted exchange
/// rates for converting fiat minor units into millisatoshis.
///
/// Exchange rates are represented as:
///
/// `msats / minor_units`
pub trait CurrencyConversion {
	/// Returns the accepted conversion range for the given currency.
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRange, ()>;
}

impl<T: CurrencyConversion + ?Sized, CC: Deref<Target = T>> CurrencyConversion for CC {
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRange, ()> {
		self.deref().conversion_range(currency)
	}
}

/// A [`CurrencyConversion`] implementation that does not support
/// any fiat currency conversions.
#[derive(Clone, Copy, Debug)]
pub struct NullCurrencyConversion;

impl CurrencyConversion for NullCurrencyConversion {
	fn conversion_range(&self, _currency: CurrencyCode) -> Result<ExchangeRange, ()> {
		Err(())
	}
}
