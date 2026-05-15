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

/// A tolerance applied to an [`ExchangeRate`] when determining acceptable
/// conversion rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tolerance {
	/// A tolerance expressed as a percentage of the exchange rate.
	///
	/// For example, `Percentage(5)` represents a tolerance of ±5% relative
	/// to the exchange rate being evaluated.
	Percentage(u8),

	/// A tolerance expressed as an absolute exchange-rate deviation.
	///
	/// For example, `AbsoluteMsats(10)` permits a deviation of up to
	/// 10 millisatoshis per minor currency unit.
	AbsoluteMsats(u64),
}

/// An exchange rate together with acceptable lower and upper tolerances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeRateBound {
	/// The reference exchange rate.
	rate: ExchangeRate,

	/// The maximum tolerated deviation below the reference exchange rate.
	lower_tolerance: Tolerance,

	/// The maximum tolerated deviation above the reference exchange rate.
	upper_tolerance: Tolerance,
}

impl ExchangeRateBound {
	/// Constructs a new exchange rate bound from a reference rate and its
	/// tolerated lower and upper deviations.
	///
	/// The tolerances may be asymmetric. For example, a payer may be willing to
	/// accept a 1% worse exchange rate than quoted while only accepting a 0.1%
	/// better rate.
	///
	/// The tolerances can be expressed either as percentages of the exchange rate
	/// or as absolute exchange-rate deviations.
	///
	/// Returns `Err(())` if:
	/// - either percentage tolerance is greater than or equal to 100, or
	/// - the lower absolute tolerance would make the minimum exchange rate
	///   negative.
	pub fn new(
		rate: ExchangeRate, lower_tolerance: Tolerance, upper_tolerance: Tolerance,
	) -> Result<Self, ()> {
		for tolerance in [lower_tolerance, upper_tolerance] {
			if let Tolerance::Percentage(percent) = tolerance {
				if percent >= 100 {
					return Err(());
				}
			}
		}

		if let Tolerance::AbsoluteMsats(msats) = lower_tolerance {
			let lower_tolerance_msats =
				u128::from(msats).checked_mul(u128::from(rate.minor_units.get())).ok_or(())?;

			if lower_tolerance_msats > u128::from(rate.msats) {
				return Err(());
			}
		}

		Ok(Self { rate, lower_tolerance, upper_tolerance })
	}

	/// Converts this bound into the corresponding accepted exchange-rate range.
	///
	/// Returns `Err(())` if the calculation overflows.
	pub(crate) fn to_range(self) -> Result<ExchangeRange, ()> {
		let lower_tolerance_msats: u64 = match self.lower_tolerance {
			Tolerance::Percentage(percent) => u128::from(self.rate.msats)
				.checked_mul(u128::from(u64::from(percent)))
				.and_then(|v| v.checked_div(100))
				.and_then(|v| v.try_into().ok())
				.ok_or(())?,
			Tolerance::AbsoluteMsats(msats) => u128::from(msats)
				.checked_mul(u128::from(self.rate.minor_units.get()))
				.and_then(|v| v.try_into().ok())
				.ok_or(())?,
		};

		let upper_tolerance_msats: u64 = match self.upper_tolerance {
			Tolerance::Percentage(percent) => u128::from(self.rate.msats)
				.checked_mul(u128::from(u64::from(percent)))
				.and_then(|v| v.checked_div(100))
				.and_then(|v| v.try_into().ok())
				.ok_or(())?,
			Tolerance::AbsoluteMsats(msats) => u128::from(msats)
				.checked_mul(u128::from(self.rate.minor_units.get()))
				.and_then(|v| v.try_into().ok())
				.ok_or(())?,
		};

		let minimum_rate = ExchangeRate {
			msats: self.rate.msats.saturating_sub(lower_tolerance_msats),
			minor_units: self.rate.minor_units,
		};

		let maximum_rate = ExchangeRate {
			msats: self.rate.msats.checked_add(upper_tolerance_msats).ok_or(())?,
			minor_units: self.rate.minor_units,
		};

		Ok(ExchangeRange { minimum: minimum_rate, maximum: maximum_rate })
	}
}

/// A range of accepted exchange rates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExchangeRange {
	/// The minimum accepted exchange rate.
	pub(crate) minimum: ExchangeRate,

	/// The maximum accepted exchange rate.
	pub(crate) maximum: ExchangeRate,
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
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRateBound, ()>;
}

impl<T: CurrencyConversion + ?Sized, CC: Deref<Target = T>> CurrencyConversion for CC {
	fn conversion_range(&self, currency: CurrencyCode) -> Result<ExchangeRateBound, ()> {
		self.deref().conversion_range(currency)
	}
}

/// A [`CurrencyConversion`] implementation that does not support
/// any fiat currency conversions.
#[derive(Clone, Copy, Debug)]
pub struct NullCurrencyConversion;

impl CurrencyConversion for NullCurrencyConversion {
	fn conversion_range(&self, _currency: CurrencyCode) -> Result<ExchangeRateBound, ()> {
		Err(())
	}
}
