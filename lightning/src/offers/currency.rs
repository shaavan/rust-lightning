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

/// Number of basis points representing 100% of a value.
///
/// One basis point is 0.01%, so 100 basis points represents 1% and 10,000
/// basis points represents 100%. A proportional tolerance is calculated as:
///
/// `tolerance = value * basis_points / BASIS_POINTS_DENOMINATOR`
const BASIS_POINTS_DENOMINATOR: u16 = 10_000;

/// Builds an exchange rate from large intermediate numbers and reduces the
/// fraction, e.g. `19800 / 10000` becomes `99 / 50`.
///
/// Reducing keeps precise fractional rates while avoiding overflow when the
/// rate is later multiplied by a currency amount.
fn reduced_exchange_rate_from_parts(msats: u128, minor_units: u128) -> Result<ExchangeRate, ()> {
	fn gcd(mut a: u128, mut b: u128) -> u128 {
		while b != 0 {
			let remainder = a % b;
			a = b;
			b = remainder;
		}
		a
	}

	let gcd = gcd(msats, minor_units);
	let msats = msats.checked_div(gcd).and_then(|msats| msats.try_into().ok()).ok_or(())?;
	let minor_units = minor_units
		.checked_div(gcd)
		.and_then(|minor_units| minor_units.try_into().ok())
		.and_then(NonZeroU64::new)
		.ok_or(())?;
	Ok(ExchangeRate { msats, minor_units })
}

/// Applies a percentage-like basis-points multiplier while preserving fractional
/// msats, e.g. 99% of 2 msats becomes `19800 / 10000`, not 1 msat.
///
/// For example, if 1,000 units cost 2,000 msats, a 1% lower bound should be
/// 1,980 msats. Rounding first would lose the 20-msat tolerance.
fn exchange_rate_from_basis_points_multiplier(
	rate: ExchangeRate, multiplier: u32,
) -> Result<ExchangeRate, ()> {
	reduced_exchange_rate_from_parts(
		u128::from(rate.msats).checked_mul(u128::from(multiplier)).ok_or(())?,
		u128::from(rate.minor_units.get())
			.checked_mul(u128::from(BASIS_POINTS_DENOMINATOR))
			.ok_or(())?,
	)
}

/// An exchange rate represented as `msats / minor_units`.
///
/// Most exchange rates should be constructed with [`ExchangeRate::new`], which
/// represents a whole number of millisatoshis per one minor currency unit.
/// [`ExchangeRate::from_parts`] is available for rates that require fractional
/// precision.
///
/// ## Minor Units
///
/// Minor units are the smallest unit of an ISO 4217 currency.
///
/// For example:
/// - USD (exponent 2) uses cents (0.01 USD)
/// - JPY (exponent 0) uses yen
///
/// ## Fractional Precision
///
/// For example,
///
/// ExchangeRate::from_parts(123, NonZeroU64::new(1_000_000).unwrap())
///
/// represents `123 millisatoshis per 1,000,000 minor currency units`.
#[derive(Clone, Copy, Debug)]
pub struct ExchangeRate {
	msats: u64,
	minor_units: NonZeroU64,
}

impl ExchangeRate {
	/// Creates a new exchange rate in millisatoshis per one minor currency unit.
	pub fn new(msats_per_minor_unit: u64) -> Self {
		Self { msats: msats_per_minor_unit, minor_units: NonZeroU64::MIN }
	}

	/// Creates a new exchange rate represented as `msats / minor_units`.
	///
	/// This should only be used when the exchange rate cannot be represented as a
	/// whole number of millisatoshis per one minor currency unit.
	pub fn from_parts(msats: u64, minor_units: NonZeroU64) -> Self {
		Self { msats, minor_units }
	}

	/// The millisatoshi numerator of the exchange-rate ratio.
	pub fn msats(&self) -> u64 {
		self.msats
	}

	/// The fiat minor-unit denominator of the exchange-rate ratio.
	pub fn minor_units(&self) -> NonZeroU64 {
		self.minor_units
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
	/// A tolerance expressed in basis points relative to the exchange rate.
	///
	/// One basis point is equal to 0.01%.
	///
	/// For example, `BasisPoints(100)` represents a tolerance of 1%.
	BasisPoints(u16),

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
	/// The tolerances may be asymmetric. For example, a caller may accept an
	/// exchange rate up to 1% below the reference rate while only accepting an
	/// exchange rate up to 0.1% above it.
	///
	/// The tolerances can be expressed either in basis points relative to the
	/// exchange rate or as absolute exchange-rate deviations.
	///
	/// Lower tolerances must keep the minimum accepted exchange rate positive.
	/// Upper tolerances greater than or equal to 100% are permitted, provided the
	/// resulting maximum exchange rate can be represented without overflow.
	///
	/// Returns `Err(())` if:
	/// - the lower basis-points tolerance is greater than or equal to 100%,
	/// - the lower absolute tolerance would make the minimum exchange rate
	///   zero or negative, or
	/// - computing either tolerance bound would overflow.
	pub fn new(
		rate: ExchangeRate, lower_tolerance: Tolerance, upper_tolerance: Tolerance,
	) -> Result<Self, ()> {
		let bound = Self { rate, lower_tolerance, upper_tolerance };
		ExchangeRange::from_exchange_rate_bound(bound)?;
		Ok(bound)
	}

	/// Converts this bound into the corresponding accepted exchange-rate range.
	pub(crate) fn to_range(self) -> ExchangeRange {
		ExchangeRange::from_exchange_rate_bound(self)
			.expect("exchange-rate bound is checked during construction")
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

impl ExchangeRange {
	fn from_exchange_rate_bound(bound: ExchangeRateBound) -> Result<Self, ()> {
		let minimum_rate = match bound.lower_tolerance {
			Tolerance::BasisPoints(bps) => {
				if bps >= BASIS_POINTS_DENOMINATOR {
					return Err(());
				}

				exchange_rate_from_basis_points_multiplier(
					bound.rate,
					u32::from(BASIS_POINTS_DENOMINATOR - bps),
				)?
			},
			Tolerance::AbsoluteMsats(msats_per_minor_unit) => u128::from(msats_per_minor_unit)
				.checked_mul(u128::from(bound.rate.minor_units.get()))
				.and_then(|lower_tolerance_msats| {
					bound.rate.msats.checked_sub(lower_tolerance_msats.try_into().ok()?)
				})
				.map(|msats| ExchangeRate { msats, minor_units: bound.rate.minor_units })
				.ok_or(())?,
		};

		// Ensure the minimum accepted rate remains positive. Otherwise the lower
		// bound becomes zero, causing underpayment checks to accept any amount.
		if minimum_rate.msats == 0 {
			return Err(());
		}

		// Ensure the maximum exchange rate can be represented.
		//
		// ExchangeRate stores the rate as `msats / minor_units`, with `msats` as the
		// numerator. Validate that applying the upper tolerance does not overflow the
		// resulting numerator.
		let maximum_rate = match bound.upper_tolerance {
			Tolerance::BasisPoints(bps) => exchange_rate_from_basis_points_multiplier(
				bound.rate,
				u32::from(BASIS_POINTS_DENOMINATOR) + u32::from(bps),
			)?,
			Tolerance::AbsoluteMsats(msats_per_minor_unit) => u128::from(msats_per_minor_unit)
				.checked_mul(u128::from(bound.rate.minor_units.get()))
				.and_then(|upper_tolerance_msats| {
					bound.rate.msats.checked_add(upper_tolerance_msats.try_into().ok()?)
				})
				.map(|msats| ExchangeRate { msats, minor_units: bound.rate.minor_units })
				.ok_or(())?,
		};

		Ok(Self { minimum: minimum_rate, maximum: maximum_rate })
	}
}

/// A trait for retrieving fiat-to-bitcoin conversion ranges.
///
/// The returned range defines the minimum and maximum accepted exchange
/// rates for converting fiat minor units into millisatoshis.
///
/// This is a synchronous interface and may be called while LDK internal
/// locks are held. Implementations must return promptly using cached
/// exchange-rate data. They must not block, perform network or disk I/O,
/// or call back into LDK while this method is executing, as doing so
/// may cause deadlocks.
///
/// # Cached rate freshness
///
/// Implementations are responsible for maintaining fresh cached rates,
/// including defining a maximum acceptable age and refreshing them
/// independently of this method.
///
/// LDK does not receive rate timestamps or enforce freshness. Returning a
/// conversion range authorizes LDK to use it for amount validation, so stale
/// rates may cause amounts outside the intended tolerances to be accepted.
///
/// Once a cached rate exceeds the acceptable age, implementations must return
/// `Err(())` rather than risk incorrect amount validation. This temporarily
/// prevents operations requiring conversion until acceptable rates are available.
///
/// Exchange rates are represented as:
///
/// `msats / minor_units`
pub trait CurrencyConversion {
	/// Returns the cached conversion range for the given currency.
	///
	/// Returns `Err(())` if the currency is unsupported or no acceptable cached
	/// rate is available, including when the cached rate is too old to trust.
	///
	/// # Conversion failures
	///
	/// Temporary unavailability and unsupported currencies are treated alike:
	/// conversions return [`Bolt12SemanticError::UnsupportedCurrency`].
	/// Operations requiring currency conversion will fail until this method
	/// successfully returns a conversion range.
	///
	/// [`Bolt12SemanticError::UnsupportedCurrency`]: crate::offers::parse::Bolt12SemanticError::UnsupportedCurrency
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

#[cfg(test)]
mod tests {
	use crate::offers::currency::{ExchangeRate, ExchangeRateBound, Tolerance};
	use core::num::NonZeroU64;

	#[test]
	fn creates_fractional_basis_points_exchange_rate_range() {
		// Basis-point tolerances preserve fractional msats instead of truncating
		// the per-unit tolerance before the rate is applied to a currency amount.
		let rate = ExchangeRate::from_parts(101, NonZeroU64::new(4).unwrap());
		let bound =
			ExchangeRateBound::new(rate, Tolerance::BasisPoints(100), Tolerance::BasisPoints(200))
				.unwrap();

		let range = bound.to_range();
		assert_eq!(range.minimum.msats(), 9999);
		assert_eq!(range.minimum.minor_units(), NonZeroU64::new(400).unwrap());
		assert_eq!(range.maximum.msats(), 5151);
		assert_eq!(range.maximum.minor_units(), NonZeroU64::new(200).unwrap());
		assert!(range.minimum < rate);
		assert!(rate < range.maximum);
	}

	#[test]
	fn creates_sub_msat_basis_points_exchange_rate_range() {
		// At 2 msats per unit, a 1% tolerance is less than one msat per unit. Keep
		// it as 99 / 50 so a 1,000-unit amount can still use a 1,980-msat lower
		// bound instead of requiring the full 2,000 msats.
		let rate = ExchangeRate::new(2);
		let bound =
			ExchangeRateBound::new(rate, Tolerance::BasisPoints(100), Tolerance::BasisPoints(100))
				.unwrap();

		let range = bound.to_range();
		assert_eq!(range.minimum.msats(), 99);
		assert_eq!(range.minimum.minor_units(), NonZeroU64::new(50).unwrap());
		assert_eq!(range.maximum.msats(), 101);
		assert_eq!(range.maximum.minor_units(), NonZeroU64::new(50).unwrap());
	}

	#[test]
	fn creates_absolute_exchange_rate_range() {
		// Absolute tolerances are expressed per minor unit. For fractional rates,
		// they must be scaled by the exchange-rate denominator before being
		// applied to the numerator.
		let rate = ExchangeRate::from_parts(1000, NonZeroU64::new(4).unwrap());
		let bound =
			ExchangeRateBound::new(rate, Tolerance::AbsoluteMsats(3), Tolerance::AbsoluteMsats(5))
				.unwrap();

		let range = bound.to_range();
		assert_eq!(range.minimum.msats(), 988);
		assert_eq!(range.minimum.minor_units(), NonZeroU64::new(4).unwrap());
		assert_eq!(range.maximum.msats(), 1020);
		assert_eq!(range.maximum.minor_units(), NonZeroU64::new(4).unwrap());
	}

	#[test]
	fn rejects_invalid_exchange_rate_ranges() {
		// A lower basis-points tolerance of 100% or more is rejected so the
		// minimum accepted exchange rate cannot become zero or negative.
		assert!(ExchangeRateBound::new(
			ExchangeRate::new(1000),
			Tolerance::BasisPoints(10_000),
			Tolerance::BasisPoints(0),
		)
		.is_err());

		// Absolute lower tolerances must also be rejected when they exactly cancel the
		// reference rate, otherwise the minimum accepted exchange rate becomes zero.
		assert!(ExchangeRateBound::new(
			ExchangeRate::new(1000),
			Tolerance::AbsoluteMsats(1000),
			Tolerance::BasisPoints(0),
		)
		.is_err());

		// Absolute lower tolerances are scaled by the denominator before being
		// subtracted from the numerator, and must not underflow the reference rate.
		assert!(ExchangeRateBound::new(
			ExchangeRate::from_parts(5, NonZeroU64::new(2).unwrap()),
			Tolerance::AbsoluteMsats(3),
			Tolerance::BasisPoints(0),
		)
		.is_err());

		// Basis-point upper tolerances must not overflow the resulting numerator.
		assert!(ExchangeRateBound::new(
			ExchangeRate::new(u64::MAX),
			Tolerance::BasisPoints(0),
			Tolerance::BasisPoints(1),
		)
		.is_err());

		// Absolute upper tolerances are also scaled by the denominator and must
		// leave the resulting numerator representable as a u64.
		assert!(ExchangeRateBound::new(
			ExchangeRate::from_parts(u64::MAX - 1, NonZeroU64::new(2).unwrap()),
			Tolerance::BasisPoints(0),
			Tolerance::AbsoluteMsats(1),
		)
		.is_err());
	}
}
