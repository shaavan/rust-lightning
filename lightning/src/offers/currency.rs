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
use core::ops::Deref;

/// A trait for converting fiat currencies into millisatoshis (msats).
///
/// Implementations must return the conversion rate in **msats per minor unit**
/// of the currency. For example:
///
/// USD (exponent 2) → per **cent** (0.01 USD), not per dollar.
///
/// The returned tolerance percent is the acceptable variance around the resolved
/// msat amount derived from that conversion factor. For example, returning
/// `(_, 5)` means callers may derive a 5% tolerance window from the same lookup
/// they used to resolve the fiat amount into msats.
pub trait CurrencyConversion {
	/// Returns the conversion rate in **msats per minor unit** for the given
	/// ISO-4217 currency code together with the acceptable tolerance, expressed
	/// as a percentage of the resolved msat amount, used when deriving conversion
	/// ranges.
	fn msats_per_minor_unit(&self, iso4217_code: CurrencyCode) -> Result<(f64, u8), ()>;
}

impl<T: CurrencyConversion + ?Sized, CC: Deref<Target = T>> CurrencyConversion for CC {
	fn msats_per_minor_unit(&self, iso4217_code: CurrencyCode) -> Result<(f64, u8), ()> {
		self.deref().msats_per_minor_unit(iso4217_code)
	}
}

/// A [`CurrencyConversion`] implementation that does not support
/// any fiat currency conversions.
pub struct DefaultCurrencyConversion;

impl CurrencyConversion for DefaultCurrencyConversion {
	fn msats_per_minor_unit(&self, _iso4217_code: CurrencyCode) -> Result<(f64, u8), ()> {
		Err(())
	}
}
