// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Recurrence schedules, request fields, payment windows, and validation for offers.

use crate::io;
use crate::ln::msgs::DecodeError;
use crate::offers::parse::Bolt12SemanticError;
use crate::prelude::Vec;
use crate::util::ser::{HighZeroBytesDroppedBigSize, Readable, Writeable, Writer};
use core::num::NonZeroU32;

/// The length and time unit of a recurrence period.
///
/// The full duration of a recurrence period combines its time unit with a nonzero count.
///
/// For example, [`Self::Days`] with a count of 7 represents a recurrence every seven days.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Period {
	/// A recurrence period measured in whole seconds.
	Seconds(NonZeroU32),
	/// A recurrence period measured in whole days.
	Days(NonZeroU32),
	/// A recurrence period measured in whole calendar months.
	Months(NonZeroU32),
}

impl Period {
	/// A day has 24 hours of 60 minutes of 60 seconds; Unix time does not count leap seconds.
	const SECONDS_PER_DAY: u64 = 86_400;

	/// Returns the start of the recurrence period at zero-based `period_count`.
	///
	/// `basetime` anchors period zero. Day and month periods preserve the time of day. Month
	/// periods clamp the original day of the month to the last day in the target month when needed.
	/// Returns an error on arithmetic overflow.
	pub fn start_time(self, basetime: u64, period_count: u32) -> Result<u64, ()> {
		match self {
			Period::Seconds(seconds) => {
				let offset = u64::from(seconds.get()).checked_mul(period_count.into()).ok_or(())?;
				basetime.checked_add(offset).ok_or(())
			},

			Period::Days(days) => {
				let days_since_epoch = basetime / Self::SECONDS_PER_DAY;
				let seconds = basetime % Self::SECONDS_PER_DAY;

				let offset_days =
					u64::from(days.get()).checked_mul(period_count.into()).ok_or(())?;
				let start_day = days_since_epoch.checked_add(offset_days).ok_or(())?;

				start_day
					.checked_mul(Self::SECONDS_PER_DAY)
					.and_then(|day_seconds| day_seconds.checked_add(seconds))
					.ok_or(())
			},

			Period::Months(months) => {
				let days_since_epoch = basetime / Self::SECONDS_PER_DAY;
				let seconds = basetime % Self::SECONDS_PER_DAY;

				let (year, month, day) = civil_from_days(days_since_epoch as i128);

				let offset_months =
					i128::from(months.get()).checked_mul(period_count.into()).ok_or(())?;

				let total_months = year
					.checked_mul(12)
					.and_then(|year_in_months| year_in_months.checked_add(month as i128 - 1))
					.and_then(|base_month| base_month.checked_add(offset_months))
					.ok_or(())?;

				let target_year = total_months.div_euclid(12);
				let target_month = total_months.rem_euclid(12) + 1;
				let target_day = day.min(days_in_month(target_year, target_month as u64));

				let start_day = days_from_civil(target_year, target_month as u64, target_day);

				u64::try_from(start_day)
					.ok()
					.and_then(|start_day| start_day.checked_mul(Self::SECONDS_PER_DAY))
					.and_then(|day_seconds| day_seconds.checked_add(seconds))
					.ok_or(())
			},
		}
	}
}

/// Returns whether a Gregorian year has a leap day.
///
/// Century years are leap years only when divisible by 400, keeping each 400-year cycle regular.
fn is_leap_year(year: i128) -> bool {
	(year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Returns the number of days in a Gregorian month, accounting for leap years in February.
///
/// Panics if `month` is outside `1..=12`.
fn days_in_month(year: i128, month: u64) -> u64 {
	match month {
		1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
		4 | 6 | 9 | 11 => 30,
		2 if is_leap_year(year) => 29,
		2 => 28,
		_ => panic!("invalid month"),
	}
}

/// Converts a Gregorian date to a signed day offset from January 1, 1970.
///
/// Panics if the month or day is invalid. March is treated as the first month of the year so
/// February's leap day falls at the end, allowing the same month calculation in every year.
fn days_from_civil(year: i128, month: u64, day: u64) -> i128 {
	assert!((1..=12).contains(&month));
	assert!((1..=days_in_month(year, month)).contains(&day));

	let mut y = year;
	let m = month as i128;
	let d = day as i128;

	if m <= 2 {
		y -= 1;
	}

	// Gregorian leap-year rules repeat every 400 years. Euclidean division also handles
	// years before the start of the cycle consistently.
	let era = y.div_euclid(400);
	let yoe = y - era * 400;
	let mp = m + if m > 2 { -3 } else { 9 };
	// This formula gives each month's starting day in the March-based year: the month
	// lengths follow a five-month pattern totaling 153 days, with February last.
	let doy = (153 * mp + 2) / 5 + d - 1;
	let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

	// Each 400-year cycle has 146,097 days. The offset of 719,468 days places day zero
	// at the Unix epoch rather than March 1 of year zero.
	era * 146_097 + doe - 719_468
}

/// Converts a signed day offset from January 1, 1970 to a Gregorian `(year, month, day)`.
///
/// Uses March-based years and 400-year cycles to account for leap days without iterating over
/// individual years or months. The returned month and day are one-based.
fn civil_from_days(days: i128) -> (i128, u64, u64) {
	// Shift the Unix epoch to March 1 of year zero, then split into 146,097-day cycles.
	let z = days + 719_468;
	let era = z.div_euclid(146_097);
	let doe = z - era * 146_097;
	// Correct the year estimate for four-year leap days, skipped century leap days,
	// and the final leap day of the 400-year cycle.
	let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
	let mut year = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	// Invert the March-based month calculation, then restore January-based numbering.
	let mp = (5 * doy + 2) / 153;
	let day = doy - (153 * mp + 2) / 5 + 1;
	let month = mp + if mp < 10 { 3 } else { -9 };

	if month <= 2 {
		year += 1;
	}

	(year, month as u64, day as u64)
}

impl Writeable for Period {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let (tag, period) = match self {
			Period::Seconds(p) => (0u8, p),
			Period::Days(p) => (1u8, p),
			Period::Months(p) => (2u8, p),
		};

		tag.write(writer)?;
		HighZeroBytesDroppedBigSize(period.get()).write(writer)
	}
}

impl Readable for Period {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let time_unit_byte: u8 = Readable::read(r)?;
		let period: HighZeroBytesDroppedBigSize<u32> = Readable::read(r)?;

		let period = NonZeroU32::new(period.0).ok_or(DecodeError::InvalidValue)?;

		match time_unit_byte {
			0 => Ok(Self::Seconds(period)),
			1 => Ok(Self::Days(period)),
			2 => Ok(Self::Months(period)),
			_ => Err(DecodeError::InvalidValue),
		}
	}
}

/// Whether a payer must support recurrence to pay an offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
	/// Payers without recurrence support may still attempt a single payment.
	Optional,
	/// Payers must understand and follow the recurrence schedule.
	Compulsory,
}

// Requirement is persisted in payment contexts independently of the offer's wire TLVs.
impl_ser_tlv_based_enum!(Requirement,
	(0, Optional) => {},
	(1, Compulsory) => {},
);

/// How the start of recurrence period zero is determined.
///
/// Serialization reads and writes only the payload of a `recurrence_base` TLV, without an enum
/// discriminant. Only [`Self::Fixed`] has such a payload; writing [`Self::FirstInvoice`] returns an
/// error. Offers represent [`Self::FirstInvoice`] by omitting the TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
	/// Period zero starts at the first invoice's `invoice_created_at` timestamp.
	FirstInvoice,
	/// Period zero starts at an explicit timestamp. Only permitted for compulsory recurrence.
	Fixed {
		/// The start of period zero, in seconds since the Unix epoch.
		basetime: u64,
		/// Whether the initial invoice's price is proportional to the time remaining in its period.
		///
		/// Requires an offer amount. For example, joining three days into a 30-day period
		/// reduces the initial price by approximately 10%. Later periods use the full price.
		proportional: bool,
	},
}

// Only fixed anchors have a recurrence_base TLV. FirstInvoice is represented by its absence.
impl Writeable for Anchor {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Fixed { basetime, proportional } => {
				(*proportional as u8).write(writer)?;
				HighZeroBytesDroppedBigSize(*basetime).write(writer)
			},
			Self::FirstInvoice => Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"first-invoice anchors have no recurrence_base TLV",
			)),
		}
	}
}

impl Readable for Anchor {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let proportional_byte: u8 = Readable::read(r)?;
		let proportional = match proportional_byte {
			0 => false,
			1 => true,
			_ => return Err(DecodeError::InvalidValue),
		};
		let basetime: HighZeroBytesDroppedBigSize<u64> = Readable::read(r)?;
		Ok(Self::Fixed { basetime: basetime.0, proportional })
	}
}

/// The window around a recurrence period's start in which payment SHOULD be accepted.
///
/// Serialization reads and writes only the payload of a `recurrence_paywindow` TLV, without an
/// enum discriminant. Only [`Self::Custom`] has such a payload; writing [`Self::Default`] returns an
/// error. Offers represent [`Self::Default`] by omitting the TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Paywindow {
	/// The entire previous and current periods. Period zero opens at its own start.
	///
	/// This is used when the offer has no explicit paywindow.
	Default,
	/// An explicit window relative to the start of the period being paid for.
	Custom {
		/// Seconds before the period starts in which payment SHOULD be accepted.
		seconds_before: u32,
		/// Seconds after the period starts in which payment SHOULD be accepted.
		seconds_after: u32,
	},
}

// Only custom windows have a recurrence_paywindow TLV. Default is represented by its absence.
impl Writeable for Paywindow {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Custom { seconds_before, seconds_after } => {
				seconds_before.write(writer)?;
				HighZeroBytesDroppedBigSize(*seconds_after).write(writer)
			},
			Self::Default => Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"default paywindows have no recurrence_paywindow TLV",
			)),
		}
	}
}

impl Readable for Paywindow {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let seconds_before = Readable::read(r)?;
		let seconds_after: HighZeroBytesDroppedBigSize<u32> = Readable::read(r)?;
		Ok(Self::Custom { seconds_before, seconds_after: seconds_after.0 })
	}
}

/// Whether a recurring offer limits the period indices for which payment is allowed.
///
/// Serialization reads and writes only the payload of a `recurrence_limit` TLV, without an enum
/// discriminant. Only [`Self::Bounded`] has such a payload; writing [`Self::Unbounded`] returns an
/// error. Offers represent [`Self::Unbounded`] by omitting the TLV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
	/// No maximum recurrence period index is specified by the offer.
	Unbounded,
	/// Maximum zero-based period index allowed for this offer.
	///
	/// A value of one permits periods zero and one. Counting starts at period zero as determined
	/// by [`Recurrence::anchor`], even if the payer starts later. Payments for period indices
	/// greater than this limit must not be accepted.
	Bounded(NonZeroU32),
}

impl Writeable for Limit {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		match self {
			Self::Bounded(limit) => HighZeroBytesDroppedBigSize(limit.get()).write(writer),
			Self::Unbounded => Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				"unbounded recurrence has no recurrence_limit TLV",
			)),
		}
	}
}

impl Readable for Limit {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let value: HighZeroBytesDroppedBigSize<u32> = Readable::read(r)?;
		let limit = NonZeroU32::new(value.0).ok_or(DecodeError::InvalidValue)?;
		Ok(Self::Bounded(limit))
	}
}

/// The schedule and payment rules for a recurring offer.
///
/// Values and field combinations are validated by [`OfferBuilder::build`]. Optional recurrence
/// must use [`Anchor::FirstInvoice`], and proportional pricing requires an offer amount.
///
/// [`OfferBuilder::build`]: crate::offers::offer::OfferBuilder::build
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recurrence {
	/// Whether recurrence is optional or compulsory.
	pub requirement: Requirement,
	/// The recurrence schedule: a nonzero period length and its unit.
	pub period: Period,
	/// How the start of period zero is determined.
	pub anchor: Anchor,
	/// The allowed early/late window for paying a given period.
	pub paywindow: Paywindow,
	/// The maximum allowed period index, or [`Limit::Unbounded`] for no limit.
	pub limit: Limit,
}

// Payment contexts persist flattened recurrence terms. Default anchors, windows, and limits
// are represented by absent TLVs, matching the payload encodings of their explicit variants.
impl Writeable for Recurrence {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		let anchor = match &self.anchor {
			Anchor::FirstInvoice => None,
			anchor @ Anchor::Fixed { .. } => Some(anchor),
		};
		let paywindow = match &self.paywindow {
			Paywindow::Default => None,
			window @ Paywindow::Custom { .. } => Some(window),
		};
		let limit = match &self.limit {
			Limit::Unbounded => None,
			limit @ Limit::Bounded(_) => Some(limit),
		};
		write_tlv_fields!(writer, {
			(0, self.requirement, required),
			(1, anchor, option),
			(2, self.period, required),
			(3, paywindow, option),
			(5, limit, option),
		});
		Ok(())
	}
}

impl Readable for Recurrence {
	fn read<R: io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
		_init_and_read_len_prefixed_tlv_fields!(reader, {
			(0, requirement, required),
			(1, anchor, option),
			(2, period, required),
			(3, paywindow, option),
			(5, limit, option),
		});
		Ok(Self {
			requirement: requirement.0.unwrap(),
			period: period.0.unwrap(),
			anchor: anchor.unwrap_or(Anchor::FirstInvoice),
			paywindow: paywindow.unwrap_or(Paywindow::Default),
			limit: limit.unwrap_or(Limit::Unbounded),
		})
	}
}

impl Recurrence {
	/// Returns the schedule period index for an invoice request.
	///
	/// For an offer with an explicit basetime, `start` identifies the initial schedule period and
	/// the result is `start + counter`. For an offer without an explicit basetime, `start` must be
	/// absent and `counter` is the schedule period index. Recurrence failures currently use
	/// [`Bolt12SemanticError::InvalidRecurrence`]; more granular errors may be added later if
	/// callers need distinctions that canonical pre-validation cannot provide.
	pub fn period_index(
		&self, counter: u32, start: Option<u32>,
	) -> Result<u32, Bolt12SemanticError> {
		match self.anchor {
			Anchor::Fixed { .. } => start
				.and_then(|start| start.checked_add(counter))
				.ok_or(Bolt12SemanticError::InvalidRecurrence),
			Anchor::FirstInvoice => {
				if start.is_some() {
					Err(Bolt12SemanticError::InvalidRecurrence)
				} else {
					Ok(counter)
				}
			},
		}
	}

	/// Calculates the initial payment's joining price. Follow-up requests use the full amount.
	///
	/// `amount_msats` includes quantity. `period_index` selects the period being joined, and
	/// `created_at` is the invoice creation time in seconds since the Unix epoch.
	///
	/// Only fixed anchors with proportional pricing adjust the amount: full price before the
	/// period starts, scaled by time remaining during it, and zero at or after its end.
	/// Uses the period's actual length and rounds up to the nearest millisatoshi.
	///
	/// Returns an error on arithmetic overflow. Does not check the paywindow or period limit.
	pub fn proportional_amount_msats(
		&self, amount_msats: u64, period_index: u32, created_at: u64,
	) -> Result<u64, ()> {
		let basetime = match self.anchor {
			Anchor::Fixed { basetime, proportional: true } => basetime,
			_ => return Ok(amount_msats),
		};

		let period_start = self.period.start_time(basetime, period_index)?;
		if created_at <= period_start {
			return Ok(amount_msats);
		}
		let period_end =
			self.period.start_time(basetime, period_index.checked_add(1).ok_or(())?)?;
		if created_at >= period_end {
			// The period has ended, so the proportional amount is zero. Whether an invoice
			// can be issued for this request requires separate validation.
			// TODO: Add this validation in part 2/3 of recurrence support (payee handling).
			return Ok(0);
		}

		let duration = u128::from(period_end - period_start);
		let remaining = u128::from(period_end - created_at);

		// Round up so a positive price never becomes free through rounding.
		let numerator = u128::from(amount_msats) * remaining;
		let scaled = numerator / duration + u128::from(numerator % duration != 0);
		Ok(scaled as u64)
	}

	/// Returns inclusive opening and exclusive closing UNIX timestamps for a recurrence period.
	///
	/// [`Paywindow::Custom`] uses its `seconds_before` and `seconds_after` bounds.
	/// With [`Paywindow::Default`], period zero opens at its start and later periods span
	/// the preceding and paid-for periods. `basetime` must match [`Self::anchor`]: the explicit
	/// timestamp for a fixed anchor, or the first invoice's creation time otherwise.
	///
	/// Returns an error on arithmetic overflow. This calculation does not enforce [`Self::limit`].
	pub fn payment_window(&self, basetime: u64, period_count: u32) -> Result<(u64, u64), ()> {
		let period_start = self.period.start_time(basetime, period_count)?;
		match self.paywindow {
			Paywindow::Custom { seconds_before, seconds_after } => {
				let opening = period_start.saturating_sub(u64::from(seconds_before));
				let closing = period_start.checked_add(u64::from(seconds_after)).ok_or(())?;
				Ok((opening, closing))
			},
			Paywindow::Default => {
				let opening = match period_count {
					0 => period_start,
					count => self.period.start_time(basetime, count - 1)?,
				};
				let closing =
					self.period.start_time(basetime, period_count.checked_add(1).ok_or(())?)?;
				Ok((opening, closing))
			},
		}
	}

	/// Validates recurrence values and field combinations permitted in an offer.
	///
	/// `has_amount` is used to enforce that proportional pricing is only advertised when the offer
	/// has an amount whose price can be adjusted.
	pub(super) fn validate(&self, has_amount: bool) -> Result<(), Bolt12SemanticError> {
		// Optional recurrence cannot advertise a fixed anchor. Proportional pricing also
		// requires an amount, regardless of how the recurrence was constructed.
		match (self.requirement, self.anchor) {
			(Requirement::Optional, Anchor::Fixed { .. }) => {
				Err(Bolt12SemanticError::InvalidRecurrence)
			},
			(_, Anchor::Fixed { proportional: true, .. }) if !has_amount => {
				Err(Bolt12SemanticError::InvalidRecurrence)
			},
			_ => Ok(()),
		}
	}
}

/// Recurrence fields carried by an invoice request.
///
/// The counter identifies the payer's request number. The start offset, when present, identifies
/// where the payer began in a fixed schedule. Parsed and built requests are checked against the
/// offer's recurrence terms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestFields {
	/// The payer's recurring request number, starting at zero.
	pub counter: u32,
	/// The schedule period where the payer begins recurring payments.
	///
	/// Required for a fixed offer anchor and absent for a first-invoice anchor. The requested
	/// schedule period is `start + counter` when present, or `counter` otherwise.
	pub start: Option<u32>,
	/// Opaque state from the previous invoice, echoed unchanged by the payer.
	///
	/// Must be absent on the first request. The payer must not interpret or modify these bytes.
	pub prev_state: Option<Vec<u8>>,
	/// Whether this request cancels the recurrence. Must be false on the first request.
	pub cancel: bool,
}

impl RequestFields {
	/// Constructs recurrence fields from TLV values, rejecting fields without a counter
	/// and invalid first-request fields. Field absence represents a non-recurring request.
	pub(super) fn from_tlv_fields(
		counter: Option<u32>, start: Option<u32>, prev_state: Option<Vec<u8>>, cancel: Option<()>,
	) -> Result<Option<Self>, ()> {
		match (counter, start, prev_state, cancel) {
			(None, None, None, None) => Ok(None),
			(Some(counter), start, prev_state, cancel) => {
				let request = Self { counter, start, prev_state, cancel: cancel.is_some() };
				if request.counter == 0 && (request.prev_state.is_some() || request.cancel) {
					return Err(());
				}
				Ok(Some(request))
			},
			_ => Err(()),
		}
	}

	/// Validates request recurrence against the offer's recurrence terms.
	///
	/// Checks whether recurrence is required or allowed, validates first-request fields, and
	/// ensures the requested period matches the offer's anchor and does not exceed its limit.
	pub(super) fn validate_for_offer(
		offer_recurrence: Option<Recurrence>, request_recurrence: Option<&Self>,
	) -> Result<(), Bolt12SemanticError> {
		// Offer validation guarantees that optional recurrence has no fixed anchor.
		if let Some(terms) = offer_recurrence {
			debug_assert!(
				terms.requirement != Requirement::Optional || terms.anchor == Anchor::FirstInvoice,
				"optional recurrence must use a first-invoice anchor"
			);
		}

		let (terms, request) = match (offer_recurrence, request_recurrence) {
			(None, None) => return Ok(()),
			(Some(terms), None) if terms.requirement == Requirement::Optional => {
				return Ok(());
			},
			(Some(terms), Some(request)) => (terms, request),
			_ => return Err(Bolt12SemanticError::InvalidRecurrence),
		};

		if request.counter == 0 && (request.prev_state.is_some() || request.cancel) {
			return Err(Bolt12SemanticError::InvalidRecurrence);
		}

		let period_index = terms.period_index(request.counter, request.start)?;
		if let Limit::Bounded(limit) = terms.limit {
			if period_index > limit.get() {
				return Err(Bolt12SemanticError::InvalidRecurrence);
			}
		}

		Ok(())
	}

	/// Returns the wire fields, encoding cancellation as an optional empty TLV payload.
	pub(super) fn fields(&self) -> (Option<u32>, Option<u32>, Option<&Vec<u8>>, Option<&()>) {
		(Some(self.counter), self.start, self.prev_state.as_ref(), self.cancel.then_some(&()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::prelude::*;

	/// Supplies default terms so each test can change the rule it exercises.
	fn recurrence(period: Period) -> Recurrence {
		Recurrence {
			requirement: Requirement::Compulsory,
			period,
			anchor: Anchor::FirstInvoice,
			paywindow: Paywindow::Default,
			limit: Limit::Unbounded,
		}
	}

	/// Checks exact payload bytes as well as decoding, so matching reader/writer bugs cannot hide.
	fn check_encoding<T: Writeable + Readable + core::fmt::Debug + PartialEq>(
		value: T, bytes: &[u8],
	) {
		assert_eq!(value.encode(), bytes);
		assert_eq!(T::read(&mut bytes.as_ref()).unwrap(), value);
	}

	/// Seconds and days preserve the anchor's time of day and report timestamp overflow.
	#[test]
	fn recurrence_seconds_and_days() {
		for period in [
			Period::Seconds(NonZeroU32::new(172_800).unwrap()),
			Period::Days(NonZeroU32::new(2).unwrap()),
		] {
			assert_eq!(period.start_time(12_345, 0), Ok(12_345));
			assert_eq!(period.start_time(12_345, 3), Ok(530_745));
			assert_eq!(period.start_time(u64::MAX, 0), Ok(u64::MAX));
			assert_eq!(period.start_time(u64::MAX, 1), Err(()));
		}
		let max = NonZeroU32::new(u32::MAX).unwrap();
		assert_eq!(Period::Seconds(max).start_time(0, u32::MAX), Ok(u64::from(u32::MAX).pow(2)));
		assert_eq!(Period::Days(max).start_time(0, u32::MAX), Err(()));
	}

	/// Month offsets clamp from the original date, rather than carrying February's shorter day forward.
	#[test]
	fn recurrence_calendar_months() {
		let month = Period::Months(NonZeroU32::new(1).unwrap());
		// These are UTC timestamps for January 31, February's last day, and March 31.
		for (january, february, march) in [
			(1_612_051_200, 1_614_470_400, 1_617_148_800), // 2021: ordinary year.
			(1_580_428_800, 1_582_934_400, 1_585_612_800), // 2020: leap year.
		] {
			assert_eq!(month.start_time(january + 12_345, 1), Ok(february + 12_345));
			assert_eq!(month.start_time(january + 12_345, 2), Ok(march + 12_345));
		}
		// December advances into the next year; a twelve-month period preserves leap-day clamping.
		assert_eq!(month.start_time(1_609_372_800, 1), Ok(1_612_051_200));
		let year = Period::Months(NonZeroU32::new(12).unwrap());
		assert_eq!(year.start_time(1_582_934_400, 1), Ok(1_614_470_400));
		assert_eq!(year.start_time(1_582_934_400, 4), Ok(1_709_164_800));
		assert_eq!(month.start_time(u64::MAX, 0), Ok(u64::MAX));
		assert_eq!(month.start_time(u64::MAX, 1), Err(()));
		assert_eq!(
			Period::Months(NonZeroU32::new(u32::MAX).unwrap()).start_time(0, u32::MAX),
			Err(())
		);
	}

	/// Gregorian century exceptions remain correct on both sides of the Unix epoch.
	#[test]
	fn recurrence_gregorian_cycles() {
		for (year, leap) in [(1600, true), (1900, false), (2000, true), (2100, false), (2400, true)]
		{
			assert_eq!(is_leap_year(year), leap);
			let last_day = if leap { 29 } else { 28 };
			let february = days_from_civil(year, 2, last_day);
			assert_eq!(civil_from_days(february), (year, 2, last_day));
			assert_eq!(civil_from_days(february + 1), (year, 3, 1));
		}
		assert_eq!(days_from_civil(1970, 1, 1), 0);
		assert_eq!(civil_from_days(-1), (1969, 12, 31));
	}

	/// Fixed schedules require a start index; first-invoice schedules must not carry one.
	#[test]
	fn recurrence_period_indices() {
		let mut terms = recurrence(Period::Seconds(NonZeroU32::new(60).unwrap()));
		assert_eq!(terms.period_index(u32::MAX, None), Ok(u32::MAX));
		assert_eq!(terms.period_index(0, Some(0)), Err(Bolt12SemanticError::InvalidRecurrence));
		terms.anchor = Anchor::Fixed { basetime: 100, proportional: false };
		assert_eq!(terms.period_index(0, None), Err(Bolt12SemanticError::InvalidRecurrence));
		assert_eq!(terms.period_index(0, Some(0)), Ok(0));
		assert_eq!(terms.period_index(2, Some(3)), Ok(5));
		assert_eq!(
			terms.period_index(1, Some(u32::MAX)),
			Err(Bolt12SemanticError::InvalidRecurrence)
		);
	}

	/// Default windows include the preceding period, while custom bounds saturate only at zero.
	#[test]
	fn recurrence_payment_windows() {
		let mut terms = recurrence(Period::Seconds(NonZeroU32::new(60).unwrap()));
		assert_eq!(terms.payment_window(100, 0), Ok((100, 160)));
		// Window calculation does not enforce the offer's period limit.
		terms.limit = Limit::Bounded(NonZeroU32::new(1).unwrap());
		assert_eq!(terms.payment_window(100, 2), Ok((160, 280)));
		assert_eq!(terms.payment_window(0, u32::MAX), Err(()));
		assert_eq!(terms.payment_window(u64::MAX, 0), Err(()));
		terms.paywindow = Paywindow::Custom { seconds_before: 120, seconds_after: 30 };
		assert_eq!(terms.payment_window(100, 0), Ok((0, 130)));
		assert_eq!(terms.payment_window(100, 2), Ok((100, 250)));
		assert_eq!(terms.payment_window(u64::MAX, 0), Err(()));
		terms.paywindow = Paywindow::Custom { seconds_before: 0, seconds_after: 0 };
		assert_eq!(terms.payment_window(100, 0), Ok((100, 100)));
		terms.period = Period::Months(NonZeroU32::new(1).unwrap());
		terms.paywindow = Paywindow::Default;
		assert_eq!(terms.payment_window(1_612_051_200, 1), Ok((1_612_051_200, 1_617_148_800)));
	}

	/// Joining prices use the selected period and round up, without overflowing large amounts.
	#[test]
	fn recurrence_proportional_amounts() {
		let mut terms = recurrence(Period::Seconds(NonZeroU32::new(100).unwrap()));
		terms.anchor = Anchor::Fixed { basetime: 1000, proportional: true };
		for (time, amount) in
			[(999, 1000), (1000, 1000), (1025, 750), (1099, 10), (1100, 0), (1101, 0)]
		{
			assert_eq!(terms.proportional_amount_msats(1000, 0, time), Ok(amount));
		}
		assert_eq!(terms.proportional_amount_msats(1000, 2, 1225), Ok(750));
		assert_eq!(terms.proportional_amount_msats(1, 0, 1099), Ok(1));
		assert_eq!(terms.proportional_amount_msats(101, 0, 1025), Ok(76));
		assert_eq!(terms.proportional_amount_msats(0, 0, 1025), Ok(0));
		assert_eq!(terms.proportional_amount_msats(u64::MAX, 0, 1050), Ok(u64::MAX / 2 + 1));
		assert_eq!(terms.proportional_amount_msats(1000, u32::MAX, u64::MAX), Err(()));
		terms.anchor = Anchor::Fixed { basetime: u64::MAX - 1, proportional: true };
		assert_eq!(terms.proportional_amount_msats(1000, 0, u64::MAX), Err(()));
		// Non-proportional schedules do not apply a discount, even after the period ends.
		for anchor in [Anchor::FirstInvoice, Anchor::Fixed { basetime: 1000, proportional: false }]
		{
			terms.anchor = anchor;
			assert_eq!(terms.proportional_amount_msats(1000, 0, 2000), Ok(1000));
		}
		// February 2021 lasts 28 days; joining halfway through costs half the full amount.
		terms.period = Period::Months(NonZeroU32::new(1).unwrap());
		terms.anchor = Anchor::Fixed { basetime: 1_609_459_200, proportional: true };
		assert_eq!(terms.proportional_amount_msats(1000, 1, 1_613_347_200), Ok(500));
	}

	/// Literal wire vectors cover truncated integers, including their empty encoding for zero.
	#[test]
	fn recurrence_wire_encodings() {
		check_encoding(Period::Seconds(NonZeroU32::new(1).unwrap()), &[0, 1]);
		check_encoding(Period::Days(NonZeroU32::new(256).unwrap()), &[1, 1, 0]);
		check_encoding(
			Period::Months(NonZeroU32::new(u32::MAX).unwrap()),
			&[2, 255, 255, 255, 255],
		);
		check_encoding(Anchor::Fixed { basetime: 0, proportional: false }, &[0]);
		check_encoding(Anchor::Fixed { basetime: 256, proportional: true }, &[1, 1, 0]);
		check_encoding(
			Anchor::Fixed { basetime: u64::MAX, proportional: false },
			&[0, 255, 255, 255, 255, 255, 255, 255, 255],
		);
		check_encoding(Paywindow::Custom { seconds_before: 1, seconds_after: 0 }, &[0, 0, 0, 1]);
		check_encoding(
			Paywindow::Custom { seconds_before: 1, seconds_after: 256 },
			&[0, 0, 0, 1, 1, 0],
		);
		check_encoding(
			Paywindow::Custom { seconds_before: u32::MAX, seconds_after: u32::MAX },
			&[255; 8],
		);
		check_encoding(Limit::Bounded(NonZeroU32::new(256).unwrap()), &[1, 0]);
		check_encoding(Limit::Bounded(NonZeroU32::new(u32::MAX).unwrap()), &[255; 4]);
		check_encoding(Requirement::Optional, &[0, 0]);
		check_encoding(Requirement::Compulsory, &[1, 0]);
		assert!(Anchor::FirstInvoice.write(&mut Vec::new()).is_err());
		assert!(Paywindow::Default.write(&mut Vec::new()).is_err());
		assert!(Limit::Unbounded.write(&mut Vec::new()).is_err());
	}

	/// Malformed payloads must not accept zero counts, unknown tags, or noncanonical integers.
	#[test]
	fn recurrence_invalid_wire_encodings() {
		for bytes in [&[][..], &[0], &[0, 0], &[0, 0, 1], &[3, 1]] {
			assert!(Period::read(&mut bytes.as_ref()).is_err());
		}
		for bytes in [&[][..], &[2], &[0, 0], &[1, 0, 1]] {
			assert!(Anchor::read(&mut bytes.as_ref()).is_err());
		}
		for bytes in [&[][..], &[0, 0, 0], &[0, 0, 0, 1, 0], &[0, 0, 0, 1, 0, 1]] {
			assert!(Paywindow::read(&mut bytes.as_ref()).is_err());
		}
		for bytes in [&[][..], &[0], &[0, 1]] {
			assert!(Limit::read(&mut bytes.as_ref()).is_err());
		}
	}

	/// Persisted terms restore omitted defaults and retain each explicit setting.
	#[test]
	fn recurrence_persistence() {
		let mut terms = recurrence(Period::Days(NonZeroU32::new(7).unwrap()));
		check_encoding(terms, &[8, 0, 2, 1, 0, 2, 2, 1, 7]);
		terms.anchor = Anchor::Fixed { basetime: 12345, proportional: true };
		terms.paywindow = Paywindow::Custom { seconds_before: 100, seconds_after: 256 };
		terms.limit = Limit::Bounded(NonZeroU32::new(10).unwrap());
		assert_eq!(Recurrence::read(&mut terms.encode().as_slice()).unwrap(), terms);
		terms.requirement = Requirement::Optional;
		terms.anchor = Anchor::FirstInvoice;
		assert_eq!(Recurrence::read(&mut terms.encode().as_slice()).unwrap(), terms);
	}
}
