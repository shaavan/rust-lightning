// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Data structures and encoding for dealing with OffersMessage

use core::ops::Deref;

use crate::util::logger::Logger;

/// TODO
pub struct OffersMessageFlow<L: Deref>
where
	L::Target: Logger,
{
	/// The Logger for use in the OffersMessageFlow and which may be used to log
	/// information during deserialization.
	pub logger: L,
}

impl<L: Deref> OffersMessageFlow<L>
where
	L::Target: Logger,
{
	/// Creates a new [`OffersMessageFlow`]
	pub fn new(logger: L) -> Self {
		Self { logger }
	}
}
