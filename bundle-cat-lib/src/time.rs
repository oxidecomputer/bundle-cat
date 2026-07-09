// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp};

/// Ignore lines with timestamps from the previous millenium.
pub const JANUARY_1_2001: &Timestamp = &Timestamp::constant(978307200, 0);

pub fn parse_timestamp(relative_to: Timestamp, date_str: &str) -> Result<Timestamp, anyhow::Error> {
    // Parse as both a TimeStamp, DateTime, and Span to provide maximum flexibility to users.
    // Timestamp must have a timezone, while DateTime must not have a "Z" TZ.
    let timestamp = date_str.parse::<Timestamp>();
    let datetime = date_str.parse::<DateTime>();
    let span = date_str.parse::<Span>();

    match (timestamp, datetime, span) {
        (Ok(ts), _, _) => Ok(ts),
        (_, Ok(dt), _) => Ok(dt.to_zoned(TimeZone::UTC)?.timestamp()),
        (_, _, Ok(s)) => {
            // Convert to Zoned for addition, Timestamp cannot be offset by a full day or more.
            let zoned = relative_to.to_zoned(TimeZone::UTC);
            Ok(zoned.saturating_add(s).timestamp())
        }
        (Err(e), Err(_), Err(_)) => Err(anyhow::anyhow!("could not parse timestamp: {e}")),
    }
}

pub(crate) fn within_time_range(
    ts: &Timestamp,
    before: &Option<Timestamp>,
    after: &Option<Timestamp>,
) -> bool {
    if ts < JANUARY_1_2001 {
        return false;
    }

    let before = &before.unwrap_or(Timestamp::MAX);
    let after = &after.unwrap_or(Timestamp::MIN);

    ts < before && ts > after
}
