// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use glob::Pattern;
use jiff::Timestamp;
use std::num::NonZeroUsize;

/// Filter for log file queries.
#[derive(Default, Debug)]
pub struct LogFilter {
    pub sled: Vec<Pattern>,
    pub service: Vec<Pattern>,
    pub zone: Vec<Pattern>,
    pub path: Vec<Pattern>,
    pub after: Option<Timestamp>,
    pub before: Option<Timestamp>,
    pub list: bool,
    pub line_ct: Option<NonZeroUsize>,
    pub no_header: bool,
}

/// Data-selection filter for structured ereport queries.
#[derive(Default, Debug)]
pub struct EreportFilter {
    pub part: Vec<Pattern>,
    pub serial: Vec<Pattern>,
    pub class: Vec<Pattern>,
}

/// Filter for the ereport list command.
#[derive(Default, Debug)]
pub struct EreportListFilter {
    pub part: Vec<Pattern>,
    pub serial: Vec<Pattern>,
    pub class: Vec<Pattern>,
}

/// Filter for the ereport show command.
#[derive(Default, Debug)]
pub struct EreportShowFilter {
    pub part: Vec<Pattern>,
    pub serial: Vec<Pattern>,
    pub class: Vec<Pattern>,
    pub no_header: bool,
}
