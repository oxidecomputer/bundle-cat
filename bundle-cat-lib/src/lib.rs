// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

//! Filter and extract logs, ereports, sled info, and zone/service lists
//! from Oxide rack support bundles.
//!
//! # Example
//!
//! ```no_run
//! use bundle_cat_lib::Bundle;
//!
//! let bundle = Bundle::open("support-bundle.zip")?;
//! bundle.write_sleds(&mut std::io::stdout())?;
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! # Bundle sources
//!
//! [`Bundle::open`] and [`Bundle::from_reader`] construct zip-backed bundles.
//! [`Bundle::open_dir`] reads an unpacked bundle, while
//! [`Bundle::from_source`] accepts any custom [`BundleSource`], including a
//! `Box<dyn BundleSource>` selected at runtime.
//!
//! # Structured access
//!
//! [`Bundle::info`] exposes sled metadata. [`Bundle::for_each_log`] streams
//! matching logs, and [`Bundle::for_each_ereport`] or [`Bundle::ereports`]
//! expose display-neutral ereport metadata and raw contents. The
//! [`parse_sled_txt`] and [`parse_ereport_path`] helpers provide narrow parsing
//! primitives when constructing a complete bundle is unnecessary.

mod bundle;
mod ereport;
mod filter;
mod io;
mod log;
mod source;
mod time;

#[cfg(test)]
mod tests;

pub use bundle::{BundleInfo, SledInfo, SledTxtInfo, parse_sled_txt};
pub use ereport::{Ereport, EreportEntry, parse_ereport_path};
pub use filter::{EreportFilter, EreportListFilter, EreportShowFilter, LogFilter};
pub use io::write_file_content;
pub use log::LogFile;
pub use source::{BundleFileMetadata, BundleSource, DirectoryBundleSource, ZipBundleSource};
pub use time::{JANUARY_1_2001, parse_timestamp};

use anyhow::{Context as _, Result};
use glob::Pattern;
use std::fs::File;
use std::io::{BufReader, Read, Seek, Write};
use std::path::Path;

/// A handle to a parsed support bundle.
///
/// Constructed via [`Bundle::open`] (from a file path) or
/// [`Bundle::from_reader`] (from any zip `Read + Seek` source), via
/// [`Bundle::open_dir`] (from an unpacked directory), or via
/// [`Bundle::from_source`] (from any [`BundleSource`]).
pub struct Bundle<S> {
    pub(crate) source: S,
    pub(crate) info: BundleInfo,
}

impl Bundle<ZipBundleSource<BufReader<File>>> {
    /// Open a support bundle from a file path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref()).with_context(|| {
            format!(
                "failed to open support bundle zip: {}",
                path.as_ref().display()
            )
        })?;
        let reader = BufReader::new(file);
        Self::from_reader(reader)
    }
}

impl<R: Read + Seek> Bundle<ZipBundleSource<R>> {
    /// Create a `Bundle` from any reader that implements `Read + Seek`.
    pub fn from_reader(reader: R) -> Result<Self> {
        Self::from_source(ZipBundleSource::new(reader)?)
    }
}

impl Bundle<DirectoryBundleSource> {
    /// Open an unpacked support bundle from a directory path.
    pub fn open_dir(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_source(DirectoryBundleSource::open(path)?)
    }
}

impl<S: BundleSource> Bundle<S> {
    /// Create a `Bundle` from a support bundle source.
    pub fn from_source(mut source: S) -> Result<Self> {
        let info = BundleInfo::from_source(&mut source)
            .context("failed to parse sled information from bundle")?;
        Ok(Bundle { source, info })
    }
}

impl<S> Bundle<S> {
    /// Access the parsed bundle metadata.
    pub fn info(&self) -> &BundleInfo {
        &self.info
    }

    /// Write a sled listing to the given sink.
    pub fn write_sleds(&self, out: impl Write) -> Result<()> {
        bundle::write_sleds(&self.info, out)
    }

    /// Write a services listing to the given sink, filtered by sled patterns.
    pub fn write_services(&self, sled_patterns: &[Pattern], out: impl Write) -> Result<()> {
        bundle::write_services(&self.info, sled_patterns, out)
    }

    /// Write a zones listing to the given sink, filtered by sled patterns.
    pub fn write_zones(&self, sled_patterns: &[Pattern], out: impl Write) -> Result<()> {
        bundle::write_zones(&self.info, sled_patterns, out)
    }
}

impl<S: BundleSource> Bundle<S> {
    /// Iterate over structured ereports matching the data-selection filter.
    pub fn for_each_ereport<F>(&mut self, filter: &EreportFilter, handler: F) -> Result<()>
    where
        F: FnMut(EreportEntry) -> Result<()>,
    {
        ereport::for_each_ereport(&mut self.source, filter, handler)
    }

    /// Collect structured ereports matching the data-selection filter.
    pub fn ereports(&mut self, filter: &EreportFilter) -> Result<Vec<EreportEntry>> {
        let mut entries = Vec::new();
        self.for_each_ereport(filter, |entry| {
            entries.push(entry);
            Ok(())
        })?;
        Ok(entries)
    }

    /// Write an ereport listing to the given sink.
    pub fn write_ereports_list(
        &mut self,
        filter: &EreportListFilter,
        out: impl Write,
    ) -> Result<()> {
        ereport::write_ereports_list(&mut self.source, filter, out)
    }

    /// Write ereport contents to the given sink.
    pub fn write_ereports_show(
        &mut self,
        filter: &EreportShowFilter,
        out: impl Write,
    ) -> Result<()> {
        ereport::write_ereports_show(&mut self.source, filter, out)
    }
}
