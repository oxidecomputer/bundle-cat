// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use bstr::ByteSlice;
use glob::Pattern;
use jiff::Timestamp;
use serde::Deserialize;

use std::io::{Read, Write};

use crate::filter::LogFilter;
use crate::time::JANUARY_1_2001;
use crate::{Bundle, BundleSource};

#[derive(Debug)]
pub struct LogFile {
    pub path: String,
    pub sled_uuid: String,
    pub service: Option<String>,
    pub zone: Option<String>,
    pub timestamp: Option<i64>,
}

impl LogFile {
    pub(crate) fn from_path(path: &str) -> Option<Self> {
        // Ignore directories.
        if path.ends_with('/') {
            return None;
        }

        // For logs rack/{rack_uuid}/sled/{sled_uuid}/logs/{zone}/{service}/...
        // Or for health checks rack/{rack_uuid}/sled/{sled_uuid}/{check}.json
        let parts: Vec<_> = path.split('/').collect();

        if parts.len() < 5 {
            return None;
        }

        let sled_uuid = parts.get(3)?.to_string();

        let zone = parts.get(5).map(|s| s.to_string());
        let service = parts.get(6).map(|s| s.to_string());

        // Only archived logs have a trailing timestamp.
        let timestamp = Self::extract_timestamp(path);

        Some(LogFile {
            path: path.to_string(),
            sled_uuid,
            service,
            zone,
            timestamp,
        })
    }

    /// Extract trailing timestamp from paths with a file name like:
    /// "oxide-mg-ddm:default.log.1758510604".
    fn extract_timestamp(path: &str) -> Option<i64> {
        let suffix = path.split('.').next_back()?;
        suffix.parse::<i64>().ok()
    }

    pub(crate) fn matches_services(&self, service_patterns: &[Pattern]) -> bool {
        // Match all files if unspecified.
        if service_patterns.is_empty() {
            return true;
        }

        let Some(service) = &self.service else {
            return false;
        };
        service_patterns.iter().any(|p| p.matches(service))
    }

    pub(crate) fn matches_zones(&self, zone_patterns: &[Pattern]) -> bool {
        // Match all files if unspecified.
        if zone_patterns.is_empty() {
            return true;
        }

        let Some(zone) = &self.zone else {
            return false;
        };
        zone_patterns.iter().any(|p| p.matches(zone))
    }

    pub(crate) fn matches_paths(&self, path_patterns: &[Pattern]) -> bool {
        // Match all files if unspecified.
        if path_patterns.is_empty() {
            return true;
        }
        path_patterns.iter().any(|p| p.matches(&self.path))
    }
}

/// Minimal struct to grab the timestamp from a JSON log event.
#[derive(Deserialize, Default, Debug)]
struct LogTimestamp {
    time: Timestamp,
}

fn read_timestamp_from_contents(buf: &[u8]) -> Option<Timestamp> {
    for line in buf.lines() {
        if line.starts_with(b"{")
            && let Ok(ts) = serde_json::from_slice::<LogTimestamp>(line)
            && &ts.time > JANUARY_1_2001
        {
            return Some(ts.time);
        }
    }

    None
}

const TIME_CHECK_MAX: u64 = 1 << 16;

impl<S: BundleSource> Bundle<S> {
    /// Iterate over log files in the bundle that match the given filter,
    /// calling `handler` for each match.
    ///
    /// When time filtering is active (`filter.before` or `filter.after` is
    /// set), the first 64KB of each file is read into a buffer to determine
    /// the file's timestamp. If the timestamp passes the filter, the buffer
    /// is passed as `Some(buf)` so the handler can use it without re-reading.
    /// When no time filtering is active, `None` is passed.
    pub fn for_each_log<F>(&mut self, filter: &LogFilter, mut handler: F) -> Result<()>
    where
        F: FnMut(&LogFile, &mut dyn Read, Option<Vec<u8>>) -> Result<()>,
    {
        // Step 1: Collect matching (path, LogFile) pairs before opening any
        // readers, which borrow the source mutably for their lifetime.
        let matching_files: Vec<_> = self
            .source
            .file_names()
            .into_iter()
            .filter_map(|path| {
                let log_file = LogFile::from_path(&path)?;

                let sled_info = self.info.sleds.get(&log_file.sled_uuid)?;

                if sled_info.matches_patterns(&filter.sled)
                    && log_file.matches_services(&filter.service)
                    && log_file.matches_zones(&filter.zone)
                    && log_file.matches_paths(&filter.path)
                {
                    Some((path, log_file))
                } else {
                    None
                }
            })
            .collect();

        // Step 2: Iterate by path, performing time-check buffering.
        for (path, log) in matching_files {
            let time_filtering = filter.before.is_some() || filter.after.is_some();
            // Metadata must be owned before opening the reader because the
            // reader keeps the source mutably borrowed.
            let metadata = time_filtering
                .then(|| {
                    self.source
                        .metadata(&path)
                        .with_context(|| format!("failed to read metadata for {path}"))
                })
                .transpose()?;
            let mut file = self
                .source
                .open_file(&path)
                .with_context(|| format!("failed to open {path}"))?;

            let time_check_buf = if let Some(metadata) = metadata {
                let capacity = metadata.len.unwrap_or(TIME_CHECK_MAX).min(TIME_CHECK_MAX) as usize;
                let mut tc = Vec::with_capacity(capacity);
                (&mut *file)
                    .take(TIME_CHECK_MAX)
                    .read_to_end(&mut tc)
                    .with_context(|| format!("failed to read file {path}"))?;

                // Try several methods of finding the log's timeframe,
                // in order of decreasing accuracy:
                // 1. Parse a valid timestamp from the first 64k of the
                //    file contents.
                // 2. Check for the timestamp appended to the file name,
                //    only available for archived logs.
                // 3. Check the file's mtime in the zip, available with
                //    R17 bundles.
                // In all cases ignore times from before 2001, and skip
                // any file where we cannot find a valid time.
                let ts = read_timestamp_from_contents(&tc)
                    .or_else(|| {
                        let ts = log.timestamp?;
                        Timestamp::from_second(ts).ok()
                    })
                    .or(metadata.modified);

                if !ts.is_some_and(|ts| {
                    crate::time::within_time_range(&ts, &filter.before, &filter.after)
                }) {
                    continue;
                }

                Some(tc)
            } else {
                None
            };

            // Step 3: Call handler.
            handler(&log, &mut *file, time_check_buf)?;
        }

        Ok(())
    }

    /// Write matching log files to `out`, applying the filter's header,
    /// list, and line-count settings.
    pub fn write_logs(&mut self, filter: &LogFilter, mut out: impl Write) -> Result<()> {
        self.for_each_log(filter, |log_file, file, time_check_buf| {
            if filter.list {
                writeln!(out, "{}", log_file.path)?;
                return Ok(());
            }

            if !filter.no_header {
                writeln!(out, "==> {} <==", log_file.path)?;
            }

            crate::io::write_file_content(
                &time_check_buf,
                file,
                &mut out,
                filter.line_ct.map(|l| l.get()),
            )?;

            if !filter.no_header {
                writeln!(out)?;
            }

            Ok(())
        })
    }
}
