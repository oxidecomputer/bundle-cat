// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use glob::Pattern;
use serde_json::Value;
use std::io::Write;

use crate::BundleSource;
use crate::filter::{EreportFilter, EreportListFilter, EreportShowFilter};
use crate::io::read_file_to_string;

/// Metadata encoded in an ereport's bundle-relative path.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Ereport {
    /// Hardware part number.
    pub part: String,
    /// Hardware serial number.
    pub serial: String,
    /// Restart identifier containing this ereport.
    pub restart_id: String,
    /// Error numeric association identifying the report.
    pub ena: u64,
}

/// Structured ereport data suitable for non-text renderers.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EreportEntry {
    /// Bundle-relative path of the ereport file.
    pub path: String,
    /// Metadata parsed from `path`.
    pub metadata: Ereport,
    /// Extracted ereport class, if present in the raw contents.
    pub class: Option<String>,
    /// Original UTF-8 file contents.
    pub contents: String,
}

/// Parse an ereport's metadata from its bundle-relative path.
pub fn parse_ereport_path(path: &str) -> Option<Ereport> {
    // ereports/{part-number}-{serial_number}/{restart_id}/{ENA}.json
    let mut splits = path.split('/');
    if splits.next()? != "ereports" {
        return None;
    }

    let part_and_serial = splits.next()?;
    let restart_id = splits.next()?;
    let file_name = splits.next()?;
    if splits.next().is_some() || restart_id.is_empty() {
        return None;
    }

    // Part numbers contain a '-', but serials do not, at least currently.
    // Split from the right to ensure we're finding the boundary between the two.
    let (part, serial) = part_and_serial.rsplit_once('-')?;
    if part.is_empty() || serial.is_empty() {
        return None;
    }
    let ena = file_name
        .strip_suffix(".json")
        .and_then(|n| n.parse::<u64>().ok())?;

    Some(Ereport {
        part: part.to_string(),
        serial: serial.to_string(),
        restart_id: restart_id.to_string(),
        ena,
    })
}

fn matches_patterns(patterns: &[Pattern], s: &str) -> bool {
    if patterns.is_empty() {
        return true;
    }

    patterns.iter().any(|p| p.matches(s))
}

fn read_ereport_class(ereport_raw: &str) -> Option<&str> {
    const CLASS_PREFIX: &str = "\"class\":\"";
    let class_start = ereport_raw.find(CLASS_PREFIX)? + CLASS_PREFIX.len();
    let class_end = class_start + ereport_raw[class_start..].find("\"")?;

    Some(&ereport_raw[class_start..class_end])
}

fn for_each_ereport_filtered<S, F>(
    source: &mut S,
    part: &[Pattern],
    serial: &[Pattern],
    class: &[Pattern],
    mut handler: F,
) -> Result<()>
where
    S: BundleSource + ?Sized,
    F: FnMut(EreportEntry) -> Result<()>,
{
    let matching_reports: Vec<_> = source
        .file_names()
        .into_iter()
        .filter_map(|path| {
            let metadata = parse_ereport_path(&path)?;
            if matches_patterns(part, &metadata.part) && matches_patterns(serial, &metadata.serial)
            {
                Some((path, metadata))
            } else {
                None
            }
        })
        .collect();

    for (path, metadata) in matching_reports {
        let mut file = source
            .open_file(&path)
            .with_context(|| format!("failed to open {path}"))?;
        let contents = read_file_to_string(&mut *file, &path, None)?;
        let ereport_class = read_ereport_class(&contents).map(str::to_owned);

        if let Some(ereport_class) = &ereport_class
            && !matches_patterns(class, ereport_class)
        {
            continue;
        }

        handler(EreportEntry {
            path,
            metadata,
            class: ereport_class,
            contents,
        })?;
    }

    Ok(())
}

pub(crate) fn for_each_ereport<S, F>(
    source: &mut S,
    filter: &EreportFilter,
    handler: F,
) -> Result<()>
where
    S: BundleSource + ?Sized,
    F: FnMut(EreportEntry) -> Result<()>,
{
    for_each_ereport_filtered(source, &filter.part, &filter.serial, &filter.class, handler)
}

pub(crate) fn write_ereports_list<S: BundleSource + ?Sized, W: Write>(
    source: &mut S,
    filter: &EreportListFilter,
    mut out: W,
) -> Result<()> {
    let ereports: Vec<_> = source
        .file_names()
        .into_iter()
        .filter_map(|path| {
            let ereport = parse_ereport_path(&path)?;

            if matches_patterns(&filter.part, &ereport.part)
                && matches_patterns(&filter.serial, &ereport.serial)
            {
                Some((path, ereport))
            } else {
                None
            }
        })
        .collect();

    let max_ena_len = ereports
        .iter()
        .map(|(_, ereport)| ereport.ena)
        .max()
        .map(|max| max.to_string().len())
        .unwrap_or(3);

    writeln!(
        out,
        "{:<11}\t{:<11}\t{:<36}\t{:<max_ena_len$}\tCLASS",
        "PART", "SERIAL", "RESTART_ID", "ENA",
    )?;
    for (path, ereport) in ereports {
        let mut file = source
            .open_file(&path)
            .with_context(|| format!("failed to open {path}"))?;
        let contents = read_file_to_string(&mut *file, &path, None)?;
        let class = read_ereport_class(&contents);

        if let Some(class) = class
            && !matches_patterns(&filter.class, class)
        {
            continue;
        }
        writeln!(
            out,
            "{:<11}\t{:<11}\t{:<36}\t{:>max_ena_len$}\t{}",
            ereport.part,
            ereport.serial,
            ereport.restart_id,
            ereport.ena,
            class.unwrap_or("unknown"),
        )?;
    }

    Ok(())
}

pub(crate) fn write_ereports_show<S: BundleSource + ?Sized, W: Write>(
    source: &mut S,
    filter: &EreportShowFilter,
    mut out: W,
) -> Result<()> {
    for_each_ereport_filtered(
        source,
        &filter.part,
        &filter.serial,
        &filter.class,
        |entry| {
            if !filter.no_header {
                writeln!(out, "==> {} <==", entry.path)?;
            }

            if let Ok(json) = serde_json::from_str::<Value>(&entry.contents)
                && let Ok(pretty) = serde_json::to_string_pretty(&json)
            {
                writeln!(out, "{pretty}")?;
            } else {
                out.write_all(entry.contents.as_bytes())?;
            }

            if !filter.no_header {
                writeln!(out)?;
            }

            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_ereport_class() {
        let ereport_str = serde_json::json!({
          "restart_id": "550e8400-e29b-41d4-a716-446655440000",
          "ena": "0x0000000012345678",
          "time_collected": "2025-10-11T14:32:15.123Z",
          "time_deleted": null,
          "collector_id": "7c3a8b90-f234-4567-89ab-cdef01234567",
          "part_number": "907-0000023",
          "serial_number": "BRM03250000",
          "class": "ereport.io.pci.device",
          "reporter": {
            "Sp": {
              "sp_type": "Sled",
              "slot": 5
            }
          },
          "fault_class": "fault.io.pci.device.error",
          "severity": "major",
          "timestamp": 12345,
          "details": {
            "device_id": "0x1234",
            "vendor_id": "0x8086"
          }
        })
        .to_string();
        assert_eq!(
            read_ereport_class(&ereport_str),
            Some("ereport.io.pci.device")
        );
    }
}
