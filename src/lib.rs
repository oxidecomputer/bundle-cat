// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use bstr::ByteSlice;
use glob::Pattern;
use jiff::Timestamp;
use serde::Deserialize;
use serde_json::Value;
use zip::ZipArchive;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, Write};
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str;
use std::thread;

mod source;

pub use source::{BundleFileMetadata, BundleSource, DirectoryBundleSource, ZipBundleSource};

/// Ignore lines with timestamps from the previous millenium.
const JANUARY_1_2001: &Timestamp = &Timestamp::constant(978307200, 0);

/// Glob-pattern filters selecting ereports by hardware component.
#[derive(Clone, Copy, Default, Debug)]
pub struct ComponentInfo<'a> {
    /// Part number glob patterns, (e.g., "123-0000456", "123-0004*").
    pub part: &'a [Pattern],
    /// Serial number glob patterns, (e.g., "BRM03250000", "BRM0325*").
    pub serial: &'a [Pattern],
    /// Class glob patterns, (e.g., "hw.insert.psu", "hw.*").
    pub class: &'a [Pattern],
}

/// Glob-pattern filters selecting which log files to include.
#[derive(Clone, Copy, Default, Debug)]
pub struct LogFilter<'a> {
    /// Sled cubby number, serial number or UUID glob patterns (e.g., "16", "BRM032500*", "0f16e501-*").
    pub sled: &'a [Pattern],

    /// Service name glob patterns to filter (e.g., "mg-ddm", "ntp*").
    pub service: &'a [Pattern],

    /// Zone name glob patterns to filter (e.g., "oxz_switch", "oxz_nexus*").
    pub zone: &'a [Pattern],

    /// File path glob patterns to filter (e.g., "bundle_id.txt", "*nvmeadm.json").
    pub path: &'a [Pattern],
}

/// A time window bounding which archived log files to include.
#[derive(Clone, Copy, Default, Debug)]
pub struct TimeRange {
    /// Only include files with timestamps after this time.
    pub after: Option<Timestamp>,

    /// Only include files with timestamps before this time.
    pub before: Option<Timestamp>,
}

impl TimeRange {
    /// Whether either bound is set, i.e. whether time filtering was requested.
    pub fn is_set(&self) -> bool {
        self.after.is_some() || self.before.is_some()
    }

    /// Whether `ts` falls within the range. Timestamps from before 2001 are
    /// always excluded, as they indicate a missing or bogus time.
    pub fn contains(&self, ts: Timestamp) -> bool {
        if &ts < JANUARY_1_2001 {
            return false;
        }

        let before = self.before.unwrap_or(Timestamp::MAX);
        let after = self.after.unwrap_or(Timestamp::MIN);

        ts < before && ts > after
    }
}

/// How to render the selected log files.
#[derive(Clone, Copy, Default, Debug)]
pub struct LogOutput<'a> {
    /// List matching files without printing their contents.
    pub list: bool,

    /// Number of lines to print from matching files.
    pub line_ct: Option<NonZeroUsize>,

    /// Don't display the file name header when outputting file contents.
    pub no_header: bool,

    /// Pipe the contents of each selected file to the standard input of this command.
    /// The command will be executed as `$SHELL -c <EXEC>`.
    pub exec: Option<&'a str>,
}

#[derive(Debug)]
struct LogFile {
    path: String,
    sled_uuid: String,
    service: Option<String>,
    zone: Option<String>,
    timestamp: Option<i64>,
}

impl LogFile {
    fn from_path(path: &str) -> Option<Self> {
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

    /// Extract trailing timestamp from paths with a file name like: "oxide-mg-ddm:default.log.1758510604".
    fn extract_timestamp(path: &str) -> Option<i64> {
        let suffix = path.split('.').next_back()?;

        suffix.parse::<i64>().ok()
    }

    fn matches_services(&self, service_patterns: &[Pattern]) -> bool {
        // Match all files if unspecified.
        if service_patterns.is_empty() {
            return true;
        }

        let Some(service) = &self.service else {
            return false;
        };
        service_patterns.iter().any(|p| p.matches(service))
    }

    fn matches_zones(&self, zone_patterns: &[Pattern]) -> bool {
        // Match all files if unspecified.
        if zone_patterns.is_empty() {
            return true;
        }

        let Some(zone) = &self.zone else {
            return false;
        };
        zone_patterns.iter().any(|p| p.matches(zone))
    }

    fn matches_paths(&self, path_patterns: &[Pattern]) -> bool {
        // Match all files if unspecified.
        if path_patterns.is_empty() {
            return true;
        }
        path_patterns.iter().any(|p| p.matches(&self.path))
    }
}

/// An Oxide support bundle.
pub struct Bundle<S> {
    info: BundleInfo,
    source: RefCell<S>,
}

impl<R: Read + Seek> Bundle<ZipBundleSource<R>> {
    /// Construct a `Bundle` from a `ZipArchive`.
    pub fn from_archive(archive: ZipArchive<R>) -> Result<Self> {
        Self::from_source(ZipBundleSource::from_archive(archive)?)
    }
}

impl Bundle<DirectoryBundleSource> {
    /// Construct a `Bundle` from an unpacked directory tree.
    pub fn open_dir(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_source(DirectoryBundleSource::open(path)?)
    }
}

impl<S: BundleSource> Bundle<S> {
    /// Construct a `Bundle` from a bundle source.
    pub fn from_source(mut source: S) -> Result<Self> {
        let info = BundleInfo::from_source(&mut source)?;
        Ok(Self {
            info,
            source: RefCell::new(source),
        })
    }

    /// List all ereports in the archive.
    pub fn ereports_list<W: Write>(&self, components: ComponentInfo<'_>, mut out: W) -> Result<()> {
        let source = &mut self.source.borrow_mut();

        let ereports: Vec<_> = source
            .file_names()
            .into_iter()
            .filter_map(|path| {
                let ereport = Ereport::from_path(&path)?;

                if matches_patterns(components.part, &ereport.part)
                    && matches_patterns(components.serial, &ereport.serial)
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
            let contents = read_file_to_string(&mut file, &path)?;
            let ereport_class = read_ereport_class(&contents);

            if let Some(ereport_class) = ereport_class
                && !matches_patterns(components.class, ereport_class)
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
                ereport_class.unwrap_or("unknown"),
            )?;
        }

        Ok(())
    }

    /// Display all ereports matching the filter criteria.
    pub fn ereports_show<W: Write>(
        &self,
        components: ComponentInfo<'_>,
        no_header: bool,
        mut out: W,
    ) -> Result<()> {
        let source = &mut self.source.borrow_mut();
        let matching_reports: Vec<_> = source
            .file_names()
            .into_iter()
            .filter_map(|path| {
                let ereport = Ereport::from_path(&path)?;

                if matches_patterns(components.part, &ereport.part)
                    && matches_patterns(components.serial, &ereport.serial)
                {
                    Some((path, ereport))
                } else {
                    None
                }
            })
            .collect();

        for (path, _ereport) in matching_reports {
            let mut file = source
                .open_file(&path)
                .with_context(|| format!("failed to open {path}"))?;

            let contents = read_file_to_string(&mut file, &path)?;

            if let Some(ereport_class) = read_ereport_class(&contents)
                && !matches_patterns(components.class, ereport_class)
            {
                continue;
            }

            if !no_header {
                writeln!(out, "==> {path} <==")?;
            }

            if let Ok(json) = serde_json::from_str::<Value>(&contents)
                && let Ok(pretty) = serde_json::to_string_pretty(&json)
            {
                writeln!(out, "{pretty}")?;
            } else {
                out.write_all(contents.as_bytes())?;
            }

            if !no_header {
                writeln!(out)?;
            }
        }

        Ok(())
    }

    /// Display all logs in the archive matching the filter criteria.
    pub fn logs<W: Write + Send>(
        &self,
        filter: LogFilter<'_>,
        time: TimeRange,
        output: LogOutput<'_>,
        mut out: W,
    ) -> Result<()> {
        let source = &mut self.source.borrow_mut();
        let matching_files: Vec<_> = source
            .file_names()
            .into_iter()
            .filter_map(|path| {
                let log_file = LogFile::from_path(&path)?;

                let sled_info = self
                    .info
                    .sleds
                    .get(&log_file.sled_uuid)
                    .expect("BUG: UUID was not found in collected sled info");

                if sled_info.matches_patterns(filter.sled)
                    && log_file.matches_services(filter.service)
                    && log_file.matches_zones(filter.zone)
                    && log_file.matches_paths(filter.path)
                {
                    Some((path, log_file))
                } else {
                    None
                }
            })
            .collect();

        for (path, log) in matching_files {
            let metadata = time
                .is_set()
                .then(|| source.metadata(&path))
                .transpose()
                .with_context(|| format!("failed to read metadata for {path}"))?;
            let mut file = source
                .open_file(&path)
                .with_context(|| format!("failed to open {path}"))?;

            let time_check_buf = if time.is_set() {
                const TIME_CHECK_MAX: u64 = 1 << 16;
                let mut tc = Vec::with_capacity(
                    metadata
                        .as_ref()
                        .and_then(|metadata| metadata.len)
                        .unwrap_or(TIME_CHECK_MAX)
                        .min(TIME_CHECK_MAX) as usize,
                );
                file.by_ref()
                    .take(TIME_CHECK_MAX)
                    .read_to_end(&mut tc)
                    .with_context(|| format!("failed to read file {path}"))?;

                // Try several methods of finding the log's timeframe, in order of decreasing accuracy:
                // 1. Try to find a valid timestamp from the first 64k of the file.
                // 2. Check for a the timestamp appended to the file name, only available for archived
                //    logs.
                // 3. Check the file's mtime in the zip, which will be available with R17.
                // In all cases ignore times from before 2001, and skip any file where we cannot find a
                // valid time.
                let ts = read_timestamp_from_contents(&tc)
                    .or_else(|| {
                        let ts = log.timestamp?;
                        Timestamp::from_second(ts).ok()
                    })
                    .or_else(|| metadata.as_ref()?.modified);

                if !ts.is_some_and(|ts| time.contains(ts)) {
                    continue;
                }

                // Only retain buffer if we'll need it for output
                (!output.list).then_some(tc)
            } else {
                None
            };

            if output.list {
                writeln!(out, "{path}")?;
                continue;
            }

            if !output.no_header {
                writeln!(out, "==> {path} <==")?;
            }

            if let Some(exec) = output.exec {
                let shell = std::env::var("SHELL").unwrap_or("/bin/sh".to_string());
                let mut child = Command::new(&shell)
                    .arg("-c")
                    .arg(exec)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()?;

                let mut child_in = child.stdin.take().unwrap();
                let mut child_out = child.stdout.take().unwrap();

                let copy_result = thread::scope(|s| {
                    let out_writer = s.spawn(|| io::copy(&mut child_out, &mut out));

                    let in_result = write_file_content(
                        &time_check_buf,
                        &mut file,
                        &mut child_in,
                        output.line_ct.map(|l| l.get()),
                    );
                    drop(child_in); // EOF.

                    let out_result = out_writer.join().unwrap();
                    in_result.and(out_result)
                });
                copy_result?;

                let status = child.wait()?;
                if !status.success() {
                    anyhow::bail!("command '{exec}' exited with {status}");
                }
            } else {
                write_file_content(
                    &time_check_buf,
                    &mut file,
                    &mut out,
                    output.line_ct.map(|l| l.get()),
                )?;
            }

            if !output.no_header {
                writeln!(out)?;
            }
        }

        Ok(())
    }

    /// List all services with logs present in the archive.
    pub fn services<W: Write>(&self, sled: &[Pattern], mut out: W) -> Result<()> {
        let services: BTreeSet<_> = self
            .info
            .sleds
            .values()
            .filter(|s| s.matches_patterns(sled))
            .flat_map(|s| &s.services)
            .collect();

        for service in services {
            writeln!(out, "{service}")?;
        }

        Ok(())
    }

    /// List all sleds shown in the bundle's inventory.
    pub fn sleds<W: Write>(&self, mut out: W) -> Result<()> {
        let mut by_cubby: Vec<_> = self.info.sleds.values().collect();
        by_cubby.sort_by(|a, b| a.cubby.cmp(&b.cubby));

        writeln!(
            out,
            "{:>2}\t{:<11}\t{:<36}\tSCRIMLET",
            "CUBBY", "SERIAL", "ID"
        )?;
        for sled in by_cubby {
            let cubby = sled.cubby.map(|c| c.to_string()).unwrap_or_default();
            writeln!(
                out,
                "{:>2}\t{}\t{}\t{:>8}",
                cubby, sled.serial, sled.uuid, sled.is_scrimlet
            )?;
        }

        let mut unhealthy_by_cubby: Vec<_> = self.info.unhealthy_sleds.iter().collect();
        unhealthy_by_cubby.sort_by(|(_, a), (_, b)| a.cmp(b));

        if !unhealthy_by_cubby.is_empty() {
            writeln!(out, "\nUNHEALTHY SLEDS\n{:>2}\tSERIAL", "CUBBY")?;
            for (serial, cubby) in unhealthy_by_cubby {
                let cubby = cubby.map(|c| c.to_string()).unwrap_or_default();
                writeln!(out, "{:>2}\t{}", cubby, serial,)?;
            }
        }

        let incomplete: Vec<_> = self
            .info
            .sleds
            .values()
            .filter(|s| s.services.is_empty() || s.zones.is_empty())
            .collect();

        if !incomplete.is_empty() {
            writeln!(
                out,
                "\nPOSSIBLY UNREACHABLE SLEDS \n{:>2}\t{:<11}\t{:<36}\tMISSING BUNDLE OUTPUT",
                "CUBBY", "SERIAL", "ID"
            )?;
            for sled in &incomplete {
                let cubby = sled.cubby.map(|c| c.to_string()).unwrap_or_default();
                let missing = match (sled.services.is_empty(), sled.zones.is_empty()) {
                    (true, true) => "services, zones",
                    (true, false) => "services",
                    (false, true) => "zones",
                    _ => unreachable!(),
                };
                writeln!(
                    out,
                    "{:>2}\t{}\t{}\t{}",
                    cubby, sled.serial, sled.uuid, missing
                )?;
            }
        }

        Ok(())
    }

    /// List all zones found in the archive.
    pub fn zones<W: Write>(&self, sled: &[Pattern], mut out: W) -> Result<()> {
        let zones: BTreeSet<_> = self
            .info
            .sleds
            .values()
            .filter(|s| s.matches_patterns(sled))
            .flat_map(|s| &s.zones)
            .collect();

        for zone in zones {
            writeln!(out, "{zone}")?;
        }

        Ok(())
    }
}

#[derive(Debug)]
struct BundleInfo {
    sleds: BTreeMap<String, SledInfo>,
    unhealthy_sleds: BTreeMap<String, Option<u16>>,
}

impl BundleInfo {
    fn from_source<S: BundleSource>(source: &mut S) -> Result<Self> {
        let mut sled_txt_paths = Vec::with_capacity(32);

        let mut sleds = BTreeMap::new();
        let mut sled_services: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut sled_zones: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        let names = source.file_names();
        for name in &names {
            // rack/{rack_uuid}/sled/{sled_uuid}/logs/{zone}/{service}/...
            let splits: Vec<_> = name.split('/').collect();
            let is_log_file = !name.ends_with('/')
                && splits.first() == Some(&"rack")
                && splits.get(2) == Some(&"sled")
                && splits.get(4) == Some(&"logs");

            // Infer inventory only from descendants. Directory sources do not list
            // directories, and empty ZIP directories must not count.
            if is_log_file
                && let (Some(sled_uuid), Some(zone), Some(service), Some(descendant)) =
                    (splits.get(3), splits.get(5), splits.get(6), splits.get(7))
                && !sled_uuid.is_empty()
                && !zone.is_empty()
                && !service.is_empty()
                && !descendant.is_empty()
            {
                sled_zones
                    .entry((*sled_uuid).to_string())
                    .or_default()
                    .insert((*zone).to_string());
                sled_services
                    .entry((*sled_uuid).to_string())
                    .or_default()
                    .insert((*service).to_string());
            }

            if splits.first() == Some(&"rack")
                && splits.get(2) == Some(&"sled")
                && splits.get(4) == Some(&"sled.txt")
                && splits.len() == 5
            {
                sled_txt_paths.push(name.clone());
            }
        }

        for path in sled_txt_paths {
            let mut file = source
                .open_file(&path)
                .with_context(|| format!("failed to open {path}"))?;
            let contents = read_file_to_string(&mut file, &path)?;
            let (serial, is_scrimlet) = read_sled_serial(&contents)
                .ok_or_else(|| anyhow::anyhow!("failed to parse sled serial from {path}"))?;

            // UNWRAP: We've confirmed above that the split length is five.
            let uuid = path.split('/').nth(3).unwrap().to_string();

            let services = sled_services
                .remove(&uuid)
                .unwrap_or_default()
                .into_iter()
                .collect();
            let zones = sled_zones
                .remove(&uuid)
                .unwrap_or_default()
                .into_iter()
                .collect();

            let sled_info = SledInfo {
                uuid: uuid.clone(),
                cubby: None,
                serial,
                services,
                zones,
                is_scrimlet,
            };

            sleds.insert(uuid, sled_info);
        }

        let mut unhealthy_sleds = BTreeMap::new();
        if names.iter().any(|name| name == "sled_info.json") {
            let mut sled_info = source
                .open_file("sled_info.json")
                .context("failed to open sled_info.json")?;
            #[derive(Deserialize, Debug)]
            struct SledId {
                cubby: Option<u16>,
                uuid: Option<String>,
            }

            let mut contents = Vec::new();
            sled_info
                .read_to_end(&mut contents)
                .context("failed to read sled_info.json")?;
            match serde_json::from_slice::<BTreeMap<String, SledId>>(&contents) {
                Ok(cubby_info) => {
                    for (serial, id) in cubby_info.into_iter() {
                        if let Some(uuid) = id.uuid {
                            // UUIDs are from Nexus, we will always have an existing entry.
                            if let Some(sled) = sleds.get_mut(&uuid) {
                                sled.cubby = id.cubby;
                            }
                        } else {
                            // Sleds unknown to Nexus will have their serial and cubby from MGS.
                            unhealthy_sleds.insert(serial, id.cubby);
                        }
                    }
                }
                Err(e) => writeln!(io::stderr(), "Failed to parse sled_info.json: {e}")?,
            }
        }

        Ok(BundleInfo {
            sleds,
            unhealthy_sleds,
        })
    }
}

fn read_file_to_string(file: &mut dyn Read, path: &str) -> Result<String> {
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .with_context(|| format!("failed to read contents of {path}"))?;
    String::from_utf8(buf).with_context(|| format!("contents of {path} were not valid UTF-8"))
}

fn read_sled_serial(sled_info: &str) -> Option<(String, bool)> {
    const SERIAL_PREFIX: &str = " serial_number: \"";
    let serial_start = sled_info.find(SERIAL_PREFIX)? + SERIAL_PREFIX.len();
    let serial_end = serial_start + sled_info[serial_start..].find("\"")?;

    const SCRIMLET_PREFIX: &str = " is_scrimlet: ";
    let scrimlet_start = sled_info.find(SCRIMLET_PREFIX)? + SCRIMLET_PREFIX.len();
    let scrimlet_end = scrimlet_start + sled_info[scrimlet_start..].find(",")?;
    let is_scrimlet = sled_info[scrimlet_start..scrimlet_end].parse().ok()?;

    Some((sled_info[serial_start..serial_end].to_string(), is_scrimlet))
}

#[derive(PartialEq, Debug)]
struct SledInfo {
    uuid: String,
    cubby: Option<u16>,
    serial: String,
    zones: Vec<String>,
    services: Vec<String>,
    is_scrimlet: bool,
}

impl PartialOrd for SledInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.uuid.partial_cmp(&other.uuid)
    }
}

impl SledInfo {
    pub fn matches_patterns(&self, patterns: &[Pattern]) -> bool {
        // Match all sleds if unspecified.
        if patterns.is_empty() {
            return true;
        }
        patterns.iter().any(|p| {
            // If the pattern can be parsed into a digit, it must be an cubby number.
            // All valid serials and UUIDs will fail to parse, as will any wildcard
            // patterns that are only numbers.
            if let Some(cubby) = self.cubby
                && let Ok(requested_cubby) = p.as_str().parse::<u16>()
            {
                requested_cubby == cubby
            } else {
                p.matches(&self.uuid) || p.matches(&self.serial)
            }
        })
    }
}

#[derive(PartialEq, Debug)]
struct Ereport {
    part: String,
    serial: String,
    restart_id: String,
    ena: u64,
}

impl Ereport {
    fn from_path(path: &str) -> Option<Self> {
        // ereports/{part-number}-{serial_number}/{restart_id}/{ENA}.json
        if !path.starts_with("ereports") {
            return None;
        }

        let splits: Vec<_> = path.split('/').collect();
        if splits.len() < 4 {
            return None;
        }

        // Part numbers contain a '-', but serials do not, at least currently.
        // Split from the right to ensure we're finding the boundary between the two.
        let (part, serial) = splits[1].rsplit_once('-')?;
        let restart_id = splits[2].to_string();
        let file_name = splits[3];
        let ena = file_name
            .strip_suffix(".json")
            .and_then(|n| n.parse::<u64>().ok())?;

        Some(Ereport {
            part: part.to_string(),
            serial: serial.to_string(),
            restart_id,
            ena,
        })
    }
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

/// Minimal struct to grab the timestamp from a JSON log event.
#[derive(Deserialize, Default, Debug)]
struct LogTimestamp {
    time: Timestamp,
}

fn write_file_content<R: Read, W: Write>(
    time_check_buf: &Option<Vec<u8>>,
    file: &mut R,
    out: &mut W,
    line_ct: Option<usize>,
) -> io::Result<()> {
    if let Some(line_ct) = line_ct {
        let (cached_lines, ending_offset) = time_check_buf
            .as_ref()
            .map(|tc| {
                let mut cached = 0;
                let mut end = 0;
                for i in tc.find_iter(b"\n").take(line_ct) {
                    cached += 1;
                    end = i;
                }
                (cached, end)
            })
            .unwrap_or((0, 0));

        match time_check_buf {
            Some(tc) if cached_lines == line_ct => out.write_all(&tc[..=ending_offset])?,
            Some(tc) => {
                out.write_all(tc)?;
                write_n_lines(file, out, line_ct - cached_lines)?;
            }
            None => write_n_lines(file, out, line_ct)?,
        }
    } else {
        if let Some(tc) = time_check_buf {
            out.write_all(tc)?;
        }
        io::copy(file, out)?;
    }
    Ok(())
}

fn write_n_lines<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    line_ct: usize,
) -> io::Result<()> {
    if line_ct == 0 {
        return Ok(());
    }

    let mut count = 0;
    let mut buf = [0u8; 8192];

    loop {
        let bytes_read = reader.read(&mut buf)?;
        if bytes_read == 0 {
            return Ok(());
        }

        let chunk = &buf[..bytes_read];

        for byte_pos in chunk.find_iter(b"\n") {
            count += 1;
            if count == line_ct {
                writer.write_all(&chunk[..=byte_pos])?;
                return Ok(());
            }
        }

        writer.write_all(chunk)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use insta::assert_snapshot;
    use serde_json::json;
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::{CompressionMethod, DateTime};

    use std::fs::{self, FileTimes};
    use std::io::Cursor;
    use std::rc::Rc;
    use std::str::FromStr;

    const TEST_RACK: &str = "34261901-b550-451c-9bd0-3926bb29c40d";
    const TEST_SLED: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    #[derive(Default)]
    struct MemorySource {
        files: BTreeMap<String, Vec<u8>>,
        events: Option<Rc<RefCell<Vec<String>>>>,
        modified: Option<Timestamp>,
    }

    impl MemorySource {
        fn bundle() -> Self {
            let sled_path = format!("rack/{TEST_RACK}/sled/{TEST_SLED}/sled.txt");
            let log_path = format!(
                "rack/{TEST_RACK}/sled/{TEST_SLED}/logs/global/sled-agent/current/oxide-sled-agent:default.log"
            );
            let sled =
                r#"Sled { is_scrimlet: false, serial_number: "BRM99990001", ignored: true }"#
                    .to_string();
            Self {
                files: BTreeMap::from([
                    (sled_path, sled.into_bytes()),
                    (
                        log_path,
                        b"{\"time\":\"2025-09-24T06:30:00Z\",\"msg\":\"complete\"}\nsecond line\n"
                            .to_vec(),
                    ),
                ]),
                ..Default::default()
            }
        }
    }

    impl BundleSource for MemorySource {
        fn file_names(&self) -> Vec<String> {
            self.files.keys().cloned().collect()
        }

        fn open_file<'a>(&'a mut self, path: &str) -> Result<Box<dyn Read + 'a>> {
            if let Some(events) = &self.events {
                events.borrow_mut().push(format!("open:{path}"));
            }
            let contents = self
                .files
                .get(path)
                .with_context(|| format!("missing test file {path}"))?
                .clone();
            Ok(Box::new(Cursor::new(contents)))
        }

        fn metadata(&mut self, path: &str) -> Result<BundleFileMetadata> {
            if let Some(events) = &self.events {
                events.borrow_mut().push(format!("metadata:{path}"));
            }
            Ok(BundleFileMetadata {
                len: self.files.get(path).map(|contents| contents.len() as u64),
                modified: self.modified,
            })
        }
    }

    #[derive(Default)]
    struct ZipFile {
        name: &'static str,
        contents: Option<String>,
        mtime: Option<DateTime>,
    }

    fn zip_files() -> Vec<ZipFile> {
        vec![
            ZipFile {
                name: "ereports",
                ..Default::default()
            },
            ZipFile {
                name: "ereports/907-0000023-BRM03250000/",
                ..Default::default()
            },
            ZipFile {
                name: "ereports/907-0000023-BRM03250000/550e8400-e29b-41d4-a716-446655440000/",
                ..Default::default()
            },
            ZipFile {
                name: "ereports/907-0000023-BRM03250000/550e8400-e29b-41d4-a716-446655440000/305419896.json",
                contents: Some(
                    json!({
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
                    .to_string(),
                ),
                ..Default::default()
            },
            ZipFile {
                name: "ereports/913-0000019-BRM09250001/",
                ..Default::default()
            },
            ZipFile {
                name: "ereports/913-0000019-BRM09250001/660f9511-f3ac-52e5-b827-557766551111/",
                ..Default::default()
            },
            ZipFile {
                name: "ereports/913-0000019-BRM09250001/660f9511-f3ac-52e5-b827-557766551111/2596069104.json",
                contents: Some(
                    json!({
                      "restart_id": "660f9511-f3ac-52e5-b827-557766551111",
                      "ena": "0x000000009abcdef0",
                      "time_collected": "2025-10-11T14:45:22.456Z",
                      "time_deleted": "2025-10-11T15:00:00.000Z",
                      "collector_id": "8d4b9c01-e345-5678-90bc-def012345678",
                      "part_number": "913-0000019",
                      "serial_number": "BRM09250001",
                      "class": "ereport.cpu.amd.bus_interconnect_error",
                      "reporter": {
                        "HostOs": {
                          "sled": "9e5cad12-f456-6789-a1cd-ef0123456789"
                        }
                      },
                      "error_type": "bus_interconnect",
                      "cpu_id": 3,
                      "machine_check": {
                        "bank": 0,
                        "status": "0x1234567890abcdef"
                      }
                    })
                    .to_string(),
                ),
                ..Default::default()
            },
            ZipFile {
                name: "rack/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/archive/",
                ..Default::default()
            },
            // An archived log with all 1986 timestamps in its body. We should find this by the
            // file timestamp.
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/archive/oxide-dendrite:default.log.1758702600",
                contents: Some([
                    r#"{"msg":"loopback entry fd69:644c:516f:ee88::1 already set","v":0,"name":"dpd","level":20,"time":"1986-12-26T07:30:02.0679829Z","hostname":"oxz_switch","pid":1717}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068057082Z","hostname":"oxz_switch","pid":1717,"uri":"/loopback/ipv6","method":"POST","req_id":"ce63fccd-fb9e-4a99-a3a8-5c1677740099","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":92,"response_code":"204"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068201157Z","hostname":"oxz_switch","pid":1717,"uri":"/route/ipv4/0.0.0.0%2F0","method":"GET","req_id":"af76ae57-5dbf-42c2-91c7-9a376a779188","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":49,"response_code":"200"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068945446Z","hostname":"oxz_switch","pid":1717,"uri":"/ports/qsfp0/links/0","method":"GET","req_id":"d3df6b3b-48e8-4ffb-ab03-1fe07c5e0126","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":78,"response_code":"200"}"#
                ].join("\n").to_string()),
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/current/",
                ..Default::default()
            },
            // A current log with all 1986 timestamps in its body and a valid mtime.
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/current/oxide-dendrite:default.log",
                contents: Some([
                    r#"{"msg":"loopback entry fd69:644c:516f:ee88::1 already set","v":0,"name":"dpd","level":20,"time":"1986-12-26T07:30:02.0679829Z","hostname":"oxz_switch","pid":1717}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068057082Z","hostname":"oxz_switch","pid":1717,"uri":"/loopback/ipv6","method":"POST","req_id":"ce63fccd-fb9e-4a99-a3a8-5c1677740099","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":92,"response_code":"204"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068201157Z","hostname":"oxz_switch","pid":1717,"uri":"/route/ipv4/0.0.0.0%2F0","method":"GET","req_id":"af76ae57-5dbf-42c2-91c7-9a376a779188","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":49,"response_code":"200"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068945446Z","hostname":"oxz_switch","pid":1717,"uri":"/ports/qsfp0/links/0","method":"GET","req_id":"d3df6b3b-48e8-4ffb-ab03-1fe07c5e0126","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":78,"response_code":"200"}"#
                ].join("\n").to_string()),
                mtime: Some(DateTime::from_date_and_time(2025, 9, 24, 6, 30, 0).unwrap()),
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/sled.txt",
                contents: Some(r#"Sled { identity: SledIdentity { id: 690650fd-4f95-4b3a-b2ec-977d47154383, time_created: 2025-05-08T20:31:05.863348Z, time_modified: 2025-05-08T20:31:05.863348Z }, time_deleted: None, rcgen: Generation(Generation(21)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: true, serial_number: "BRM03250013", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:108::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:108::1:7, policy: InService, state: Active, sled_agent_gen: Generation(Generation(1)), repo_depot_port: SqlU16(12348) }"#.to_string()),
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/",
                ..Default::default()
            },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/archive/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/archive/oxide-sled-agent:default.log.1758382851",
                contents: Some(r#"{"msg":"accepted connection","v":0,"name":"SledAgent","level":30,"time":"2025-09-20T03:10:05.955267578Z","hostname":"BRM03250017","pid":653,"local_addr":"[fd00:1122:3344:10b::1]:12345","component":"dropshot (SledAgent)","file":"/home/build/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/dropshot-0.16.2/src/server.rs:1025","remote_addr":"[fd00:1122:3344:110::3]:58794"}"#.to_string()),
                ..Default::default()
            },
            // A log with its first valid timestamp in 1986, but subsequent lines with a good
            // time.
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/archive/oxide-sled-agent:default.log.1759246835",
                contents: Some([
                    r#"{"msg":"request completed","v":0,"name":"SledAgent","level":30,"time":"1986-12-28T03:10:06.955544333Z","hostname":"BRM03250017","pid":653,"uri":"/vmms/6534d5a9-a7b7-4fc6-b593-c4fa2a1105bd/state","method":"GET","req_id":"28f129e9-8291-4f2a-a239-d86ae96baf49","remote_addr":"[fd00:1122:3344:110::3]:58794","local_addr":"[fd00:1122:3344:10b::1]:12345","component":"dropshot (SledAgent)","file":"/home/build/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/dropshot-0.16.2/src/server.rs:867","latency_us":162,"response_code":200}"#,
                    r#"{"msg":"request completed","v":0,"name":"SledAgent","level":30,"time":"2025-09-30T18:46:54.021483428Z","hostname":"BRM03250017","pid":653,"uri":"/vpc-routes","method":"GET","req_id":"0a7087c0-dec9-43f5-b0a3-a4567f73853a","remote_addr":"[fd00:1122:3344:10e::3]:42087","local_addr":"[fd00:1122:3344:10b::1]:12345","component":"dropshot (SledAgent)","file":"/home/build/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/dropshot-0.16.2/src/server.rs:867","latency_us":45,"response_code":200}"#,
                ].join("\n").to_string()),
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/current/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/current/oxide-sled-agent:default.log",
                contents: Some(r#"{"msg":"request completed","v":0,"name":"SledAgent","level":30,"time":"2025-10-05T16:13:17.955544333Z","hostname":"BRM03250017","pid":653,"uri":"/vmms/6534d5a9-a7b7-4fc6-b593-c4fa2a1105bd/state","method":"GET","req_id":"28f129e9-8291-4f2a-a239-d86ae96baf49","remote_addr":"[fd00:1122:3344:110::3]:58794","local_addr":"[fd00:1122:3344:10b::1]:12345","component":"dropshot (SledAgent)","file":"/home/build/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/dropshot-0.16.2/src/server.rs:867","latency_us":162,"response_code":200}"#.to_string()),
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_nexus_b48c76b6-656f-4258-862a-4d2a2b9abfc0/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_nexus_b48c76b6-656f-4258-862a-4d2a2b9abfc0/nexus/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_nexus_b48c76b6-656f-4258-862a-4d2a2b9abfc0/nexus/current/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_nexus_b48c76b6-656f-4258-862a-4d2a2b9abfc0/nexus/current/oxide-nexus:default.log",
                contents: Some(r#"{"msg":"client response","v":0,"name":"nexus","level":20,"time":"2025-09-24T09:00:01.813252417Z","hostname":"oxz_nexus_b48c76b6-656f-4258-862a-4d2a2b9abfc0","pid":10391,"gateway_url":"http://[fd00:1122:3344:108::2]:12225","background_task":"inventory_collection","component":"BackgroundTasks","component":"nexus","component":"ServerContext","name":"b48c76b6-656f-4258-862a-4d2a2b9abfc0","result":"Ok(Response { url: \"http://[fd00:1122:3344:108::2]:12225/sp/sled/20/component/rot/caboose?firmware_slot=1\", status: 200, headers: {\"content-type\": \"application/json\", \"x-request-id\": \"c41ca417-a096-458c-98c3-d0604e66d5a9\", \"content-length\": \"206\", \"date\": \"Wed, 24 Sep 2025 09:00:01 GMT\"} })"}"#.to_string()),
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_ntp_b4c60b54-c6e8-40e8-90f6-57a7ee2ce107/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_ntp_b4c60b54-c6e8-40e8-90f6-57a7ee2ce107/ntp/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_ntp_b4c60b54-c6e8-40e8-90f6-57a7ee2ce107/ntp/archive/",
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/oxz_ntp_b4c60b54-c6e8-40e8-90f6-57a7ee2ce107/ntp/archive/oxide-ntp:default.log.1758698540",
                contents: Some(r#"2025-09-24T05:58:09Z Selected source fd00:1122:3344:101::e (boundary-ntp.control-plane.oxide.internal)"#.to_string()),
                ..Default::default()
                },
            ZipFile {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/sled.txt",
                contents: Some(r#"Sled { identity: SledIdentity { id: f589c739-3c4c-4731-8f6f-41c8b2e72f89, time_created: 2025-05-08T20:31:07.381152Z, time_modified: 2025-09-22T15:44:13.232736Z }, time_deleted: None, rcgen: Generation(Generation(21)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: false, serial_number: "BRM03250017", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:10b::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:10b::1:8, policy: InService, state: Active, sled_agent_gen: Generation(Generation(3)), repo_depot_port: SqlU16(12348) }"#.to_string()),
                ..Default::default()
                },
            ZipFile {
                name: "sled_info.json",
                contents: Some(r##"{
  "BRM03250017": {
    "cubby": 8,
    "uuid": "f589c739-3c4c-4731-8f6f-41c8b2e72f89"
  },
  "BRM03250013": {
    "cubby": 14,
    "uuid": "690650fd-4f95-4b3a-b2ec-977d47154383"
  },
  "BRM03250666": {
    "cubby": 13,
    "uuid": null
  }
}"##.to_string()),
  ..Default::default()
            }
        ]
    }

    fn build_zip(buf: &mut Vec<u8>) -> ZipArchive<Cursor<&mut Vec<u8>>> {
        let mut zip = ZipWriter::new(Cursor::new(buf));

        for file in zip_files() {
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .last_modified_time(file.mtime.unwrap_or_default());
            if let Some(contents) = file.contents {
                zip.start_file(file.name, options).unwrap();
                zip.write_all(contents.as_bytes()).unwrap();
                zip.write_all(b"\n").unwrap();
            } else {
                zip.add_directory(file.name, options).unwrap();
            }
        }

        zip.finish_into_readable().unwrap()
    }

    fn build_directory(root: &Path) {
        for file in zip_files() {
            let path = root.join(file.name);
            if let Some(contents) = file.contents {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, [contents.as_bytes(), b"\n"].concat()).unwrap();

                let civil =
                    jiff::civil::DateTime::try_from(file.mtime.unwrap_or_default()).unwrap();
                let timestamp = civil.to_zoned(jiff::tz::TimeZone::UTC).unwrap().timestamp();
                fs::File::options()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_times(FileTimes::new().set_modified(timestamp.into()))
                    .unwrap();
            } else {
                fs::create_dir_all(path).unwrap();
            }
        }
    }

    #[derive(Debug, PartialEq)]
    struct RenderedBundle {
        sleds: Vec<u8>,
        services: Vec<u8>,
        zones: Vec<u8>,
        logs: Vec<u8>,
        logs_after: Vec<u8>,
        ereports_list: Vec<u8>,
        ereports_show: Vec<u8>,
    }

    fn render_bundle(bundle: &Bundle<Box<dyn BundleSource>>) -> RenderedBundle {
        let mut rendered = RenderedBundle {
            sleds: Vec::new(),
            services: Vec::new(),
            zones: Vec::new(),
            logs: Vec::new(),
            logs_after: Vec::new(),
            ereports_list: Vec::new(),
            ereports_show: Vec::new(),
        };

        bundle.sleds(&mut rendered.sleds).unwrap();
        bundle.services(&[], &mut rendered.services).unwrap();
        bundle.zones(&[], &mut rendered.zones).unwrap();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange::default(),
                LogOutput::default(),
                &mut rendered.logs,
            )
            .unwrap();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange {
                    after: Some("2025-09-24T06:00:00Z".parse().unwrap()),
                    ..Default::default()
                },
                LogOutput::default(),
                &mut rendered.logs_after,
            )
            .unwrap();
        bundle
            .ereports_list(ComponentInfo::default(), &mut rendered.ereports_list)
            .unwrap();
        bundle
            .ereports_show(ComponentInfo::default(), false, &mut rendered.ereports_show)
            .unwrap();

        rendered
    }

    #[test]
    fn zip_and_directory_sources_have_matching_text_output() {
        let mut buf = Vec::new();
        drop(build_zip(&mut buf));
        let zip_source: Box<dyn BundleSource> = Box::new(
            ZipBundleSource::from_archive(ZipArchive::new(Cursor::new(buf)).unwrap()).unwrap(),
        );

        let temp = tempfile::tempdir().unwrap();
        build_directory(temp.path());
        let directory_source: Box<dyn BundleSource> =
            Box::new(DirectoryBundleSource::open(temp.path()).unwrap());

        let zip_bundle = Bundle::from_source(zip_source).unwrap();
        let directory_bundle = Bundle::from_source(directory_source).unwrap();

        let zip_rendered = render_bundle(&zip_bundle);
        let directory_rendered = render_bundle(&directory_bundle);
        assert_eq!(zip_rendered, directory_rendered);
    }

    #[test]
    fn test_ereports_list() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let bundle = Bundle::from_archive(zip).unwrap();

        let mut unfiltered_out = Vec::new();
        bundle
            .ereports_list(ComponentInfo::default(), &mut unfiltered_out)
            .unwrap();
        assert_snapshot!(
            "ereport_list_unfiltered",
            String::from_utf8_lossy(&unfiltered_out)
        );

        let mut serial_out = Vec::new();
        bundle
            .ereports_list(
                ComponentInfo {
                    serial: &[Pattern::from_str("BRM09*").unwrap()],
                    ..Default::default()
                },
                &mut serial_out,
            )
            .unwrap();
        assert_snapshot!(
            "ereport_list_by_serial",
            String::from_utf8_lossy(&serial_out)
        );

        let mut part_out = Vec::new();
        bundle
            .ereports_list(
                ComponentInfo {
                    part: &[Pattern::from_str("907*").unwrap()],
                    ..Default::default()
                },
                &mut part_out,
            )
            .unwrap();
        assert_snapshot!("ereport_list_by_part", String::from_utf8_lossy(&part_out));

        let mut class_out = Vec::new();
        bundle
            .ereports_list(
                ComponentInfo {
                    class: &[Pattern::from_str("ereport.cpu*").unwrap()],
                    ..Default::default()
                },
                &mut class_out,
            )
            .unwrap();
        assert_snapshot!("ereport_list_by_class", String::from_utf8_lossy(&class_out));
    }

    #[test]
    fn test_ereports_show() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let bundle = Bundle::from_archive(zip).unwrap();

        let mut unfiltered_out = Vec::new();
        bundle
            .ereports_show(ComponentInfo::default(), false, &mut unfiltered_out)
            .unwrap();
        assert_snapshot!(
            "ereport_show_unfiltered",
            String::from_utf8_lossy(&unfiltered_out)
        );

        let mut no_header_out = Vec::new();
        bundle
            .ereports_show(ComponentInfo::default(), true, &mut no_header_out)
            .unwrap();
        assert_snapshot!(
            "ereport_show_no_header",
            String::from_utf8_lossy(&no_header_out)
        );

        let mut serial_out = Vec::new();
        bundle
            .ereports_show(
                ComponentInfo {
                    serial: &[Pattern::from_str("BRM09*").unwrap()],
                    ..Default::default()
                },
                false,
                &mut serial_out,
            )
            .unwrap();
        assert_snapshot!(
            "ereport_show_by_serial",
            String::from_utf8_lossy(&serial_out)
        );

        let mut part_out = Vec::new();
        bundle
            .ereports_show(
                ComponentInfo {
                    part: &[Pattern::from_str("907*").unwrap()],
                    ..Default::default()
                },
                false,
                &mut part_out,
            )
            .unwrap();
        assert_snapshot!("ereport_show_by_part", String::from_utf8_lossy(&part_out));

        let mut class_out = Vec::new();
        bundle
            .ereports_show(
                ComponentInfo {
                    class: &[Pattern::from_str("ereport.cpu*").unwrap()],
                    ..Default::default()
                },
                false,
                &mut class_out,
            )
            .unwrap();
        assert_snapshot!("ereport_show_by_class", String::from_utf8_lossy(&class_out));
    }

    #[test]
    fn test_logs() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let bundle = Bundle::from_archive(zip).unwrap();

        let mut unfiltered_out = Vec::new();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange::default(),
                LogOutput::default(),
                &mut unfiltered_out,
            )
            .unwrap();
        assert_snapshot!("logs_unfiltered", String::from_utf8_lossy(&unfiltered_out));

        let mut sled_out = Vec::new();
        bundle
            .logs(
                LogFilter {
                    sled: &[Pattern::from_str("BRM03250013").unwrap()],
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput::default(),
                &mut sled_out,
            )
            .unwrap();
        assert_snapshot!("logs_by_sled", String::from_utf8_lossy(&sled_out));

        let mut zone_out = Vec::new();
        bundle
            .logs(
                LogFilter {
                    zone: &[Pattern::from_str("oxz_switch").unwrap()],
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput::default(),
                &mut zone_out,
            )
            .unwrap();
        assert_snapshot!("logs_by_zone", String::from_utf8_lossy(&zone_out));

        let mut path_out = Vec::new();
        bundle
            .logs(
                LogFilter {
                    path: &[Pattern::from_str("*sled.txt").unwrap()],
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput::default(),
                &mut path_out,
            )
            .unwrap();
        assert_snapshot!("logs_by_path", String::from_utf8_lossy(&path_out));

        let mut after_out = Vec::new();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange {
                    after: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
                    ..Default::default()
                },
                LogOutput::default(),
                &mut after_out,
            )
            .unwrap();
        assert_snapshot!("logs_by_after", String::from_utf8_lossy(&after_out));

        let mut before_out = Vec::new();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange {
                    before: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
                    ..Default::default()
                },
                LogOutput::default(),
                &mut before_out,
            )
            .unwrap();
        assert_snapshot!("logs_by_before", String::from_utf8_lossy(&before_out));

        let mut list_out = Vec::new();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange::default(),
                LogOutput {
                    list: true,
                    ..Default::default()
                },
                &mut list_out,
            )
            .unwrap();
        assert_snapshot!("logs_list", String::from_utf8_lossy(&list_out));

        let mut line_ct_out = Vec::new();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange::default(),
                LogOutput {
                    line_ct: Some(NonZeroUsize::new(2).unwrap()),
                    ..Default::default()
                },
                &mut line_ct_out,
            )
            .unwrap();
        assert_snapshot!("logs_line_ct", String::from_utf8_lossy(&line_ct_out));

        let mut no_header_out = Vec::new();
        bundle
            .logs(
                LogFilter::default(),
                TimeRange::default(),
                LogOutput {
                    no_header: true,
                    ..Default::default()
                },
                &mut no_header_out,
            )
            .unwrap();
        assert_snapshot!("logs_no_header", String::from_utf8_lossy(&no_header_out));

        let mut exec_out = Vec::new();
        bundle
            .logs(
                LogFilter {
                    service: &[Pattern::new("dendrite").unwrap()],
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput {
                    exec: Some("jq -C ."),
                    ..Default::default()
                },
                &mut exec_out,
            )
            .unwrap();
        assert_snapshot!("logs_exec", String::from_utf8_lossy(&exec_out));

        let mut exec_head_out = Vec::new();
        bundle
            .logs(
                LogFilter {
                    service: &[Pattern::new("dendrite").unwrap()],
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput {
                    line_ct: Some(NonZeroUsize::new(2).unwrap()),
                    exec: Some("jq -C ."),
                    ..Default::default()
                },
                &mut exec_head_out,
            )
            .unwrap();
        assert_snapshot!("logs_exec_head", String::from_utf8_lossy(&exec_head_out));
    }

    #[test]
    fn test_services() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let bundle = Bundle::from_archive(zip).unwrap();

        let mut unfiltered_out = Vec::new();
        bundle.services(&[], &mut unfiltered_out).unwrap();
        assert_snapshot!(
            "services_unfiltered",
            String::from_utf8_lossy(&unfiltered_out)
        );

        let mut sled_uuid_out = Vec::new();
        bundle
            .services(&[Pattern::from_str("f589c*").unwrap()], &mut sled_uuid_out)
            .unwrap();
        assert_snapshot!("services_by_uuid", String::from_utf8_lossy(&sled_uuid_out));

        let mut sled_serial_out = Vec::new();
        bundle
            .services(
                &[Pattern::from_str("BRM03250013").unwrap()],
                &mut sled_serial_out,
            )
            .unwrap();
        assert_snapshot!(
            "services_by_serial",
            String::from_utf8_lossy(&sled_serial_out)
        );
    }

    #[test]
    fn test_sleds() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let bundle = Bundle::from_archive(zip).unwrap();

        let mut out = Vec::new();
        bundle.sleds(&mut out).unwrap();
        assert_snapshot!("sleds", String::from_utf8_lossy(&out));
    }

    #[test]
    fn test_zones() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let bundle = Bundle::from_archive(zip).unwrap();

        let mut unfiltered_out = Vec::new();
        bundle.zones(&[], &mut unfiltered_out).unwrap();
        assert_snapshot!("zones_unfiltered", String::from_utf8_lossy(&unfiltered_out));

        let mut sled_uuid_out = Vec::new();
        bundle
            .zones(&[Pattern::from_str("f589c*").unwrap()], &mut sled_uuid_out)
            .unwrap();
        assert_snapshot!("zones_by_uuid", String::from_utf8_lossy(&sled_uuid_out));

        let mut sled_serial_out = Vec::new();
        bundle
            .zones(
                &[Pattern::from_str("BRM03250013").unwrap()],
                &mut sled_serial_out,
            )
            .unwrap();
        assert_snapshot!("zones_by_serial", String::from_utf8_lossy(&sled_serial_out));
    }

    #[test]
    fn test_read_ereport_class() {
        let ereport_str = &zip_files()[3].contents.clone().unwrap();
        assert_eq!(
            read_ereport_class(ereport_str),
            Some("ereport.io.pci.device")
        );
    }

    /// Build a zip containing a sled with sled.txt but no logs/{zone}/{service} descendants
    #[test]
    fn test_incomplete_bundle_sled_no_services_or_zones() {
        let sled_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let sled_txt = format!(
            r#"Sled {{ identity: SledIdentity {{ id: {sled_uuid}, time_created: 2025-05-08T20:31:05.863348Z, time_modified: 2025-05-08T20:31:05.863348Z }}, time_deleted: None, rcgen: Generation(Generation(1)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: false, serial_number: "BRM99990001", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:108::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:108::1:7, policy: InService, state: Active, sled_agent_gen: Generation(Generation(1)), repo_depot_port: SqlU16(12348) }}"#
        );

        let sled_dir = format!("rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/{sled_uuid}/");
        let sled_txt_path =
            format!("rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/{sled_uuid}/sled.txt");

        let files: Vec<(&str, Option<&str>)> = vec![
            ("rack/", None),
            ("rack/34261901-b550-451c-9bd0-3926bb29c40d/", None),
            ("rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/", None),
            (&sled_dir, None),
            (&sled_txt_path, Some(sled_txt.as_str())),
        ];

        let mut buf = Vec::new();
        {
            let mut zip = ZipWriter::new(Cursor::new(&mut buf));
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            for (name, contents) in &files {
                if let Some(contents) = contents {
                    zip.start_file(*name, options).unwrap();
                    zip.write_all(contents.as_bytes()).unwrap();
                    zip.write_all(b"\n").unwrap();
                } else {
                    zip.add_directory(*name, options).unwrap();
                }
            }
            zip.finish().unwrap();
        }

        let cursor = Cursor::new(&mut buf);
        let archive = ZipArchive::new(cursor).unwrap();
        let bundle = Bundle::from_archive(archive).unwrap();

        let mut out = Vec::new();
        bundle.sleds(&mut out).unwrap();
        assert_snapshot!("sleds_incomplete_bundle", String::from_utf8_lossy(&out));
    }

    #[test]
    fn test_read_sled_txt() {
        const SCRIMLET_INFO: &str = r#"Sled { identity: SledIdentity { id: f589c739-3c4c-4731-8f6f-41c8b2e72f89, time_created: 2025-05-08T20:31:07.381152Z, time_modified: 2025-09-22T15:44:13.232736Z }, time_deleted: None, rcgen: Generation(Generation(21)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: true, serial_number: "BRM03250000", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:10b::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:10b::1:8, policy: InService, state: Active, sled_agent_gen: Generation(Generation(3)), repo_depot_port: SqlU16(12348) }"#;

        const SLED_INFO: &str = r#"Sled { identity: SledIdentity { id: f1e02cab-ef5a-4405-974c-f8cf7df7d4ea, time_created: 2025-05-08T20:31:06.943606Z, time_modified: 2025-05-08T20:31:06.943606Z }, time_deleted: None, rcgen: Generation(Generation(21)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: false, serial_number: "BRM03250001", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:102::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:102::1:3, policy: InService, state: Active, sled_agent_gen: Generation(Generation(1)), repo_depot_port: SqlU16(12348) }"#;

        assert_eq!(
            read_sled_serial(SCRIMLET_INFO),
            Some(("BRM03250000".to_string(), true))
        );
        assert_eq!(
            read_sled_serial(SLED_INFO),
            Some(("BRM03250001".to_string(), false))
        );
    }

    #[test]
    fn bundle_from_source_reads_inventory() {
        let bundle = Bundle::from_source(MemorySource::bundle()).unwrap();
        let mut out = Vec::new();
        bundle.services(&[], &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "sled-agent\n");
    }

    #[test]
    fn shallow_regular_log_path_does_not_infer_zone_or_service() {
        let mut source = MemorySource::bundle();
        source.files.retain(|path, _| path.ends_with("sled.txt"));
        source.files.insert(
            format!("rack/{TEST_RACK}/sled/{TEST_SLED}/logs/global/sled-agent"),
            Vec::new(),
        );

        let bundle = Bundle::from_source(source).unwrap();
        let mut zones = Vec::new();
        let mut services = Vec::new();
        bundle.zones(&[], &mut zones).unwrap();
        bundle.services(&[], &mut services).unwrap();

        assert!(zones.is_empty());
        assert!(services.is_empty());
    }

    #[test]
    fn empty_inventory_path_components_do_not_infer_zone_or_service() {
        let mut source = MemorySource::bundle();
        source.files.retain(|path, _| path.ends_with("sled.txt"));
        for path in ["logs//service/file", "logs/zone//file"] {
            source.files.insert(
                format!("rack/{TEST_RACK}/sled/{TEST_SLED}/{path}"),
                Vec::new(),
            );
        }

        let bundle = Bundle::from_source(source).unwrap();
        let mut zones = Vec::new();
        let mut services = Vec::new();
        bundle.zones(&[], &mut zones).unwrap();
        bundle.services(&[], &mut services).unwrap();

        assert!(zones.is_empty());
        assert!(services.is_empty());
    }

    #[test]
    fn bundle_open_dir_reads_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let source = MemorySource::bundle();
        for (name, contents) in source.files {
            let path = temp.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        let bundle = Bundle::open_dir(temp.path()).unwrap();
        let mut out = Vec::new();
        bundle.zones(&[], &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "global\n");
    }

    #[test]
    fn time_filtered_logs_fetch_metadata_before_open_and_write_complete_file_once() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut source = MemorySource::bundle();
        source.events = Some(Rc::clone(&events));
        let bundle = Bundle::from_source(source).unwrap();
        events.borrow_mut().clear();

        let mut out = Vec::new();
        bundle
            .logs(
                LogFilter {
                    service: &[Pattern::new("sled-agent").unwrap()],
                    ..Default::default()
                },
                TimeRange {
                    after: Some("2025-09-01T00:00:00Z".parse().unwrap()),
                    before: Some("2025-10-01T00:00:00Z".parse().unwrap()),
                },
                LogOutput {
                    no_header: true,
                    ..Default::default()
                },
                &mut out,
            )
            .unwrap();

        let log_path = format!(
            "rack/{TEST_RACK}/sled/{TEST_SLED}/logs/global/sled-agent/current/oxide-sled-agent:default.log"
        );
        assert_eq!(
            *events.borrow(),
            [format!("metadata:{log_path}"), format!("open:{log_path}")]
        );
        assert_eq!(
            out,
            b"{\"time\":\"2025-09-24T06:30:00Z\",\"msg\":\"complete\"}\nsecond line\n"
        );
    }

    #[test]
    fn log_timestamp_fallbacks_follow_content_filename_metadata_precedence() {
        let cases = [
            (
                "content timestamp",
                "test.log.1749945600",
                b"{\"time\":\"2024-06-15T00:00:00Z\"}\n".as_slice(),
                b"".as_slice(),
            ),
            (
                "filename timestamp",
                "test.log.1718409600",
                b"no timestamp\n".as_slice(),
                b"".as_slice(),
            ),
            (
                "metadata timestamp",
                "test.log",
                b"selected exactly once\n".as_slice(),
                b"selected exactly once\n".as_slice(),
            ),
        ];

        for (label, file_name, contents, expected) in cases {
            let sled_path = format!("rack/{TEST_RACK}/sled/{TEST_SLED}/sled.txt");
            let log_path = format!("rack/{TEST_RACK}/sled/{TEST_SLED}/logs/zone/test/{file_name}");
            let source = MemorySource {
                files: BTreeMap::from([
                    (
                        sled_path,
                        br#"Sled { is_scrimlet: false, serial_number: "BRM99990001" }"#.to_vec(),
                    ),
                    (log_path, contents.to_vec()),
                ]),
                modified: Some("2025-06-15T00:00:00Z".parse().unwrap()),
                ..Default::default()
            };
            let bundle = Bundle::from_source(source).unwrap();
            let mut out = Vec::new();

            bundle
                .logs(
                    LogFilter {
                        service: &[Pattern::new("test").unwrap()],
                        ..Default::default()
                    },
                    TimeRange {
                        after: Some("2025-01-01T00:00:00Z".parse().unwrap()),
                        before: Some("2026-01-01T00:00:00Z".parse().unwrap()),
                    },
                    LogOutput {
                        no_header: true,
                        ..Default::default()
                    },
                    &mut out,
                )
                .unwrap();

            assert_eq!(out, expected, "{label}");
        }
    }

    #[test]
    fn boxed_bundle_source_executes_existing_operation() {
        let source: Box<dyn BundleSource> = Box::new(MemorySource::bundle());
        let bundle = Bundle::from_source(source).unwrap();
        let mut out = Vec::new();
        bundle.services(&[], &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "sled-agent\n");
    }
}
