// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use bstr::ByteSlice;
use clap::{Args, Parser, Subcommand};
use glob::Pattern;
use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp};
use serde::Deserialize;
use serde_json::Value;
use zip::ZipArchive;
use zip::read::ZipFile;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process;
use std::str;

/// Ignore lines with timestamps from the previous millenium.
const JANUARY_1_2001: &Timestamp = &Timestamp::constant(978307200, 0);

#[derive(Parser, Debug)]
#[command(about = "Filter and extract logs from support bundles")]
struct Cli {
    /// Path to the support bundle zip file.
    zip_path: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List and display ereports.
    #[command(subcommand)]
    Ereports(EreportCmds),
    /// Filter for and print log files.
    Logs(LogsArgs),
    /// List services in the support bundle.
    Services(ServicesArgs),
    /// List sleds in the support bundle.
    Sleds,
    /// List zones in the support bundle.
    Zones(ZonesArgs),
}

#[derive(Subcommand, Debug)]
enum EreportCmds {
    /// List ereports.
    List(EreportListArgs),
    /// Display error reports.
    Show(EreportShowArgs),
}

#[derive(Args, Default, Debug)]
struct EreportListArgs {
    /// Part number glob patterns, (e.g., "123-0000456", "123-0004*").
    #[arg(short, long, value_name = "PART_PATTERN")]
    part: Vec<Pattern>,
    /// Serial number glob patterns, (e.g., "BRM03250000", "BRM0325*").
    #[arg(short, long, value_name = "SERIAL_PATTERN")]
    serial: Vec<Pattern>,
    /// Class glob patterns, (e.g., "hw.insert.psu", "hw.*").
    #[arg(short, long, value_name = "CLASS_PATTERN")]
    class: Vec<Pattern>,
}

#[derive(Args, Default, Debug)]
struct EreportShowArgs {
    /// Part number glob patterns, (e.g., "123-0000456", "123-0004*").
    #[arg(short, long, value_name = "PART_PATTERN")]
    part: Vec<Pattern>,
    /// Serial number glob patterns, (e.g., "BRM03250000", "BRM0325*").
    #[arg(short, long, value_name = "SERIAL_PATTERN")]
    serial: Vec<Pattern>,
    /// Class glob patterns, (e.g., "hw.insert.psu", "hw.*").
    #[arg(short, long, value_name = "CLASS_PATTERN")]
    class: Vec<Pattern>,
    /// Don't display the file name header when outputting file contents.
    #[arg(long)]
    no_header: bool,
}

#[derive(Args, Default, Debug)]
struct LogsArgs {
    /// Sled cubby number, serial number or UUID glob patterns (e.g., "16", "BRM032500*", "0f16e501-*").
    #[arg(short, long, value_name = "SLED_PATTERN")]
    sled: Vec<Pattern>,

    /// Service name glob patterns to filter (e.g., "mg-ddm", "ntp*").
    #[arg(short = 'S', long, value_name = "SERVICE_PATTERN")]
    service: Vec<Pattern>,

    /// Zone name glob patterns to filter (e.g., "oxz_switch", "oxz_nexus*").
    #[arg(short, long, value_name = "ZONE_PATTERN")]
    zone: Vec<Pattern>,

    /// File path glob patterns to filter (e.g., "bundle_id.txt", "*nvmeadm.json").
    #[arg(short, long, value_name = "PATH_PATTERN")]
    path: Vec<Pattern>,

    /// Only include archived files with timestamps after this time.
    #[arg(short = 'A', long, value_parser = parse_timestamp_now, value_name = "TIMESTAMP")]
    after: Option<Timestamp>,

    /// Only include archived files with timestamps before this time.
    #[arg(short = 'B', long, value_parser = parse_timestamp_now, value_name = "TIMESTAMP")]
    before: Option<Timestamp>,

    /// List matching files without printing their contents.
    #[arg(short, long)]
    list: bool,

    /// Number of lines to print from matching files.
    #[arg(short = 'L', long = "head", default_missing_value = "5", num_args = 0..=1)]
    line_ct: Option<NonZeroUsize>,

    /// Don't display the file name header when outputting file contents.
    #[arg(long)]
    no_header: bool,
}

#[derive(Args, Default, Debug)]
struct ServicesArgs {
    /// Sled cubby number, serial number or UUID glob patterns (e.g., "16", "BRM032500*", "0f16e501-*").
    #[arg(short, long, value_name = "SLED_PATTERN")]
    sled: Vec<Pattern>,
}

#[derive(Args, Default, Debug)]
struct ZonesArgs {
    /// Sled cubby number, serial number or UUID glob patterns (e.g., "16", "BRM032500*", "0f16e501-*").
    #[arg(short, long, value_name = "SLED_PATTERN")]
    sled: Vec<Pattern>,
}

fn parse_timestamp_now(date_str: &str) -> Result<Timestamp, anyhow::Error> {
    parse_timestamp(Timestamp::now(), date_str)
}

fn parse_timestamp(relative_to: Timestamp, date_str: &str) -> Result<Timestamp, anyhow::Error> {
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

fn main() {
    if let Err(e) = exec() {
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return;
        }

        let _ = writeln!(io::stderr(), "{e:#}");
        process::exit(1);
    }
}

fn exec() -> Result<()> {
    let args = Cli::parse();

    let file = File::open(&args.zip_path).with_context(|| {
        format!(
            "failed to open suppport bundle zip: {}",
            args.zip_path.display()
        )
    })?;
    let reader = BufReader::new(file);
    let mut archive = ZipArchive::new(reader).context("failed to read zip archive")?;

    let bundle_info = BundleInfo::from_archive(&mut archive)
        .context("failed to parse sled information from bundle")?;

    let stdout = io::stdout().lock();
    match &args.command {
        Commands::Ereports(EreportCmds::List(l)) => exec_ereports_list(&mut archive, l, stdout),
        Commands::Ereports(EreportCmds::Show(s)) => exec_ereports_show(&mut archive, s, stdout),

        Commands::Logs(l) => exec_logs(&mut archive, &bundle_info, l, stdout),
        Commands::Services(s) => exec_services(&bundle_info, s, stdout),
        Commands::Sleds => exec_sleds(&bundle_info, stdout),
        Commands::Zones(z) => exec_zones(&bundle_info, z, stdout),
    }
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

#[derive(Debug)]
struct BundleInfo {
    sleds: BTreeMap<String, SledInfo>,
    unhealthy_sleds: BTreeMap<String, Option<u16>>,
}

impl BundleInfo {
    fn from_archive<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<Self> {
        let mut sled_txt_indices = Vec::with_capacity(32);

        let mut sleds = BTreeMap::new();
        let mut sled_services = BTreeMap::new();
        let mut sled_zones = BTreeMap::new();

        let mut splits = Vec::with_capacity(10);
        for (i, name) in archive.file_names().enumerate() {
            splits.clear();

            // rack/{rack_uuid}/sled/{sled_uuid}/logs/{zone}/{service}/...
            splits.extend(name.split('/'));

            // The zone directory itself will have a length of 7, but we want zone directories that have at least one child.
            // Empty directories may exist for zones that don't actually exist on the sled, e.g., `oxz_switch`.
            if name.starts_with("rack") && splits.len() == 8 {
                let sled_uuid = splits[3];
                let zone = splits[5];

                let sled_entry = sled_zones.entry(sled_uuid).or_insert_with(BTreeSet::new);
                sled_entry.insert(zone);
            }

            if name.starts_with("rack") && splits.len() == 9 {
                let sled_uuid = splits[3];
                let service = splits[6];

                let sled_entry = sled_services.entry(sled_uuid).or_insert_with(BTreeSet::new);
                sled_entry.insert(service);
            }

            if name.starts_with("rack") && name.ends_with("sled.txt") && splits.len() == 5 {
                sled_txt_indices.push(i);
            }
        }

        let mut sled_services: BTreeMap<_, BTreeSet<_>> = sled_services
            .into_iter()
            .map(|(sled, services)| {
                (
                    sled.to_string(),
                    services.into_iter().map(|s| s.to_string()).collect(),
                )
            })
            .collect();
        let mut sled_zones: BTreeMap<_, BTreeSet<_>> = sled_zones
            .into_iter()
            .map(|(sled, zones)| {
                (
                    sled.to_string(),
                    zones.into_iter().map(|s| s.to_string()).collect(),
                )
            })
            .collect();

        for i in sled_txt_indices {
            let mut file = archive.by_index(i)?;

            let contents = read_file_to_string(&mut file)?;
            let (serial, is_scrimlet) = read_sled_serial(&contents).ok_or_else(|| {
                anyhow::anyhow!("failed to parse sled serial from {}", file.name())
            })?;

            // UNWRAP: We've confirmed above that the split length is five.
            let uuid = file.name().split('/').nth(3).unwrap().to_string();

            let services = sled_services
                .remove(&uuid)
                .expect("BUG: no services for sled")
                .into_iter()
                .collect();
            let zones = sled_zones
                .remove(&uuid)
                .expect("BUG: no zones for sled")
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
        if let Ok(mut sled_info) = archive.by_name("sled_info.json") {
            #[derive(Deserialize, Debug)]
            struct SledId {
                cubby: Option<u16>,
                uuid: Option<String>,
            }

            match serde_json::from_reader::<_, BTreeMap<String, SledId>>(&mut sled_info) {
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

fn read_file_to_string<R: Read>(file: &mut ZipFile<R>) -> Result<String> {
    let mut buf = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut buf)
        .with_context(|| format!("failed to read contents of {}", file.name()))?;
    String::from_utf8(buf)
        .with_context(|| format!("contents of {} were not valid UTF-8", file.name()))
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

fn exec_ereports_list<R: Read + Seek, W: Write>(
    archive: &mut ZipArchive<R>,
    args: &EreportListArgs,
    mut out: W,
) -> Result<()> {
    let ereports: Vec<_> = archive
        .file_names()
        .enumerate()
        .filter_map(|(i, path)| {
            let ereport = Ereport::from_path(path)?;

            if matches_patterns(&args.part, &ereport.part)
                && matches_patterns(&args.serial, &ereport.serial)
            {
                Some((i, ereport))
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
    for (i, ereport) in ereports {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("failed to access file index {i}"))?;
        let contents = read_file_to_string(&mut file)?;
        let class = read_ereport_class(&contents);

        if let Some(class) = class
            && !matches_patterns(&args.class, class)
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

fn exec_ereports_show<R: Read + Seek, W: Write>(
    archive: &mut ZipArchive<R>,
    args: &EreportShowArgs,
    mut out: W,
) -> Result<()> {
    let matching_reports: Vec<_> = archive
        .file_names()
        .enumerate()
        .filter_map(|(i, path)| {
            let ereport = Ereport::from_path(path)?;

            if matches_patterns(&args.part, &ereport.part)
                && matches_patterns(&args.serial, &ereport.serial)
            {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    for i in matching_reports {
        let mut file = archive
            .by_index(i)
            .with_context(|| format!("failed to access file index {i}"))?;

        let contents = read_file_to_string(&mut file)?;

        if let Some(class) = read_ereport_class(&contents)
            && !matches_patterns(&args.class, class)
        {
            continue;
        }

        if !args.no_header {
            writeln!(out, "==> {} <==", file.name())?;
        }

        if let Ok(json) = serde_json::from_str::<Value>(&contents)
            && let Ok(pretty) = serde_json::to_string_pretty(&json)
        {
            writeln!(out, "{pretty}")?;
        } else {
            out.write_all(contents.as_bytes())?;
        }

        if !args.no_header {
            writeln!(out)?;
        }
    }

    Ok(())
}

fn exec_logs<R: Read + Seek, W: Write>(
    archive: &mut ZipArchive<R>,
    bundle_info: &BundleInfo,
    args: &LogsArgs,
    mut out: W,
) -> Result<()> {
    let matching_files: Vec<_> = archive
        .file_names()
        .enumerate()
        .filter_map(|(i, name)| {
            let log_file = LogFile::from_path(name)?;

            let sled_info = bundle_info
                .sleds
                .get(&log_file.sled_uuid)
                .expect("BUG: UUID was not found in collected sled info");

            if sled_info.matches_patterns(&args.sled)
                && log_file.matches_services(&args.service)
                && log_file.matches_zones(&args.zone)
                && log_file.matches_paths(&args.path)
            {
                Some((i, log_file))
            } else {
                None
            }
        })
        .collect();

    for (i, log) in matching_files {
        let mut file = archive.by_index(i)?;

        let time_check_buf = if args.before.is_some() || args.after.is_some() {
            const TIME_CHECK_MAX: u64 = 1 << 16;
            let buf_size = file.size().min(TIME_CHECK_MAX) as usize;
            let mut tc = vec![0u8; buf_size];

            file.read_exact(&mut tc)
                .with_context(|| format!("failed to read file {}", file.name()))?;

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
                .or_else(|| {
                    let zip_time = file.last_modified()?;
                    let civil = jiff::civil::DateTime::try_from(zip_time).ok()?;
                    civil.in_tz("UTC").ok().map(|t| t.timestamp())
                });

            if !ts.map_or_else(
                || false,
                |ts| within_time_range(&ts, &args.before, &args.after),
            ) {
                continue;
            }

            // Only retain buffer if we'll need it for output
            (!args.list).then_some(tc)
        } else {
            None
        };

        if args.list {
            writeln!(out, "{}", file.name())?;
            continue;
        }

        if !args.no_header {
            writeln!(out, "==> {} <==", file.name())?;
        }

        if let Some(line_ct) = args.line_ct.map(|l| l.get()) {
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

            match &time_check_buf {
                Some(tc) if cached_lines == line_ct => out.write_all(&tc[..=ending_offset])?,
                Some(tc) => {
                    out.write_all(tc)?;
                    write_n_lines(&mut file, &mut out, line_ct - cached_lines)?;
                }
                None => write_n_lines(&mut file, &mut out, line_ct)?,
            }
        } else {
            if let Some(tc) = &time_check_buf {
                out.write_all(tc)?;
            }
            io::copy(&mut file, &mut out)?;
        }

        if !args.no_header {
            writeln!(out)?;
        }
    }

    Ok(())
}

fn within_time_range(
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

/// Minimal struct to grab the timestamp from a JSON log event.
#[derive(Deserialize, Default, Debug)]
struct LogTimestamp {
    time: Timestamp,
}

fn write_n_lines<R: Read, W: Write>(mut reader: R, mut writer: W, line_ct: usize) -> Result<()> {
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

fn exec_services<W: Write>(
    bundle_info: &BundleInfo,
    args: &ServicesArgs,
    mut out: W,
) -> Result<()> {
    let services: BTreeSet<_> = bundle_info
        .sleds
        .values()
        .filter(|s| s.matches_patterns(&args.sled))
        .flat_map(|s| &s.services)
        .collect();

    for service in services {
        writeln!(out, "{service}")?;
    }

    Ok(())
}

fn exec_sleds<W: Write>(bundle_info: &BundleInfo, mut out: W) -> Result<()> {
    let mut by_cubby: Vec<_> = bundle_info.sleds.values().collect();
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

    let mut unhealthy_by_cubby: Vec<_> = bundle_info.unhealthy_sleds.iter().collect();
    unhealthy_by_cubby.sort_by(|(_, a), (_, b)| a.cmp(b));

    if !unhealthy_by_cubby.is_empty() {
        writeln!(out, "\nUNHEALTHY SLEDS\n{:>2}\tSERIAL", "CUBBY")?;
        for (serial, cubby) in unhealthy_by_cubby {
            let cubby = cubby.map(|c| c.to_string()).unwrap_or_default();
            writeln!(out, "{:>2}\t{}", cubby, serial,)?;
        }
    }

    Ok(())
}

fn exec_zones<W: Write>(bundle_info: &BundleInfo, args: &ZonesArgs, mut out: W) -> Result<()> {
    let zones: BTreeSet<_> = bundle_info
        .sleds
        .values()
        .filter(|s| s.matches_patterns(&args.sled))
        .flat_map(|s| &s.zones)
        .collect();

    for zone in zones {
        writeln!(out, "{zone}")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use insta::assert_snapshot;
    use serde_json::json;
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::{CompressionMethod, DateTime};

    use std::io::Cursor;
    use std::str::FromStr;

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

    #[test]
    fn test_ereports_list() {
        let mut buf = Vec::new();
        let mut zip = build_zip(&mut buf);

        let mut unfiltered_out = Vec::new();
        exec_ereports_list(&mut zip, &EreportListArgs::default(), &mut unfiltered_out).unwrap();
        assert_snapshot!(
            "ereport_list_unfiltered",
            String::from_utf8_lossy(&unfiltered_out)
        );

        let mut serial_out = Vec::new();
        exec_ereports_list(
            &mut zip,
            &EreportListArgs {
                serial: vec![Pattern::from_str("BRM09*").unwrap()],
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
        exec_ereports_list(
            &mut zip,
            &EreportListArgs {
                part: vec![Pattern::from_str("907*").unwrap()],
                ..Default::default()
            },
            &mut part_out,
        )
        .unwrap();
        assert_snapshot!("ereport_list_by_part", String::from_utf8_lossy(&part_out));

        let mut class_out = Vec::new();
        exec_ereports_list(
            &mut zip,
            &EreportListArgs {
                class: vec![Pattern::from_str("ereport.cpu*").unwrap()],
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
        let mut zip = build_zip(&mut buf);

        let mut unfiltered_out = Vec::new();
        exec_ereports_show(&mut zip, &EreportShowArgs::default(), &mut unfiltered_out).unwrap();
        assert_snapshot!(
            "ereport_show_unfiltered",
            String::from_utf8_lossy(&unfiltered_out)
        );

        let mut no_header_out = Vec::new();
        exec_ereports_show(
            &mut zip,
            &EreportShowArgs {
                no_header: true,
                ..Default::default()
            },
            &mut no_header_out,
        )
        .unwrap();
        assert_snapshot!(
            "ereport_show_no_header",
            String::from_utf8_lossy(&no_header_out)
        );

        let mut serial_out = Vec::new();
        exec_ereports_show(
            &mut zip,
            &EreportShowArgs {
                serial: vec![Pattern::from_str("BRM09*").unwrap()],
                ..Default::default()
            },
            &mut serial_out,
        )
        .unwrap();
        assert_snapshot!(
            "ereport_show_by_serial",
            String::from_utf8_lossy(&serial_out)
        );

        let mut part_out = Vec::new();
        exec_ereports_show(
            &mut zip,
            &EreportShowArgs {
                part: vec![Pattern::from_str("907*").unwrap()],
                ..Default::default()
            },
            &mut part_out,
        )
        .unwrap();
        assert_snapshot!("ereport_show_by_part", String::from_utf8_lossy(&part_out));

        let mut class_out = Vec::new();
        exec_ereports_show(
            &mut zip,
            &EreportShowArgs {
                class: vec![Pattern::from_str("ereport.cpu*").unwrap()],
                ..Default::default()
            },
            &mut class_out,
        )
        .unwrap();
        assert_snapshot!("ereport_show_by_class", String::from_utf8_lossy(&class_out));
    }

    #[test]
    fn test_logs() {
        let mut buf = Vec::new();
        let mut zip = build_zip(&mut buf);
        let bundle_info = BundleInfo::from_archive(&mut zip).unwrap();

        let mut unfiltered_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs::default(),
            &mut unfiltered_out,
        )
        .unwrap();
        assert_snapshot!("logs_unfiltered", String::from_utf8_lossy(&unfiltered_out));

        let mut sled_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                sled: vec![Pattern::from_str("BRM03250013").unwrap()],
                ..Default::default()
            },
            &mut sled_out,
        )
        .unwrap();
        assert_snapshot!("logs_by_sled", String::from_utf8_lossy(&sled_out));

        let mut zone_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                zone: vec![Pattern::from_str("oxz_switch").unwrap()],
                ..Default::default()
            },
            &mut zone_out,
        )
        .unwrap();
        assert_snapshot!("logs_by_zone", String::from_utf8_lossy(&zone_out));

        let mut path_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                path: vec![Pattern::from_str("*sled.txt").unwrap()],
                ..Default::default()
            },
            &mut path_out,
        )
        .unwrap();
        assert_snapshot!("logs_by_path", String::from_utf8_lossy(&path_out));

        let mut after_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                after: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
                ..Default::default()
            },
            &mut after_out,
        )
        .unwrap();
        assert_snapshot!("logs_by_after", String::from_utf8_lossy(&after_out));

        let mut before_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                before: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
                ..Default::default()
            },
            &mut before_out,
        )
        .unwrap();
        assert_snapshot!("logs_by_before", String::from_utf8_lossy(&before_out));

        let mut list_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                list: true,
                ..Default::default()
            },
            &mut list_out,
        )
        .unwrap();
        assert_snapshot!("logs_list", String::from_utf8_lossy(&list_out));

        let mut line_ct_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                line_ct: Some(NonZeroUsize::new(2).unwrap()),
                ..Default::default()
            },
            &mut line_ct_out,
        )
        .unwrap();
        assert_snapshot!("logs_line_ct", String::from_utf8_lossy(&line_ct_out));

        let mut no_header_out = Vec::new();
        exec_logs(
            &mut zip,
            &bundle_info,
            &LogsArgs {
                no_header: true,
                ..Default::default()
            },
            &mut no_header_out,
        )
        .unwrap();
        assert_snapshot!("logs_no_header", String::from_utf8_lossy(&no_header_out));
    }

    #[test]
    fn test_services() {
        let mut buf = Vec::new();
        let mut zip = build_zip(&mut buf);
        let bundle_info = BundleInfo::from_archive(&mut zip).unwrap();

        let mut unfiltered_out = Vec::new();
        exec_services(&bundle_info, &ServicesArgs::default(), &mut unfiltered_out).unwrap();
        assert_snapshot!(
            "services_unfiltered",
            String::from_utf8_lossy(&unfiltered_out)
        );

        let mut sled_uuid_out = Vec::new();
        exec_services(
            &bundle_info,
            &ServicesArgs {
                sled: vec![Pattern::from_str("f589c*").unwrap()],
            },
            &mut sled_uuid_out,
        )
        .unwrap();
        assert_snapshot!("services_by_uuid", String::from_utf8_lossy(&sled_uuid_out));

        let mut sled_serial_out = Vec::new();
        exec_services(
            &bundle_info,
            &ServicesArgs {
                sled: vec![Pattern::from_str("BRM03250013").unwrap()],
            },
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
        let mut zip = build_zip(&mut buf);
        let bundle_info = BundleInfo::from_archive(&mut zip).unwrap();

        let mut out = Vec::new();
        exec_sleds(&bundle_info, &mut out).unwrap();
        assert_snapshot!("sleds", String::from_utf8_lossy(&out));
    }

    #[test]
    fn test_zones() {
        let mut buf = Vec::new();
        let mut zip = build_zip(&mut buf);
        let bundle_info = BundleInfo::from_archive(&mut zip).unwrap();

        let mut unfiltered_out = Vec::new();
        exec_zones(&bundle_info, &ZonesArgs::default(), &mut unfiltered_out).unwrap();
        assert_snapshot!("zones_unfiltered", String::from_utf8_lossy(&unfiltered_out));

        let mut sled_uuid_out = Vec::new();
        exec_zones(
            &bundle_info,
            &ZonesArgs {
                sled: vec![Pattern::from_str("f589c*").unwrap()],
            },
            &mut sled_uuid_out,
        )
        .unwrap();
        assert_snapshot!("zones_by_uuid", String::from_utf8_lossy(&sled_uuid_out));

        let mut sled_serial_out = Vec::new();
        exec_zones(
            &bundle_info,
            &ZonesArgs {
                sled: vec![Pattern::from_str("BRM03250013").unwrap()],
            },
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
}
