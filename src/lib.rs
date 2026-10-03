// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use bstr::ByteSlice;
use flate2::bufread::DeflateDecoder;
use glob::Pattern;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use rawzip::{
    CompressionMethod, ReaderAt, ZipArchive, ZipArchiveEntryWayfinder, ZipFileHeaderRecord,
};
use serde::Deserialize;
use serde_json::Value;
use zstd::zstd_safe::{DCtx, ResetDirective};

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader, Read, Write};
use std::num::NonZeroUsize;
use std::process::{Command, Stdio};
use std::str;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

/// Ignore lines with timestamps from the previous millenium.
const JANUARY_1_2001: &Timestamp = &Timestamp::constant(978307200, 0);

/// How much of a log file to search for a timestamp.
const TIME_CHECK_MAX: u64 = 1 << 16;

/// How much of a log file to read first when searching it for a timestamp. Most logs have one on
/// their first line, so reading more is usually wasted.
const TIME_CHECK_STEP: u64 = 1 << 12;

/// The suffix of files compressed with zstd before being added to the bundle.
const ZSTD_SUFFIX: &str = ".zst";

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
    /// The command will be executed as '$SHELL -c <EXEC>'.
    pub exec: Option<&'a str>,
}

#[derive(Debug)]
struct LogFile<'a> {
    path: &'a str,
    sled_uuid: &'a str,
    service: Option<&'a str>,
    zone: Option<&'a str>,
    timestamp: Option<i64>,
}

impl<'a> LogFile<'a> {
    fn from_path(path: &'a str) -> Option<Self> {
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

        let sled_uuid = parts.get(3)?;

        let zone = parts.get(5).copied();
        let service = parts.get(6).copied();

        // Only archived logs have a trailing timestamp.
        let timestamp = Self::extract_timestamp(strip_zstd_suffix(path));

        Some(LogFile {
            path,
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

        // Match compressed files by their original name too, so that patterns like
        // "*default.log" find both old and new bundles' logs.
        let uncompressed = strip_zstd_suffix(self.path);
        path_patterns
            .iter()
            .any(|p| p.matches(self.path) || p.matches(uncompressed))
    }
}

/// The name a file had before it was compressed with zstd.
fn strip_zstd_suffix(path: &str) -> &str {
    path.strip_suffix(ZSTD_SUFFIX).unwrap_or(path)
}

/// The location of an entry's data within the archive, and how it is compressed.
#[derive(Clone, Copy, Debug)]
struct EntryLoc {
    wayfinder: ZipArchiveEntryWayfinder,
    method: CompressionMethod,
    /// The entry holds a zstd stream, independent of the zip's own compression `method`.
    zstd: bool,
}

impl EntryLoc {
    fn new(record: &ZipFileHeaderRecord<'_>) -> Self {
        let path = record.file_path();
        EntryLoc {
            wayfinder: record.wayfinder(),
            method: record.compression_method(),
            // An empty entry holds no zstd frame for the decoder to read, so it would fail as
            // truncated. Read it as the empty file it is instead.
            zstd: path.as_ref().ends_with(ZSTD_SUFFIX.as_bytes())
                && record.uncompressed_size_hint() > 0,
        }
    }
}

/// A log file selected by the path-based filters, pending the time check.
#[derive(Debug)]
struct LogEntry {
    loc: EntryLoc,
    path: String,
    /// The timestamp appended to the file name, only available for archived logs.
    name_timestamp: Option<i64>,
    /// The entry's modification time in the zip, only collected when filtering by time.
    mtime: Option<Timestamp>,
}

/// An Oxide support bundle.
pub struct Bundle<R> {
    info: BundleInfo,
    archive: ZipArchive<R>,
    threads: NonZeroUsize,
}

impl<R: ReaderAt + Sync> Bundle<R> {
    /// Construct a `Bundle` from a `ZipArchive`.
    pub fn from_archive(archive: ZipArchive<R>) -> Result<Self> {
        let info = BundleInfo::from_archive(&archive)?;
        Ok(Self {
            info,
            archive,
            threads: NonZeroUsize::MIN,
        })
    }

    /// Set the number of threads used to search log files for timestamps. Defaults to one.
    pub fn with_threads(mut self, threads: NonZeroUsize) -> Self {
        self.threads = threads;
        self
    }

    /// List all ereports in the archive.
    pub fn ereports_list<W: Write>(&self, components: ComponentInfo<'_>, mut out: W) -> Result<()> {
        let ereports = self.matching_ereports(components)?;

        let max_ena_len = ereports
            .iter()
            .map(|(_, _, ereport)| ereport.ena)
            .max()
            .map(|max| max.to_string().len())
            .unwrap_or(3);

        writeln!(
            out,
            "{:<11}\t{:<11}\t{:<36}\t{:<max_ena_len$}\tCLASS",
            "PART", "SERIAL", "RESTART_ID", "ENA",
        )?;
        let mut dctx = DCtx::create();
        for (loc, path, ereport) in ereports {
            let contents = read_to_string(&self.archive, loc, &path, &mut dctx)?;
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

        out.flush()?;
        Ok(())
    }

    /// Display all ereports matching the filter criteria.
    pub fn ereports_show<W: Write>(
        &self,
        components: ComponentInfo<'_>,
        no_header: bool,
        mut out: W,
    ) -> Result<()> {
        let mut dctx = DCtx::create();
        for (loc, path, _) in self.matching_ereports(components)? {
            let contents = read_to_string(&self.archive, loc, &path, &mut dctx)?;

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

        out.flush()?;
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
        let mut logs = Vec::new();
        for_each_entry(&self.archive, |name, record| {
            let Some(log_file) = LogFile::from_path(name) else {
                return Ok(());
            };

            let sled_info = self
                .info
                .sleds
                .get(log_file.sled_uuid)
                .expect("BUG: UUID was not found in collected sled info");

            if sled_info.matches_patterns(filter.sled)
                && log_file.matches_services(filter.service)
                && log_file.matches_zones(filter.zone)
                && log_file.matches_paths(filter.path)
            {
                logs.push(LogEntry {
                    loc: EntryLoc::new(record),
                    path: name.to_string(),
                    name_timestamp: log_file.timestamp,
                    mtime: if time.is_set() {
                        entry_mtime(record)
                    } else {
                        None
                    },
                });
            }
            Ok(())
        })?;

        let in_range = if time.is_set() {
            Some(self.check_times(&logs, time)?)
        } else {
            None
        };

        let mut dctx = DCtx::create();
        for (i, log) in logs.iter().enumerate() {
            if in_range.as_ref().is_some_and(|in_range| !in_range[i]) {
                continue;
            }

            if output.list {
                writeln!(out, "{}", log.path)?;
                continue;
            }

            if !output.no_header {
                writeln!(out, "==> {} <==", log.path)?;
            }

            let mut file = open_entry(&self.archive, log.loc, &mut dctx)
                .with_context(|| format!("failed to open file {}", log.path))?;

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
                        &mut file,
                        &mut child_in,
                        output.line_ct.map(|l| l.get()),
                    );
                    drop(child_in); // EOF.

                    let out_result = out_writer.join().unwrap();
                    in_result.and(out_result)
                });
                copy_result.with_context(|| format!("failed to copy file {}", log.path))?;

                let status = child.wait()?;
                if !status.success() {
                    anyhow::bail!("command '{exec}' exited with {status}");
                }
            } else {
                write_file_content(&mut file, &mut out, output.line_ct.map(|l| l.get()))
                    .with_context(|| format!("failed to copy file {}", log.path))?;
            }

            if !output.no_header {
                writeln!(out)?;
            }
        }

        out.flush()?;
        Ok(())
    }

    /// Determine which of `logs` fall within `time`, reading up to `self.threads` files at once.
    fn check_times(&self, logs: &[LogEntry], time: TimeRange) -> Result<Vec<bool>> {
        let in_range: Vec<_> = logs.iter().map(|_| AtomicBool::new(false)).collect();
        let next = AtomicUsize::new(0);
        let failed = AtomicBool::new(false);
        let threads = self.threads.get().min(logs.len()).max(1);

        thread::scope(|s| {
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    s.spawn(|| -> Result<()> {
                        let mut buf = Vec::with_capacity(TIME_CHECK_MAX as usize);
                        let mut dctx = DCtx::create();
                        while !failed.load(Ordering::Relaxed) {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(log) = logs.get(i) else {
                                break;
                            };

                            match self.log_timestamp(log, &mut buf, &mut dctx) {
                                Ok(ts) => in_range[i].store(
                                    ts.is_some_and(|ts| time.contains(ts)),
                                    Ordering::Relaxed,
                                ),
                                Err(e) => {
                                    failed.store(true, Ordering::Relaxed);
                                    return Err(e);
                                }
                            }
                        }
                        Ok(())
                    })
                })
                .collect();

            workers
                .into_iter()
                .try_for_each(|worker| worker.join().unwrap())
        })?;

        Ok(in_range.into_iter().map(AtomicBool::into_inner).collect())
    }

    /// Find the log's timeframe, using `buf` to hold the start of the file and `dctx` to decode it.
    fn log_timestamp(
        &self,
        log: &LogEntry,
        buf: &mut Vec<u8>,
        dctx: &mut DCtx<'static>,
    ) -> Result<Option<Timestamp>> {
        let contents_ts = open_entry_unverified(&self.archive, log.loc, dctx)
            .and_then(|file| Ok(find_timestamp(file, buf)?))
            .with_context(|| format!("failed to read file {}", log.path))?;

        // Try several methods of finding the log's timeframe, in order of decreasing accuracy:
        // 1. Try to find a valid timestamp from the first 64k of the file.
        // 2. Check for a the timestamp appended to the file name, only available for archived
        //    logs.
        // 3. Check the file's mtime in the zip, which will be available with R17.
        // In all cases ignore times from before 2001, and skip any file where we cannot find a
        // valid time.
        Ok(contents_ts
            .or_else(|| Timestamp::from_second(log.name_timestamp?).ok())
            .or(log.mtime))
    }

    /// Find all ereports whose part and serial number match `components`.
    fn matching_ereports(
        &self,
        components: ComponentInfo<'_>,
    ) -> Result<Vec<(EntryLoc, String, Ereport)>> {
        let mut ereports = Vec::new();
        for_each_entry(&self.archive, |path, record| {
            if let Some(ereport) = Ereport::from_path(path)
                && matches_patterns(components.part, &ereport.part)
                && matches_patterns(components.serial, &ereport.serial)
            {
                ereports.push((EntryLoc::new(record), path.to_string(), ereport));
            }
            Ok(())
        })?;
        Ok(ereports)
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

        out.flush()?;
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

        out.flush()?;
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

        out.flush()?;
        Ok(())
    }
}

#[derive(Debug)]
struct BundleInfo {
    sleds: BTreeMap<String, SledInfo>,
    unhealthy_sleds: BTreeMap<String, Option<u16>>,
}

impl BundleInfo {
    pub fn from_archive<R: ReaderAt>(archive: &ZipArchive<R>) -> Result<Self> {
        let mut sled_txts = Vec::with_capacity(32);
        let mut sled_info_json = None;

        let mut sleds = BTreeMap::new();
        let mut sled_services = BTreeMap::new();
        let mut sled_zones = BTreeMap::new();

        for_each_entry(archive, |name, record| {
            if name == "sled_info.json" {
                sled_info_json = Some(EntryLoc::new(record));
            }

            if !name.starts_with("rack") {
                return Ok(());
            }

            // rack/{rack_uuid}/sled/{sled_uuid}/logs/{zone}/{service}/...
            let splits: Vec<_> = name.split('/').collect();

            // The zone directory itself will have a length of 7, but we want zone directories that have at least one child.
            // Empty directories may exist for zones that don't actually exist on the sled, e.g., `oxz_switch`.
            if splits.len() == 8 {
                insert_nested(&mut sled_zones, splits[3], splits[5]);
            }

            if splits.len() == 9 {
                insert_nested(&mut sled_services, splits[3], splits[6]);
            }

            if name.ends_with("sled.txt") && splits.len() == 5 {
                sled_txts.push((EntryLoc::new(record), name.to_string()));
            }
            Ok(())
        })?;

        let mut dctx = DCtx::create();
        for (loc, name) in sled_txts {
            let contents = read_to_string(archive, loc, &name, &mut dctx)?;
            let (serial, is_scrimlet) = read_sled_serial(&contents)
                .ok_or_else(|| anyhow::anyhow!("failed to parse sled serial from {name}"))?;

            // UNWRAP: We've confirmed above that the split length is five.
            let uuid = name.split('/').nth(3).unwrap().to_string();

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
        if let Some(loc) = sled_info_json
            && let Ok(mut sled_info) = open_entry(archive, loc, &mut dctx)
        {
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

/// Call `f` with the name and central directory record of each entry in the archive.
fn for_each_entry<R: ReaderAt>(
    archive: &ZipArchive<R>,
    mut f: impl FnMut(&str, &ZipFileHeaderRecord<'_>) -> Result<()>,
) -> Result<()> {
    let mut buf = vec![0u8; rawzip::RECOMMENDED_BUFFER_SIZE];
    let mut entries = archive.entries(&mut buf);
    while let Some(record) = entries
        .next_entry()
        .context("failed to read zip central directory")?
    {
        let path = record.file_path();
        let name = String::from_utf8_lossy(path.as_ref());
        f(&name, &record)?;
    }
    Ok(())
}

/// Open a reader over the decompressed contents of an entry, decoding zstd files with `dctx`. The
/// CRC is verified if the entry is read to the end.
fn open_entry<'a, R: ReaderAt>(
    archive: &'a ZipArchive<R>,
    loc: EntryLoc,
    dctx: &'a mut DCtx<'static>,
) -> Result<Box<dyn Read + 'a>> {
    let entry = archive.get_entry(loc.wayfinder)?;
    let reader = decompress(entry.reader(), loc.method)?;
    // The CRC covers the entry as stored, i.e. the compressed bytes of a zstd file, so verify
    // before decoding it. The decoder reads until EOF, letting the verifier see the end.
    decompress_zstd(entry.verifying_reader(reader), loc.zstd, dctx)
}

/// Open a reader over the decompressed contents of an entry without verifying its CRC, for callers
/// that will only read the start of the file.
fn open_entry_unverified<'a, R: ReaderAt>(
    archive: &'a ZipArchive<R>,
    loc: EntryLoc,
    dctx: &'a mut DCtx<'static>,
) -> Result<Box<dyn Read + 'a>> {
    let entry = archive.get_entry(loc.wayfinder)?;
    decompress_zstd(decompress(entry.reader(), loc.method)?, loc.zstd, dctx)
}

fn decompress<'a>(raw: impl Read + 'a, method: CompressionMethod) -> Result<Box<dyn Read + 'a>> {
    let raw = BufReader::new(raw);
    let reader: Box<dyn Read + 'a> = match method {
        CompressionMethod::STORE => Box::new(raw),
        CompressionMethod::DEFLATE => Box::new(DeflateDecoder::new(raw)),
        method => anyhow::bail!("unsupported compression method {method:?}"),
    };
    Ok(reader)
}

/// Decode a file that was compressed with zstd before being added to the zip, if `zstd` is set.
///
/// Callers pass in a `dctx` that they reuse from file to file. Creating a decoder per file would
/// allocate its buffers, sized for the window of up to several MiB, each time, which adds
/// noticeably to the cost of reading the start of many small logs.
fn decompress_zstd<'a>(
    reader: impl Read + 'a,
    zstd: bool,
    dctx: &'a mut DCtx<'static>,
) -> Result<Box<dyn Read + 'a>> {
    if !zstd {
        return Ok(Box::new(reader));
    }

    // Discard any frame the last file using `dctx` stopped partway through.
    dctx.reset(ResetDirective::SessionOnly).map_err(|code| {
        anyhow::anyhow!(
            "failed to reset zstd decoder: {}",
            zstd::zstd_safe::get_error_name(code)
        )
    })?;
    Ok(Box::new(zstd::Decoder::with_context(
        BufReader::new(reader),
        dctx,
    )))
}

fn read_to_string<R: ReaderAt>(
    archive: &ZipArchive<R>,
    loc: EntryLoc,
    name: &str,
    dctx: &mut DCtx<'static>,
) -> Result<String> {
    let mut buf = Vec::new();
    open_entry(archive, loc, dctx)
        .and_then(|mut file| Ok(file.read_to_end(&mut buf)?))
        .with_context(|| format!("failed to read contents of {name}"))?;
    String::from_utf8(buf).with_context(|| format!("contents of {name} were not valid UTF-8"))
}

/// The entry's modification time. DOS times carry no time zone, so treat them as UTC.
fn entry_mtime(record: &ZipFileHeaderRecord<'_>) -> Option<Timestamp> {
    let t = record.last_modified();
    let civil = jiff::civil::DateTime::new(
        i16::try_from(t.year()).ok()?,
        i8::try_from(t.month()).ok()?,
        i8::try_from(t.day()).ok()?,
        i8::try_from(t.hour()).ok()?,
        i8::try_from(t.minute()).ok()?,
        i8::try_from(t.second()).ok()?,
        i32::try_from(t.nanosecond()).ok()?,
    )
    .ok()?;
    civil.to_zoned(TimeZone::UTC).ok().map(|t| t.timestamp())
}

fn insert_nested(map: &mut BTreeMap<String, BTreeSet<String>>, key: &str, value: &str) {
    match map.get_mut(key) {
        Some(set) if set.contains(value) => {}
        Some(set) => {
            set.insert(value.to_string());
        }
        None => {
            map.insert(key.to_string(), BTreeSet::from([value.to_string()]));
        }
    }
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
    file: &mut R,
    out: &mut W,
    line_ct: Option<usize>,
) -> io::Result<()> {
    match line_ct {
        Some(line_ct) => write_n_lines(file, out, line_ct),
        None => io::copy(file, out).map(|_| ()),
    }
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

/// Search the first `TIME_CHECK_MAX` bytes of `file` for a timestamp, using `buf` to hold them.
///
/// Read in steps that double in size, searching the complete lines from each step before reading
/// more, so a timestamp near the start is found without reading the rest. Lines are searched in
/// order and the final, partial line only once nothing more will be read, so this finds the same
/// timestamp as reading everything up front.
fn find_timestamp(mut file: impl Read, buf: &mut Vec<u8>) -> io::Result<Option<Timestamp>> {
    buf.clear();
    let mut searched = 0;
    let mut step = TIME_CHECK_STEP;
    loop {
        let limit = step.min(TIME_CHECK_MAX - buf.len() as u64);
        let read = (&mut file).take(limit).read_to_end(buf)?;
        let done = (read as u64) < limit || buf.len() as u64 >= TIME_CHECK_MAX;

        let end = if done {
            buf.len()
        } else {
            buf[searched..]
                .rfind_byte(b'\n')
                .map_or(searched, |i| searched + i + 1)
        };
        if let Some(ts) = read_timestamp_from_contents(&buf[searched..end]) {
            return Ok(Some(ts));
        }
        if done {
            return Ok(None);
        }

        searched = end;
        step *= 2;
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

    use std::io::Cursor;
    use std::str::FromStr;

    /// Pretty-print JSON in color. `-b` keeps jq on Windows from writing CRLF line endings, and
    /// changes nothing elsewhere.
    const JQ_COLOR: &str = "jq -b -C .";

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

    fn build_zip(buf: &mut Vec<u8>) -> ZipArchive<Cursor<&[u8]>> {
        build_zip_from(buf, zip_files(), false)
    }

    /// Build a zip of `files`. With `zstd_logs`, each file under a "logs/" directory is
    /// compressed with zstd and given a ".zst" suffix, as in newer bundles.
    fn build_zip_from(
        buf: &mut Vec<u8>,
        files: Vec<ZipFile>,
        zstd_logs: bool,
    ) -> ZipArchive<Cursor<&[u8]>> {
        let mut zip = ZipWriter::new(Cursor::new(&mut *buf));

        // Alternate between stored and deflated files, as found in real bundles, so that each kind
        // of file is read through both paths.
        let mut deflate = false;
        for file in files {
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Stored)
                .last_modified_time(file.mtime.unwrap_or_default());
            if let Some(contents) = file.contents {
                let options = if deflate {
                    options.compression_method(CompressionMethod::Deflated)
                } else {
                    options
                };
                deflate = !deflate;

                let mut contents = contents.into_bytes();
                contents.push(b'\n');

                if zstd_logs && file.name.contains("/logs/") {
                    let compressed = zstd::encode_all(&contents[..], 3).unwrap();
                    zip.start_file(format!("{}{ZSTD_SUFFIX}", file.name), options)
                        .unwrap();
                    zip.write_all(&compressed).unwrap();
                } else {
                    zip.start_file(file.name, options).unwrap();
                    zip.write_all(&contents).unwrap();
                }
            } else {
                zip.add_directory(file.name, options).unwrap();
            }
        }

        zip.finish().unwrap();

        ZipArchive::from_slice(&buf[..])
            .unwrap()
            .into_cursor_archive()
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
                    exec: Some(JQ_COLOR),
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
                    exec: Some(JQ_COLOR),
                    ..Default::default()
                },
                &mut exec_head_out,
            )
            .unwrap();
        assert_snapshot!("logs_exec_head", String::from_utf8_lossy(&exec_head_out));
    }

    /// Logs compressed with zstd print the same as uncompressed ones, apart from the ".zst" on
    /// their names.
    #[test]
    fn test_logs_zstd() {
        let mut plain_buf = Vec::new();
        let plain = Bundle::from_archive(build_zip(&mut plain_buf)).unwrap();

        let mut zstd_buf = Vec::new();
        let zstd = Bundle::from_archive(build_zip_from(&mut zstd_buf, zip_files(), true)).unwrap();

        // Patterns written against the uncompressed names, as users of older bundles would have.
        let current_log = [Pattern::new("*/current/oxide-sled-agent:default.log").unwrap()];
        let dendrite = [Pattern::new("dendrite").unwrap()];
        let middle = "2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap();

        let cases = [
            (
                LogFilter::default(),
                TimeRange::default(),
                LogOutput::default(),
            ),
            (
                LogFilter {
                    path: &current_log,
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput::default(),
            ),
            // The name timestamp is the only valid time in the oxz_switch archived log.
            (
                LogFilter::default(),
                TimeRange {
                    after: Some(middle),
                    ..Default::default()
                },
                LogOutput::default(),
            ),
            (
                LogFilter::default(),
                TimeRange {
                    before: Some(middle),
                    ..Default::default()
                },
                LogOutput::default(),
            ),
            (
                LogFilter::default(),
                TimeRange::default(),
                LogOutput {
                    list: true,
                    ..Default::default()
                },
            ),
            (
                LogFilter::default(),
                TimeRange::default(),
                LogOutput {
                    line_ct: Some(NonZeroUsize::new(1).unwrap()),
                    ..Default::default()
                },
            ),
            (
                LogFilter {
                    service: &dendrite,
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput {
                    line_ct: Some(NonZeroUsize::new(2).unwrap()),
                    exec: Some(JQ_COLOR),
                    ..Default::default()
                },
            ),
        ];

        for (filter, time, output) in cases {
            let mut plain_out = Vec::new();
            plain.logs(filter, time, output, &mut plain_out).unwrap();

            let mut zstd_out = Vec::new();
            zstd.logs(filter, time, output, &mut zstd_out).unwrap();
            let zstd_out = String::from_utf8(zstd_out).unwrap();

            // Guard against the cases passing without reading any compressed logs.
            assert!(zstd_out.contains(ZSTD_SUFFIX), "no .zst logs in {zstd_out}");
            assert_eq!(
                zstd_out.replace(ZSTD_SUFFIX, ""),
                String::from_utf8(plain_out).unwrap(),
                "{filter:?} {time:?} {output:?}"
            );
        }
    }

    /// Reading only the start of a large zstd log leaves its frame partly decoded, which must not
    /// affect the next log decoded with the same context.
    #[test]
    fn test_logs_zstd_partial_read() {
        let big_log = (0..20_000)
            .map(|i| {
                format!(
                    r#"{{"msg":"line {i}","time":"2025-09-24T07:00:00Z","n":{}}}"#,
                    i * 7919
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Place the big log ahead of the others, so that they are read after it.
        let files = || {
            let mut files = zip_files();
            let first_log = files
                .iter()
                .position(|f| f.name.contains("/logs/") && f.contents.is_some())
                .unwrap();
            files.insert(
                first_log,
                ZipFile {
                    name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/archive/oxide-dendrite:default.log.1758700000",
                    contents: Some(big_log.clone()),
                    ..Default::default()
                },
            );
            files
        };

        let mut plain_buf = Vec::new();
        let plain = Bundle::from_archive(build_zip_from(&mut plain_buf, files(), false)).unwrap();

        let mut zstd_buf = Vec::new();
        let zstd = Bundle::from_archive(build_zip_from(&mut zstd_buf, files(), true)).unwrap();

        let cases = [
            (
                TimeRange::default(),
                LogOutput {
                    line_ct: Some(NonZeroUsize::new(1).unwrap()),
                    ..Default::default()
                },
            ),
            (
                TimeRange {
                    after: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
                    ..Default::default()
                },
                LogOutput::default(),
            ),
        ];

        for (time, output) in cases {
            let mut plain_out = Vec::new();
            plain
                .logs(LogFilter::default(), time, output, &mut plain_out)
                .unwrap();

            let mut zstd_out = Vec::new();
            zstd.logs(LogFilter::default(), time, output, &mut zstd_out)
                .unwrap();

            assert_eq!(
                String::from_utf8(zstd_out)
                    .unwrap()
                    .replace(ZSTD_SUFFIX, ""),
                String::from_utf8(plain_out).unwrap(),
                "{time:?} {output:?}"
            );
        }
    }

    #[test]
    fn test_logs_zstd_corrupt() {
        let path = "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/current/oxide-sled-agent:default.log.zst";
        let mut files = zip_files();
        files.push(ZipFile {
            name: path,
            contents: Some("not zstd".to_string()),
            ..Default::default()
        });

        let mut buf = Vec::new();
        let bundle = Bundle::from_archive(build_zip_from(&mut buf, files, false)).unwrap();

        let err = bundle
            .logs(
                LogFilter {
                    path: &[Pattern::new(path).unwrap()],
                    ..Default::default()
                },
                TimeRange::default(),
                LogOutput::default(),
                Vec::new(),
            )
            .unwrap_err();
        assert_eq!(err.to_string(), format!("failed to copy file {path}"));
    }

    #[test]
    fn test_logs_zstd_empty() {
        let path = "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/f589c739-3c4c-4731-8f6f-41c8b2e72f89/logs/global/sled-agent/current/oxide-sled-agent:default.log.zst";

        let mut buf = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(&mut buf));
        for file in zip_files() {
            match file.contents {
                Some(contents) => {
                    zip.start_file(file.name, SimpleFileOptions::default())
                        .unwrap();
                    zip.write_all(contents.as_bytes()).unwrap();
                }
                None => zip
                    .add_directory(file.name, SimpleFileOptions::default())
                    .unwrap(),
            }
        }
        zip.start_file(path, SimpleFileOptions::default()).unwrap();
        zip.finish().unwrap();

        let archive = ZipArchive::from_slice(&buf[..])
            .unwrap()
            .into_cursor_archive();
        let bundle = Bundle::from_archive(archive).unwrap();

        let filter = LogFilter {
            path: &[Pattern::new(path).unwrap()],
            ..Default::default()
        };
        let after = TimeRange {
            after: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
            ..Default::default()
        };

        let mut out = Vec::new();
        bundle
            .logs(filter, TimeRange::default(), LogOutput::default(), &mut out)
            .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("==> {path} <==\n\n")
        );

        // The time check finds no timestamp in the empty contents, rather than failing to read them.
        let mut out = Vec::new();
        bundle
            .logs(filter, after, LogOutput::default(), &mut out)
            .unwrap();
        assert!(out.is_empty());
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

        let archive = ZipArchive::from_slice(&buf[..])
            .unwrap()
            .into_cursor_archive();
        let bundle = Bundle::from_archive(archive).unwrap();

        let mut out = Vec::new();
        bundle.sleds(&mut out).unwrap();
        assert_snapshot!("sleds_incomplete_bundle", String::from_utf8_lossy(&out));
    }

    /// Reading in steps finds the same timestamp as searching the whole start of the file.
    #[test]
    fn test_find_timestamp() {
        let bogus = r#"{"msg":"m","time":"1986-12-26T07:30:02Z"}"#;
        let good = r#"{"msg":"m","time":"2025-09-24T07:30:02Z"}"#;
        let line_len = bogus.len() + 1;

        let mut cases = vec![
            String::new(),
            good.to_string(),
            format!("{good}\n"),
            format!("{good}\r\n{bogus}"),
            "not json\n".repeat(20_000),
        ];
        // Put a good line after bogus ones, so it starts, ends or straddles each step boundary,
        // and at and past the end of what is searched.
        for n in (0..=TIME_CHECK_MAX as usize / line_len + 1).step_by(7) {
            cases.push(format!(
                "{}{good}\n{bogus}\n",
                format!("{bogus}\n").repeat(n)
            ));
        }
        for boundary in [TIME_CHECK_STEP, 3 * TIME_CHECK_STEP, 7 * TIME_CHECK_STEP] {
            let pad = "x".repeat(boundary as usize - 10);
            cases.push(format!("{pad}\n{good}\n"));
            cases.push(format!("{pad}{good}\n"));
        }
        let pad = "x".repeat(TIME_CHECK_MAX as usize - good.len());
        cases.push(format!("{pad}{good}"));
        cases.push(format!("{pad}\n{good}"));

        let mut buf = Vec::new();
        for contents in &cases {
            let start = &contents.as_bytes()[..contents.len().min(TIME_CHECK_MAX as usize)];
            assert_eq!(
                find_timestamp(contents.as_bytes(), &mut buf).unwrap(),
                read_timestamp_from_contents(start),
                "{} bytes",
                contents.len()
            );
        }
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
