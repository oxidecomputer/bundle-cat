// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};
use glob::Pattern;
use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use jiff::{Span, Timestamp};
use zip::ZipArchive;

use std::fs::File;
use std::io::{self, BufReader, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process;

use bundle_cat::{Bundle, ComponentInfo, LogFilter, LogOutput, TimeRange};

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

    /// Pipe the contents of each selected file to the standard input of this command.
    /// The command will be executed as '$SHELL -c <EXEC>'.
    #[arg(short, long)]
    exec: Option<String>,
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

/// Parse a timestamp, span, or datetime string relative to the current time.
pub fn parse_timestamp_now(date_str: &str) -> Result<Timestamp, anyhow::Error> {
    parse_timestamp(Timestamp::now(), date_str)
}

/// Parse a timestamp, span, or datetime string relative to `relative_to`.
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

fn main() {
    if let Err(e) = run() {
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_err.kind() == io::ErrorKind::BrokenPipe
        {
            return;
        }

        let _ = writeln!(io::stderr(), "{e:#}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Cli::parse();

    let file = File::open(&args.zip_path).with_context(|| {
        format!(
            "failed to open suppport bundle zip: {}",
            args.zip_path.display()
        )
    })?;
    let reader = BufReader::new(file);
    let archive = ZipArchive::new(reader).context("failed to read zip archive")?;
    let bundle =
        Bundle::from_archive(archive).context("failed to parse sled information from bundle")?;

    match &args.command {
        Commands::Ereports(EreportCmds::List(l)) => bundle.ereports_list(
            ComponentInfo {
                part: &l.part,
                serial: &l.serial,
                class: &l.class,
            },
            io::stdout(),
        ),
        Commands::Ereports(EreportCmds::Show(s)) => bundle.ereports_show(
            ComponentInfo {
                part: &s.part,
                serial: &s.serial,
                class: &s.class,
            },
            s.no_header,
            io::stdout(),
        ),

        Commands::Logs(l) => bundle.logs(
            LogFilter {
                sled: &l.sled,
                service: &l.service,
                zone: &l.zone,
                path: &l.path,
            },
            TimeRange {
                after: l.after,
                before: l.before,
            },
            LogOutput {
                list: l.list,
                line_ct: l.line_ct,
                no_header: l.no_header,
                exec: l.exec.as_deref(),
            },
            io::stdout(),
        ),
        Commands::Services(s) => bundle.services(&s.sled, io::stdout()),
        Commands::Sleds => bundle.sleds(io::stdout()),
        Commands::Zones(z) => bundle.zones(&z.sled, io::stdout()),
    }
}
