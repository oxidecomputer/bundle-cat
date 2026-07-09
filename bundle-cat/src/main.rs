// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::Result;
use bundle_cat_lib::{
    Bundle, BundleSource, EreportListFilter, EreportShowFilter, LogFilter, write_file_content,
};
use clap::{Args, Parser, Subcommand};
use glob::Pattern;
use jiff::Timestamp;

use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::thread;

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
    /// The command will be executed as `$SHELL -c EXEC`.
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

fn parse_timestamp_now(date_str: &str) -> Result<Timestamp, anyhow::Error> {
    bundle_cat_lib::parse_timestamp(Timestamp::now(), date_str)
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
    let mut bundle = Bundle::open(&args.zip_path)?;

    match &args.command {
        Commands::Ereports(EreportCmds::List(l)) => {
            let filter = EreportListFilter {
                part: l.part.clone(),
                serial: l.serial.clone(),
                class: l.class.clone(),
            };
            bundle.write_ereports_list(&filter, io::stdout())
        }
        Commands::Ereports(EreportCmds::Show(s)) => {
            let filter = EreportShowFilter {
                part: s.part.clone(),
                serial: s.serial.clone(),
                class: s.class.clone(),
                no_header: s.no_header,
            };
            bundle.write_ereports_show(&filter, io::stdout())
        }
        Commands::Logs(l) => {
            let filter = LogFilter {
                sled: l.sled.clone(),
                service: l.service.clone(),
                zone: l.zone.clone(),
                path: l.path.clone(),
                after: l.after,
                before: l.before,
                list: l.list,
                line_ct: l.line_ct,
                no_header: l.no_header,
            };
            if let Some(exec_cmd) = &l.exec {
                exec_logs_with_command(&mut bundle, &filter, exec_cmd, io::stdout())
            } else {
                bundle.write_logs(&filter, io::stdout())
            }
        }
        Commands::Services(s) => bundle.write_services(&s.sled, io::stdout()),
        Commands::Sleds => bundle.write_sleds(io::stdout()),
        Commands::Zones(z) => bundle.write_zones(&z.sled, io::stdout()),
    }
}

/// Pipe each matching log file's content through a subprocess command.
fn exec_logs_with_command<S: BundleSource, W: Write + Send>(
    bundle: &mut Bundle<S>,
    filter: &LogFilter,
    exec_cmd: &str,
    mut out: W,
) -> Result<()> {
    bundle.for_each_log(filter, |log_file, file, time_check_buf| {
        if filter.list {
            writeln!(out, "{}", log_file.path)?;
            return Ok(());
        }

        if !filter.no_header {
            writeln!(out, "==> {} <==", log_file.path)?;
        }

        let shell = std::env::var("SHELL").unwrap_or("/bin/sh".to_string());
        let mut child = Command::new(&shell)
            .arg("-c")
            .arg(exec_cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut child_in = child.stdin.take().unwrap();
        let mut child_out = child.stdout.take().unwrap();

        let copy_result = thread::scope(|s| {
            let out_writer = s.spawn(|| io::copy(&mut child_out, &mut out));

            let in_result = write_file_content(
                &time_check_buf,
                file,
                &mut child_in,
                filter.line_ct.map(|l| l.get()),
            );
            drop(child_in); // EOF.

            let out_result = out_writer.join().unwrap();
            in_result.and(out_result)
        });
        copy_result?;

        let status = child.wait()?;
        if !status.success() {
            anyhow::bail!("command '{exec_cmd}' exited with {status}");
        }

        if !filter.no_header {
            writeln!(out)?;
        }

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use bundle_cat_lib::ZipBundleSource;
    use insta::assert_snapshot;
    use serde_json::json;
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::{CompressionMethod, DateTime, ZipArchive};

    use std::io::Cursor;

    #[derive(Default)]
    struct ZipFileEntry {
        name: &'static str,
        contents: Option<String>,
        mtime: Option<DateTime>,
    }

    /// Build the minimal zip fixture containing just the dendrite service
    /// logs and necessary sled metadata for the exec tests.
    fn zip_files() -> Vec<ZipFileEntry> {
        vec![
            ZipFileEntry {
                name: "rack/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/archive/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/archive/oxide-dendrite:default.log.1758702600",
                contents: Some([
                    r#"{"msg":"loopback entry fd69:644c:516f:ee88::1 already set","v":0,"name":"dpd","level":20,"time":"1986-12-26T07:30:02.0679829Z","hostname":"oxz_switch","pid":1717}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068057082Z","hostname":"oxz_switch","pid":1717,"uri":"/loopback/ipv6","method":"POST","req_id":"ce63fccd-fb9e-4a99-a3a8-5c1677740099","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":92,"response_code":"204"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068201157Z","hostname":"oxz_switch","pid":1717,"uri":"/route/ipv4/0.0.0.0%2F0","method":"GET","req_id":"af76ae57-5dbf-42c2-91c7-9a376a779188","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":49,"response_code":"200"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068945446Z","hostname":"oxz_switch","pid":1717,"uri":"/ports/qsfp0/links/0","method":"GET","req_id":"d3df6b3b-48e8-4ffb-ab03-1fe07c5e0126","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":78,"response_code":"200"}"#
                ].join("\n").to_string()),
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/current/",
                ..Default::default()
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/oxz_switch/dendrite/current/oxide-dendrite:default.log",
                contents: Some([
                    r#"{"msg":"loopback entry fd69:644c:516f:ee88::1 already set","v":0,"name":"dpd","level":20,"time":"1986-12-26T07:30:02.0679829Z","hostname":"oxz_switch","pid":1717}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068057082Z","hostname":"oxz_switch","pid":1717,"uri":"/loopback/ipv6","method":"POST","req_id":"ce63fccd-fb9e-4a99-a3a8-5c1677740099","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":92,"response_code":"204"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068201157Z","hostname":"oxz_switch","pid":1717,"uri":"/route/ipv4/0.0.0.0%2F0","method":"GET","req_id":"af76ae57-5dbf-42c2-91c7-9a376a779188","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":49,"response_code":"200"}"#,
                    r#"{"msg":"request completed","v":0,"name":"dpd","level":30,"time":"1986-12-28T07:30:02.068945446Z","hostname":"oxz_switch","pid":1717,"uri":"/ports/qsfp0/links/0","method":"GET","req_id":"d3df6b3b-48e8-4ffb-ab03-1fe07c5e0126","remote_addr":"[::1]:60692","local_addr":"[::1]:12224","server_id":"2","unit":"api-server","latency_us":78,"response_code":"200"}"#
                ].join("\n").to_string()),
                mtime: Some(DateTime::from_date_and_time(2025, 9, 24, 6, 30, 0).unwrap()),
            },
            ZipFileEntry {
                name: "rack/34261901-b550-451c-9bd0-3926bb29c40d/sled/690650fd-4f95-4b3a-b2ec-977d47154383/sled.txt",
                contents: Some(r#"Sled { identity: SledIdentity { id: 690650fd-4f95-4b3a-b2ec-977d47154383, time_created: 2025-05-08T20:31:05.863348Z, time_modified: 2025-05-08T20:31:05.863348Z }, time_deleted: None, rcgen: Generation(Generation(21)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: true, serial_number: "BRM03250013", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:108::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:108::1:7, policy: InService, state: Active, sled_agent_gen: Generation(Generation(1)), repo_depot_port: SqlU16(12348) }"#.to_string()),
                ..Default::default()
            },
            ZipFileEntry {
                name: "sled_info.json",
                contents: Some(json!({
                    "BRM03250013": {
                        "cubby": 14,
                        "uuid": "690650fd-4f95-4b3a-b2ec-977d47154383"
                    }
                }).to_string()),
                ..Default::default()
            },
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
    fn logs_exec() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let source: Box<dyn BundleSource> =
            Box::new(ZipBundleSource::new(zip.into_inner()).unwrap());
        let mut bundle = Bundle::from_source(source).unwrap();

        let filter = LogFilter {
            service: vec![Pattern::new("dendrite").unwrap()],
            ..Default::default()
        };
        let exec_cmd = "jq -M .";

        let mut exec_out = Vec::new();
        exec_logs_with_command(&mut bundle, &filter, exec_cmd, &mut exec_out).unwrap();
        assert_snapshot!("logs_exec", String::from_utf8_lossy(&exec_out));
    }

    #[test]
    fn logs_exec_head() {
        let mut buf = Vec::new();
        let zip = build_zip(&mut buf);
        let mut bundle = Bundle::from_reader(zip.into_inner()).unwrap();

        let filter = LogFilter {
            service: vec![Pattern::new("dendrite").unwrap()],
            line_ct: Some(NonZeroUsize::new(2).unwrap()),
            ..Default::default()
        };
        let exec_cmd = "jq -M .";

        let mut exec_head_out = Vec::new();
        exec_logs_with_command(&mut bundle, &filter, exec_cmd, &mut exec_head_out).unwrap();
        assert_snapshot!("logs_exec_head", String::from_utf8_lossy(&exec_head_out));
    }
}
