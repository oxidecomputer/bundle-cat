// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

mod bundle;
mod ereport;
mod log;
mod parsing;
mod source;

use serde_json::json;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::{CompressionMethod, DateTime};

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

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

fn build_zip(buf: &mut Vec<u8>) {
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

    zip.finish().unwrap();
}

fn build_directory(root: &Path) {
    for file in zip_files() {
        let path = root.join(file.name.trim_end_matches('/'));
        if let Some(contents) = file.contents {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut output = fs::File::create(path).unwrap();
            output.write_all(contents.as_bytes()).unwrap();
            output.write_all(b"\n").unwrap();
            let zip_time = file.mtime.unwrap_or_default();
            let civil = jiff::civil::DateTime::try_from(zip_time).unwrap();
            let modified: std::time::SystemTime = civil
                .to_zoned(jiff::tz::TimeZone::UTC)
                .unwrap()
                .timestamp()
                .into();
            output
                .set_times(fs::FileTimes::new().set_modified(modified))
                .unwrap();
        } else {
            fs::create_dir_all(path).unwrap();
        }
    }
}
