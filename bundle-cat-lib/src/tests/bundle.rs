// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use glob::Pattern;
use insta::assert_snapshot;
use zip::CompressionMethod;
use zip::write::{SimpleFileOptions, ZipWriter};

use std::io::{Cursor, Write};
use std::str::FromStr;

use crate::Bundle;

use super::build_zip;

#[test]
fn test_sleds() {
    let mut buf = Vec::new();
    build_zip(&mut buf);
    let bundle = Bundle::from_reader(Cursor::new(&mut buf)).unwrap();

    let mut out = Vec::new();
    bundle.write_sleds(&mut out).unwrap();
    assert_snapshot!("sleds", String::from_utf8_lossy(&out));
}

#[test]
fn test_services() {
    let mut buf = Vec::new();
    build_zip(&mut buf);
    let bundle = Bundle::from_reader(Cursor::new(&mut buf)).unwrap();

    let mut unfiltered_out = Vec::new();
    bundle.write_services(&[], &mut unfiltered_out).unwrap();
    assert_snapshot!(
        "services_unfiltered",
        String::from_utf8_lossy(&unfiltered_out)
    );

    let mut sled_uuid_out = Vec::new();
    bundle
        .write_services(&[Pattern::from_str("f589c*").unwrap()], &mut sled_uuid_out)
        .unwrap();
    assert_snapshot!("services_by_uuid", String::from_utf8_lossy(&sled_uuid_out));

    let mut sled_serial_out = Vec::new();
    bundle
        .write_services(
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
fn test_zones() {
    let mut buf = Vec::new();
    build_zip(&mut buf);
    let bundle = Bundle::from_reader(Cursor::new(&mut buf)).unwrap();

    let mut unfiltered_out = Vec::new();
    bundle.write_zones(&[], &mut unfiltered_out).unwrap();
    assert_snapshot!("zones_unfiltered", String::from_utf8_lossy(&unfiltered_out));

    let mut sled_uuid_out = Vec::new();
    bundle
        .write_zones(&[Pattern::from_str("f589c*").unwrap()], &mut sled_uuid_out)
        .unwrap();
    assert_snapshot!("zones_by_uuid", String::from_utf8_lossy(&sled_uuid_out));

    let mut sled_serial_out = Vec::new();
    bundle
        .write_zones(
            &[Pattern::from_str("BRM03250013").unwrap()],
            &mut sled_serial_out,
        )
        .unwrap();
    assert_snapshot!("zones_by_serial", String::from_utf8_lossy(&sled_serial_out));
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
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
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

    let bundle = Bundle::from_reader(Cursor::new(&mut buf)).unwrap();

    let mut out = Vec::new();
    bundle.write_sleds(&mut out).unwrap();
    assert_snapshot!("sleds_incomplete_bundle", String::from_utf8_lossy(&out));
}
