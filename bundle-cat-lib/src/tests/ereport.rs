// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use glob::Pattern;
use insta::assert_snapshot;

use std::collections::BTreeMap;
use std::io::Cursor;
use std::str::FromStr;

use crate::filter::{EreportFilter, EreportListFilter, EreportShowFilter};
use crate::{Bundle, BundleFileMetadata, BundleSource};

use super::build_zip;

#[derive(Default)]
struct EreportSource {
    files: BTreeMap<String, Vec<u8>>,
}

impl BundleSource for EreportSource {
    fn file_names(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    fn open_file<'a>(&'a mut self, path: &str) -> anyhow::Result<Box<dyn std::io::Read + 'a>> {
        Ok(Box::new(Cursor::new(self.files[path].clone())))
    }

    fn metadata(&mut self, path: &str) -> anyhow::Result<BundleFileMetadata> {
        Ok(BundleFileMetadata {
            len: Some(self.files[path].len() as u64),
            modified: None,
        })
    }
}

fn structured_ereport_source() -> EreportSource {
    let mut source = EreportSource::default();
    source.files.insert(
        "ereports/913-0000019-SERIAL1/restart-1/100.json".to_string(),
        br#"{"class":"ereport.cpu.match","value":1}"#.to_vec(),
    );
    source.files.insert(
        "ereports/913-0000019-SERIAL2/restart-2/200.json".to_string(),
        br#"{"class":"ereport.io.other","value":2}"#.to_vec(),
    );
    source.files.insert(
        "ereports/913-0000019-SERIAL3/restart-3/300.json".to_string(),
        br#"{"value":3}"#.to_vec(),
    );
    source
}

#[test]
fn structured_ereports_expose_data_and_retain_missing_classes() {
    let mut bundle = Bundle::from_source(structured_ereport_source()).unwrap();
    let filter = EreportFilter {
        class: vec![Pattern::new("ereport.cpu*").unwrap()],
        ..Default::default()
    };

    let entries = bundle.ereports(&filter).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].path,
        "ereports/913-0000019-SERIAL1/restart-1/100.json"
    );
    assert_eq!(entries[0].metadata.serial, "SERIAL1");
    assert_eq!(entries[0].metadata.ena, 100);
    assert_eq!(entries[0].class.as_deref(), Some("ereport.cpu.match"));
    assert_eq!(
        entries[0].contents,
        r#"{"class":"ereport.cpu.match","value":1}"#
    );
    assert_eq!(entries[1].metadata.serial, "SERIAL3");
    assert_eq!(entries[1].class, None);

    let mut serials = Vec::new();
    bundle
        .for_each_ereport(&filter, |entry| {
            serials.push(entry.metadata.serial);
            Ok(())
        })
        .unwrap();
    assert_eq!(serials, ["SERIAL1", "SERIAL3"]);
}

#[test]
fn test_ereports_list() {
    let mut buf = Vec::new();
    build_zip(&mut buf);
    let mut bundle = Bundle::from_reader(Cursor::new(&mut buf)).unwrap();

    let mut unfiltered_out = Vec::new();
    bundle
        .write_ereports_list(&EreportListFilter::default(), &mut unfiltered_out)
        .unwrap();
    assert_snapshot!(
        "ereport_list_unfiltered",
        String::from_utf8_lossy(&unfiltered_out)
    );

    let mut serial_out = Vec::new();
    bundle
        .write_ereports_list(
            &EreportListFilter {
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
    bundle
        .write_ereports_list(
            &EreportListFilter {
                part: vec![Pattern::from_str("907*").unwrap()],
                ..Default::default()
            },
            &mut part_out,
        )
        .unwrap();
    assert_snapshot!("ereport_list_by_part", String::from_utf8_lossy(&part_out));

    let mut class_out = Vec::new();
    bundle
        .write_ereports_list(
            &EreportListFilter {
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
    build_zip(&mut buf);
    let mut bundle = Bundle::from_reader(Cursor::new(&mut buf)).unwrap();

    let mut unfiltered_out = Vec::new();
    bundle
        .write_ereports_show(&EreportShowFilter::default(), &mut unfiltered_out)
        .unwrap();
    assert_snapshot!(
        "ereport_show_unfiltered",
        String::from_utf8_lossy(&unfiltered_out)
    );

    let mut no_header_out = Vec::new();
    bundle
        .write_ereports_show(
            &EreportShowFilter {
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
    bundle
        .write_ereports_show(
            &EreportShowFilter {
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
    bundle
        .write_ereports_show(
            &EreportShowFilter {
                part: vec![Pattern::from_str("907*").unwrap()],
                ..Default::default()
            },
            &mut part_out,
        )
        .unwrap();
    assert_snapshot!("ereport_show_by_part", String::from_utf8_lossy(&part_out));

    let mut class_out = Vec::new();
    bundle
        .write_ereports_show(
            &EreportShowFilter {
                class: vec![Pattern::from_str("ereport.cpu*").unwrap()],
                ..Default::default()
            },
            &mut class_out,
        )
        .unwrap();
    assert_snapshot!("ereport_show_by_class", String::from_utf8_lossy(&class_out));
}
