// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use glob::Pattern;
use insta::assert_snapshot;
use jiff::Timestamp;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::num::NonZeroUsize;
use std::rc::Rc;

use crate::filter::LogFilter;
use crate::{Bundle, BundleFileMetadata, BundleSource};

use super::build_zip;

const SLED_UUID: &str = "690650fd-4f95-4b3a-b2ec-977d47154383";
const LOG_PATH: &str =
    "rack/rack-id/sled/690650fd-4f95-4b3a-b2ec-977d47154383/logs/zone/service/example.log";

struct RecordingSource {
    files: BTreeMap<String, Vec<u8>>,
    log_events: Rc<RefCell<Vec<String>>>,
}

impl BundleSource for RecordingSource {
    fn file_names(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    fn open_file<'a>(&'a mut self, path: &str) -> anyhow::Result<Box<dyn Read + 'a>> {
        if path == LOG_PATH {
            self.log_events.borrow_mut().push(format!("open:{path}"));
        }
        Ok(Box::new(Cursor::new(self.files[path].clone())))
    }

    fn metadata(&mut self, path: &str) -> anyhow::Result<BundleFileMetadata> {
        if path == LOG_PATH {
            self.log_events
                .borrow_mut()
                .push(format!("metadata:{path}"));
        }
        Ok(BundleFileMetadata {
            len: Some(self.files[path].len() as u64),
            modified: Some("2002-01-01T00:00:00Z".parse().unwrap()),
        })
    }
}

fn recording_source(events: Rc<RefCell<Vec<String>>>) -> RecordingSource {
    let mut files = BTreeMap::new();
    files.insert(
        format!("rack/rack-id/sled/{SLED_UUID}/sled.txt"),
        br#"Sled { is_scrimlet: false, serial_number: "BRM03250013", }"#.to_vec(),
    );
    files.insert(
        LOG_PATH.to_string(),
        b"{\"time\":\"2025-09-24T06:30:00Z\"}\nlog body\n".to_vec(),
    );
    RecordingSource {
        files,
        log_events: events,
    }
}

#[test]
fn time_filter_fetches_metadata_before_opening_read_callback() {
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut bundle = Bundle::from_source(recording_source(Rc::clone(&events))).unwrap();
    let filter = LogFilter {
        after: Some("2025-09-24T06:00:00Z".parse().unwrap()),
        ..Default::default()
    };
    let mut contents = Vec::new();

    bundle
        .for_each_log(&filter, |_log, reader: &mut dyn Read, prefix| {
            contents.extend(prefix.unwrap());
            reader.read_to_end(&mut contents)?;
            Ok(())
        })
        .unwrap();

    assert_eq!(
        *events.borrow(),
        vec![format!("metadata:{LOG_PATH}"), format!("open:{LOG_PATH}")]
    );
    assert_eq!(contents, b"{\"time\":\"2025-09-24T06:30:00Z\"}\nlog body\n");
}

#[test]
fn test_logs() {
    let mut buf = Vec::new();
    build_zip(&mut buf);
    let mut bundle = Bundle::from_reader(Cursor::new(&mut buf)).unwrap();

    let mut unfiltered_out = Vec::new();
    bundle
        .write_logs(&LogFilter::default(), &mut unfiltered_out)
        .unwrap();
    assert_snapshot!("logs_unfiltered", String::from_utf8_lossy(&unfiltered_out));

    let mut sled_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                sled: vec![Pattern::new("BRM03250013").unwrap()],
                ..Default::default()
            },
            &mut sled_out,
        )
        .unwrap();
    assert_snapshot!("logs_by_sled", String::from_utf8_lossy(&sled_out));

    let mut zone_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                zone: vec![Pattern::new("oxz_switch").unwrap()],
                ..Default::default()
            },
            &mut zone_out,
        )
        .unwrap();
    assert_snapshot!("logs_by_zone", String::from_utf8_lossy(&zone_out));

    let mut path_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                path: vec![Pattern::new("*sled.txt").unwrap()],
                ..Default::default()
            },
            &mut path_out,
        )
        .unwrap();
    assert_snapshot!("logs_by_path", String::from_utf8_lossy(&path_out));

    let mut after_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                after: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
                ..Default::default()
            },
            &mut after_out,
        )
        .unwrap();
    assert_snapshot!("logs_by_after", String::from_utf8_lossy(&after_out));

    let mut before_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                before: Some("2025-09-24T06:00:00.0Z".parse::<Timestamp>().unwrap()),
                ..Default::default()
            },
            &mut before_out,
        )
        .unwrap();
    assert_snapshot!("logs_by_before", String::from_utf8_lossy(&before_out));

    let mut list_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                list: true,
                ..Default::default()
            },
            &mut list_out,
        )
        .unwrap();
    assert_snapshot!("logs_list", String::from_utf8_lossy(&list_out));

    let mut line_ct_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                line_ct: Some(NonZeroUsize::new(2).unwrap()),
                ..Default::default()
            },
            &mut line_ct_out,
        )
        .unwrap();
    assert_snapshot!("logs_line_ct", String::from_utf8_lossy(&line_ct_out));

    let mut no_header_out = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                no_header: true,
                ..Default::default()
            },
            &mut no_header_out,
        )
        .unwrap();
    assert_snapshot!("logs_no_header", String::from_utf8_lossy(&no_header_out));
}
