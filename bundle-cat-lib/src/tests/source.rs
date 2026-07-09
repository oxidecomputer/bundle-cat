// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use jiff::Timestamp;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::{CompressionMethod, DateTime};

use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};

use crate::{
    Bundle, BundleFileMetadata, BundleSource, DirectoryBundleSource, EreportFilter,
    EreportListFilter, EreportShowFilter, LogFilter, ZipBundleSource,
};

use super::{build_directory, build_zip};

const FILE_NAME: &str = "logs/example.log";
const FILE_CONTENTS: &[u8] = b"hello";

#[derive(Default)]
struct MemorySource {
    files: BTreeMap<String, Option<Vec<u8>>>,
}

struct ReadFailureSource;

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected read failure"))
    }
}

impl BundleSource for ReadFailureSource {
    fn file_names(&self) -> Vec<String> {
        vec!["sled_info.json".to_string()]
    }

    fn open_file<'a>(&'a mut self, path: &str) -> anyhow::Result<Box<dyn Read + 'a>> {
        assert_eq!(path, "sled_info.json");
        Ok(Box::new(FailingReader))
    }

    fn metadata(&mut self, _path: &str) -> anyhow::Result<BundleFileMetadata> {
        unreachable!("sled_info.json metadata is not needed")
    }
}

impl BundleSource for MemorySource {
    fn file_names(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    fn open_file<'a>(&'a mut self, path: &str) -> anyhow::Result<Box<dyn Read + 'a>> {
        let contents = self
            .files
            .get(path)
            .ok_or_else(|| anyhow::anyhow!("unknown test file"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("injected open failure"))?;
        Ok(Box::new(Cursor::new(contents)))
    }

    fn metadata(&mut self, path: &str) -> anyhow::Result<BundleFileMetadata> {
        let len = self
            .files
            .get(path)
            .and_then(|contents| contents.as_ref())
            .map(|contents| contents.len() as u64);
        Ok(BundleFileMetadata {
            len,
            modified: None,
        })
    }
}

fn zip_source() -> ZipBundleSource<Cursor<Vec<u8>>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::from_date_and_time(2025, 9, 24, 6, 30, 0).unwrap());
    zip.start_file(FILE_NAME, options).unwrap();
    zip.write_all(FILE_CONTENTS).unwrap();

    ZipBundleSource::new(zip.finish().unwrap()).unwrap()
}

fn read_file<S: BundleSource + ?Sized>(source: &mut S, path: &str) -> String {
    let mut contents = String::new();
    source
        .open_file(path)
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
    contents
}

#[test]
fn boxed_source_forwards_listing_and_file_reads() {
    let mut source: Box<dyn BundleSource> = Box::new(zip_source());

    assert_eq!(source.file_names(), vec![FILE_NAME]);
    assert_eq!(read_file(&mut source, FILE_NAME), "hello");
}

#[test]
fn zip_source_returns_normalized_metadata() {
    let mut source = zip_source();

    let metadata = source.metadata(FILE_NAME).unwrap();
    assert_eq!(metadata.len, Some(FILE_CONTENTS.len() as u64));
    assert_eq!(
        metadata.modified,
        Some("2025-09-24T06:30:00Z".parse::<Timestamp>().unwrap())
    );
}

#[test]
fn bundle_can_be_built_from_a_source() {
    let bundle = Bundle::from_source(zip_source()).unwrap();

    assert!(bundle.info().sleds.is_empty());
}

#[test]
fn bundle_info_reads_sled_txt_through_source() {
    let sled_uuid = "690650fd-4f95-4b3a-b2ec-977d47154383";
    let path = format!("rack/rack-id/sled/{sled_uuid}/sled.txt");
    let contents = br#"Sled { is_scrimlet: false, serial_number: "BRM03250013", }"#;
    let mut source = MemorySource::default();
    source.files.insert(path, Some(contents.to_vec()));

    let bundle = Bundle::from_source(source).unwrap();
    let sled = &bundle.info().sleds[sled_uuid];
    assert_eq!(sled.serial, "BRM03250013");
    assert!(!sled.is_scrimlet);
}

#[test]
fn malformed_sled_info_json_remains_best_effort() {
    let mut source = MemorySource::default();
    source
        .files
        .insert("sled_info.json".to_string(), Some(b"not json".to_vec()));

    let bundle = Bundle::from_source(source).unwrap();
    assert!(bundle.info().unhealthy_sleds.is_empty());
}

#[test]
fn listed_unreadable_sled_info_has_path_context() {
    let mut source = MemorySource::default();
    source.files.insert("sled_info.json".to_string(), None);

    let error = Bundle::from_source(source)
        .err()
        .expect("bundle should fail");
    assert!(
        format!("{error:#}").contains("failed to open sled_info.json"),
        "{error:#}"
    );
}

#[test]
fn sled_info_read_failure_has_path_context() {
    let error = Bundle::from_source(ReadFailureSource)
        .err()
        .expect("bundle should fail");
    let message = format!("{error:#}");
    assert!(
        message.contains("failed to read sled_info.json"),
        "{message}"
    );
    assert!(message.contains("injected read failure"), "{message}");
}

#[test]
fn directory_source_lists_files_and_provides_metadata() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("logs/empty")).unwrap();
    fs::write(temp.path().join(FILE_NAME), FILE_CONTENTS).unwrap();

    let mut source = DirectoryBundleSource::open(temp.path()).unwrap();

    assert_eq!(source.file_names(), [FILE_NAME]);
    assert_eq!(read_file(&mut source, FILE_NAME), "hello");
    let metadata = source.metadata(FILE_NAME).unwrap();
    assert_eq!(metadata.len, Some(FILE_CONTENTS.len() as u64));
    assert!(metadata.modified.is_some());
}

#[test]
fn directory_source_rejects_unknown_and_traversal_paths() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("known.txt"), b"known").unwrap();
    let mut source = DirectoryBundleSource::open(temp.path()).unwrap();

    for path in ["unknown.txt", "../known.txt", "logs/../../known.txt"] {
        let error = source
            .open_file(path)
            .err()
            .expect("path should be rejected");
        assert!(format!("{error:#}").contains(path), "{error:#}");
    }
}

#[test]
fn open_dir_parses_bundle_information() {
    let temp = tempfile::tempdir().unwrap();
    let sled_uuid = "690650fd-4f95-4b3a-b2ec-977d47154383";
    let sled_path = temp
        .path()
        .join(format!("rack/rack-id/sled/{sled_uuid}/sled.txt"));
    fs::create_dir_all(sled_path.parent().unwrap()).unwrap();
    fs::write(
        sled_path,
        br#"Sled { is_scrimlet: false, serial_number: "BRM03250013", }"#,
    )
    .unwrap();

    let bundle = Bundle::open_dir(temp.path()).unwrap();

    assert_eq!(bundle.info().sleds[sled_uuid].serial, "BRM03250013");
}

#[cfg(unix)]
#[test]
fn directory_source_does_not_discover_symlinks() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside.txt"), b"outside").unwrap();
    symlink(
        outside.path().join("outside.txt"),
        root.path().join("file-link"),
    )
    .unwrap();
    symlink(outside.path(), root.path().join("directory-link")).unwrap();
    fs::write(root.path().join("regular.txt"), b"regular").unwrap();

    let source = DirectoryBundleSource::open(root.path()).unwrap();

    assert_eq!(source.file_names(), ["regular.txt"]);
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn directory_source_rejects_non_utf8_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let temp = tempfile::tempdir().unwrap();
    let file_name = OsString::from_vec(b"invalid-\xff".to_vec());
    fs::write(temp.path().join(file_name), b"contents").unwrap();

    let error = DirectoryBundleSource::open(temp.path()).unwrap_err();
    assert!(
        format!("{error:#}").contains("not valid UTF-8"),
        "{error:#}"
    );
}

#[derive(Debug, Eq, PartialEq)]
struct RenderedBundle {
    sleds: Vec<u8>,
    services: Vec<u8>,
    zones: Vec<u8>,
    logs: Vec<u8>,
    time_filtered_logs: Vec<u8>,
    ereport_list: Vec<u8>,
    ereport_show: Vec<u8>,
}

fn render_bundle<S: BundleSource>(bundle: &mut Bundle<S>) -> RenderedBundle {
    let mut sleds = Vec::new();
    bundle.write_sleds(&mut sleds).unwrap();
    let mut services = Vec::new();
    bundle.write_services(&[], &mut services).unwrap();
    let mut zones = Vec::new();
    bundle.write_zones(&[], &mut zones).unwrap();
    let mut logs = Vec::new();
    bundle.write_logs(&LogFilter::default(), &mut logs).unwrap();
    let mut time_filtered_logs = Vec::new();
    bundle
        .write_logs(
            &LogFilter {
                after: Some("2025-09-24T06:00:00Z".parse().unwrap()),
                ..Default::default()
            },
            &mut time_filtered_logs,
        )
        .unwrap();
    let mut ereport_list = Vec::new();
    bundle
        .write_ereports_list(&EreportListFilter::default(), &mut ereport_list)
        .unwrap();
    let mut ereport_show = Vec::new();
    bundle
        .write_ereports_show(&EreportShowFilter::default(), &mut ereport_show)
        .unwrap();
    RenderedBundle {
        sleds,
        services,
        zones,
        logs,
        time_filtered_logs,
        ereport_list,
        ereport_show,
    }
}

#[test]
fn zip_and_directory_sources_have_matching_structured_and_text_output() {
    let mut zip_bytes = Vec::new();
    build_zip(&mut zip_bytes);
    let directory = tempfile::tempdir().unwrap();
    build_directory(directory.path());

    let zip_source: Box<dyn BundleSource> =
        Box::new(ZipBundleSource::new(Cursor::new(zip_bytes)).unwrap());
    let directory_source: Box<dyn BundleSource> =
        Box::new(DirectoryBundleSource::open(directory.path()).unwrap());
    let mut zip_bundle = Bundle::from_source(zip_source).unwrap();
    let mut directory_bundle = Bundle::from_source(directory_source).unwrap();

    assert_eq!(zip_bundle.info().sleds, directory_bundle.info().sleds);
    assert_eq!(
        zip_bundle.info().unhealthy_sleds,
        directory_bundle.info().unhealthy_sleds
    );
    assert_eq!(
        zip_bundle.ereports(&EreportFilter::default()).unwrap(),
        directory_bundle
            .ereports(&EreportFilter::default())
            .unwrap()
    );
    assert_eq!(
        render_bundle(&mut zip_bundle),
        render_bundle(&mut directory_bundle)
    );
}
