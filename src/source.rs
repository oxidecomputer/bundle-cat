// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use jiff::Timestamp;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};
use zip::ZipArchive;

/// Metadata available for a file in a support bundle.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BundleFileMetadata {
    /// File length in bytes, when the source provides it.
    pub len: Option<u64>,
    /// UTC modification timestamp, when the source provides it.
    pub modified: Option<Timestamp>,
}

/// A synchronous, object-safe source of files in a support bundle.
///
/// Names are owned, bundle-relative UTF-8 paths. Opened files require only
/// sequential [`Read`] access.
pub trait BundleSource {
    /// Return the bundle-relative names of files in this source.
    fn file_names(&self) -> Vec<String>;
    /// Open one file by its bundle-relative name.
    fn open_file<'a>(&'a mut self, path: &str) -> Result<Box<dyn Read + 'a>>;
    /// Return metadata for one file by its bundle-relative name.
    fn metadata(&mut self, path: &str) -> Result<BundleFileMetadata>;
}

impl<T: BundleSource + ?Sized> BundleSource for Box<T> {
    fn file_names(&self) -> Vec<String> {
        (**self).file_names()
    }
    fn open_file<'a>(&'a mut self, path: &str) -> Result<Box<dyn Read + 'a>> {
        (**self).open_file(path)
    }
    fn metadata(&mut self, path: &str) -> Result<BundleFileMetadata> {
        (**self).metadata(path)
    }
}

/// A ZIP-backed support bundle source.
///
/// Archive order is preserved. Duplicate names are unsupported because
/// lookup uses the ZIP archive's name lookup semantics.
pub struct ZipBundleSource<R: Read + Seek> {
    archive: ZipArchive<R>,
}

impl<R: Read + Seek> ZipBundleSource<R> {
    /// Create a source by parsing a ZIP archive reader.
    pub fn new(reader: R) -> Result<Self> {
        Self::from_archive(ZipArchive::new(reader).context("failed to read ZIP archive")?)
    }

    pub(crate) fn from_archive(archive: ZipArchive<R>) -> Result<Self> {
        Ok(Self { archive })
    }
}

impl<R: Read + Seek> BundleSource for ZipBundleSource<R> {
    fn file_names(&self) -> Vec<String> {
        self.archive.file_names().map(str::to_owned).collect()
    }

    fn open_file<'a>(&'a mut self, path: &str) -> Result<Box<dyn Read + 'a>> {
        Ok(Box::new(self.archive.by_name(path).with_context(|| {
            format!("failed to open ZIP file {path:?}")
        })?))
    }

    fn metadata(&mut self, path: &str) -> Result<BundleFileMetadata> {
        let file = self
            .archive
            .by_name(path)
            .with_context(|| format!("failed to read metadata for ZIP file {path:?}"))?;
        let modified = file.last_modified().and_then(|time| {
            let civil = jiff::civil::DateTime::try_from(time).ok()?;
            civil
                .to_zoned(jiff::tz::TimeZone::UTC)
                .ok()
                .map(|zoned| zoned.timestamp())
        });
        Ok(BundleFileMetadata {
            len: Some(file.size()),
            modified,
        })
    }
}

/// A support bundle source backed by an unpacked directory tree.
///
/// Regular files are discovered exactly once and symbolic links are ignored.
/// The tree must remain stable while the source is in use; hardening against
/// hostile mutation races is out of scope.
#[derive(Debug)]
pub struct DirectoryBundleSource {
    root: PathBuf,
    files: BTreeMap<String, PathBuf>,
}

impl DirectoryBundleSource {
    /// Canonicalize a directory and discover its regular files recursively.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let requested = path.as_ref();
        let root = fs::canonicalize(requested).with_context(|| {
            format!("failed to resolve bundle directory {}", requested.display())
        })?;
        if !root.is_dir() {
            anyhow::bail!("bundle root is not a directory: {}", root.display());
        }
        let mut files = BTreeMap::new();
        discover_files(&root, &root, &mut files)?;
        Ok(Self { root, files })
    }

    fn discovered_path(&self, requested: &str) -> Result<&Path> {
        let valid = !requested.is_empty()
            && requested
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && Path::new(requested)
                .components()
                .all(|component| matches!(component, Component::Normal(_)));
        if !valid {
            anyhow::bail!("invalid bundle path {requested:?}");
        }
        self.files
            .get(requested)
            .map(PathBuf::as_path)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown bundle path {requested:?} under {}",
                    self.root.display()
                )
            })
    }
}

impl BundleSource for DirectoryBundleSource {
    fn file_names(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    fn open_file<'a>(&'a mut self, path: &str) -> Result<Box<dyn Read + 'a>> {
        let discovered = self.discovered_path(path)?;
        Ok(Box::new(File::open(discovered).with_context(|| {
            format!("failed to open bundle file {path:?}")
        })?))
    }

    fn metadata(&mut self, path: &str) -> Result<BundleFileMetadata> {
        let discovered = self.discovered_path(path)?;
        let metadata = fs::metadata(discovered)
            .with_context(|| format!("failed to read metadata for bundle file {path:?}"))?;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| Timestamp::try_from(time).ok());
        Ok(BundleFileMetadata {
            len: Some(metadata.len()),
            modified,
        })
    }
}

fn discover_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read bundle directory {}", directory.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry under {}", root.display()))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .with_context(|| format!("failed to inspect bundle path {path:?}"))?;
        if kind.is_dir() {
            relative_bundle_name(root, &path)?;
            discover_files(root, &path, files)?;
        } else if kind.is_file() {
            files.insert(relative_bundle_name(root, &path)?, path);
        }
    }
    Ok(())
}

fn relative_bundle_name(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .expect("discovered path is below root");
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            anyhow::bail!("invalid discovered bundle path {path:?}");
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| anyhow::anyhow!("bundle path {path:?} is not valid UTF-8"))?,
        );
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::{CompressionMethod, DateTime};

    const FILE_NAME: &str = "logs/example.log";
    const FILE_CONTENTS: &[u8] = b"hello";

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
    fn directory_listing_is_recursive_file_only_and_lexical() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("z/empty")).unwrap();
        fs::create_dir_all(temp.path().join("a/b")).unwrap();
        fs::write(temp.path().join("z/file"), b"z").unwrap();
        fs::write(temp.path().join("a/b/file"), FILE_CONTENTS).unwrap();
        let mut source = DirectoryBundleSource::open(temp.path()).unwrap();
        assert_eq!(source.file_names(), ["a/b/file", "z/file"]);
        assert_eq!(read_file(&mut source, "a/b/file"), "hello");
        let metadata = source.metadata("a/b/file").unwrap();
        assert_eq!(metadata.len, Some(5));
        assert!(metadata.modified.is_some());
    }

    #[test]
    fn directory_rejects_unknown_and_invalid_names_contextually() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("known"), b"known").unwrap();
        let mut source = DirectoryBundleSource::open(temp.path()).unwrap();
        for path in [
            "",
            ".",
            "..",
            "unknown",
            "a//b",
            "/known",
            "../known",
            "a/../../known",
        ] {
            let error = source.open_file(path).err().expect("path should fail");
            assert!(format!("{error:#}").contains(path), "{error:#}");
            let error = source.metadata(path).expect_err("path should fail");
            assert!(format!("{error:#}").contains(path), "{error:#}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn directory_omits_file_and_directory_symlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("outside"), b"outside").unwrap();
        symlink(
            outside.path().join("outside"),
            root.path().join("file-link"),
        )
        .unwrap();
        symlink(outside.path(), root.path().join("dir-link")).unwrap();
        fs::write(root.path().join("regular"), b"regular").unwrap();
        let source = DirectoryBundleSource::open(root.path()).unwrap();
        assert_eq!(source.file_names(), ["regular"]);
    }

    #[cfg(unix)]
    #[test]
    fn relative_bundle_name_rejects_non_utf8_components() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let root = Path::new("root");
        let path = root.join(OsString::from_vec(b"bad-\xff".to_vec()));
        let error = relative_bundle_name(root, &path).unwrap_err();
        assert!(format!("{error:#}").contains("not valid UTF-8"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn directory_rejects_empty_non_utf8_directories() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join(OsString::from_vec(b"bad-\xff".to_vec()))).unwrap();
        let error = DirectoryBundleSource::open(temp.path()).unwrap_err();
        assert!(format!("{error:#}").contains("not valid UTF-8"));
    }
}
