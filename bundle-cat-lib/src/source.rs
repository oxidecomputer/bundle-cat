// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use jiff::Timestamp;
use zip::ZipArchive;

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};

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
/// sequential [`Read`] access. `Box<dyn BundleSource>` can be passed directly
/// to [`crate::Bundle::from_source`].
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

/// A zip-backed support bundle source.
pub struct ZipBundleSource<R: Read + Seek> {
    archive: ZipArchive<R>,
}

impl<R: Read + Seek> ZipBundleSource<R> {
    /// Create a source from a zip archive reader.
    pub fn new(reader: R) -> Result<Self> {
        let archive = ZipArchive::new(reader).context("failed to read zip archive")?;
        Ok(Self { archive })
    }
}

impl<R: Read + Seek> BundleSource for ZipBundleSource<R> {
    fn file_names(&self) -> Vec<String> {
        self.archive.file_names().map(str::to_owned).collect()
    }

    fn open_file<'a>(&'a mut self, path: &str) -> Result<Box<dyn Read + 'a>> {
        let file = self
            .archive
            .by_name(path)
            .with_context(|| format!("failed to access file {path}"))?;
        Ok(Box::new(file))
    }

    fn metadata(&mut self, path: &str) -> Result<BundleFileMetadata> {
        let file = self
            .archive
            .by_name(path)
            .with_context(|| format!("failed to access file {path}"))?;
        let modified = file.last_modified().and_then(|zip_time| {
            let civil = jiff::civil::DateTime::try_from(zip_time).ok()?;
            civil
                .to_zoned(jiff::tz::TimeZone::UTC)
                .ok()
                .map(|time| time.timestamp())
        });

        Ok(BundleFileMetadata {
            len: Some(file.size()),
            modified,
        })
    }
}

/// A support bundle source backed by an unpacked directory tree.
///
/// Files are discovered once when the source is opened, and symbolic links
/// are ignored. The unpacked bundle tree must remain stable while the source
/// is in use; replacing discovered paths after construction is unsupported.
#[derive(Debug)]
pub struct DirectoryBundleSource {
    root: PathBuf,
    files: BTreeMap<String, PathBuf>,
}

impl DirectoryBundleSource {
    /// Discover the files below an unpacked support-bundle root.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let requested_root = path.as_ref();
        let root = fs::canonicalize(requested_root).with_context(|| {
            format!(
                "failed to resolve support bundle directory {}",
                requested_root.display()
            )
        })?;
        if !root.is_dir() {
            anyhow::bail!(
                "support bundle directory is not a directory: {}",
                root.display()
            );
        }

        let mut files = BTreeMap::new();
        discover_files(&root, &root, &mut files)?;
        Ok(Self { root, files })
    }

    fn discovered_path(&self, path: &str) -> Result<&Path> {
        let valid_components = !path.is_empty()
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && Path::new(path)
                .components()
                .all(|component| matches!(component, Component::Normal(_)));
        if !valid_components {
            anyhow::bail!("invalid bundle path {path:?}: path traversal is not allowed");
        }

        self.files.get(path).map(PathBuf::as_path).ok_or_else(|| {
            anyhow::anyhow!("unknown bundle path {path:?} under {}", self.root.display())
        })
    }
}

impl BundleSource for DirectoryBundleSource {
    fn file_names(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    fn open_file<'a>(&'a mut self, path: &str) -> Result<Box<dyn Read + 'a>> {
        let discovered = self.discovered_path(path)?;
        let file = File::open(discovered).with_context(|| {
            format!(
                "failed to open bundle file {path:?} under {}",
                self.root.display()
            )
        })?;
        Ok(Box::new(file))
    }

    fn metadata(&mut self, path: &str) -> Result<BundleFileMetadata> {
        let discovered = self.discovered_path(path)?;
        let metadata = fs::metadata(discovered).with_context(|| {
            format!(
                "failed to read metadata for bundle file {path:?} under {}",
                self.root.display()
            )
        })?;
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
    let entries = fs::read_dir(directory).with_context(|| {
        format!(
            "failed to read support bundle directory {}",
            directory.display()
        )
    })?;

    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to read an entry under support bundle root {}",
                root.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect support bundle path {path:?}"))?;

        if file_type.is_dir() {
            discover_files(root, &path, files)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).with_context(|| {
                format!("support bundle path {path:?} was outside root {root:?}")
            })?;
            let mut parts = Vec::new();
            for component in relative.components() {
                let Component::Normal(part) = component else {
                    anyhow::bail!("invalid discovered support bundle path {path:?}");
                };
                let part = part.to_str().ok_or_else(|| {
                    anyhow::anyhow!("support bundle path {path:?} is not valid UTF-8")
                })?;
                parts.push(part);
            }
            files.insert(parts.join("/"), path);
        }
    }

    Ok(())
}
