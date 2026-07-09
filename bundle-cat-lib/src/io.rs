// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use bstr::ByteSlice;

use std::io::{self, Read, Write};

pub(crate) fn read_file_to_string<R: Read + ?Sized>(
    file: &mut R,
    path: &str,
    len: Option<u64>,
) -> Result<String> {
    let capacity = len
        .and_then(|len| usize::try_from(len).ok())
        .unwrap_or_default();
    let mut buf = Vec::with_capacity(capacity);
    file.read_to_end(&mut buf)
        .with_context(|| format!("failed to read contents of {path}"))?;
    String::from_utf8(buf).with_context(|| format!("contents of {path} were not valid UTF-8"))
}

pub fn write_file_content<R: Read + ?Sized, W: Write>(
    time_check_buf: &Option<Vec<u8>>,
    file: &mut R,
    out: &mut W,
    line_ct: Option<usize>,
) -> io::Result<()> {
    if let Some(line_ct) = line_ct {
        let (cached_lines, ending_offset) = time_check_buf
            .as_ref()
            .map(|tc| {
                let mut cached = 0;
                let mut end = 0;
                for i in tc.find_iter(b"\n").take(line_ct) {
                    cached += 1;
                    end = i;
                }
                (cached, end)
            })
            .unwrap_or((0, 0));

        match time_check_buf {
            Some(tc) if cached_lines == line_ct => out.write_all(&tc[..=ending_offset])?,
            Some(tc) => {
                out.write_all(tc)?;
                write_n_lines(file, out, line_ct - cached_lines)?;
            }
            None => write_n_lines(file, out, line_ct)?,
        }
    } else {
        if let Some(tc) = time_check_buf {
            out.write_all(tc)?;
        }
        io::copy(file, out)?;
    }
    Ok(())
}

pub(crate) fn write_n_lines<R: Read, W: Write>(
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{self, Cursor};

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failed"))
        }
    }

    #[test]
    fn string_reader_uses_explicit_path_context() {
        let mut reader = Cursor::new(b"hello".as_slice());
        let contents = read_file_to_string(&mut reader, "logs/example.log", Some(5)).unwrap();

        assert_eq!(contents, "hello");
    }

    #[test]
    fn string_reader_reports_invalid_utf8_with_path() {
        let mut reader = Cursor::new([0xff]);
        let error = read_file_to_string(&mut reader, "logs/bad.log", Some(1)).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("contents of logs/bad.log were not valid UTF-8")
        );
    }

    #[test]
    fn string_reader_reports_read_failure_with_path() {
        let error = read_file_to_string(&mut FailingReader, "logs/broken.log", None).unwrap_err();

        assert_eq!(
            error.to_string(),
            "failed to read contents of logs/broken.log"
        );
    }
}
