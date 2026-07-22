// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

/// Fields parsed from a bundle's `sled.txt` inventory record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SledTxtInfo {
    /// The sled's serial number.
    pub serial: String,
    /// Whether the sled is a scrimlet.
    pub is_scrimlet: bool,
}

/// Parses the serial number and scrimlet flag from `sled.txt` contents.
///
/// Returns `None` when the input is invalid or does not contain both fields.
pub fn parse_sled_txt(contents: &str) -> Option<SledTxtInfo> {
    const SERIAL_PREFIX: &str = " serial_number: \"";
    let serial_start = contents.find(SERIAL_PREFIX)? + SERIAL_PREFIX.len();
    let serial_end = serial_start + contents[serial_start..].find('"')?;

    const SCRIMLET_PREFIX: &str = " is_scrimlet: ";
    let scrimlet_start = contents.find(SCRIMLET_PREFIX)? + SCRIMLET_PREFIX.len();
    let scrimlet_end = scrimlet_start + contents[scrimlet_start..].find(',')?;
    let is_scrimlet = contents[scrimlet_start..scrimlet_end].parse().ok()?;

    Some(SledTxtInfo {
        serial: contents[serial_start..serial_end].to_string(),
        is_scrimlet,
    })
}

/// Fields parsed from an ereport path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EreportPathInfo {
    /// The reporting component's part number.
    pub part: String,
    /// The reporting component's serial number.
    pub serial: String,
    /// The ereport restart identifier.
    pub restart_id: String,
    /// The ereport's event number association (ENA).
    pub ena: u64,
}

/// An owned ereport read from a bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EreportEntry {
    /// The bundle-relative ereport path.
    pub path: String,
    /// Metadata parsed from the ereport path.
    pub metadata: EreportPathInfo,
    /// The top-level string `class`, when present and valid.
    pub class: Option<String>,
    /// The unchanged UTF-8 file contents.
    pub contents: String,
}

pub(crate) fn parse_ereport_class(contents: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(contents)
        .ok()?
        .as_object()?
        .get("class")?
        .as_str()
        .map(str::to_owned)
}

/// Parses an ereport path with the strict grammar
/// `ereports/{part}-{serial}/{restart_id}/{decimal_ena}.json`.
///
/// The part and serial are separated at the final `-`. Returns `None` when the
/// input is invalid or does not match this grammar exactly.
pub fn parse_ereport_path(path: &str) -> Option<EreportPathInfo> {
    let mut components = path.split('/');
    let root = components.next()?;
    let identity = components.next()?;
    let restart_id = components.next()?;
    let file_name = components.next()?;
    if root != "ereports" || components.next().is_some() {
        return None;
    }

    let (part, serial) = identity.rsplit_once('-')?;
    if part.is_empty() || serial.is_empty() || restart_id.is_empty() {
        return None;
    }
    let ena_text = file_name.strip_suffix(".json")?;
    if ena_text.is_empty() || !ena_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let ena = ena_text.parse().ok()?;

    Some(EreportPathInfo {
        part: part.to_string(),
        serial: serial.to_string(),
        restart_id: restart_id.to_string(),
        ena,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sled_txt_fields() {
        let contents = r#"Sled { is_scrimlet: true, serial_number: "BRM03250000" }"#;
        assert_eq!(
            parse_sled_txt(contents),
            Some(SledTxtInfo {
                serial: "BRM03250000".to_string(),
                is_scrimlet: true,
            })
        );
    }

    #[test]
    fn rejects_invalid_sled_txt() {
        for contents in [
            "Sled { is_scrimlet: true }",
            r#"Sled { serial_number: "BRM03250000" }"#,
            r#"Sled { is_scrimlet: true, serial_number: "BRM03250000 }"#,
            r#"Sled { is_scrimlet: yes, serial_number: "BRM03250000" }"#,
        ] {
            assert_eq!(parse_sled_txt(contents), None, "accepted {contents:?}");
        }
    }

    #[test]
    fn parses_strict_ereport_path() {
        assert_eq!(
            parse_ereport_path("ereports/907-0000023-BRM03250000/restart-id/305419896.json"),
            Some(EreportPathInfo {
                part: "907-0000023".to_string(),
                serial: "BRM03250000".to_string(),
                restart_id: "restart-id".to_string(),
                ena: 305419896,
            })
        );
    }

    #[test]
    fn rejects_invalid_ereport_paths() {
        for path in [
            "reports/907-0000023-BRM03250000/restart-id/1.json",
            "ereports/907-0000023-BRM03250000/restart-id",
            "ereports/907-0000023-BRM03250000/restart-id/1.json/extra",
            "ereports/-BRM03250000/restart-id/1.json",
            "ereports/907-0000023-/restart-id/1.json",
            "ereports/907-0000023-BRM03250000//1.json",
            "ereports/907-0000023-BRM03250000/restart-id/1.txt",
            "ereports/907-0000023-BRM03250000/restart-id/.json",
            "ereports/907-0000023-BRM03250000/restart-id/+1.json",
            "ereports/907-0000023-BRM03250000/restart-id/not-decimal.json",
        ] {
            assert_eq!(parse_ereport_path(path), None, "accepted {path:?}");
        }
    }
}
