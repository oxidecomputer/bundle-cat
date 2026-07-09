// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use crate::{Ereport, SledTxtInfo, parse_ereport_path, parse_sled_txt};

#[test]
fn parses_sled_txt_identity_fields() {
    let contents =
        r#"Sled { is_scrimlet: true, serial_number: "BRM03250000", part_number: "913-0000019" }"#;

    assert_eq!(
        parse_sled_txt(contents),
        Some(SledTxtInfo {
            serial: "BRM03250000".to_string(),
            is_scrimlet: true,
        })
    );
}

#[test]
fn rejects_incomplete_sled_txt() {
    assert_eq!(
        parse_sled_txt(r#"Sled { serial_number: "BRM03250000" }"#),
        None
    );
}

#[test]
fn parses_ereport_path() {
    let path =
        "ereports/907-0000023-BRM03250000/550e8400-e29b-41d4-a716-446655440000/305419896.json";

    assert_eq!(
        parse_ereport_path(path),
        Some(Ereport {
            part: "907-0000023".to_string(),
            serial: "BRM03250000".to_string(),
            restart_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            ena: 305419896,
        })
    );
}

#[test]
fn rejects_malformed_ereport_paths() {
    for path in [
        "other/907-0000023-BRM03250000/restart/1.json",
        "ereports/no-part-serial-boundary/restart/not-an-ena.json",
        "ereports/907-0000023-BRM03250000/restart/1.json/extra",
        "ereports/-BRM03250000/restart/1.json",
        "ereports/907-0000023-/restart/1.json",
    ] {
        assert_eq!(parse_ereport_path(path), None, "accepted {path}");
    }
}
