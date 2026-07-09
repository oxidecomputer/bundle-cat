// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Oxide Computer Company

use anyhow::{Context as _, Result};
use glob::Pattern;
use serde::Deserialize;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use crate::io::read_file_to_string;
use crate::source::BundleSource;

#[derive(Debug)]
pub struct BundleInfo {
    pub sleds: BTreeMap<String, SledInfo>,
    pub unhealthy_sleds: BTreeMap<String, Option<u16>>,
}

impl BundleInfo {
    pub(crate) fn from_source<S: BundleSource + ?Sized>(source: &mut S) -> Result<Self> {
        let names = source.file_names();
        let mut sled_txt_paths = Vec::with_capacity(32);

        let mut sleds = BTreeMap::new();
        let mut sled_services = BTreeMap::new();
        let mut sled_zones = BTreeMap::new();

        let mut splits = Vec::with_capacity(10);
        for name in &names {
            splits.clear();

            // rack/{rack_uuid}/sled/{sled_uuid}/logs/{zone}/{service}/...
            splits.extend(name.split('/'));

            // Infer zones and services from descendants rather than relying on
            // explicit directory entries, which directory sources omit.
            // Requiring a child after the service also ignores empty zone and
            // service directories.
            if name.starts_with("rack") && splits.get(4) == Some(&"logs") && splits.len() >= 8 {
                let sled_uuid = splits[3];
                let zone = splits[5];
                let service = splits[6];

                sled_zones
                    .entry(sled_uuid.to_string())
                    .or_insert_with(BTreeSet::new)
                    .insert(zone.to_string());
                if splits.len() >= 9 || !name.ends_with('/') {
                    sled_services
                        .entry(sled_uuid.to_string())
                        .or_insert_with(BTreeSet::new)
                        .insert(service.to_string());
                }
            }

            if name.starts_with("rack") && name.ends_with("sled.txt") && splits.len() == 5 {
                sled_txt_paths.push(name.clone());
            }
        }

        for path in sled_txt_paths {
            let len = source
                .metadata(&path)
                .with_context(|| format!("failed to read metadata for {path}"))?
                .len;
            let mut file = source
                .open_file(&path)
                .with_context(|| format!("failed to open {path}"))?;

            let contents = read_file_to_string(&mut *file, &path, len)?;
            let sled_txt = parse_sled_txt(&contents)
                .ok_or_else(|| anyhow::anyhow!("failed to parse sled serial from {path}"))?;

            // UNWRAP: We've confirmed above that the split length is five.
            let uuid = path.split('/').nth(3).unwrap().to_string();

            let services = sled_services
                .remove(&uuid)
                .unwrap_or_default()
                .into_iter()
                .collect();
            let zones = sled_zones
                .remove(&uuid)
                .unwrap_or_default()
                .into_iter()
                .collect();

            let sled_info = SledInfo {
                uuid: uuid.clone(),
                cubby: None,
                serial: sled_txt.serial,
                services,
                zones,
                is_scrimlet: sled_txt.is_scrimlet,
            };

            sleds.insert(uuid, sled_info);
        }

        let mut unhealthy_sleds = BTreeMap::new();
        if names.iter().any(|name| name == "sled_info.json") {
            #[derive(Deserialize, Debug)]
            struct SledId {
                cubby: Option<u16>,
                uuid: Option<String>,
            }

            let mut sled_info = source
                .open_file("sled_info.json")
                .context("failed to open sled_info.json")?;
            match serde_json::from_reader::<_, BTreeMap<String, SledId>>(&mut sled_info) {
                Ok(cubby_info) => {
                    for (serial, id) in cubby_info.into_iter() {
                        if let Some(uuid) = id.uuid {
                            // UUIDs are from Nexus, we will always have an existing entry.
                            if let Some(sled) = sleds.get_mut(&uuid) {
                                sled.cubby = id.cubby;
                            }
                        } else {
                            // Sleds unknown to Nexus will have their serial and cubby from MGS.
                            unhealthy_sleds.insert(serial, id.cubby);
                        }
                    }
                }
                Err(e) if e.is_io() => {
                    return Err(e).context("failed to read sled_info.json");
                }
                Err(e) => writeln!(std::io::stderr(), "Failed to parse sled_info.json: {e}")?,
            }
        }

        Ok(BundleInfo {
            sleds,
            unhealthy_sleds,
        })
    }
}

/// Identity fields parsed from a bundle's `sled.txt` contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SledTxtInfo {
    pub serial: String,
    pub is_scrimlet: bool,
}

/// Parse the serial number and scrimlet status from `sled.txt` contents.
pub fn parse_sled_txt(sled_info: &str) -> Option<SledTxtInfo> {
    const SERIAL_PREFIX: &str = " serial_number: \"";
    let serial_start = sled_info.find(SERIAL_PREFIX)? + SERIAL_PREFIX.len();
    let serial_end = serial_start + sled_info[serial_start..].find("\"")?;

    const SCRIMLET_PREFIX: &str = " is_scrimlet: ";
    let scrimlet_start = sled_info.find(SCRIMLET_PREFIX)? + SCRIMLET_PREFIX.len();
    let scrimlet_end = scrimlet_start + sled_info[scrimlet_start..].find(",")?;
    let is_scrimlet = sled_info[scrimlet_start..scrimlet_end].parse().ok()?;

    Some(SledTxtInfo {
        serial: sled_info[serial_start..serial_end].to_string(),
        is_scrimlet,
    })
}

#[derive(PartialEq, Debug)]
pub struct SledInfo {
    pub uuid: String,
    pub cubby: Option<u16>,
    pub serial: String,
    pub zones: Vec<String>,
    pub services: Vec<String>,
    pub is_scrimlet: bool,
}

impl PartialOrd for SledInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.uuid.partial_cmp(&other.uuid)
    }
}

impl SledInfo {
    pub fn matches_patterns(&self, patterns: &[Pattern]) -> bool {
        // Match all sleds if unspecified.
        if patterns.is_empty() {
            return true;
        }
        patterns.iter().any(|p| {
            // If the pattern can be parsed into a digit, it must be an cubby number.
            // All valid serials and UUIDs will fail to parse, as will any wildcard
            // patterns that are only numbers.
            if let Some(cubby) = self.cubby
                && let Ok(requested_cubby) = p.as_str().parse::<u16>()
            {
                requested_cubby == cubby
            } else {
                p.matches(&self.uuid) || p.matches(&self.serial)
            }
        })
    }
}

pub(crate) fn write_sleds<W: Write>(info: &BundleInfo, mut out: W) -> Result<()> {
    let mut by_cubby: Vec<_> = info.sleds.values().collect();
    by_cubby.sort_by(|a, b| a.cubby.cmp(&b.cubby));

    writeln!(
        out,
        "{:>2}\t{:<11}\t{:<36}\tSCRIMLET",
        "CUBBY", "SERIAL", "ID"
    )?;
    for sled in by_cubby {
        let cubby = sled.cubby.map(|c| c.to_string()).unwrap_or_default();
        writeln!(
            out,
            "{:>2}\t{}\t{}\t{:>8}",
            cubby, sled.serial, sled.uuid, sled.is_scrimlet
        )?;
    }

    let mut unhealthy_by_cubby: Vec<_> = info.unhealthy_sleds.iter().collect();
    unhealthy_by_cubby.sort_by(|(_, a), (_, b)| a.cmp(b));

    if !unhealthy_by_cubby.is_empty() {
        writeln!(out, "\nUNHEALTHY SLEDS\n{:>2}\tSERIAL", "CUBBY")?;
        for (serial, cubby) in unhealthy_by_cubby {
            let cubby = cubby.map(|c| c.to_string()).unwrap_or_default();
            writeln!(out, "{:>2}\t{}", cubby, serial,)?;
        }
    }

    let incomplete: Vec<_> = info
        .sleds
        .values()
        .filter(|s| s.services.is_empty() || s.zones.is_empty())
        .collect();

    if !incomplete.is_empty() {
        writeln!(
            out,
            "\nPOSSIBLY UNREACHABLE SLEDS \n{:>2}\t{:<11}\t{:<36}\tMISSING BUNDLE OUTPUT",
            "CUBBY", "SERIAL", "ID"
        )?;
        for sled in &incomplete {
            let cubby = sled.cubby.map(|c| c.to_string()).unwrap_or_default();
            let missing = match (sled.services.is_empty(), sled.zones.is_empty()) {
                (true, true) => "services, zones",
                (true, false) => "services",
                (false, true) => "zones",
                _ => unreachable!(),
            };
            writeln!(
                out,
                "{:>2}\t{}\t{}\t{}",
                cubby, sled.serial, sled.uuid, missing
            )?;
        }
    }

    Ok(())
}

pub(crate) fn write_services<W: Write>(
    info: &BundleInfo,
    sled_patterns: &[Pattern],
    mut out: W,
) -> Result<()> {
    let services: BTreeSet<_> = info
        .sleds
        .values()
        .filter(|s| s.matches_patterns(sled_patterns))
        .flat_map(|s| &s.services)
        .collect();

    for service in services {
        writeln!(out, "{service}")?;
    }

    Ok(())
}

pub(crate) fn write_zones<W: Write>(
    info: &BundleInfo,
    sled_patterns: &[Pattern],
    mut out: W,
) -> Result<()> {
    let zones: BTreeSet<_> = info
        .sleds
        .values()
        .filter(|s| s.matches_patterns(sled_patterns))
        .flat_map(|s| &s.zones)
        .collect();

    for zone in zones {
        writeln!(out, "{zone}")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_sled_txt() {
        const SCRIMLET_INFO: &str = r#"Sled { identity: SledIdentity { id: f589c739-3c4c-4731-8f6f-41c8b2e72f89, time_created: 2025-05-08T20:31:07.381152Z, time_modified: 2025-09-22T15:44:13.232736Z }, time_deleted: None, rcgen: Generation(Generation(21)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: true, serial_number: "BRM03250000", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:10b::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:10b::1:8, policy: InService, state: Active, sled_agent_gen: Generation(Generation(3)), repo_depot_port: SqlU16(12348) }"#;

        const SLED_INFO: &str = r#"Sled { identity: SledIdentity { id: f1e02cab-ef5a-4405-974c-f8cf7df7d4ea, time_created: 2025-05-08T20:31:06.943606Z, time_modified: 2025-05-08T20:31:06.943606Z }, time_deleted: None, rcgen: Generation(Generation(21)), rack_id: 34261901-b550-451c-9bd0-3926bb29c40d, is_scrimlet: false, serial_number: "BRM03250001", part_number: "913-0000019", revision: SqlU32(14), usable_hardware_threads: SqlU32(128), usable_physical_ram: ByteCount(ByteCount(2186120527872)), reservoir_size: ByteCount(ByteCount(1790577737728)), ip: fd00:1122:3344:102::1, port: SqlU16(12345), last_used_address: fd00:1122:3344:102::1:3, policy: InService, state: Active, sled_agent_gen: Generation(Generation(1)), repo_depot_port: SqlU16(12348) }"#;

        assert_eq!(
            parse_sled_txt(SCRIMLET_INFO),
            Some(SledTxtInfo {
                serial: "BRM03250000".to_string(),
                is_scrimlet: true,
            })
        );
        assert_eq!(
            parse_sled_txt(SLED_INFO),
            Some(SledTxtInfo {
                serial: "BRM03250001".to_string(),
                is_scrimlet: false,
            })
        );
    }
}
