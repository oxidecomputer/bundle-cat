# Changelog

## Unreleased

### Fixed

- `ereports list` and `ereports show` find ereports in real bundles, whose
  files are named by ENA in hex (`0x1.json`). `ereports list` prints the ENA in
  hex, and files under `ereports/` that cannot be parsed are reported on
  stderr rather than skipped silently.

## 0.1.0 - 2026-10-04

The first release of bundle-cat, a tool to find and print files from Oxide
support bundles.

### Added

- `sleds`, `zones` and `services` subcommands to list what a bundle holds.
- A `logs` subcommand to print or list log files, filtered by sled (cubby,
  serial number or UUID), service, zone, path glob and time range
  (`--after`, `--before`). `--head` prints only the first lines of each file,
  and `--exec` pipes each file through a shell command.
- An `ereports` subcommand to list and show error reports, filtered by part
  number, serial number and class.
- Support for bundles whose logs are stored compressed with zstd, as `.zst`
  files.
- A `bundle-cat` library crate with the `Bundle` type, usable without the
  command-line interface by turning off the default `cli` feature.
