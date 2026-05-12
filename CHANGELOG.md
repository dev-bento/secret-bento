# Changelog

## Unreleased

### Changed
- Split the Rust entrypoint into smaller core modules for findings, redaction, and Markdown report rendering.
- Updated Gitleaks integration to read JSON from stdout with `--report-path -` instead of writing a raw JSON report file during normal operation.
- Invoke Gitleaks with `--redact` so raw `Secret` and `Match` report fields are redacted before Secret Bento normalizes findings.

### Added
- Added sentinel regression tests to help ensure raw secret values do not appear in generated Markdown reports.

## v0.3.0 - 2026-05-11

### Added
- Added `secret-bento --version` using Cargo package metadata.
- Added GitHub Actions release packaging for Windows x64, Linux x64, and Apple Silicon macOS.
- Added release archives that include the binary, README, LICENSE, and CHANGELOG.
- Added SHA256 checksum files for release assets.

### Changed
- Updated README usage guidance around binary downloads, first-run verification, local scans, Gitleaks scans, and GitHub Actions usage.

## v0.2.1 - 2026-05-11

### Added
- Added CI-friendly exit codes for clean scans, completed scans with findings, usage/configuration errors, and runtime failures.
- Added tests for exit code decision logic.

### Changed
- Reworked README usage guidance around local scanning, Gitleaks scanning, excludes, custom report paths, CI usage, and safe AI handoff.
- Expanded Gitleaks installation and PATH troubleshooting notes.

## v0.2.0 - 2026-05-11

### Added
- Added repeatable `--exclude <glob>` scan filters for reducing local noise from docs, tests, fixtures, and sample reports.
- Added `--output <path>` for writing reports outside the default `SECRET_BENTO_REPORT.md` location.
- Added README Quick Start examples and project badges.
- Added `--scanner gitleaks` using the external gitleaks CLI as the detection engine.
- Added gitleaks JSON parsing into normalized `SecretBentoFinding` values.
- Added redacted AI-ready Markdown fields for scanner, rule ID, severity, file, line, secret type, fingerprint, description, risk, remediation steps, and verification commands.
- Added fixture-based gitleaks tests that do not require the gitleaks binary.

### Changed
- Secret Bento now acts as a scanner orchestrator, finding normalizer, and remediation report writer for gitleaks findings.

## v0.1.1 - 2026-05-11

### Fixed
- Reduced false positives from Rust/TypeScript-style type annotations.
- Rendered evidence as fenced text blocks to avoid broken Markdown.
- Added focused tests for generic assignment detection and evidence rendering.

## v0.1.0

### Added
- Initial `secret-bento scan <path>` command.
- Built-in local scanner.
- Markdown report generation.
- Scanner abstraction with `builtin` as default.
- Redacted evidence output.
- AI handoff prompt.
