# Changelog

## v0.6.2 - 2026-07-11

### Added
- Added finding classifications for candidates that need human review, safe placeholders, and safe environment-variable references.
- Added classification counts and per-finding classification labels to generated Markdown reports.

### Changed
- Built-in generic-secret checks now keep obvious placeholders and environment-variable references visible as safe observations instead of treating them as unresolved candidates.
- Exit code `1` is now reserved for candidates that need human review; reports containing only safe observations exit with code `0`.
- Completion summaries now show the number of candidates that need human review.

### Safety Notes
- Specific token-shaped findings and Gitleaks findings continue to require human review.
- A clean exit does not guarantee that a repository contains no secrets or replace Gitleaks, GitHub secret scanning, credential rotation, or human review.

## v0.6.1 - 2026-06-17

### Changed
- Updated the paid Starter Kit link from Gumroad to Polar.
- Added release automation that publishes the crate to crates.io before building GitHub Release assets for `v*` tags.

## v0.6.0 - 2026-05-23

### Added
- Added `secret-bento handoff <path>` as a first-class beginner-facing command for creating AI-safe handoff reports.
- Added `SECRET_BENTO_HANDOFF.md` as the default handoff report output file.
- Added a Safe to Share Checklist to generated Markdown reports.
- Added AI Agent Instructions that tell coding assistants what they may and may not do.
- Added Human-Only Actions for rotation, revocation, provider dashboard changes, and git history decisions.
- Added target-specific AI handoff prompt blocks for Codex/Cursor, Claude Code, and ChatGPT.

### Changed
- Reframed generated reports around AI-safe handoff instead of generic scan output.
- Differentiated handoff reports with a dedicated title and report-purpose status line.
- Trimmed duplicated warnings and remediation text from handoff reports.
- Updated README Quick Start to use `secret-bento handoff .` for beginner-facing AI handoff.
- Updated README Quick Start language to emphasize safe AI handoff for beginner vibe coders.
- Improved per-finding report structure to separate finding details, risk, suggested AI-assisted fixes, and human verification.
- Updated the sample report to match the handoff-first report format.

### Safety Notes
- Secret Bento still runs locally and does not upload code or reports.
- Secret Bento still does not call AI APIs.
- Secret Bento still does not intentionally render raw secret values.
- Existing scan commands and exit-code behavior are unchanged.
- `handoff` mirrors `scan` exit-code behavior: clean scans return 0 and findings return 1.
- The built-in scanner remains a basic smoke check, not comprehensive security coverage.

## v0.5.0 - 2026-05-14

### Added
- Added concise CLI help for top-level, scan, and doctor commands.
- Added compact scan completion summaries with scanner, report path, finding count, exit-code meaning, and safe next steps.
- Added binary-level CLI integration tests for help, usage errors, and scan summaries.
- Added report status metadata, stable `SB-001` style finding display IDs, and a final verification section to Markdown reports.
- Expanded `secret-bento doctor` into a non-invasive readiness check for Secret Bento, Gitleaks, Git, current git repository status, optional scan path status, and output directory writeability.
- Added `secret-bento doctor <path>` support.

### Changed
- Improved usage/configuration errors for unknown commands, unknown scan options, missing scan paths, duplicate scan paths, invalid scanner names, and invalid doctor options.
- Hardened Gitleaks runtime diagnostics by redacting token-shaped values from stderr while continuing to avoid echoing scanner stdout on runtime failures.

## v0.4.0 - 2026-05-12

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
