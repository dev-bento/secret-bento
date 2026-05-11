# Changelog

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
