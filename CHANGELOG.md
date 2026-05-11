# Changelog

## Unreleased v0.1.2

### Added
- Added repeatable `--exclude <glob>` scan filters for reducing local noise from docs, tests, fixtures, and sample reports.
- Added `--output <path>` for writing reports outside the default `SECRET_BENTO_REPORT.md` location.
- Added README Quick Start examples and project badges.

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
