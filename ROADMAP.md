# Secret Bento Roadmap

Secret Bento is starting as a small, local-first CLI focused on safe AI handoff reports for secret remediation.

## v0.1 - Local Markdown Report

- Create a Rust CLI skeleton.
- Add `secret-bento scan <path>`.
- Add scanner selection with `--scanner builtin`, using `builtin` as the default.
- Detect common secret-like patterns in text files.
- Flag `.env` files that appear to be tracked.
- Flag `.env.example` values that look real instead of illustrative.
- Scan README, docs, and log files for secret-like values.
- Redact detected values in all output.
- Generate `SECRET_BENTO_REPORT.md`.
- Include severity, confidence, file path, line number, evidence summary, and suggested remediation.

## v0.2 - Gitleaks Scanner Integration

- Add `--scanner gitleaks`.
- Run the external `gitleaks` CLI as the detection engine.
- Do not copy, vendor, or reimplement gitleaks rules.
- Emit a clear missing-binary error when `gitleaks` is not installed or not on `PATH`.
- Parse gitleaks JSON reports into an internal `SecretBentoFinding` model.
- Normalize scanner findings into scanner, rule ID, severity, file, line, secret type, fingerprint, description, risk, remediation steps, and verification commands.
- Keep raw gitleaks `Secret` and `Match` values out of Markdown output.
- Keep Markdown-first AI handoff reports as the primary user experience.

## v0.3 - Better Context And Prioritization

- Add concise CLI help and clearer usage errors.
- Add compact scan completion summaries.
- Add stable finding display IDs such as `SB-001`.
- Add report status metadata and final verification guidance.
- Expand `secret-bento doctor` into a non-invasive local readiness check.

## v0.4 - Gitleaks Safety Hardening

- Read Gitleaks JSON from stdout instead of writing a raw JSON report file during normal operation.
- Invoke Gitleaks with redaction enabled.
- Keep raw Gitleaks `Secret` and `Match` values out of normalized findings and Markdown reports.
- Redact token-shaped values from scanner runtime diagnostics.
- Add sentinel regression tests for report and diagnostic redaction.

## Next

- Add configurable include paths.
- Add machine-readable Secret Bento output, likely JSON, for editor and CI workflows.
- Improve severity scoring based on file type, key type, and exposure likelihood.
- Add deeper guidance for rotation, revocation, and git history cleanup.
- Add safer snippets with strict redaction and minimal surrounding context.
- Evaluate additional scanner integrations using the same adapter and normalization pattern.
- Add baseline support for known accepted findings.
- Add pre-commit usage documentation.
- Add templates for AI handoff prompts.
- Add release archive smoke checks.
- Add Linux CI coverage alongside Windows.
- Consider splitting `src/lib.rs` into focused CLI, doctor, scanner, and output modules after behavior stabilizes.

## Future Bento Products

Dev Bento is intended as a small family of local-first CLIs for indie developers. Future Bento products should follow the same constraints:

- local-first by default
- no SaaS dashboard requirement
- no telemetry by default
- no code upload
- Markdown or file-based handoff where useful
- narrow command surfaces
- clear paid Starter Kit boundaries when a workflow package exists

## Non-Goals

- No SaaS dashboard.
- No AI API calls.
- No code upload.
- No automatic secret rotation.
- No claim that Secret Bento replaces professional security review.
