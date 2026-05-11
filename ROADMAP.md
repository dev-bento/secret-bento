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

- Add configurable include paths.
- Add machine-readable Secret Bento output, likely JSON, for editor and CI workflows.
- Improve severity scoring based on file type, key type, and exposure likelihood.
- Add deeper guidance for rotation, revocation, and git history cleanup.
- Add safer snippets with strict redaction and minimal surrounding context.
- Evaluate additional scanner integrations using the same adapter and normalization pattern.

## Later

- Add CI-friendly exit codes.
- Add baseline support for known accepted findings.
- Add pre-commit usage documentation.
- Add templates for AI handoff prompts.
- Package binaries for common platforms.

## Non-Goals

- No SaaS dashboard.
- No AI API calls.
- No code upload.
- No automatic secret rotation.
- No claim that Secret Bento replaces professional security review.
