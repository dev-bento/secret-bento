# Secret Bento Roadmap

Secret Bento is starting as a small, local-first CLI focused on safe AI handoff reports for secret remediation.

## v0.1 - Local Markdown Report

- Create a Rust CLI skeleton.
- Add `secret-bento scan <path>`.
- Detect common secret-like patterns in text files.
- Flag `.env` files that appear to be tracked.
- Flag `.env.example` values that look real instead of illustrative.
- Scan README, docs, and log files for secret-like values.
- Redact detected values in all output.
- Generate `SECRET_BENTO_REPORT.md`.
- Include severity, confidence, file path, line number, evidence summary, and suggested remediation.

## v0.2 - Better Context And Prioritization

- Add configurable include and exclude paths.
- Add machine-readable output, likely JSON, for editor and CI workflows.
- Improve severity scoring based on file type, key type, and exposure likelihood.
- Add guidance for rotation, revocation, and git history cleanup.
- Add safer snippets with strict redaction and minimal surrounding context.

## v0.3 - OSS Scanner Integration

- Evaluate integration with established open source secret scanners.
- Document exactly which scanner is used and how it runs locally.
- Normalize scanner findings into the Secret Bento report format.
- Keep Markdown-first output as the primary user experience.

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
