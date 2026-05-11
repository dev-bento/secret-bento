# Secret Bento

[![Rust](https://github.com/dev-bento/secret-bento/actions/workflows/rust.yml/badge.svg)](https://github.com/dev-bento/secret-bento/actions/workflows/rust.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/dev-bento/secret-bento)](https://github.com/dev-bento/secret-bento/releases)

Tiny local secret scanning reports for AI-assisted indie developers.

Part of **Dev Bento**: tiny local CLIs for AI-assisted indie developers.

Don’t dump your repo. Pack it into a bento.

## What Is Secret Bento?

Secret Bento is a tiny local CLI that scans a local repository for accidentally leaked secrets and generates an AI-ready remediation report in Markdown.

It is not trying to invent secret scanning or replace mature OSS scanners. Secret Bento starts with simple built-in checks and is designed to integrate transparently with tools like gitleaks or other open source scanners in the future. The value is the report: safe context packaging, practical prioritization, and remediation guidance that is easy to hand to an AI assistant without uploading your codebase.

## Current Status

Secret Bento has a small v0.1 Rust CLI MVP. It can scan a local path with the default `builtin` scanner and write a redacted Markdown report.

The `builtin` scanner is intentionally basic. It does not replace established secret scanners or professional security review.

## Quick Start

From a built local binary:

```sh
secret-bento scan .
```

Reduce local report noise from docs, tests, fixtures, and sample reports:

```sh
secret-bento scan . --exclude docs/** --exclude tests/**
```

Write the report to a custom path:

```sh
secret-bento scan . --output reports/secret-report.md
```

By default, Secret Bento writes `SECRET_BENTO_REPORT.md` at the scanned root.

## Usage

The scanner option is available now, with `builtin` as the default:

```sh
secret-bento scan . --scanner builtin
```

You can provide multiple `--exclude <glob>` values to skip noisy local paths during scanning:

```sh
secret-bento scan . --exclude docs/** --exclude tests/** --exclude **/*.md
```

Use `--output <path>` to choose where the Markdown report is written. Relative output paths are resolved from the scanned root, and parent directories are created when needed:

```sh
secret-bento scan . --output reports/secret-report.md
```

During development:

```sh
cargo run -- scan .
```

Example output:

```text
SECRET_BENTO_REPORT.md
```

## Who It Is For

Secret Bento is for indie developers, solo builders, and small teams who use AI tools to maintain side projects and early products.

It is especially useful when you want to ask ChatGPT, Claude, Codex, Cursor, or Gemini for help cleaning up possible secret exposure without pasting an entire repository into a chat.

## Why It Exists

AI tools are good at explaining risk and turning findings into a cleanup plan, but they need structured context.

Secret Bento prepares that context locally:

- where possible secret-like values were found
- why each finding may matter
- how urgent the finding appears
- what remediation steps are likely needed
- what can be safely shared with an AI assistant

## v0.1 Built-In Checks

The current `builtin` scanner checks for:

- possible hardcoded API keys
- `.env` tracking risk
- `.env.example` files containing real-looking values
- README, docs, and logs containing secret-like values
- OpenAI-style keys starting with `sk-`
- Stripe secret keys starting with `sk_live_` or `sk_test_`
- GitHub tokens starting with `ghp_` or `github_pat_`
- AWS access key IDs starting with `AKIA`
- Supabase service role style variable names
- generic lines containing `API_KEY`, `SECRET_KEY`, `TOKEN`, or `DATABASE_URL` with non-placeholder values

Findings redact detected values by default.

## What It Does Not Do

Secret Bento:

- does not upload code
- does not call AI APIs
- does not automatically fix secrets
- does not replace professional security review
- does not guarantee every secret will be found

## AI Handoff Philosophy

Secret Bento is local-first and Markdown-first.

It prepares clean local context so you can hand the report to ChatGPT, Claude, Codex, Cursor, or Gemini and ask for help with remediation planning. Secret Bento's core value is AI-ready remediation reporting, prioritization, and safe context packaging.

Never paste real secrets into AI chats. Secret Bento reports should redact detected values and include only enough surrounding context to support safe cleanup.

## Future OSS Scanner Integration

Secret Bento may integrate with gitleaks or other existing open source secret scanners in future versions instead of maintaining every detection rule itself.

No gitleaks integration is included yet. A future command may look like:

```sh
secret-bento scan . --scanner gitleaks
```

Any integration should be documented clearly, including what scanner is used, what data stays local, and how results are transformed into the Markdown report.

## Rust CLI Structure

This repository includes a minimal Rust command-line tool.

Possible future structure:

```text
src/
  main.rs          CLI entrypoint
  scanner.rs       local scanning orchestration
  findings.rs      finding model and severity logic
  report.rs        Markdown report generation
```

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

MIT. See [LICENSE](LICENSE).
