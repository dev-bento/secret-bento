# Secret Bento

[![Rust](https://github.com/dev-bento/secret-bento/actions/workflows/rust.yml/badge.svg)](https://github.com/dev-bento/secret-bento/actions/workflows/rust.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/dev-bento/secret-bento)](https://github.com/dev-bento/secret-bento/releases)

Local secret scanning reports for AI-assisted cleanup.

Part of **Dev Bento**: tiny local CLIs for AI-assisted indie developers.

Don’t dump your repo. Pack it into a bento.

## Quick Start

Secret Bento is a local CLI that scans a repository for possible leaked secrets and writes a redacted Markdown cleanup report.

It is for indie developers, solo builders, and small teams who use AI assistants but do not want to paste raw repository contents or credentials into chat.

Download the latest binary for your platform from [GitHub Releases](https://github.com/dev-bento/secret-bento/releases). Release assets include SHA256 checksum files.

For v0.3.0, release assets are named by platform:

- `secret-bento-v0.3.0-x86_64-pc-windows-msvc.zip`
- `secret-bento-v0.3.0-x86_64-unknown-linux-gnu.tar.gz`
- `secret-bento-v0.3.0-aarch64-apple-darwin.tar.gz`

After unpacking the archive, verify the binary:

```sh
secret-bento --version
```

Then scan the current repository with the default `builtin` scanner:

```sh
secret-bento scan .
```

Secret Bento writes `SECRET_BENTO_REPORT.md` at the scanned root. Review the report locally before sharing any excerpt with an AI assistant.

For stronger detection, install Gitleaks separately and run:

```sh
secret-bento scan . --scanner gitleaks
```

## What Is Secret Bento?

Secret Bento is a small Rust CLI that scans a local repository for accidentally leaked secrets and writes a redacted Markdown report you can review before asking an AI assistant for cleanup help.

It is built for indie developers, solo builders, and small teams who want a practical local check before sharing security context with ChatGPT, Claude, Codex, Cursor, Gemini, or another assistant.

Secret Bento does three things:

- runs locally against a repository path
- detects possible secrets with the built-in scanner or a local Gitleaks install
- turns findings into redacted, prioritized remediation guidance in Markdown

It does not upload code, call AI APIs, automatically fix secrets, or replace mature scanners and professional security review. The value is the report: safe context packaging, practical prioritization, and remediation guidance that is easy to hand to an AI assistant without uploading your codebase.

## Current Status

Secret Bento has a small Rust CLI. It can scan a local path with the default `builtin` scanner or orchestrate the external `gitleaks` CLI, normalize findings, and write a redacted Markdown remediation report.

The `builtin` scanner is intentionally basic. It does not replace established secret scanners or professional security review.

## Use Gitleaks For Stronger Scanning

Use Gitleaks as the detection engine when you want stronger scanner coverage:

```sh
secret-bento scan . --scanner gitleaks
```

Secret Bento does not bundle Gitleaks. The `--scanner gitleaks` mode shells out to a locally installed `gitleaks` binary, runs `gitleaks detect --report-format json --report-path <temp-file>`, parses the JSON report, drops raw secret values, and converts each result into a Secret Bento finding.

Before using this mode, verify that Gitleaks is installed and available in the same shell:

```sh
gitleaks version
```

If `gitleaks version` does not work, Secret Bento will not be able to run `--scanner gitleaks` either.

## Reduce Noise With --exclude

Use repeatable `--exclude <glob>` filters with the built-in scanner to skip noisy local paths during scanning:

```sh
secret-bento scan . --exclude docs/** --exclude tests/** --exclude **/*.md
```

This is useful for sample reports, fixtures, generated files, or documentation snippets that are intentionally fake. When using `--scanner gitleaks`, use Gitleaks configuration or ignore files for Gitleaks-specific allowlisting.

## Write Reports With --output

Use `--output <path>` to choose where the Markdown report is written:

```sh
secret-bento scan . --output reports/secret-report.md
```

Relative output paths are resolved from the scanned root, and parent directories are created when needed. Absolute output paths are used as provided.

## Use In CI

Secret Bento uses CI-friendly exit codes:

| Exit code | Meaning |
| ---: | --- |
| 0 | Scan completed and no findings were found. |
| 1 | Scan completed and findings were found. |
| 2 | CLI usage or configuration error. |
| 3 | Scanner execution, file IO, JSON parse, or internal error. |

Example GitHub Actions workflow:

```yaml
name: Secret scan

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  secret-bento:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Download Secret Bento
        run: |
          curl -L \
            -o secret-bento.tar.gz \
            https://github.com/dev-bento/secret-bento/releases/download/v0.3.0/secret-bento-v0.3.0-x86_64-unknown-linux-gnu.tar.gz
          tar -xzf secret-bento.tar.gz
          sudo install \
            secret-bento-v0.3.0-x86_64-unknown-linux-gnu/secret-bento \
            /usr/local/bin/secret-bento

      - name: Verify Secret Bento
        run: secret-bento --version

      - name: Scan repository
        run: secret-bento scan . --output reports/secret-bento.md

      - name: Upload Secret Bento report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: secret-bento-report
          path: reports/secret-bento.md
          if-no-files-found: ignore
```

Exit code `1` means the scan completed and found possible secrets. GitHub Actions treats that as a failed step by default, which is useful for protected branches. The artifact step still runs so you can inspect the generated Markdown report before deciding what to rotate or clean up.

To use Gitleaks in CI, install Gitleaks separately before the scan step, then run:

```sh
secret-bento scan . --scanner gitleaks --output reports/secret-bento.md
```

## Hand The Report To An AI Assistant Safely

Secret Bento is designed to produce redacted, AI-ready remediation context. Before pasting any report excerpt into ChatGPT, Claude, Codex, Cursor, Gemini, or another AI assistant:

- Review the report locally.
- Confirm that no real secret values appear in the Markdown.
- Share only the findings and remediation context needed for help.
- Do not paste raw credentials, `.env` contents, or unredacted scanner output into chat.

The report includes an AI handoff prompt you can use after that local review.

## Gitleaks Installation And PATH

Secret Bento does not bundle Gitleaks. The `--scanner gitleaks` mode requires a locally installed `gitleaks` binary that is available on your `PATH`.

Install Gitleaks using the official instructions for your operating system, then verify:

```sh
gitleaks version
```

If that command fails, check that the directory containing the `gitleaks` binary is on `PATH`, then open a new shell and try again. Secret Bento runs the same `gitleaks` command your shell resolves.

When Gitleaks is missing or not on `PATH`, Secret Bento prints:

```text
error: gitleaks is not installed or not available on PATH. Install gitleaks, or use --scanner builtin.
```

Use the built-in scanner as a fallback while you fix the Gitleaks installation:

```sh
secret-bento scan . --scanner builtin
```

After `gitleaks version` works in the same shell, rerun Secret Bento with:

```sh
secret-bento scan . --scanner gitleaks
```

Never paste raw secrets into AI chats. Secret Bento's Markdown report is designed to omit raw Gitleaks `Secret` and `Match` values, but you should still review reports locally before sharing excerpts.

## Usage Reference

The scanner option supports `builtin` and `gitleaks`, with `builtin` as the default:

```sh
secret-bento scan . --scanner builtin
secret-bento scan . --scanner gitleaks
```

Example output:

```text
SECRET_BENTO_REPORT.md
```

## Build From Source

Building from source requires Rust and Cargo:

```sh
cargo run -- scan .
```

For a local release build:

```sh
cargo build --release
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

## v0.2 Gitleaks Integration

With `--scanner gitleaks`, Secret Bento uses gitleaks as the detection engine and focuses on orchestration, normalization, and safe remediation reporting.

Normalized report fields include:

- scanner
- rule ID
- severity
- file
- line
- secret type
- fingerprint when available
- description
- risk
- remediation steps
- verification commands

Markdown reports do not include gitleaks raw `Secret` or `Match` values.

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

## OSS Scanner Integration

Secret Bento integrates with gitleaks without maintaining its rule set. Future scanner integrations should follow the same adapter pattern: run the scanner locally, parse its machine-readable output, normalize into Secret Bento findings, and keep Markdown output redacted.

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
