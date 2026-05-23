# Secret Bento

[![Rust](https://github.com/dev-bento/secret-bento/actions/workflows/rust.yml/badge.svg)](https://github.com/dev-bento/secret-bento/actions/workflows/rust.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/dev-bento/secret-bento)](https://github.com/dev-bento/secret-bento/releases)

AI-safe secret cleanup handoffs for beginner vibe coders.

Secret Bento creates AI-safe handoff reports from local secret checks, so you can ask Codex, Claude Code, Cursor, ChatGPT, or another AI tool for cleanup help without exposing raw secrets.

It runs locally. It does not upload your code. It does not call AI APIs. It does not intentionally print raw secrets.

Part of **Dev Bento**: small AI-handoff kits for builders who use AI tools to change, ship, and maintain apps without leaking secrets or wrecking their repo.

Don’t dump your repo. Pack it into a bento.

## Quick Start

After installing Secret Bento, verify the binary:

```sh
secret-bento --version
```

Check your local setup:

```sh
secret-bento doctor .
```

Create a redacted AI handoff report:

```sh
secret-bento handoff .
```

Secret Bento writes:

```text
SECRET_BENTO_HANDOFF.md
```

Open that report locally first. Before pasting anything into an AI chat, confirm that no real API keys, passwords, tokens, database URLs, or `.env` values appear in it.

Download the latest binary for your platform from [GitHub Releases](https://github.com/dev-bento/secret-bento/releases). Release assets include SHA256 checksum files.

Release assets are named by version and platform:

- `secret-bento-vX.Y.Z-x86_64-pc-windows-msvc.zip`
- `secret-bento-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
- `secret-bento-vX.Y.Z-aarch64-apple-darwin.tar.gz`

## What To Do If Secret Bento Finds Something

1. Do not paste the raw secret into chat.
2. Read the finding in `SECRET_BENTO_HANDOFF.md`.
3. Paste the report's AI handoff prompt into Codex, Claude Code, Cursor, ChatGPT, or your AI tool of choice.
4. Let the AI help with code, docs, `.gitignore`, and `.env.example`.
5. Rotate or revoke real exposed keys yourself in the provider dashboard.
6. Re-run `secret-bento handoff .` or `secret-bento scan .`.

## Use With Codex, Claude Code, Cursor, Or ChatGPT

The report includes tool-specific prompts. Use the Codex/Cursor or Claude Code prompt when the AI can edit your local repo. Use the ChatGPT prompt when you only want explanation and a checklist.

The prompts tell AI tools not to ask for secret values, not to print secret values, not to run destructive git commands, and not to rewrite git history.

Use `handoff` when you want a report to paste into Codex, Claude Code, Cursor, or ChatGPT:

```sh
secret-bento handoff .
```

Use `scan` when you want the standard scan report or CI-compatible workflow:

```sh
secret-bento scan .
```

## Standard Scan Report For Existing Users And CI

Use `scan` when you want the standard report filename, CI-friendly behavior, or compatibility with existing workflows:

```sh
secret-bento scan .
```

This uses the lightweight built-in scanner. It is useful for a quick local smoke check, but it is not a full secret scanner.

Secret Bento writes `SECRET_BENTO_REPORT.md` at the scanned root. Review the report locally before sharing any excerpt with an AI assistant.

For beginner-facing AI handoff, use `secret-bento handoff .`, which writes `SECRET_BENTO_HANDOFF.md`.

After a scan, Secret Bento prints a compact local summary with the scanner name, report path, finding count, exit-code meaning, and safe next steps.

## Recommended: Use Gitleaks For Stronger Detection

Install Gitleaks separately, then run:

```sh
secret-bento handoff . --scanner gitleaks
```

In this mode, Gitleaks does the detection. Secret Bento turns the results into a redacted Markdown handoff report that you can review locally and safely give to an AI assistant.

For standard reports or CI workflows, use:

```sh
secret-bento scan . --scanner gitleaks
```

## What Is Secret Bento?

Secret Bento is a small Rust CLI that creates AI-safe handoff reports from local secret checks. It helps indie developers, solo builders, and small teams ask ChatGPT, Claude, Codex, Cursor, Gemini, or another assistant for cleanup help without pasting raw credentials or an entire repository into chat.

Secret Bento does three things:

- runs local secret checks against a repository path
- normalizes possible findings from the built-in checker or a local Gitleaks install
- writes redacted Markdown handoff reports with AI prompts, human-only actions, and verification steps

It does not upload code, call AI APIs, automatically fix secrets, or replace mature scanners and professional security review. The value is the handoff: safe context packaging, practical prioritization, and remediation guidance that is easy to give an AI assistant without leaking secrets.

## Starter Kit

Secret Bento CLI is open source.

If you want the full workflow package, the paid Secret Bento Starter Kit is a separate package that includes setup guides, AI handoff prompts, checklists, GitHub Actions templates, and sanitized examples.

Get the Starter Kit: https://hunon.gumroad.com/l/secret-bento-starter-kit

## Current Status

Secret Bento v0.6 has two local report workflows:

- `secret-bento handoff .` writes `SECRET_BENTO_HANDOFF.md`, a concise AI-safe handoff report for Codex, Claude Code, Cursor, ChatGPT, or another assistant.
- `secret-bento scan .` writes `SECRET_BENTO_REPORT.md`, the standard scan report for existing users, CI, and scanner-style workflows.

Both workflows use the same local secret checks, scanner redaction behavior, and anti-leak guarantees. Secret Bento can use the default `builtin` checker or orchestrate the external `gitleaks` CLI, normalize findings, and write redacted Markdown.

The CLI also includes concise help output, clearer usage errors, compact completion summaries, and a non-invasive `doctor` readiness check.

The `builtin` scanner is intentionally basic. It does not replace established secret scanners or professional security review.

## Check Local Readiness With Doctor

Run:

```sh
secret-bento doctor
```

Or check a specific path:

```sh
secret-bento doctor .
```

Doctor reports Secret Bento version, Gitleaks availability, Git availability, whether the current directory appears to be inside a git repository, optional scan path status, and whether the default output directory appears writable.

Doctor does not scan files, read file contents, inspect secrets, upload anything, or call AI APIs. If Gitleaks is missing, Doctor still exits successfully and notes that the built-in scanner remains available as a smoke check.

## Use Gitleaks For Stronger Scanning

Use Gitleaks as the detection engine when you want stronger scanner coverage:

```sh
secret-bento scan . --scanner gitleaks
```

Secret Bento does not bundle Gitleaks. The `--scanner gitleaks` mode shells out to a locally installed `gitleaks` binary, reads JSON from stdout with `gitleaks detect --report-format json --report-path - --redact`, ignores raw Gitleaks `Secret` and `Match` fields during normalization, and converts each result into a Secret Bento finding.

Before using this mode, verify that Gitleaks is installed and available in the same shell:

```sh
gitleaks version
```

If `gitleaks version` does not work, Secret Bento will not be able to run `--scanner gitleaks` either.

## Recommended: Install Gitleaks

Secret Bento works without extra tools, but Gitleaks is recommended when detection coverage matters.

- Secret Bento does not bundle Gitleaks.
- Secret Bento does not replace Gitleaks.
- Gitleaks is the detection engine.
- Secret Bento is the report and context packer.
- Use `builtin` for a no-dependency smoke check.
- Use `gitleaks` when you care about detection coverage.

After installing Gitleaks, verify it is available:

```sh
gitleaks version
```

Then run:

```sh
secret-bento scan . --scanner gitleaks
```

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
            https://github.com/dev-bento/secret-bento/releases/download/vX.Y.Z/secret-bento-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
          tar -xzf secret-bento.tar.gz
          sudo install \
            secret-bento-vX.Y.Z-x86_64-unknown-linux-gnu/secret-bento \
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

The report includes AI handoff prompts you can use after that local review.

## Gitleaks Installation And PATH

Secret Bento does not bundle Gitleaks. The `--scanner gitleaks` mode requires a locally installed `gitleaks` binary that is available on your `PATH`.

Install Gitleaks using the official instructions for your operating system, then verify:

```sh
gitleaks version
```

If that command fails, check that the directory containing the `gitleaks` binary is on `PATH`, then open a new shell and try again. Secret Bento runs the same `gitleaks` command your shell resolves.

When Gitleaks is missing or not on `PATH`, Secret Bento prints:

```text
error: gitleaks was not found on PATH. Gitleaks is optional, but recommended for stronger detection.
```

Use the built-in scanner as a fallback while you fix the Gitleaks installation:

```sh
secret-bento scan . --scanner builtin
```

After `gitleaks version` works in the same shell, rerun Secret Bento with:

```sh
secret-bento scan . --scanner gitleaks
```

Never paste raw secrets into AI chats. Secret Bento runs Gitleaks with redaction enabled and its Markdown report is designed to omit raw Gitleaks `Secret` and `Match` values, but you should still review reports locally before sharing excerpts.

## Usage Reference

Use `handoff` when you want AI-safe context to paste into an assistant:

```sh
secret-bento handoff .
secret-bento handoff . --scanner gitleaks
secret-bento handoff . --output SECRET_BENTO_HANDOFF.md
```

Use `scan` when you want the standard scan report or CI-compatible workflow:

```sh
secret-bento scan .
secret-bento scan . --scanner builtin
secret-bento scan . --scanner gitleaks
```

Example output:

```text
Secret Bento handoff complete

Scanner: builtin
Report: /path/to/repo/SECRET_BENTO_HANDOFF.md
Findings: 0 total
Exit code: 0 = clean scan

Note: builtin scanner is a smoke check. Use `--scanner gitleaks` for stronger detection.
```

Standard scan output uses the scan report filename:

```text
Secret Bento scan complete

Scanner: builtin
Report: /path/to/repo/SECRET_BENTO_REPORT.md
Findings: 0 total
Exit code: 0 = clean scan

Note: builtin scanner is a smoke check. Use `--scanner gitleaks` for stronger detection.
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

Secret Bento reads the Gitleaks JSON report from stdout using `--report-path -` and invokes Gitleaks with `--redact`. It does not persist a raw Gitleaks JSON report file as part of normal operation.

Normalized report fields include:

- stable display ID, such as `SB-001`
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

Markdown reports include a report status block and final verification guidance. They do not include gitleaks raw `Secret` or `Match` values, and those fields are not used when normalizing Gitleaks findings.

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

Current high-level structure:

```text
src/
  main.rs          thin process wrapper
  lib.rs           CLI parsing, scan orchestration, and scanner adapters
  finding.rs       finding model and severity labels
  redaction.rs     redaction helpers
  report.rs        Markdown report rendering
```

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

MIT. See [LICENSE](LICENSE).
