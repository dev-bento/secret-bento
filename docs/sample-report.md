# Secret Bento Handoff Report

## Report Status

- Scanner: `builtin`
- Report type: redacted summary
- Report purpose: AI-safe handoff
- Redaction status: raw secret values are not intentionally rendered
- Local-first note: generated locally without uploading code or calling AI APIs
Scanned path: `example-app`

Scanner: `builtin`

## Summary

Secret Bento generated this AI-ready remediation report locally without uploading code or calling AI APIs.

Secret Bento orchestrates local scanners, normalizes findings, and writes redacted Markdown context for remediation. It does not replace professional security review.

| Severity | Count |
| --- | ---: |
| High | 1 |
| Medium | 1 |
| Low | 1 |

## Safe to Share Checklist

Before pasting any part of this report into an AI chat:

- I reviewed this report locally.
- I do not see any real API key, password, token, private URL, or `.env` value.
- I will not paste raw `.env` files or unredacted scanner output.
- I understand the AI can help edit code, docs, `.gitignore`, and `.env.example`, but I must rotate or revoke real keys myself.

## AI Handoff Prompts

After confirming this report contains no real secret values, paste the most relevant prompt below into your AI assistant along with the redacted findings you want help with.

### Codex / Cursor

```text
I scanned my local repository with Secret Bento. The report below contains redacted possible secret exposure findings. Help me safely clean up code, docs, `.gitignore`, and `.env.example`. Do not ask for or print secret values. Before editing, check `git status --short` and propose a small plan. Do not run destructive git commands, rewrite history, rotate credentials, or change production settings.
```

### Claude Code

```text
I scanned my local repository with Secret Bento. Use this redacted report to help remove hardcoded secrets, improve `.gitignore`, and update `.env.example`. Do not ask me to reveal secrets. Do not print secret values. Do not rotate credentials or rewrite git history. Ask before broad changes.
```

### ChatGPT

```text
I scanned my repository with Secret Bento. I do not want to paste raw secrets. Based on this redacted report, help me understand the risk, decide what I should verify locally, and make a safe cleanup checklist. Do not ask me to reveal any secret values.
```

## AI Agent Instructions

Use this report as redacted context for safe cleanup. You may help update code, docs, `.gitignore`, and `.env.example`.

Do not ask for or print secret values. Do not delete files broadly, rewrite git history, run destructive git commands, rotate credentials, or change production settings.

## Human-Only Actions

- Rotate real keys in provider dashboards.
- Revoke exposed keys so they can no longer be used.
- Update deployment secrets in GitHub, Vercel, Netlify, Supabase, Stripe, OpenAI, AWS, or other services.
- Approve any git history cleanup before an AI agent attempts it.

## Findings

### SB-001. Possible OpenAI API Key

#### Finding

- ID: `SB-001`
- Scanner: `builtin`
- Severity: High
- File: `src/config.example`
- Line: 14
- Secret type: OpenAI API Key
- Description: OPENAI_API_KEY=<REDACTED>

#### Risk

An OpenAI-style API key may allow API usage billed to the key owner.

#### Suggested AI-Assisted Fix

- Review the value locally and confirm whether it is real.
- Move real secrets to a local `.env` file or secret manager.
- Apply any needed code, docs, `.gitignore`, or `.env.example` cleanup.

#### Human Verification

- Inspect the referenced file locally and confirm whether the finding is real.
- Run `git status --short`
- Run `git log --all -- <file>`
- Review `git diff` and `git status --short` before committing cleanup changes.
- Re-run Secret Bento with the same scanner: `secret-bento handoff <path> --scanner builtin`

### SB-002. Tracked `.env` Risk

#### Finding

- ID: `SB-002`
- Scanner: `builtin`
- Severity: Medium
- File: `.env`
- Secret type: Environment File
- Description: `.env` file exists in the scanned repository path.

#### Risk

Environment files often contain deploy tokens, database URLs, API credentials, or other private configuration.

#### Suggested AI-Assisted Fix

- Confirm whether `.env` is tracked by git.
- Stop tracking `.env` if it contains local or production configuration.
- Add `.env` and `.env.*` to `.gitignore`, while allowing `.env.example`.
- Create a sanitized `.env.example` with placeholder values only.
- Apply any needed code, docs, `.gitignore`, or `.env.example` cleanup.

#### Human Verification

- Inspect the referenced file locally and confirm whether the finding is real.
- Run `git status --short`
- Run `git ls-files -- .env`
- Review `git diff` and `git status --short` before committing cleanup changes.
- Re-run Secret Bento with the same scanner: `secret-bento handoff <path> --scanner builtin`

### SB-003. Secret-Like Value In Documentation

#### Finding

- ID: `SB-003`
- Scanner: `builtin`
- Severity: Low
- File: `README.md`
- Line: 42
- Secret type: Generic Secret-Like Value
- Description: EXAMPLE_SERVICE_TOKEN=<REDACTED>

#### Risk

Documentation sometimes contains copied local commands or logs with credentials.

#### Suggested AI-Assisted Fix

- Replace the example with an obvious placeholder value.
- Avoid including real hostnames, usernames, passwords, or provider-issued credentials in public docs.
- Re-run the scan after updating documentation examples.
- Apply any needed code, docs, `.gitignore`, or `.env.example` cleanup.

#### Human Verification

- Inspect the referenced file locally and confirm whether the finding is real.
- Run `git diff -- README.md`
- Run `secret-bento scan .`
- Review `git diff` and `git status --short` before committing cleanup changes.
- Re-run Secret Bento with the same scanner: `secret-bento handoff <path> --scanner builtin`

## Final Verification

- Re-run Secret Bento with the same scanner.
- Review `git diff` before committing cleanup changes.
- Review `git status --short`.
- Confirm any real exposed keys were rotated or revoked by a human.

## Notes

Secret Bento is local-first and Markdown-first. It does not upload code, does not call AI APIs, and does not automatically fix files.
A redacted value is hidden or replaced with `<REDACTED>` so the real value is not shown. A local-first tool runs on your machine instead of uploading your code or reports.
