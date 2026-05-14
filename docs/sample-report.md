# Secret Bento Report

## Report Status

- Scanner: `builtin`
- Report type: redacted summary
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

## Safety Note

Never paste real secrets into AI chats. This report redacts detected values by default, but you should still review it locally before sharing any excerpt with ChatGPT, Claude, Codex, Cursor, Gemini, or another AI assistant.

## Findings

### SB-001. Possible OpenAI API Key

- ID: `SB-001`
- Scanner: `builtin`
- Severity: High
- File: `src/config.example`
- Line: 14
- Secret type: OpenAI API Key
- Description: OPENAI_API_KEY=<REDACTED>
- Risk: An OpenAI-style API key may allow API usage billed to the key owner.
- Remediation steps:
  - Review the value locally and confirm whether it is real.
  - Revoke or rotate the credential if it was committed or shared.
  - Move real secrets to a local `.env` file or secret manager.
  - Check git history if the value may have been committed.
- Verification commands:
  - `git status --short`
  - `git log --all -- <file>`

### SB-002. Tracked `.env` Risk

- ID: `SB-002`
- Scanner: `builtin`
- Severity: Medium
- File: `.env`
- Secret type: Environment File
- Description: `.env` file exists in the scanned repository path.
- Risk: Environment files often contain deploy tokens, database URLs, API credentials, or other private configuration.
- Remediation steps:
  - Confirm whether `.env` is tracked by git.
  - Stop tracking `.env` if it contains local or production configuration.
  - Add `.env` and `.env.*` to `.gitignore`, while allowing `.env.example`.
  - Create a sanitized `.env.example` with placeholder values only.
- Verification commands:
  - `git status --short`
  - `git ls-files -- .env`

### SB-003. Secret-Like Value In Documentation

- ID: `SB-003`
- Scanner: `builtin`
- Severity: Low
- File: `README.md`
- Line: 42
- Secret type: Generic Secret-Like Value
- Description: EXAMPLE_SERVICE_TOKEN=<REDACTED>
- Risk: Documentation sometimes contains copied local commands or logs with credentials.
- Remediation steps:
  - Replace the example with an obvious placeholder value.
  - Avoid including real hostnames, usernames, passwords, or provider-issued credentials in public docs.
  - Re-run the scan after updating documentation examples.
- Verification commands:
  - `git diff -- README.md`
  - `secret-bento scan .`

## Suggested Remediation

- Review each finding locally and confirm whether the value is real.
- Revoke or rotate any credential that was committed, shared, or exposed.
- Move real secrets into local environment files or a secret manager.
- Keep `.env` files untracked and maintain a sanitized `.env.example`.
- Review git history when a real secret may have been committed.

## AI Handoff Prompt

After confirming this report contains no real secret values, you can paste the prompt below into an AI assistant:

```text
I scanned my local repository with Secret Bento. The report below contains redacted possible secret exposure findings. Please help me prioritize remediation steps, identify which credentials likely need rotation, and draft a safe cleanup checklist. Do not ask me to reveal any secret values.
```

## Final Verification

- Re-run Secret Bento with the same scanner: `secret-bento scan <path> --scanner builtin`
- Review `git diff` and `git status --short` before committing cleanup changes.
- Do not paste raw secrets into AI chat.

## Notes

Secret Bento is local-first and Markdown-first. It does not upload code, does not call AI APIs, and does not automatically fix files.
