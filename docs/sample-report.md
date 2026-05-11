# Secret Bento Report

Repository: `example-app`
Scanned path: `.`
Generated: `2026-05-11T00:00:00Z`

## Report Status

This is a sample of the intended Markdown output from the Secret Bento v0.1 MVP.

## Summary

Secret Bento found possible secret exposure risks that should be reviewed locally before asking an AI assistant for help.

| Severity | Count |
| --- | ---: |
| High | 1 |
| Medium | 2 |
| Low | 1 |

## Safety Note

Never paste real secrets into AI chats. This report redacts detected values and includes only enough context to support remediation planning.

## Findings

### 1. Possible Hardcoded API Key

- Severity: High
- Confidence: Medium
- File: `src/config.ts`
- Line: 14
- Evidence: `OPENAI_API_KEY = "sk-...REDACTED"`
- Why it matters: A hardcoded API key may be exposed to anyone with repository access and may appear in git history.
- Suggested remediation:
  - Revoke or rotate the key in the provider dashboard.
  - Move the value to a local `.env` file or secret manager.
  - Confirm `.env` is ignored by git.
  - Check git history if the key was already committed.

### 2. Tracked `.env` Risk

- Severity: Medium
- Confidence: High
- File: `.env`
- Line: 1
- Evidence: `.env` appears to exist in the scanned repository.
- Why it matters: Environment files often contain deploy tokens, database URLs, or API credentials.
- Suggested remediation:
  - Stop tracking `.env`.
  - Add `.env` and `.env.*` to `.gitignore`, while allowing `.env.example`.
  - Create a sanitized `.env.example` for required variable names.

### 3. Real-Looking Value In `.env.example`

- Severity: Medium
- Confidence: Medium
- File: `.env.example`
- Line: 3
- Evidence: `STRIPE_SECRET_KEY=sk_live_...REDACTED`
- Why it matters: Example files should use fake placeholder values. Real-looking values can be copied into production or accidentally expose credentials.
- Suggested remediation:
  - Replace with a clearly fake value such as `STRIPE_SECRET_KEY=replace_me`.
  - Document where developers should obtain the real value.

### 4. Secret-Like Value In Documentation

- Severity: Low
- Confidence: Low
- File: `README.md`
- Line: 42
- Evidence: `DATABASE_URL=postgres://user:...REDACTED`
- Why it matters: Documentation sometimes contains copied local commands or logs with credentials.
- Suggested remediation:
  - Replace the example with a fake credential.
  - Avoid including real hostnames, usernames, or passwords in public docs.

## AI Handoff Prompt

You can paste the following prompt into an AI assistant after manually confirming that all detected values are redacted:

```text
I scanned my local repository with Secret Bento. The report below contains redacted possible secret exposure findings. Please help me prioritize remediation steps, identify which credentials likely need rotation, and draft a safe cleanup checklist. Do not ask me to reveal any secret values.
```

## Notes

Secret Bento reports are local-first and Markdown-first. Secret Bento does not upload code, does not call AI APIs, and does not automatically fix secrets.
