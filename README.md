# Secret Bento

Tiny local secret scanning reports for AI-assisted indie developers.

Part of **Dev Bento**: tiny local CLIs for AI-assisted indie developers.

Don’t dump your repo. Pack it into a bento.

## What Is Secret Bento?

Secret Bento is a tiny local CLI that scans a local repository for accidentally leaked secrets and generates an AI-ready remediation report in Markdown.

It is not trying to invent secret scanning. Secret Bento starts with simple local checks and is designed to integrate transparently with proven open source scanners in the future. The value is the report: clean context, practical prioritization, and remediation guidance that is easy to hand to an AI assistant without uploading your codebase.

```sh
secret-bento scan .
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

## v0.1 Checks

The first version is planned to check for:

- possible hardcoded API keys
- `.env` tracking risk
- `.env.example` files containing real-looking values
- README, docs, and logs containing secret-like values

Findings should redact detected values by default.

## What It Does Not Do

Secret Bento:

- does not upload code
- does not call AI APIs
- does not automatically fix secrets
- does not replace professional security review
- does not guarantee every secret will be found

## AI Handoff Philosophy

Secret Bento is local-first and Markdown-first.

It prepares clean local context so you can hand the report to ChatGPT, Claude, Codex, Cursor, or Gemini and ask for help with remediation planning.

Never paste real secrets into AI chats. Secret Bento reports should redact detected values and include only enough surrounding context to support safe cleanup.

## Future OSS Scanner Integration

Secret Bento may integrate with existing open source secret scanners in future versions instead of maintaining every detection rule itself. Any integration should be documented clearly, including what scanner is used, what data stays local, and how results are transformed into the Markdown report.

## Planned Rust CLI

This repository is expected to become a small Rust CLI.

Possible future structure:

```text
src/
  main.rs          CLI entrypoint
  scanner.rs       local scanning orchestration
  findings.rs      finding model and severity logic
  report.rs        Markdown report generation
```

The current repository is an initial public placeholder with product direction, roadmap, and sample output.

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

MIT. See [LICENSE](LICENSE).
