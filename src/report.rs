use std::path::Path;

use crate::finding::{SecretBentoFinding, Severity};

pub(crate) fn generate_report(
    root: &Path,
    scanner_name: &str,
    findings: &[SecretBentoFinding],
) -> String {
    let high = findings
        .iter()
        .filter(|finding| finding.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Low)
        .count();

    let mut report = String::new();
    report.push_str("# Secret Bento Report\n\n");
    report.push_str("## Report Status\n\n");
    report.push_str(&format!("- Scanner: `{scanner_name}`\n"));
    report.push_str("- Report type: redacted summary\n");
    report.push_str("- Redaction status: raw secret values are not intentionally rendered\n");
    report.push_str(
        "- Local-first note: generated locally without uploading code or calling AI APIs\n",
    );
    report.push_str(&format!("Scanned path: `{}`\n\n", root.display()));
    report.push_str(&format!("Scanner: `{scanner_name}`\n\n"));
    report.push_str("## Summary\n\n");
    report.push_str("Secret Bento generated this AI-ready remediation report locally without uploading code or calling AI APIs.\n\n");
    report.push_str("Secret Bento orchestrates local scanners, normalizes findings, and writes redacted Markdown context for remediation. It does not replace professional security review.\n\n");
    report.push_str("| Severity | Count |\n");
    report.push_str("| --- | ---: |\n");
    report.push_str(&format!("| High | {high} |\n"));
    report.push_str(&format!("| Medium | {medium} |\n"));
    report.push_str(&format!("| Low | {low} |\n\n"));

    report.push_str("## Safety Note\n\n");
    report.push_str("Never paste real secrets into AI chats. This report redacts detected values by default, but you should still review it locally before sharing any excerpt with ChatGPT, Claude, Codex, Cursor, Gemini, or another AI assistant.\n\n");

    report.push_str("## Findings\n\n");
    if findings.is_empty() {
        report.push_str("No findings were detected by the selected scanner. This does not guarantee that the repository has no secrets.\n\n");
    } else {
        for (index, finding) in findings.iter().enumerate() {
            let display_id = finding_display_id(index);
            report.push_str(&format!("### {display_id}. {}\n\n", finding.title));
            report.push_str(&format!("- ID: `{display_id}`\n"));
            report.push_str(&format!("- Scanner: `{}`\n", finding.scanner));
            if let Some(rule_id) = &finding.rule_id {
                report.push_str(&format!("- Rule ID: `{rule_id}`\n"));
            }
            report.push_str(&format!("- Severity: {}\n", finding.severity.as_str()));
            if let Some(file) = &finding.file {
                report.push_str(&format!("- File: `{}`\n", file.display()));
            }
            if let Some(line) = finding.line {
                report.push_str(&format!("- Line: {line}\n"));
            }
            report.push_str(&format!("- Secret type: {}\n", finding.secret_type));
            if let Some(fingerprint) = &finding.fingerprint {
                report.push_str(&format!("- Fingerprint: `{fingerprint}`\n"));
            }
            report.push_str(&format!("- Description: {}\n", finding.description));
            report.push_str(&format!("- Risk: {}\n", finding.risk));
            report.push_str("- Remediation steps:\n");
            for step in &finding.remediation {
                report.push_str(&format!("  - {step}\n"));
            }
            report.push_str("- Verification commands:\n");
            for command in &finding.verification_commands {
                report.push_str(&format!("  - `{command}`\n"));
            }
            report.push('\n');
        }
    }

    report.push_str("## Suggested Remediation\n\n");
    report.push_str("- Review each finding locally and confirm whether the value is real.\n");
    report.push_str("- Revoke or rotate any credential that was committed, shared, or exposed.\n");
    report.push_str("- Move real secrets into local environment files or a secret manager.\n");
    report.push_str("- Keep `.env` files untracked and maintain a sanitized `.env.example`.\n");
    report.push_str("- Review git history when a real secret may have been committed.\n\n");

    report.push_str("## AI Handoff Prompt\n\n");
    report.push_str("After confirming this report contains no real secret values, you can paste the prompt below into an AI assistant:\n\n");
    report.push_str("```text\n");
    report.push_str("I scanned my local repository with Secret Bento. The report below contains redacted possible secret exposure findings. Please help me prioritize remediation steps, identify which credentials likely need rotation, and draft a safe cleanup checklist. Do not ask me to reveal any secret values.\n");
    report.push_str("```\n\n");

    report.push_str("## Final Verification\n\n");
    report.push_str(&format!(
        "- Re-run Secret Bento with the same scanner: `secret-bento scan <path> --scanner {scanner_name}`\n"
    ));
    report.push_str(
        "- Review `git diff` and `git status --short` before committing cleanup changes.\n",
    );
    report.push_str("- Do not paste raw secrets into AI chat.\n\n");

    report.push_str("## Notes\n\n");
    report.push_str("Secret Bento is local-first and Markdown-first. It does not upload code, does not call AI APIs, and does not automatically fix files.\n");

    report
}

fn finding_display_id(index: usize) -> String {
    format!("SB-{:03}", index + 1)
}
