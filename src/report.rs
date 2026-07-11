use std::path::Path;

use crate::finding::{FindingClassification, SecretBentoFinding, Severity};

pub(crate) fn generate_report(
    root: &Path,
    scanner_name: &str,
    findings: &[SecretBentoFinding],
) -> String {
    generate_report_for_purpose(root, scanner_name, findings, ReportPurpose::Scan)
}

pub(crate) fn generate_handoff_report(
    root: &Path,
    scanner_name: &str,
    findings: &[SecretBentoFinding],
) -> String {
    generate_report_for_purpose(root, scanner_name, findings, ReportPurpose::Handoff)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportPurpose {
    Scan,
    Handoff,
}

impl ReportPurpose {
    fn title(self) -> &'static str {
        match self {
            ReportPurpose::Scan => "# Secret Bento Report",
            ReportPurpose::Handoff => "# Secret Bento Handoff Report",
        }
    }

    fn is_handoff(self) -> bool {
        self == ReportPurpose::Handoff
    }
}

fn generate_report_for_purpose(
    root: &Path,
    scanner_name: &str,
    findings: &[SecretBentoFinding],
    purpose: ReportPurpose,
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
    let needs_human_review = findings
        .iter()
        .filter(|finding| finding.classification.needs_human_review())
        .count();
    let safe_placeholder = findings
        .iter()
        .filter(|finding| finding.classification == FindingClassification::SafePlaceholder)
        .count();
    let safe_environment_reference = findings
        .iter()
        .filter(|finding| {
            finding.classification == FindingClassification::SafeEnvironmentVariableReference
        })
        .count();

    let mut report = String::new();
    report.push_str(purpose.title());
    report.push_str("\n\n");
    report.push_str("## Report Status\n\n");
    report.push_str(&format!("- Scanner: `{scanner_name}`\n"));
    report.push_str("- Report type: redacted summary\n");
    if purpose.is_handoff() {
        report.push_str("- Report purpose: AI-safe handoff\n");
    }
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
    report.push_str("| Classification | Count |\n");
    report.push_str("| --- | ---: |\n");
    report.push_str(&format!("| Needs human review | {needs_human_review} |\n"));
    report.push_str(&format!("| Safe placeholder | {safe_placeholder} |\n"));
    report.push_str(&format!(
        "| Safe environment-variable reference | {safe_environment_reference} |\n\n"
    ));

    if purpose.is_handoff() {
        render_safe_to_share_checklist(&mut report);
        render_ai_handoff_prompts(&mut report);
        render_ai_agent_instructions(&mut report);
        render_human_only_actions(&mut report);
    } else {
        report.push_str("## Safety Note\n\n");
        report.push_str("Never paste real secrets into AI chats. This report redacts detected values by default, but you should still review it locally before sharing any excerpt with ChatGPT, Claude, Codex, Cursor, Gemini, or another AI assistant.\n\n");

        render_safe_to_share_checklist(&mut report);
        render_ai_agent_instructions(&mut report);
        render_human_only_actions(&mut report);
    }

    report.push_str("## Findings\n\n");
    if findings.is_empty() {
        report.push_str("No findings were detected by the selected scanner. This does not guarantee that the repository has no secrets.\n\n");
    } else {
        for (index, finding) in findings.iter().enumerate() {
            let display_id = finding_display_id(index);
            report.push_str(&format!("### {display_id}. {}\n\n", finding.title));
            report.push_str("#### Finding\n\n");
            report.push_str(&format!("- ID: `{display_id}`\n"));
            report.push_str(&format!("- Scanner: `{}`\n", finding.scanner));
            if let Some(rule_id) = &finding.rule_id {
                report.push_str(&format!("- Rule ID: `{rule_id}`\n"));
            }
            report.push_str(&format!("- Severity: {}\n", finding.severity.as_str()));
            report.push_str(&format!(
                "- Classification: {}\n",
                finding.classification.as_str()
            ));
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
            report.push_str("\n#### Risk\n\n");
            report.push_str(&format!("{}\n\n", finding.risk));
            report.push_str("#### Suggested AI-Assisted Fix\n\n");
            let mut rendered_fix = false;
            for step in finding
                .remediation
                .iter()
                .filter(|step| !purpose.is_handoff() || !is_human_only_remediation(step))
            {
                report.push_str(&format!("- {step}\n"));
                rendered_fix = true;
            }
            if purpose.is_handoff() {
                report.push_str(
                    "- Apply any needed code, docs, `.gitignore`, or `.env.example` cleanup.\n",
                );
                rendered_fix = true;
            }
            if !rendered_fix {
                report.push_str("- Review and clean up the referenced file locally.\n");
            }
            if !purpose.is_handoff() {
                report.push_str(
                    "- Ask the AI assistant to explain the change before editing files.\n",
                );
                report.push_str("- Do not provide the real secret value to the AI assistant.\n");
            }
            report.push('\n');
            report.push_str("#### Human Verification\n\n");
            report.push_str(
                "- Inspect the referenced file locally and confirm whether the finding is real.\n",
            );
            for command in &finding.verification_commands {
                report.push_str(&format!("- Run `{command}`\n"));
            }
            if purpose.is_handoff() {
                report.push_str("- Review `git diff` and `git status --short` before committing cleanup changes.\n");
                report.push_str(&format!(
                    "- Re-run Secret Bento with the same scanner: `secret-bento handoff <path> --scanner {scanner_name}`\n"
                ));
            } else {
                report.push_str("- Rotate or revoke any real credential in the provider dashboard if it was committed, shared, or exposed.\n");
            }
            report.push('\n');
        }
    }

    if !purpose.is_handoff() {
        report.push_str("## Suggested Remediation\n\n");
        report.push_str("- Review each finding locally and confirm whether the value is real.\n");
        report.push_str(
            "- Revoke or rotate any credential that was committed, shared, or exposed.\n",
        );
        report.push_str("- Move real secrets into local environment files or a secret manager.\n");
        report.push_str("- Keep `.env` files untracked and maintain a sanitized `.env.example`.\n");
        report.push_str("- Review git history when a real secret may have been committed.\n\n");

        render_ai_handoff_prompts(&mut report);
    }

    report.push_str("## Final Verification\n\n");
    if purpose.is_handoff() {
        report.push_str("- Re-run Secret Bento with the same scanner.\n");
    } else {
        report.push_str(&format!(
            "- Re-run Secret Bento with the same scanner: `secret-bento scan <path> --scanner {scanner_name}`\n"
        ));
    }
    report.push_str("- Review `git diff` before committing cleanup changes.\n");
    report.push_str("- Review `git status --short`.\n");
    report.push_str("- Confirm any real exposed keys were rotated or revoked by a human.\n\n");

    report.push_str("## Notes\n\n");
    report.push_str("Secret Bento is local-first and Markdown-first. It does not upload code, does not call AI APIs, and does not automatically fix files.\n");
    report.push_str("A redacted value is hidden or replaced with `<REDACTED>` so the real value is not shown. A local-first tool runs on your machine instead of uploading your code or reports.\n");

    report
}

fn render_safe_to_share_checklist(report: &mut String) {
    report.push_str("## Safe to Share Checklist\n\n");
    report.push_str("Before pasting any part of this report into an AI chat:\n\n");
    report.push_str("- I reviewed this report locally.\n");
    report.push_str(
        "- I do not see any real API key, password, token, private URL, or `.env` value.\n",
    );
    report.push_str("- I will not paste raw `.env` files or unredacted scanner output.\n");
    report.push_str("- I understand the AI can help edit code, docs, `.gitignore`, and `.env.example`, but I must rotate or revoke real keys myself.\n\n");
}

fn render_ai_agent_instructions(report: &mut String) {
    report.push_str("## AI Agent Instructions\n\n");
    report.push_str("Use this report as redacted context for safe cleanup. You may help update code, docs, `.gitignore`, and `.env.example`.\n\n");
    report.push_str("Do not ask for or print secret values. Do not delete files broadly, rewrite git history, run destructive git commands, rotate credentials, or change production settings.\n\n");
}

fn render_human_only_actions(report: &mut String) {
    report.push_str("## Human-Only Actions\n\n");
    report.push_str("- Rotate real keys in provider dashboards.\n");
    report.push_str("- Revoke exposed keys so they can no longer be used.\n");
    report.push_str("- Update deployment secrets in GitHub, Vercel, Netlify, Supabase, Stripe, OpenAI, AWS, or other services.\n");
    report.push_str("- Approve any git history cleanup before an AI agent attempts it.\n\n");
}

fn render_ai_handoff_prompts(report: &mut String) {
    report.push_str("## AI Handoff Prompts\n\n");
    report.push_str("After confirming this report contains no real secret values, paste the most relevant prompt below into your AI assistant along with the redacted findings you want help with.\n\n");
    report.push_str("### Codex / Cursor\n\n");
    report.push_str("```text\n");
    report.push_str("I scanned my local repository with Secret Bento. The report below contains redacted possible secret exposure findings. Help me safely clean up code, docs, `.gitignore`, and `.env.example`. Do not ask for or print secret values. Before editing, check `git status --short` and propose a small plan. Do not run destructive git commands, rewrite history, rotate credentials, or change production settings.\n");
    report.push_str("```\n\n");
    report.push_str("### Claude Code\n\n");
    report.push_str("```text\n");
    report.push_str("I scanned my local repository with Secret Bento. Use this redacted report to help remove hardcoded secrets, improve `.gitignore`, and update `.env.example`. Do not ask me to reveal secrets. Do not print secret values. Do not rotate credentials or rewrite git history. Ask before broad changes.\n");
    report.push_str("```\n\n");
    report.push_str("### ChatGPT\n\n");
    report.push_str("```text\n");
    report.push_str("I scanned my repository with Secret Bento. I do not want to paste raw secrets. Based on this redacted report, help me understand the risk, decide what I should verify locally, and make a safe cleanup checklist. Do not ask me to reveal any secret values.\n");
    report.push_str("```\n\n");
}

fn is_human_only_remediation(step: &str) -> bool {
    let normalized = step.to_ascii_lowercase();
    normalized.contains("revoke")
        || normalized.contains("rotate")
        || normalized.contains("git history")
        || normalized.contains("incident policy")
}

fn finding_display_id(index: usize) -> String {
    format!("SB-{:03}", index + 1)
}
