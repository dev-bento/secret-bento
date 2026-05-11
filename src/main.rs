use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const REPORT_FILE: &str = "SECRET_BENTO_REPORT.md";
const IGNORED_DIRS: &[&str] = &[".git", "node_modules", ".next", "dist", "build", "target"];
const GENERIC_SECRET_NAMES: &[&str] = &["API_KEY", "SECRET_KEY", "TOKEN", "DATABASE_URL"];
const PLACEHOLDER_VALUES: &[&str] = &[
    "changeme",
    "change_me",
    "example",
    "fake",
    "placeholder",
    "replace_me",
    "todo",
    "your_api_key",
    "your-token",
    "your_token",
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    fn as_str(&self) -> &'static str {
        match self {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Finding {
    title: String,
    severity: Severity,
    confidence: &'static str,
    file: Option<PathBuf>,
    line: Option<usize>,
    evidence: String,
    why_it_matters: String,
    remediation: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScannerKind {
    Builtin,
}

impl ScannerKind {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "builtin" => Ok(ScannerKind::Builtin),
            "gitleaks" => Err("scanner `gitleaks` is planned but not implemented yet".to_string()),
            other => Err(format!(
                "unknown scanner `{other}`; supported scanner: builtin"
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ScanOptions {
    scanner: ScannerKind,
    path: PathBuf,
    excludes: Vec<String>,
    output: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct ScanContext {
    root: PathBuf,
    excludes: Vec<String>,
}

#[derive(Clone, Debug)]
struct ScanResult {
    scanner_name: &'static str,
    findings: Vec<Finding>,
}

trait Scanner {
    fn name(&self) -> &'static str;
    fn scan(&self, context: &ScanContext) -> Result<ScanResult, String>;
}

struct BuiltinScanner;

impl Scanner for BuiltinScanner {
    fn name(&self) -> &'static str {
        "builtin"
    }

    fn scan(&self, context: &ScanContext) -> Result<ScanResult, String> {
        let mut findings = Vec::new();
        scan_path_recursive(
            &context.root,
            &context.root,
            &context.excludes,
            &mut findings,
        )
        .map_err(|error| format!("failed while scanning files: {error}"))?;
        findings.extend(check_env_file(&context.root, &context.excludes));

        Ok(ScanResult {
            scanner_name: self.name(),
            findings,
        })
    }
}

fn main() {
    if let Err(error) = run(env::args().collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let program_name = args.first().map_or("secret-bento", String::as_str);
    let options = parse_scan_options(&args, program_name)?;

    if !options.path.exists() {
        return Err(format!(
            "scan path does not exist: {}",
            options.path.display()
        ));
    }

    let root = fs::canonicalize(&options.path)
        .map_err(|error| format!("failed to resolve scan path: {error}"))?;
    let context = ScanContext {
        root,
        excludes: options.excludes,
    };
    let scanner = scanner_for(options.scanner);
    let result = scanner.scan(&context)?;

    let report = generate_report(&context.root, result.scanner_name, &result.findings);
    let report_path = resolve_report_path(&context.root, options.output.as_deref());
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create report directory {}: {error}",
                parent.display()
            )
        })?;
    }
    fs::write(&report_path, report)
        .map_err(|error| format!("failed to write {}: {error}", report_path.display()))?;

    println!("Generated {}", report_path.display());
    Ok(())
}

fn parse_scan_options(args: &[String], program_name: &str) -> Result<ScanOptions, String> {
    if args.len() < 3 || args[1] != "scan" {
        return Err(usage(program_name));
    }

    let mut scanner = ScannerKind::Builtin;
    let mut path = None;
    let mut excludes = Vec::new();
    let mut output = None;
    let mut index = 2;

    while index < args.len() {
        match args[index].as_str() {
            "--exclude" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| usage(program_name))?;
                excludes.push(value.to_string());
            }
            value if value.starts_with("--exclude=") => {
                let value = value.trim_start_matches("--exclude=");
                excludes.push(value.to_string());
            }
            "--output" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| usage(program_name))?;
                output = Some(PathBuf::from(value));
            }
            value if value.starts_with("--output=") => {
                let value = value.trim_start_matches("--output=");
                output = Some(PathBuf::from(value));
            }
            "--scanner" => {
                index += 1;
                let value = args.get(index).ok_or_else(|| usage(program_name))?;
                scanner = ScannerKind::parse(value)?;
            }
            value if value.starts_with("--scanner=") => {
                let value = value.trim_start_matches("--scanner=");
                scanner = ScannerKind::parse(value)?;
            }
            value if value.starts_with("--") => {
                return Err(format!(
                    "unknown option `{value}`\n\n{}",
                    usage(program_name)
                ));
            }
            value => {
                if path.is_some() {
                    return Err(usage(program_name));
                }
                path = Some(PathBuf::from(value));
            }
        }

        index += 1;
    }

    let path = path.ok_or_else(|| usage(program_name))?;

    Ok(ScanOptions {
        scanner,
        path,
        excludes,
        output,
    })
}

fn scanner_for(scanner: ScannerKind) -> Box<dyn Scanner> {
    match scanner {
        ScannerKind::Builtin => Box::new(BuiltinScanner),
    }
}

fn usage(program_name: &str) -> String {
    format!(
        "{program_name} scan <path> [--scanner builtin] [--exclude <glob>]... [--output <path>]"
    )
}

fn scan_path_recursive(
    root: &Path,
    current: &Path,
    excludes: &[String],
    findings: &mut Vec<Finding>,
) -> io::Result<()> {
    for entry_result in fs::read_dir(current)? {
        let entry = entry_result?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            if should_ignore_dir(entry.file_name().as_ref()) {
                continue;
            }
            if should_exclude_path(root, &path, excludes) {
                continue;
            }
            scan_path_recursive(root, &path, excludes, findings)?;
        } else if file_type.is_file()
            && !should_exclude_path(root, &path, excludes)
            && should_scan_file(root, &path)
        {
            scan_file(root, &path, findings)?;
        }
    }

    Ok(())
}

fn should_ignore_dir(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    IGNORED_DIRS.iter().any(|ignored| *ignored == name)
}

fn should_exclude_path(root: &Path, path: &Path, excludes: &[String]) -> bool {
    let relative_path = match path.strip_prefix(root) {
        Ok(relative_path) => relative_path,
        Err(_) => path,
    };
    let normalized_path = normalize_path_for_glob(relative_path);

    excludes
        .iter()
        .any(|pattern| glob_matches(pattern, &normalized_path))
}

fn normalize_path_for_glob(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.replace('\\', "/");
    let pattern_segments = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let path_segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    glob_segments_match(&pattern_segments, &path_segments)
}

fn glob_segments_match(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((pattern_segment, remaining_pattern)) if *pattern_segment == "**" => {
            glob_segments_match(remaining_pattern, path)
                || (!path.is_empty() && glob_segments_match(pattern, &path[1..]))
        }
        Some((pattern_segment, remaining_pattern)) => match path.split_first() {
            Some((path_segment, remaining_path))
                if glob_segment_matches(pattern_segment, path_segment) =>
            {
                glob_segments_match(remaining_pattern, remaining_path)
            }
            _ => false,
        },
    }
}

fn glob_segment_matches(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts = pattern.split('*').collect::<Vec<_>>();
    let mut remaining = text;

    if let Some(first) = parts.first() {
        if !first.is_empty() {
            if !remaining.starts_with(first) {
                return false;
            }
            remaining = &remaining[first.len()..];
        }
    }

    for part in parts.iter().skip(1).take(parts.len().saturating_sub(2)) {
        if part.is_empty() {
            continue;
        }
        match remaining.find(part) {
            Some(index) => remaining = &remaining[index + part.len()..],
            None => return false,
        }
    }

    if let Some(last) = parts.last() {
        last.is_empty() || remaining.ends_with(last)
    } else {
        true
    }
}

fn resolve_report_path(root: &Path, output: Option<&Path>) -> PathBuf {
    match output {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => root.join(path),
        None => root.join(REPORT_FILE),
    }
}

fn should_scan_file(root: &Path, path: &Path) -> bool {
    if matches!(
        path.strip_prefix(root),
        Ok(relative_path) if relative_path == Path::new(REPORT_FILE)
    ) {
        return false;
    }

    match fs::metadata(path) {
        Ok(metadata) => metadata.len() <= 1_000_000,
        Err(_) => false,
    }
}

fn scan_file(root: &Path, path: &Path, findings: &mut Vec<Finding>) -> io::Result<()> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return Ok(()),
    };

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        findings.extend(detect_line(root, path, line_number, line));
    }

    Ok(())
}

fn detect_line(root: &Path, path: &Path, line_number: usize, line: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let relative_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();

    let has_openai_key = contains_openai_key(line);
    let has_stripe_secret_key = contains_stripe_secret_key(line);
    let has_github_token = contains_github_token(line);
    let has_aws_access_key_id = contains_aws_access_key_id(line);
    let has_supabase_service_role = is_supabase_service_role_line(line);

    if has_openai_key {
        findings.push(secret_finding(
            "Possible OpenAI API Key",
            Severity::High,
            "Medium",
            &relative_path,
            line_number,
            line,
            "An OpenAI-style API key may allow API usage billed to the key owner.",
        ));
    }

    if has_stripe_secret_key {
        findings.push(secret_finding(
            "Possible Stripe Secret Key",
            Severity::High,
            "Medium",
            &relative_path,
            line_number,
            line,
            "A Stripe secret key may allow access to payment-related API operations.",
        ));
    }

    if has_github_token {
        findings.push(secret_finding(
            "Possible GitHub Token",
            Severity::High,
            "Medium",
            &relative_path,
            line_number,
            line,
            "A GitHub token may allow repository or account access depending on its scopes.",
        ));
    }

    if has_aws_access_key_id {
        findings.push(secret_finding(
            "Possible AWS Access Key ID",
            Severity::High,
            "Medium",
            &relative_path,
            line_number,
            line,
            "An AWS access key ID may identify credentials that need review and possible rotation.",
        ));
    }

    if has_supabase_service_role {
        findings.push(secret_finding(
            "Possible Supabase Service Role Secret",
            Severity::High,
            "Medium",
            &relative_path,
            line_number,
            line,
            "A Supabase service role key can bypass row-level security and should stay server-side.",
        ));
    }

    let has_specific_finding = has_openai_key
        || has_stripe_secret_key
        || has_github_token
        || has_aws_access_key_id
        || has_supabase_service_role;

    if !has_specific_finding && is_generic_secret_line(line) {
        findings.push(secret_finding(
            "Possible Generic Secret",
            Severity::Medium,
            "Low",
            &relative_path,
            line_number,
            line,
            "A secret-like configuration value may be hardcoded or committed in a text file.",
        ));
    }

    findings
}

fn secret_finding(
    title: &str,
    severity: Severity,
    confidence: &'static str,
    file: &Path,
    line: usize,
    evidence: &str,
    why_it_matters: &str,
) -> Finding {
    Finding {
        title: title.to_string(),
        severity,
        confidence,
        file: Some(file.to_path_buf()),
        line: Some(line),
        evidence: redact_line(evidence),
        why_it_matters: why_it_matters.to_string(),
        remediation: vec![
            "Review the value locally and confirm whether it is real.".to_string(),
            "Revoke or rotate the credential if it was committed or shared.".to_string(),
            "Move real secrets to a local `.env` file or secret manager.".to_string(),
            "Check git history if the value may have been committed.".to_string(),
        ],
    }
}

fn contains_openai_key(line: &str) -> bool {
    line.split(|character: char| character.is_whitespace() || matches!(character, '"' | '\'' | '='))
        .any(|part| part.starts_with("sk-") && part.len() >= 12)
}

fn contains_stripe_secret_key(line: &str) -> bool {
    line.contains("sk_live_") || line.contains("sk_test_")
}

fn contains_github_token(line: &str) -> bool {
    line.contains("ghp_") || line.contains("github_pat_")
}

fn contains_aws_access_key_id(line: &str) -> bool {
    line.contains("AKIA") && line.len() >= 20
}

fn is_supabase_service_role_line(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    upper.contains("SUPABASE")
        && upper.contains("SERVICE")
        && upper.contains("ROLE")
        && match extract_assignment_value(line) {
            Some(value) => !is_placeholder_value(value),
            None => false,
        }
}

fn is_generic_secret_line(line: &str) -> bool {
    let upper = line.to_ascii_uppercase();
    GENERIC_SECRET_NAMES.iter().any(|name| upper.contains(name))
        && match extract_assignment_value(line) {
            Some(value) => !is_placeholder_value(value),
            None => false,
        }
}

fn extract_assignment_value(line: &str) -> Option<&str> {
    let separator_index = match line.find('=') {
        Some(index) if has_non_config_colon_before(line, index) => return None,
        Some(index) => index,
        None => config_like_colon_separator_index(line)?,
    };
    let value = line[separator_index + 1..].trim();
    let value = value.trim_matches(|character| {
        matches!(character, '"' | '\'' | '`' | ',' | ';') || character.is_whitespace()
    });

    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn has_non_config_colon_before(line: &str, end_index: usize) -> bool {
    let prefix = &line[..end_index];

    prefix.contains(':') && config_like_colon_separator_index(prefix).is_none()
}

fn config_like_colon_separator_index(line: &str) -> Option<usize> {
    let separator_index = line.find(':')?;
    let key = line[..separator_index].trim();
    let value = line[separator_index + 1..].trim();

    if key.is_empty() || value.is_empty() || key.contains(char::is_whitespace) {
        return None;
    }

    if key
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    {
        Some(separator_index)
    } else {
        None
    }
}

fn is_placeholder_value(value: &str) -> bool {
    let normalized = value
        .trim()
        .trim_matches(|character| matches!(character, '"' | '\'' | '`'))
        .to_ascii_lowercase();

    PLACEHOLDER_VALUES
        .iter()
        .any(|placeholder| normalized == *placeholder || normalized.contains(placeholder))
}

fn redact_line(line: &str) -> String {
    if let Some(index) = line.find('=') {
        return format!("{}=<REDACTED>", line[..index].trim());
    }

    if let Some(index) = line.find(':') {
        return format!("{}: <REDACTED>", line[..index].trim());
    }

    "<REDACTED>".to_string()
}

fn check_env_file(root: &Path, excludes: &[String]) -> Vec<Finding> {
    let env_path = root.join(".env");
    if should_exclude_path(root, &env_path, excludes) {
        return Vec::new();
    }
    if !env_path.exists() {
        return Vec::new();
    }

    let mut findings = vec![Finding {
        title: ".env File Exists".to_string(),
        severity: Severity::Low,
        confidence: "High",
        file: Some(PathBuf::from(".env")),
        line: None,
        evidence: ".env exists in the scanned path".to_string(),
        why_it_matters:
            "Environment files often contain API keys, database URLs, or deploy tokens.".to_string(),
        remediation: vec![
            "Keep `.env` local and out of git.".to_string(),
            "Use `.env.example` for variable names with fake placeholder values.".to_string(),
        ],
    }];

    if is_env_tracked_by_git(root) {
        findings.push(Finding {
            title: "Tracked .env File".to_string(),
            severity: Severity::High,
            confidence: "High",
            file: Some(PathBuf::from(".env")),
            line: None,
            evidence: ".env is tracked by git".to_string(),
            why_it_matters:
                "A tracked `.env` file may expose credentials to anyone with repository access."
                    .to_string(),
            remediation: vec![
                "Stop tracking `.env` with `git rm --cached .env` after confirming a safe backup."
                    .to_string(),
                "Add `.env` and `.env.*` to `.gitignore`, while allowing `.env.example`."
                    .to_string(),
                "Rotate any real credentials that were committed.".to_string(),
                "Review git history if real secrets were present.".to_string(),
            ],
        });
    }

    findings
}

fn is_env_tracked_by_git(root: &Path) -> bool {
    let output = Command::new("git")
        .args(["ls-files", "--error-unmatch", ".env"])
        .current_dir(root)
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

fn generate_report(root: &Path, scanner_name: &str, findings: &[Finding]) -> String {
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
    report.push_str(&format!("Scanned path: `{}`\n\n", root.display()));
    report.push_str(&format!("Scanner: `{scanner_name}`\n\n"));
    report.push_str("## Summary\n\n");
    report.push_str("Secret Bento generated this AI-ready remediation report locally without uploading code or calling AI APIs.\n\n");
    report.push_str("The `builtin` scanner uses simple checks. Secret Bento is designed to package findings into safe Markdown context, not replace mature OSS secret scanners.\n\n");
    report.push_str("| Severity | Count |\n");
    report.push_str("| --- | ---: |\n");
    report.push_str(&format!("| High | {high} |\n"));
    report.push_str(&format!("| Medium | {medium} |\n"));
    report.push_str(&format!("| Low | {low} |\n\n"));

    report.push_str("## Safety Note\n\n");
    report.push_str("Never paste real secrets into AI chats. This report redacts detected values by default, but you should still review it locally before sharing any excerpt with ChatGPT, Claude, Codex, Cursor, Gemini, or another AI assistant.\n\n");

    report.push_str("## Findings\n\n");
    if findings.is_empty() {
        report.push_str("No findings were detected by the v0.1 scanner. This does not guarantee that the repository has no secrets.\n\n");
    } else {
        for (index, finding) in findings.iter().enumerate() {
            report.push_str(&format!("### {}. {}\n\n", index + 1, finding.title));
            report.push_str(&format!("- Severity: {}\n", finding.severity.as_str()));
            report.push_str(&format!("- Confidence: {}\n", finding.confidence));
            if let Some(file) = &finding.file {
                report.push_str(&format!("- File: `{}`\n", file.display()));
            }
            if let Some(line) = finding.line {
                report.push_str(&format!("- Line: {line}\n"));
            }
            report.push_str("- Evidence:\n\n");
            push_markdown_code_block(&mut report, &finding.evidence);
            report.push_str(&format!("- Why it matters: {}\n", finding.why_it_matters));
            report.push_str("- Suggested remediation:\n");
            for step in &finding.remediation {
                report.push_str(&format!("  - {step}\n"));
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

    report.push_str("## Notes\n\n");
    report.push_str("Secret Bento is local-first and Markdown-first. It does not upload code, does not call AI APIs, and does not automatically fix files.\n");

    report
}

fn push_markdown_code_block(report: &mut String, content: &str) {
    let fence = if content.contains("```") {
        "````"
    } else {
        "```"
    };

    report.push_str(&format!("{fence}text\n{content}\n{fence}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_scan_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!("secret-bento-{name}-{nonce}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_test_file(root: &Path, relative_path: &str, content: &str) {
        let path = root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn detects_known_secret_prefixes() {
        let root = Path::new("/repo");
        let path = Path::new("/repo/src/config.ts");
        let findings = detect_line(root, path, 3, "OPENAI_API_KEY=\"sk-1234567890abcdef\"");

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Possible OpenAI API Key"));
        assert_eq!(findings[0].evidence, "OPENAI_API_KEY=<REDACTED>");
    }

    #[test]
    fn detects_openai_key_assignment() {
        let root = Path::new("/repo");
        let path = Path::new("/repo/.env");
        let findings = detect_line(
            root,
            path,
            1,
            "OPENAI_API_KEY=sk-test_fake_key_for_secret_bento_demo",
        );

        assert!(findings
            .iter()
            .any(|finding| finding.title == "Possible OpenAI API Key"));
        assert_eq!(findings[0].evidence, "OPENAI_API_KEY=<REDACTED>");
    }

    #[test]
    fn ignores_placeholder_generic_values() {
        assert!(!is_generic_secret_line("API_KEY=replace_me"));
        assert!(!is_generic_secret_line("DATABASE_URL=example"));
    }

    #[test]
    fn ignores_rust_type_annotations_as_generic_assignments() {
        assert!(!is_generic_secret_line(
            "fn contains_github_token(line: &str) -> bool {"
        ));
        assert!(!is_generic_secret_line("let value: String = token;"));
        assert!(!is_generic_secret_line("const foo: Bar = DATABASE_URL;"));
    }

    #[test]
    fn detects_generic_non_placeholder_values() {
        assert!(is_generic_secret_line(
            "DATABASE_URL=postgres://user:pass@localhost/db"
        ));
        assert!(is_generic_secret_line("SERVICE_TOKEN=real-token-value"));
        assert!(is_generic_secret_line(
            "DATABASE_URL: postgres://user:pass@localhost/db"
        ));
    }

    #[test]
    fn detects_supabase_service_role_names() {
        assert!(is_supabase_service_role_line(
            "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI"
        ));
    }

    #[test]
    fn report_includes_required_sections() {
        let report = generate_report(Path::new("/repo"), "builtin", &[]);

        assert!(report.contains("## Summary"));
        assert!(report.contains("## Findings"));
        assert!(report.contains("## Safety Note"));
        assert!(report.contains("## Suggested Remediation"));
        assert!(report.contains("## AI Handoff Prompt"));
    }

    #[test]
    fn report_renders_backtick_evidence_as_fenced_code() {
        let finding = Finding {
            title: "Possible OpenAI API Key".to_string(),
            severity: Severity::High,
            confidence: "Medium",
            file: Some(PathBuf::from("docs/sample-report.md")),
            line: Some(34),
            evidence: "- Evidence: `OPENAI_API_KEY=<REDACTED>`".to_string(),
            why_it_matters: "Test finding.".to_string(),
            remediation: vec!["Review locally.".to_string()],
        };
        let report = generate_report(Path::new("/repo"), "builtin", &[finding]);

        assert!(
            report.contains("- Evidence:\n\n```text\n- Evidence: `OPENAI_API_KEY=<REDACTED>`\n```")
        );
        assert!(!report.contains("- Evidence: `- Evidence: `OPENAI_API_KEY=<REDACTED>``"));
    }

    #[test]
    fn exclude_pattern_skips_matching_paths() {
        let root = temp_scan_root("single-exclude");
        write_test_file(
            &root,
            "docs/guide.md",
            "OPENAI_API_KEY=sk-docs-secret-value",
        );
        write_test_file(
            &root,
            "src/config.txt",
            "OPENAI_API_KEY=sk-src-secret-value",
        );

        let mut findings = Vec::new();
        scan_path_recursive(&root, &root, &["docs/**".to_string()], &mut findings).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, Some(PathBuf::from("src/config.txt")));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn multiple_excludes_skip_all_matching_paths() {
        let root = temp_scan_root("multiple-excludes");
        write_test_file(
            &root,
            "docs/guide.md",
            "OPENAI_API_KEY=sk-docs-secret-value",
        );
        write_test_file(
            &root,
            "tests/fixture.txt",
            "OPENAI_API_KEY=sk-test-secret-value",
        );
        write_test_file(
            &root,
            "src/config.txt",
            "OPENAI_API_KEY=sk-src-secret-value",
        );

        let mut findings = Vec::new();
        scan_path_recursive(
            &root,
            &root,
            &["docs/**".to_string(), "tests/**".to_string()],
            &mut findings,
        )
        .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file, Some(PathBuf::from("src/config.txt")));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn markdown_glob_excludes_matching_files_anywhere() {
        assert!(glob_matches("**/*.md", "README.md"));
        assert!(glob_matches("**/*.md", "docs/sample-report.md"));
        assert!(!glob_matches("**/*.md", "src/main.rs"));
    }

    #[test]
    fn output_path_can_be_customized() {
        let root = Path::new("repo");
        let report_path = resolve_report_path(root, Some(Path::new("reports/secret-report.md")));

        assert_eq!(
            report_path,
            PathBuf::from("repo").join("reports/secret-report.md")
        );
    }

    #[test]
    fn default_output_stays_at_scanned_root() {
        let root = Path::new("repo");
        let report_path = resolve_report_path(root, None);

        assert_eq!(report_path, PathBuf::from("repo").join(REPORT_FILE));
    }

    #[test]
    fn run_writes_custom_output_path_and_creates_parents() {
        let root = temp_scan_root("custom-output");
        write_test_file(
            &root,
            "src/config.txt",
            "OPENAI_API_KEY=sk-src-secret-value",
        );
        let output = Path::new("reports").join("secret-report.md");

        run(vec![
            "secret-bento".to_string(),
            "scan".to_string(),
            root.display().to_string(),
            "--output".to_string(),
            output.display().to_string(),
        ])
        .unwrap();

        assert!(root.join(output).exists());
        assert!(!root.join(REPORT_FILE).exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn run_writes_default_output_at_scanned_root() {
        let root = temp_scan_root("default-output");
        write_test_file(
            &root,
            "src/config.txt",
            "OPENAI_API_KEY=sk-src-secret-value",
        );

        run(vec![
            "secret-bento".to_string(),
            "scan".to_string(),
            root.display().to_string(),
        ])
        .unwrap();

        assert!(root.join(REPORT_FILE).exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_default_builtin_scanner() {
        let args = vec![
            "secret-bento".to_string(),
            "scan".to_string(),
            ".".to_string(),
        ];
        let options = parse_scan_options(&args, "secret-bento").unwrap();

        assert_eq!(options.scanner, ScannerKind::Builtin);
        assert_eq!(options.path, PathBuf::from("."));
        assert!(options.excludes.is_empty());
        assert_eq!(options.output, None);
    }

    #[test]
    fn parses_explicit_builtin_scanner() {
        let args = vec![
            "secret-bento".to_string(),
            "scan".to_string(),
            ".".to_string(),
            "--scanner".to_string(),
            "builtin".to_string(),
        ];
        let options = parse_scan_options(&args, "secret-bento").unwrap();

        assert_eq!(options.scanner, ScannerKind::Builtin);
    }

    #[test]
    fn parses_exclude_and_output_options() {
        let args = vec![
            "secret-bento".to_string(),
            "scan".to_string(),
            ".".to_string(),
            "--exclude".to_string(),
            "docs/**".to_string(),
            "--exclude=tests/**".to_string(),
            "--output".to_string(),
            "reports/secret-report.md".to_string(),
        ];
        let options = parse_scan_options(&args, "secret-bento").unwrap();

        assert_eq!(options.excludes, vec!["docs/**", "tests/**"]);
        assert_eq!(
            options.output,
            Some(PathBuf::from("reports/secret-report.md"))
        );
    }

    #[test]
    fn rejects_planned_gitleaks_scanner() {
        let args = vec![
            "secret-bento".to_string(),
            "scan".to_string(),
            ".".to_string(),
            "--scanner=gitleaks".to_string(),
        ];
        let error = parse_scan_options(&args, "secret-bento").unwrap_err();

        assert!(error.contains("planned but not implemented"));
    }
}
