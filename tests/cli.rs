use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "secret-bento-cli-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, relative_path: &str, content: &str) {
        let path = self.path.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn secret_bento(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secret-bento"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn help_flag_prints_concise_help() {
    let output = secret_bento(&["--help"]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento"));
    assert!(stdout.contains("Commands:"));
    assert!(stdout.contains("Reports are redacted summaries, not raw scanner output."));
}

#[test]
fn help_command_prints_concise_help() {
    let output = secret_bento(&["help"]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("AI-safe secret cleanup handoff reports"));
    assert!(stdout.contains("gitleaks is recommended for stronger detection."));
}

#[test]
fn scan_help_prints_scan_options() {
    let output = secret_bento(&["scan", "--help"]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento scan"));
    assert!(stdout.contains("--scanner builtin|gitleaks"));
    assert!(stdout.contains("--output <path>"));
    assert!(stdout.contains("--exclude <glob>"));
}

#[test]
fn handoff_help_prints_handoff_options() {
    let output = secret_bento(&["handoff", "--help"]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento handoff"));
    assert!(stdout.contains("secret-bento handoff <path>"));
    assert!(stdout.contains("--scanner builtin|gitleaks"));
    assert!(stdout.contains("--output <path>"));
    assert!(stdout.contains("--exclude <glob>"));
    assert!(stdout.contains("SECRET_BENTO_HANDOFF.md"));
}

#[test]
fn doctor_help_prints_optional_path_usage() {
    let output = secret_bento(&["doctor", "--help"]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento doctor"));
    assert!(stdout.contains("secret-bento doctor [path]"));
    assert!(stdout.contains("Doctor does not scan files or inspect secrets."));
}

#[test]
fn doctor_prints_readiness_summary() {
    let output = secret_bento(&["doctor"]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento doctor"));
    assert!(stdout.contains("Secret Bento: ok v"));
    assert!(stdout.contains("Gitleaks:"));
    assert!(stdout.contains("Git:"));
    assert!(stdout.contains("Git repository:"));
    assert!(stdout.contains("Output directory:"));
    assert!(stdout.contains("Doctor does not scan files or inspect secrets."));
}

#[test]
fn doctor_existing_path_reports_scan_path() {
    let root = TempRoot::new("doctor-existing-path");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["doctor", &path]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("Scan path: ok directory"));
    assert!(stdout.contains(&path));
    assert!(stdout.contains("Output directory: ok writable"));
}

#[test]
fn doctor_missing_path_reports_scan_path_without_failing() {
    let root = TempRoot::new("doctor-missing-path");
    let path = root.path().join("missing");
    let path = path.to_string_lossy().to_string();
    let output = secret_bento(&["doctor", &path]);

    assert!(output.status.success());
    let stdout = stdout(&output);
    assert!(stdout.contains("Scan path: missing"));
    assert!(stdout.contains(&path));
}

#[test]
fn unknown_doctor_option_exits_with_specific_usage_error() {
    let output = secret_bento(&["doctor", "--definitely-not-real"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown doctor option `--definitely-not-real`"));
    assert!(stderr.contains("secret-bento doctor [path]"));
}

#[test]
fn unknown_command_exits_with_specific_usage_error() {
    let output = secret_bento(&["frobnicate"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown command `frobnicate`"));
    assert!(stderr.contains("Usage:"));
}

#[test]
fn scan_without_path_exits_with_specific_usage_error() {
    let output = secret_bento(&["scan"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("scan requires a path"));
    assert!(stderr.contains("secret-bento scan <path>"));
}

#[test]
fn handoff_without_path_exits_with_specific_usage_error() {
    let output = secret_bento(&["handoff"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("handoff requires a path"));
    assert!(stderr.contains("secret-bento handoff <path>"));
}

#[test]
fn unknown_scan_option_exits_with_specific_usage_error() {
    let root = TempRoot::new("unknown-option");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["scan", &path, "--definitely-not-real"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown option `--definitely-not-real`"));
    assert!(stderr.contains("Run `secret-bento scan --help` for examples."));
}

#[test]
fn unknown_handoff_option_exits_with_specific_usage_error() {
    let root = TempRoot::new("unknown-handoff-option");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["handoff", &path, "--definitely-not-real"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown option `--definitely-not-real`"));
    assert!(stderr.contains("Run `secret-bento handoff --help` for examples."));
}

#[test]
fn invalid_scanner_exits_with_specific_usage_error() {
    let root = TempRoot::new("invalid-scanner");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["scan", &path, "--scanner", "not-a-scanner"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown scanner `not-a-scanner`"));
    assert!(stderr.contains("supported scanners: builtin, gitleaks"));
}

#[test]
fn invalid_handoff_scanner_exits_with_specific_usage_error() {
    let root = TempRoot::new("invalid-handoff-scanner");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["handoff", &path, "--scanner", "not-a-scanner"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown scanner `not-a-scanner`"));
    assert!(stderr.contains("supported scanners: builtin, gitleaks"));
    assert!(stderr.contains("secret-bento handoff <path>"));
}

#[test]
fn duplicate_scan_path_exits_with_specific_usage_error() {
    let root = TempRoot::new("duplicate-path");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["scan", &path, &path]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = stderr(&output);
    assert!(stderr.contains("duplicate scan path"));
    assert!(stderr.contains("scan accepts exactly one path"));
}

#[test]
fn clean_builtin_scan_prints_completion_summary() {
    let root = TempRoot::new("clean-summary");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["scan", &path]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento scan complete"));
    assert!(stdout.contains("Scanner: builtin"));
    assert!(stdout.contains("Findings: 0 total"));
    assert!(stdout.contains("Exit code: 0 = clean scan"));
    assert!(stdout.contains("Review the redacted report locally."));
    assert!(stdout.contains("builtin scanner is a smoke check"));
}

#[test]
fn finding_builtin_scan_prints_completion_summary() {
    let root = TempRoot::new("finding-summary");
    root.write("config.txt", "SERVICE_TOKEN=local_runtime_value_for_test");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["scan", &path]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento scan complete"));
    assert!(stdout.contains("Scanner: builtin"));
    assert!(stdout.contains("Findings: 1 total"));
    assert!(stdout.contains("Exit code: 1 = findings detected"));
    assert!(stdout.contains("Do not paste raw secrets into AI chat."));
    assert!(stdout.contains("builtin scanner is a smoke check"));
}

#[test]
fn clean_builtin_handoff_writes_default_handoff_report() {
    let root = TempRoot::new("clean-handoff");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["handoff", &path, "--scanner", "builtin"]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento handoff complete"));
    assert!(stdout.contains("Scanner: builtin"));
    assert!(stdout.contains("Findings: 0 total"));
    assert!(stdout.contains("Exit code: 0 = clean scan"));
    assert!(stdout.contains("SECRET_BENTO_HANDOFF.md"));
    assert!(root.path().join("SECRET_BENTO_HANDOFF.md").exists());
    assert!(!root.path().join("SECRET_BENTO_REPORT.md").exists());
}

#[test]
fn finding_builtin_handoff_exits_with_findings_code_and_redacts_report() {
    let root = TempRoot::new("finding-handoff");
    let raw_secret = "sk-SENTINEL_HANDOFF_RAW_SECRET_DO_NOT_RENDER_123456";
    root.write("config.txt", &format!("OPENAI_API_KEY={raw_secret}"));
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["handoff", &path]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = stdout(&output);
    assert!(stdout.contains("Secret Bento handoff complete"));
    assert!(stdout.contains("Findings: 1 total"));
    assert!(stdout.contains("Exit code: 1 = findings detected"));

    let report = fs::read_to_string(root.path().join("SECRET_BENTO_HANDOFF.md")).unwrap();
    assert!(report.contains("# Secret Bento Handoff Report"));
    assert!(report.contains("- Report purpose: AI-safe handoff"));
    assert!(report.contains("## Safe to Share Checklist"));
    assert!(report.contains("## AI Agent Instructions"));
    assert!(report.contains("## Human-Only Actions"));
    assert!(report.contains("## AI Handoff Prompts"));
    assert!(!report.contains("## Suggested Remediation"));
    assert!(report.contains("- Description: OPENAI_API_KEY=<REDACTED>"));
    assert!(!report.contains(raw_secret));
}

#[test]
fn handoff_output_path_can_be_customized() {
    let root = TempRoot::new("handoff-custom-output");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&[
        "handoff",
        &path,
        "--output",
        "reports/secret-bento-handoff.md",
    ]);

    assert_eq!(output.status.code(), Some(0));
    assert!(root.path().join("reports/secret-bento-handoff.md").exists());
    assert!(!root.path().join("SECRET_BENTO_HANDOFF.md").exists());
}

#[test]
fn handoff_exclude_skips_matching_paths() {
    let root = TempRoot::new("handoff-exclude");
    root.write("docs/guide.md", "OPENAI_API_KEY=sk-docs-secret-value");
    let path = root.path().to_string_lossy().to_string();
    let output = secret_bento(&["handoff", &path, "--exclude", "docs/**"]);

    assert_eq!(output.status.code(), Some(0));
    let report = fs::read_to_string(root.path().join("SECRET_BENTO_HANDOFF.md")).unwrap();
    assert!(report.contains("No findings were detected by the selected scanner."));
    assert!(!report.contains("sk-docs-secret-value"));
}
