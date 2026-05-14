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
    assert!(stdout.contains("Local secret scanning reports"));
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
