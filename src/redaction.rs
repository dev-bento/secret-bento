pub(crate) fn redact_line(line: &str) -> String {
    if let Some(index) = line.find('=') {
        return format!("{}=<REDACTED>", line[..index].trim());
    }

    if let Some(index) = line.find(':') {
        return format!("{}: <REDACTED>", line[..index].trim());
    }

    "<REDACTED>".to_string()
}
