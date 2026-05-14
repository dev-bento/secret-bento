pub(crate) fn redact_line(line: &str) -> String {
    if let Some(index) = line.find('=') {
        return format!("{}=<REDACTED>", line[..index].trim());
    }

    if let Some(index) = line.find(':') {
        return format!("{}: <REDACTED>", line[..index].trim());
    }

    "<REDACTED>".to_string()
}

pub(crate) fn redact_token_shaped_values(input: &str) -> String {
    let mut redacted = String::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        let remaining = &input[index..];
        let matched = TOKEN_PREFIXES
            .iter()
            .find(|prefix| remaining.starts_with(prefix.value));

        if let Some(prefix) = matched {
            let end = token_end(input, index + prefix.value.len());
            if end - index >= prefix.minimum_length {
                redacted.push_str("<REDACTED>");
                index = end;
                continue;
            }
        }

        let character = remaining.chars().next().unwrap();
        redacted.push(character);
        index += character.len_utf8();
    }

    redacted
}

struct TokenPrefix {
    value: &'static str,
    minimum_length: usize,
}

const TOKEN_PREFIXES: &[TokenPrefix] = &[
    TokenPrefix {
        value: "github_pat_",
        minimum_length: 16,
    },
    TokenPrefix {
        value: "sk_live_",
        minimum_length: 12,
    },
    TokenPrefix {
        value: "sk_test_",
        minimum_length: 12,
    },
    TokenPrefix {
        value: "ghp_",
        minimum_length: 12,
    },
    TokenPrefix {
        value: "AKIA",
        minimum_length: 16,
    },
    TokenPrefix {
        value: "sk-",
        minimum_length: 12,
    },
];

fn token_end(input: &str, mut index: usize) -> usize {
    while index < input.len() {
        let character = input[index..].chars().next().unwrap();
        if is_token_character(character) {
            index += character.len_utf8();
        } else {
            break;
        }
    }

    index
}

fn is_token_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
}
