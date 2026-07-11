use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FindingClassification {
    NeedsHumanReview,
    SafePlaceholder,
    SafeEnvironmentVariableReference,
}

impl FindingClassification {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            FindingClassification::NeedsHumanReview => "Needs human review",
            FindingClassification::SafePlaceholder => "Safe placeholder",
            FindingClassification::SafeEnvironmentVariableReference => {
                "Safe environment-variable reference"
            }
        }
    }

    pub(crate) fn needs_human_review(&self) -> bool {
        matches!(self, FindingClassification::NeedsHumanReview)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SecretBentoFinding {
    pub(crate) scanner: String,
    pub(crate) rule_id: Option<String>,
    pub(crate) title: String,
    pub(crate) severity: Severity,
    pub(crate) classification: FindingClassification,
    pub(crate) file: Option<PathBuf>,
    pub(crate) line: Option<usize>,
    pub(crate) secret_type: String,
    pub(crate) fingerprint: Option<String>,
    pub(crate) description: String,
    pub(crate) risk: String,
    pub(crate) remediation: Vec<String>,
    pub(crate) verification_commands: Vec<String>,
}
