use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingDetails {
    pub entropy: f64,
    pub token_len: usize,
    pub charset: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub location: Option<Location>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<FindingDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub duration_ms: u128,
}

impl Report {
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
