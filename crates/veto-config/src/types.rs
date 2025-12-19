use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub scope: ScopeConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub entropy_guard: EntropyGuardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String, // "text" | "json"
    #[serde(default = "default_fail_on")]
    pub fail_on: String, // "low" | "medium" | "high" | "critical"
}

fn default_format() -> String {
    "text".to_string()
}
fn default_fail_on() -> String {
    "high".to_string()
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            fail_on: default_fail_on(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    #[serde(default = "default_mode")]
    pub mode: String, // "staged" | "worktree" | "repo"
}

fn default_mode() -> String {
    "staged".to_string()
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyGuardConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default)]
    pub ignore_ext: Vec<String>,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default = "default_max_line_length")]
    pub max_line_length: usize,
    #[serde(default = "default_max_tokens_per_file")]
    pub max_tokens_per_file: usize,
}

fn default_enabled() -> bool {
    true
}
fn default_min_length() -> usize {
    24
}
fn default_threshold() -> f64 {
    4.2
}
fn default_max_file_bytes() -> u64 {
    1_048_576 // 1MB
}
fn default_max_line_length() -> usize {
    10_000
}
fn default_max_tokens_per_file() -> usize {
    2_000
}

impl Default for EntropyGuardConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            min_length: default_min_length(),
            threshold: default_threshold(),
            ignore_ext: vec![
                "png".into(),
                "jpg".into(),
                "gif".into(),
                "mp4".into(),
                "pdf".into(),
                "lock".into(),
            ],
            max_file_bytes: default_max_file_bytes(),
            max_line_length: default_max_line_length(),
            max_tokens_per_file: default_max_tokens_per_file(),
        }
    }
}
