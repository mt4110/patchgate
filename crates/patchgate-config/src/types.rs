use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub scope: ScopeConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub exclude: ExcludeConfig,
    #[serde(default)]
    pub weights: WeightsConfig,
    #[serde(default)]
    pub test_gap: TestGapConfig,
    #[serde(default)]
    pub dangerous_change: DangerousChangeConfig,
    #[serde(default)]
    pub dependency_update: DependencyUpdateConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String, // "text" | "json"
    #[serde(default = "default_mode")]
    pub mode: String, // "warn" | "enforce"
    #[serde(default = "default_fail_threshold")]
    pub fail_threshold: u8, // 0..=100
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            mode: default_mode(),
            fail_threshold: default_fail_threshold(),
        }
    }
}

fn default_format() -> String {
    "text".to_string()
}

fn default_mode() -> String {
    "warn".to_string()
}

fn default_fail_threshold() -> u8 {
    70
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    #[serde(default = "default_scope_mode")]
    pub mode: String, // "staged" | "worktree" | "repo"
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            mode: default_scope_mode(),
        }
    }
}

fn default_scope_mode() -> String {
    "staged".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            db_path: default_db_path(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_db_path() -> String {
    ".patchgate/cache.db".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExcludeConfig {
    #[serde(default)]
    pub globs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightsConfig {
    #[serde(default = "default_test_gap_max")]
    pub test_gap_max_penalty: u8,
    #[serde(default = "default_dangerous_change_max")]
    pub dangerous_change_max_penalty: u8,
    #[serde(default = "default_dependency_update_max")]
    pub dependency_update_max_penalty: u8,
}

impl Default for WeightsConfig {
    fn default() -> Self {
        Self {
            test_gap_max_penalty: default_test_gap_max(),
            dangerous_change_max_penalty: default_dangerous_change_max(),
            dependency_update_max_penalty: default_dependency_update_max(),
        }
    }
}

fn default_test_gap_max() -> u8 {
    35
}

fn default_dangerous_change_max() -> u8 {
    45
}

fn default_dependency_update_max() -> u8 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestGapConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_test_globs")]
    pub test_globs: Vec<String>,
    #[serde(default = "default_production_ignore_globs")]
    pub production_ignore_globs: Vec<String>,
    #[serde(default = "default_missing_tests_penalty")]
    pub missing_tests_penalty: u8,
    #[serde(default = "default_large_change_lines")]
    pub large_change_lines: u32,
    #[serde(default = "default_large_change_penalty")]
    pub large_change_penalty: u8,
}

impl Default for TestGapConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            test_globs: default_test_globs(),
            production_ignore_globs: default_production_ignore_globs(),
            missing_tests_penalty: default_missing_tests_penalty(),
            large_change_lines: default_large_change_lines(),
            large_change_penalty: default_large_change_penalty(),
        }
    }
}

fn default_test_globs() -> Vec<String> {
    vec![
        "tests/**".into(),
        "**/__tests__/**".into(),
        "**/*.test.*".into(),
        "**/*.spec.*".into(),
        "**/*_test.go".into(),
        "**/test_*.py".into(),
    ]
}

fn default_production_ignore_globs() -> Vec<String> {
    vec![
        "docs/**".into(),
        "**/*.md".into(),
        "**/*.txt".into(),
        "**/*.rst".into(),
        "**/*.adoc".into(),
    ]
}

fn default_missing_tests_penalty() -> u8 {
    28
}

fn default_large_change_lines() -> u32 {
    200
}

fn default_large_change_penalty() -> u8 {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousChangeConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_dangerous_patterns")]
    pub patterns: Vec<String>,
    #[serde(default = "default_critical_patterns")]
    pub critical_patterns: Vec<String>,
    #[serde(default = "default_per_file_penalty")]
    pub per_file_penalty: u8,
    #[serde(default = "default_critical_bonus_penalty")]
    pub critical_bonus_penalty: u8,
}

impl Default for DangerousChangeConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            patterns: default_dangerous_patterns(),
            critical_patterns: default_critical_patterns(),
            per_file_penalty: default_per_file_penalty(),
            critical_bonus_penalty: default_critical_bonus_penalty(),
        }
    }
}

fn default_dangerous_patterns() -> Vec<String> {
    vec![
        ".github/workflows/**".into(),
        "infra/**".into(),
        "terraform/**".into(),
        "k8s/**".into(),
        "helm/**".into(),
        "migrations/**".into(),
        "db/migrate/**".into(),
        "**/auth/**".into(),
        "**/security/**".into(),
        "Dockerfile".into(),
        "docker-compose*.yml".into(),
        "docker-compose*.yaml".into(),
    ]
}

fn default_critical_patterns() -> Vec<String> {
    vec![
        ".github/workflows/**".into(),
        "infra/**".into(),
        "terraform/**".into(),
        "k8s/**".into(),
        "migrations/**".into(),
    ]
}

fn default_per_file_penalty() -> u8 {
    10
}

fn default_critical_bonus_penalty() -> u8 {
    6
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyUpdateConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_manifest_globs")]
    pub manifest_globs: Vec<String>,
    #[serde(default = "default_lockfile_globs")]
    pub lockfile_globs: Vec<String>,
    #[serde(default = "default_manifest_penalty")]
    pub manifest_penalty: u8,
    #[serde(default = "default_lockfile_penalty")]
    pub lockfile_penalty: u8,
    #[serde(default = "default_large_lockfile_churn")]
    pub large_lockfile_churn: u32,
    #[serde(default = "default_large_lockfile_penalty")]
    pub large_lockfile_penalty: u8,
}

impl Default for DependencyUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            manifest_globs: default_manifest_globs(),
            lockfile_globs: default_lockfile_globs(),
            manifest_penalty: default_manifest_penalty(),
            lockfile_penalty: default_lockfile_penalty(),
            large_lockfile_churn: default_large_lockfile_churn(),
            large_lockfile_penalty: default_large_lockfile_penalty(),
        }
    }
}

fn default_manifest_globs() -> Vec<String> {
    vec![
        "**/Cargo.toml".into(),
        "**/package.json".into(),
        "**/go.mod".into(),
        "**/requirements*.txt".into(),
        "**/pyproject.toml".into(),
        "**/Gemfile".into(),
        "**/pom.xml".into(),
        "**/build.gradle".into(),
        "**/build.gradle.kts".into(),
    ]
}

fn default_lockfile_globs() -> Vec<String> {
    vec![
        "**/Cargo.lock".into(),
        "**/package-lock.json".into(),
        "**/yarn.lock".into(),
        "**/pnpm-lock.yaml".into(),
        "**/go.sum".into(),
        "**/Pipfile.lock".into(),
        "**/poetry.lock".into(),
        "**/Gemfile.lock".into(),
    ]
}

fn default_manifest_penalty() -> u8 {
    18
}

fn default_lockfile_penalty() -> u8 {
    8
}

fn default_large_lockfile_churn() -> u32 {
    200
}

fn default_large_lockfile_penalty() -> u8 {
    10
}
