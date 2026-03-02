use serde::{Deserialize, Serialize};

pub const POLICY_VERSION_LEGACY: u32 = 1;
pub const POLICY_VERSION_CURRENT: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_policy_version")]
    pub policy_version: u32,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub scope: ScopeConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub exclude: ExcludeConfig,
    #[serde(default)]
    pub generated_code: GeneratedCodeConfig,
    #[serde(default)]
    pub language_rules: LanguageRulesConfig,
    #[serde(default)]
    pub weights: WeightsConfig,
    #[serde(default)]
    pub test_gap: TestGapConfig,
    #[serde(default)]
    pub dangerous_change: DangerousChangeConfig,
    #[serde(default)]
    pub dependency_update: DependencyUpdateConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            policy_version: default_policy_version(),
            output: OutputConfig::default(),
            scope: ScopeConfig::default(),
            cache: CacheConfig::default(),
            exclude: ExcludeConfig::default(),
            generated_code: GeneratedCodeConfig::default(),
            language_rules: LanguageRulesConfig::default(),
            weights: WeightsConfig::default(),
            test_gap: TestGapConfig::default(),
            dangerous_change: DangerousChangeConfig::default(),
            dependency_update: DependencyUpdateConfig::default(),
        }
    }
}

fn default_policy_version() -> u32 {
    POLICY_VERSION_CURRENT
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeConfig {
    #[serde(default = "default_scope_mode")]
    pub mode: String, // "staged" | "worktree" | "repo"
    #[serde(default = "default_max_changed_files")]
    pub max_changed_files: u32,
    #[serde(default = "default_on_exceed")]
    pub on_exceed: String, // "fail_open" | "fail_closed"
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            mode: default_scope_mode(),
            max_changed_files: default_max_changed_files(),
            on_exceed: default_on_exceed(),
        }
    }
}

fn default_scope_mode() -> String {
    "staged".to_string()
}

fn default_max_changed_files() -> u32 {
    10_000
}

fn default_on_exceed() -> String {
    "fail_open".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExcludeConfig {
    #[serde(default = "default_exclude_globs")]
    pub globs: Vec<String>,
}

impl Default for ExcludeConfig {
    fn default() -> Self {
        Self {
            globs: default_exclude_globs(),
        }
    }
}

fn default_exclude_globs() -> Vec<String> {
    vec!["vendor/**".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeneratedCodeConfig {
    #[serde(default = "default_generated_mode")]
    pub mode: String, // "exclude" | "decay"
    #[serde(default = "default_generated_globs")]
    pub globs: Vec<String>,
    #[serde(default = "default_generated_decay_percent")]
    pub penalty_decay_percent: u8, // 0..=100
}

impl Default for GeneratedCodeConfig {
    fn default() -> Self {
        Self {
            mode: default_generated_mode(),
            globs: default_generated_globs(),
            penalty_decay_percent: default_generated_decay_percent(),
        }
    }
}

fn default_generated_mode() -> String {
    "exclude".to_string()
}

fn default_generated_globs() -> Vec<String> {
    vec![
        "**/generated/**".into(),
        "**/*.pb.go".into(),
        "**/*_generated.*".into(),
        "**/gen/**".into(),
    ]
}

fn default_generated_decay_percent() -> u8 {
    70
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanguageRulesConfig {
    #[serde(default = "default_true")]
    pub rust: bool,
    #[serde(default = "default_true")]
    pub typescript: bool,
    #[serde(default = "default_true")]
    pub python: bool,
    #[serde(default = "default_true")]
    pub go: bool,
    #[serde(default = "default_false")]
    pub java_kotlin: bool,
}

impl Default for LanguageRulesConfig {
    fn default() -> Self {
        Self {
            rust: default_true(),
            typescript: default_true(),
            python: default_true(),
            go: default_true(),
            java_kotlin: default_false(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default = "default_lockfile_added_or_removed_penalty")]
    pub lockfile_added_or_removed_penalty: u8,
    #[serde(default = "default_lockfile_mass_update_lines")]
    pub lockfile_mass_update_lines: u32,
    #[serde(default = "default_lockfile_mass_update_penalty")]
    pub lockfile_mass_update_penalty: u8,
    #[serde(default)]
    pub ecosystem_penalties: DependencyEcosystemPenaltyMatrix,
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
            lockfile_added_or_removed_penalty: default_lockfile_added_or_removed_penalty(),
            lockfile_mass_update_lines: default_lockfile_mass_update_lines(),
            lockfile_mass_update_penalty: default_lockfile_mass_update_penalty(),
            ecosystem_penalties: DependencyEcosystemPenaltyMatrix::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependencyEcosystemPenaltyMatrix {
    #[serde(default = "default_cargo_penalty")]
    pub cargo: DependencyEcosystemPenalty,
    #[serde(default = "default_npm_penalty")]
    pub npm: DependencyEcosystemPenalty,
    #[serde(default = "default_python_penalty")]
    pub python: DependencyEcosystemPenalty,
    #[serde(default = "default_go_penalty")]
    pub go: DependencyEcosystemPenalty,
    #[serde(default = "default_jvm_penalty")]
    pub jvm: DependencyEcosystemPenalty,
}

impl Default for DependencyEcosystemPenaltyMatrix {
    fn default() -> Self {
        Self {
            cargo: default_cargo_penalty(),
            npm: default_npm_penalty(),
            python: default_python_penalty(),
            go: default_go_penalty(),
            jvm: default_jvm_penalty(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependencyEcosystemPenalty {
    #[serde(default)]
    pub manifest_bonus_penalty: u8,
    #[serde(default)]
    pub lockfile_bonus_penalty: u8,
    #[serde(default)]
    pub large_lockfile_bonus_penalty: u8,
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

fn default_lockfile_added_or_removed_penalty() -> u8 {
    6
}

fn default_lockfile_mass_update_lines() -> u32 {
    800
}

fn default_lockfile_mass_update_penalty() -> u8 {
    6
}

fn default_cargo_penalty() -> DependencyEcosystemPenalty {
    DependencyEcosystemPenalty {
        manifest_bonus_penalty: 3,
        lockfile_bonus_penalty: 2,
        large_lockfile_bonus_penalty: 2,
    }
}

fn default_npm_penalty() -> DependencyEcosystemPenalty {
    DependencyEcosystemPenalty {
        manifest_bonus_penalty: 3,
        lockfile_bonus_penalty: 2,
        large_lockfile_bonus_penalty: 3,
    }
}

fn default_python_penalty() -> DependencyEcosystemPenalty {
    DependencyEcosystemPenalty {
        manifest_bonus_penalty: 2,
        lockfile_bonus_penalty: 1,
        large_lockfile_bonus_penalty: 2,
    }
}

fn default_go_penalty() -> DependencyEcosystemPenalty {
    DependencyEcosystemPenalty {
        manifest_bonus_penalty: 2,
        lockfile_bonus_penalty: 2,
        large_lockfile_bonus_penalty: 1,
    }
}

fn default_jvm_penalty() -> DependencyEcosystemPenalty {
    DependencyEcosystemPenalty {
        manifest_bonus_penalty: 2,
        lockfile_bonus_penalty: 0,
        large_lockfile_bonus_penalty: 0,
    }
}
