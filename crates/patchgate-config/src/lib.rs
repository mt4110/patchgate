mod types;

pub use types::*;

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Result as AnyResult;
use globset::Glob;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationCategory {
    Type,
    Range,
    Dependency,
}

impl ValidationCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ValidationCategory::Type => "type",
            ValidationCategory::Range => "range",
            ValidationCategory::Dependency => "dependency",
        }
    }
}

impl fmt::Display for ValidationCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config: {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("policy parse error [type]: {source}")]
    Parse {
        #[source]
        source: toml::de::Error,
    },

    #[error("policy validation error [{category}] for `{field}`: {message}")]
    Validation {
        category: ValidationCategory,
        field: &'static str,
        message: String,
    },
}

impl ConfigError {
    pub fn category(&self) -> Option<ValidationCategory> {
        match self {
            ConfigError::Read { .. } => None,
            ConfigError::Parse { .. } => Some(ValidationCategory::Type),
            ConfigError::Validation { category, .. } => Some(*category),
        }
    }
}

pub type Result<T> = std::result::Result<T, ConfigError>;

pub fn load_from(path: impl AsRef<Path>) -> AnyResult<Config> {
    load_from_typed(path).map_err(anyhow::Error::new)
}

pub fn load_from_typed(path: impl AsRef<Path>) -> Result<Config> {
    let path_ref = path.as_ref();
    let text = fs::read_to_string(path_ref).map_err(|source| ConfigError::Read {
        path: path_ref.to_path_buf(),
        source,
    })?;
    let cfg: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse { source })?;
    validate_config(&cfg)?;
    Ok(cfg)
}

pub fn validate_config(cfg: &Config) -> Result<()> {
    validate_enum(
        "output.format",
        cfg.output.format.as_str(),
        &["text", "json"],
    )?;
    validate_enum(
        "output.mode",
        cfg.output.mode.as_str(),
        &["warn", "enforce"],
    )?;
    validate_enum(
        "scope.mode",
        cfg.scope.mode.as_str(),
        &["staged", "worktree", "repo"],
    )?;

    validate_range_u8("output.fail_threshold", cfg.output.fail_threshold, 0, 100)?;

    validate_range_u8(
        "weights.test_gap_max_penalty",
        cfg.weights.test_gap_max_penalty,
        0,
        100,
    )?;
    validate_range_u8(
        "weights.dangerous_change_max_penalty",
        cfg.weights.dangerous_change_max_penalty,
        0,
        100,
    )?;
    validate_range_u8(
        "weights.dependency_update_max_penalty",
        cfg.weights.dependency_update_max_penalty,
        0,
        100,
    )?;

    validate_range_u8(
        "test_gap.missing_tests_penalty",
        cfg.test_gap.missing_tests_penalty,
        0,
        100,
    )?;
    validate_range_u8(
        "test_gap.large_change_penalty",
        cfg.test_gap.large_change_penalty,
        0,
        100,
    )?;
    validate_positive_u32(
        "test_gap.large_change_lines",
        cfg.test_gap.large_change_lines,
    )?;

    validate_range_u8(
        "dangerous_change.per_file_penalty",
        cfg.dangerous_change.per_file_penalty,
        0,
        100,
    )?;
    validate_range_u8(
        "dangerous_change.critical_bonus_penalty",
        cfg.dangerous_change.critical_bonus_penalty,
        0,
        100,
    )?;

    validate_range_u8(
        "dependency_update.manifest_penalty",
        cfg.dependency_update.manifest_penalty,
        0,
        100,
    )?;
    validate_range_u8(
        "dependency_update.lockfile_penalty",
        cfg.dependency_update.lockfile_penalty,
        0,
        100,
    )?;
    validate_range_u8(
        "dependency_update.large_lockfile_penalty",
        cfg.dependency_update.large_lockfile_penalty,
        0,
        100,
    )?;
    validate_positive_u32(
        "dependency_update.large_lockfile_churn",
        cfg.dependency_update.large_lockfile_churn,
    )?;

    validate_globs("exclude.globs", &cfg.exclude.globs)?;
    validate_globs("test_gap.test_globs", &cfg.test_gap.test_globs)?;
    validate_globs(
        "test_gap.production_ignore_globs",
        &cfg.test_gap.production_ignore_globs,
    )?;
    validate_globs("dangerous_change.patterns", &cfg.dangerous_change.patterns)?;
    validate_globs(
        "dangerous_change.critical_patterns",
        &cfg.dangerous_change.critical_patterns,
    )?;
    validate_globs(
        "dependency_update.manifest_globs",
        &cfg.dependency_update.manifest_globs,
    )?;
    validate_globs(
        "dependency_update.lockfile_globs",
        &cfg.dependency_update.lockfile_globs,
    )?;

    if cfg.cache.enabled && cfg.cache.db_path.trim().is_empty() {
        return Err(validation_error(
            ValidationCategory::Dependency,
            "cache.db_path",
            "must be non-empty when `cache.enabled = true`",
        ));
    }

    validate_dependency_penalty(
        "test_gap.missing_tests_penalty",
        cfg.test_gap.missing_tests_penalty,
        "weights.test_gap_max_penalty",
        cfg.weights.test_gap_max_penalty,
    )?;
    validate_dependency_penalty(
        "test_gap.large_change_penalty",
        cfg.test_gap.large_change_penalty,
        "weights.test_gap_max_penalty",
        cfg.weights.test_gap_max_penalty,
    )?;

    validate_dependency_penalty(
        "dangerous_change.per_file_penalty",
        cfg.dangerous_change.per_file_penalty,
        "weights.dangerous_change_max_penalty",
        cfg.weights.dangerous_change_max_penalty,
    )?;

    let critical_total = cfg
        .dangerous_change
        .per_file_penalty
        .saturating_add(cfg.dangerous_change.critical_bonus_penalty);
    if critical_total > cfg.weights.dangerous_change_max_penalty {
        return Err(validation_error(
            ValidationCategory::Dependency,
            "dangerous_change.critical_bonus_penalty",
            format!(
                "critical total penalty ({critical_total}) exceeds weights.dangerous_change_max_penalty ({})",
                cfg.weights.dangerous_change_max_penalty
            ),
        ));
    }

    validate_dependency_penalty(
        "dependency_update.manifest_penalty",
        cfg.dependency_update.manifest_penalty,
        "weights.dependency_update_max_penalty",
        cfg.weights.dependency_update_max_penalty,
    )?;
    validate_dependency_penalty(
        "dependency_update.lockfile_penalty",
        cfg.dependency_update.lockfile_penalty,
        "weights.dependency_update_max_penalty",
        cfg.weights.dependency_update_max_penalty,
    )?;
    validate_dependency_penalty(
        "dependency_update.large_lockfile_penalty",
        cfg.dependency_update.large_lockfile_penalty,
        "weights.dependency_update_max_penalty",
        cfg.weights.dependency_update_max_penalty,
    )?;

    let dangerous_patterns: BTreeSet<&str> = cfg
        .dangerous_change
        .patterns
        .iter()
        .map(String::as_str)
        .collect();
    for critical in &cfg.dangerous_change.critical_patterns {
        if !dangerous_patterns.contains(critical.as_str()) {
            return Err(validation_error(
                ValidationCategory::Dependency,
                "dangerous_change.critical_patterns",
                format!(
                    "critical pattern `{critical}` must also be included in dangerous_change.patterns"
                ),
            ));
        }
    }

    Ok(())
}

fn validate_enum(field: &'static str, value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(validation_error(
            ValidationCategory::Type,
            field,
            format!("invalid value `{value}` (expected: {})", allowed.join("|")),
        ))
    }
}

fn validate_range_u8(field: &'static str, value: u8, min: u8, max: u8) -> Result<()> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(validation_error(
            ValidationCategory::Range,
            field,
            format!("`{value}` is outside allowed range {min}..={max}"),
        ))
    }
}

fn validate_positive_u32(field: &'static str, value: u32) -> Result<()> {
    if value > 0 {
        Ok(())
    } else {
        Err(validation_error(
            ValidationCategory::Range,
            field,
            "must be greater than 0".to_string(),
        ))
    }
}

fn validate_dependency_penalty(
    field: &'static str,
    value: u8,
    max_field: &'static str,
    max_value: u8,
) -> Result<()> {
    if value <= max_value {
        Ok(())
    } else {
        Err(validation_error(
            ValidationCategory::Dependency,
            field,
            format!("`{value}` exceeds `{max_field}` ({max_value})"),
        ))
    }
}

fn validate_globs(field: &'static str, globs: &[String]) -> Result<()> {
    for pattern in globs {
        Glob::new(pattern).map_err(|err| {
            validation_error(
                ValidationCategory::Type,
                field,
                format!("invalid glob pattern `{pattern}`: {err}"),
            )
        })?;
    }
    Ok(())
}

fn validation_error(
    category: ValidationCategory,
    field: &'static str,
    message: impl Into<String>,
) -> ConfigError {
    ConfigError::Validation {
        category,
        field,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{load_from, load_from_typed, Config, ConfigError, ValidationCategory};

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn write_temp_policy(content: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        path.push(format!("patchgate-config-test-{ts}-{seq}.toml"));
        fs::write(&path, content).expect("write temp policy");
        path
    }

    #[test]
    fn validation_reports_type_category_for_invalid_enum() {
        let path = write_temp_policy(
            r#"
[output]
format = "markdown"
"#,
        );

        let err = load_from_typed(&path).expect_err("must fail for invalid enum");
        assert_eq!(err.category(), Some(ValidationCategory::Type));
        match err {
            ConfigError::Validation {
                category, field, ..
            } => {
                assert_eq!(category, ValidationCategory::Type);
                assert_eq!(field, "output.format");
            }
            other => panic!("unexpected error: {other}"),
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn validation_reports_range_category() {
        let path = write_temp_policy(
            r#"
[test_gap]
large_change_lines = 0
"#,
        );

        let err = load_from_typed(&path).expect_err("must fail for range violation");
        assert_eq!(err.category(), Some(ValidationCategory::Range));
        match err {
            ConfigError::Validation {
                category, field, ..
            } => {
                assert_eq!(category, ValidationCategory::Range);
                assert_eq!(field, "test_gap.large_change_lines");
            }
            other => panic!("unexpected error: {other}"),
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn validation_reports_dependency_category() {
        let path = write_temp_policy(
            r#"
[dangerous_change]
patterns = ["infra/**"]
critical_patterns = [".github/workflows/**"]
"#,
        );

        let err = load_from_typed(&path).expect_err("must fail for dependency violation");
        assert_eq!(err.category(), Some(ValidationCategory::Dependency));
        match err {
            ConfigError::Validation {
                category, field, ..
            } => {
                assert_eq!(category, ValidationCategory::Dependency);
                assert_eq!(field, "dangerous_change.critical_patterns");
            }
            other => panic!("unexpected error: {other}"),
        }

        let _ = fs::remove_file(path);
    }

    #[test]
    fn policy_example_matches_default_config() {
        let example_path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/policy.toml.example");
        let loaded = load_from(&example_path).expect("load policy example");
        assert_eq!(loaded, Config::default());
    }

    #[test]
    fn load_from_typed_preserves_structured_error_category() {
        let path = write_temp_policy(
            r#"
[output]
format = "invalid"
"#,
        );
        let err = load_from_typed(&path).expect_err("must fail");
        assert_eq!(err.category(), Some(ValidationCategory::Type));
        let _ = fs::remove_file(path);
    }
}
