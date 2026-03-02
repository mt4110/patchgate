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

const POLICY_VERSION_FIELD: &str = "policy_version";
const SUPPORTED_POLICY_VERSIONS: [u32; 2] = [POLICY_VERSION_LEGACY, POLICY_VERSION_CURRENT];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVersionSource {
    Explicit,
    LegacyImplicit,
    Default,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub version_source: PolicyVersionSource,
    pub compatibility_warnings: Vec<String>,
}

impl LoadedConfig {
    pub fn migration_required(&self) -> bool {
        self.config.policy_version < POLICY_VERSION_CURRENT
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyPreset {
    Strict,
    Balanced,
    Relaxed,
}

impl PolicyPreset {
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyPreset::Strict => "strict",
            PolicyPreset::Balanced => "balanced",
            PolicyPreset::Relaxed => "relaxed",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "strict" => Some(PolicyPreset::Strict),
            "balanced" => Some(PolicyPreset::Balanced),
            "relaxed" => Some(PolicyPreset::Relaxed),
            _ => None,
        }
    }

    pub fn allowed_values() -> &'static str {
        "strict|balanced|relaxed"
    }
}

impl fmt::Display for PolicyPreset {
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

#[derive(Debug, Error)]
pub enum PolicyMigrationError {
    #[error("policy parse error [type]: {source}")]
    Parse {
        #[source]
        source: toml::de::Error,
    },

    #[error("unsupported migration path: {from} -> {to}")]
    UnsupportedPath { from: u32, to: u32 },

    #[error("policy version field must be a positive integer")]
    InvalidVersionField,

    #[error("policy version mismatch: expected {expected}, detected {detected}")]
    VersionMismatch { expected: u32, detected: u32 },

    #[error("policy validation error after migration: {message}")]
    Validation { message: String },

    #[error("failed to render migrated policy: {source}")]
    Render {
        #[source]
        source: toml::ser::Error,
    },
}

#[derive(Debug, Clone)]
pub struct PolicyMigrationOutcome {
    pub from: u32,
    pub to: u32,
    pub changed: bool,
    pub migrated_toml: String,
}

pub type Result<T> = std::result::Result<T, ConfigError>;

pub fn load_from(path: impl AsRef<Path>) -> AnyResult<Config> {
    load_from_typed(path).map_err(anyhow::Error::new)
}

pub fn load_from_typed(path: impl AsRef<Path>) -> Result<Config> {
    let loaded = load_effective_from_typed(Some(path.as_ref()), None)?;
    Ok(loaded.config)
}

pub fn load_effective_from(
    path: Option<&Path>,
    preset: Option<PolicyPreset>,
) -> AnyResult<LoadedConfig> {
    load_effective_from_typed(path, preset).map_err(anyhow::Error::new)
}

pub fn load_effective_from_typed(
    path: Option<&Path>,
    preset: Option<PolicyPreset>,
) -> Result<LoadedConfig> {
    let (config, version_source) = if let Some(path_ref) = path {
        let text = fs::read_to_string(path_ref).map_err(|source| ConfigError::Read {
            path: path_ref.to_path_buf(),
            source,
        })?;
        let policy_value = parse_toml_value(&text)?;
        let has_explicit_version = has_explicit_policy_version(&policy_value);
        let mut merged = if has_explicit_version {
            default_config_value()
        } else {
            legacy_default_config_value()
        };
        if let Some(preset) = preset {
            let preset_value = parse_toml_value(preset_toml(preset))?;
            deep_merge(&mut merged, preset_value);
        }
        deep_merge(&mut merged, policy_value);

        let mut cfg = parse_config_from_value(merged)?;
        let source = if has_explicit_version {
            PolicyVersionSource::Explicit
        } else {
            cfg.policy_version = POLICY_VERSION_LEGACY;
            PolicyVersionSource::LegacyImplicit
        };
        (cfg, source)
    } else {
        let mut merged = default_config_value();
        if let Some(preset) = preset {
            let preset_value = parse_toml_value(preset_toml(preset))?;
            deep_merge(&mut merged, preset_value);
        }
        (
            parse_config_from_value(merged)?,
            PolicyVersionSource::Default,
        )
    };

    validate_config(&config)?;

    let compatibility_warnings = compatibility_warnings(&config, version_source);

    Ok(LoadedConfig {
        config,
        version_source,
        compatibility_warnings,
    })
}

pub fn migrate_policy_text(
    input: &str,
    from: u32,
    to: u32,
) -> std::result::Result<PolicyMigrationOutcome, PolicyMigrationError> {
    if from == to {
        let cfg_value = parse_toml_value_for_migration(input)?;
        let detected = detect_policy_version_from_toml(&cfg_value)?;
        if detected != from {
            return Err(PolicyMigrationError::VersionMismatch {
                expected: from,
                detected,
            });
        }
        let mut cfg = parse_config_for_migration(cfg_value.clone())?;
        cfg.policy_version = from;
        validate_config(&cfg).map_err(|err| PolicyMigrationError::Validation {
            message: err.to_string(),
        })?;
        return Ok(PolicyMigrationOutcome {
            from,
            to,
            changed: false,
            migrated_toml: toml::to_string_pretty(&cfg_value)
                .map_err(|source| PolicyMigrationError::Render { source })?,
        });
    }

    if !(from == POLICY_VERSION_LEGACY && to == POLICY_VERSION_CURRENT) {
        return Err(PolicyMigrationError::UnsupportedPath { from, to });
    }

    let mut cfg_value = parse_toml_value_for_migration(input)?;
    let detected = detect_policy_version_from_toml(&cfg_value)?;
    if detected != from {
        return Err(PolicyMigrationError::VersionMismatch {
            expected: from,
            detected,
        });
    }

    set_policy_version(&mut cfg_value, to);

    let mut cfg = parse_config_for_migration(cfg_value.clone())?;
    cfg.policy_version = to;
    validate_config(&cfg).map_err(|err| PolicyMigrationError::Validation {
        message: err.to_string(),
    })?;

    let migrated_toml = toml::to_string_pretty(&cfg_value)
        .map_err(|source| PolicyMigrationError::Render { source })?;

    Ok(PolicyMigrationOutcome {
        from,
        to,
        changed: true,
        migrated_toml,
    })
}

pub fn compatibility_warnings(cfg: &Config, source: PolicyVersionSource) -> Vec<String> {
    let mut warnings = Vec::new();

    if source == PolicyVersionSource::LegacyImplicit {
        warnings.push(format!(
            "policy_version is not specified; interpreted as legacy v{} for compatibility",
            POLICY_VERSION_LEGACY
        ));
    }

    if cfg.policy_version < POLICY_VERSION_CURRENT {
        warnings.push(format!(
            "policy_version {} is legacy. run `patchgate policy migrate --from {} --to {} --write`",
            cfg.policy_version, cfg.policy_version, POLICY_VERSION_CURRENT
        ));
    }

    warnings
}

pub fn validate_config(cfg: &Config) -> Result<()> {
    if !SUPPORTED_POLICY_VERSIONS.contains(&cfg.policy_version) {
        return Err(validation_error(
            ValidationCategory::Type,
            POLICY_VERSION_FIELD,
            format!(
                "invalid value `{}` (supported: {})",
                cfg.policy_version,
                SUPPORTED_POLICY_VERSIONS
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join("|")
            ),
        ));
    }

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

    let weight_sum = cfg
        .weights
        .test_gap_max_penalty
        .saturating_add(cfg.weights.dangerous_change_max_penalty)
        .saturating_add(cfg.weights.dependency_update_max_penalty);
    if weight_sum == 0 {
        return Err(validation_error(
            ValidationCategory::Dependency,
            "weights",
            "all max penalties are 0; at least one check must contribute to score",
        ));
    }

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

fn default_config_value() -> toml::Value {
    toml::Value::try_from(Config::default()).expect("default config must serialize")
}

fn legacy_default_config_value() -> toml::Value {
    parse_toml_value(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/policy.v1.legacy.toml"
    )))
    .expect("legacy default policy must be valid TOML")
}

fn preset_toml(preset: PolicyPreset) -> &'static str {
    match preset {
        PolicyPreset::Strict => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../config/presets/strict.toml"
            ))
        }
        PolicyPreset::Balanced => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../config/presets/balanced.toml"
            ))
        }
        PolicyPreset::Relaxed => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../config/presets/relaxed.toml"
            ))
        }
    }
}

fn parse_toml_value(input: &str) -> Result<toml::Value> {
    input
        .parse::<toml::Value>()
        .map_err(|source| ConfigError::Parse { source })
}

fn parse_toml_value_for_migration(
    input: &str,
) -> std::result::Result<toml::Value, PolicyMigrationError> {
    input
        .parse::<toml::Value>()
        .map_err(|source| PolicyMigrationError::Parse { source })
}

fn parse_config_from_value(value: toml::Value) -> Result<Config> {
    value
        .try_into::<Config>()
        .map_err(|source| ConfigError::Parse { source })
}

fn parse_config_for_migration(
    value: toml::Value,
) -> std::result::Result<Config, PolicyMigrationError> {
    value
        .try_into::<Config>()
        .map_err(|source| PolicyMigrationError::Parse { source })
}

fn has_explicit_policy_version(value: &toml::Value) -> bool {
    matches!(
        value.get(POLICY_VERSION_FIELD),
        Some(toml::Value::Integer(_))
    )
}

fn detect_policy_version_from_toml(
    value: &toml::Value,
) -> std::result::Result<u32, PolicyMigrationError> {
    match value.get(POLICY_VERSION_FIELD) {
        Some(toml::Value::Integer(v)) if *v > 0 => {
            u32::try_from(*v).map_err(|_| PolicyMigrationError::InvalidVersionField)
        }
        Some(_) => Err(PolicyMigrationError::InvalidVersionField),
        None => Ok(POLICY_VERSION_LEGACY),
    }
}

fn set_policy_version(value: &mut toml::Value, version: u32) {
    let root = value
        .as_table_mut()
        .expect("root of policy must be a TOML table");
    root.insert(
        POLICY_VERSION_FIELD.to_string(),
        toml::Value::Integer(version as i64),
    );
}

fn deep_merge(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) => {
            for (key, value) in overlay_table {
                if let Some(base_value) = base_table.get_mut(&key) {
                    deep_merge(base_value, value);
                } else {
                    base_table.insert(key, value);
                }
            }
        }
        (base_slot, overlay_value) => {
            *base_slot = overlay_value;
        }
    }
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

    use super::{
        compatibility_warnings, load_effective_from_typed, load_from, load_from_typed,
        migrate_policy_text, Config, ConfigError, PolicyMigrationError, PolicyPreset,
        PolicyVersionSource, ValidationCategory, POLICY_VERSION_CURRENT, POLICY_VERSION_LEGACY,
    };

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
        assert_eq!(loaded.policy_version, POLICY_VERSION_CURRENT);
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

    #[test]
    fn legacy_policy_without_version_uses_legacy_version_and_warns() {
        let path = write_temp_policy(
            r#"
[output]
mode = "warn"
"#,
        );

        let loaded = load_effective_from_typed(Some(&path), None).expect("load policy");
        assert_eq!(loaded.config.policy_version, POLICY_VERSION_LEGACY);
        assert_eq!(loaded.version_source, PolicyVersionSource::LegacyImplicit);
        assert!(loaded
            .compatibility_warnings
            .iter()
            .any(|w| w.contains("migrate")));
        assert_eq!(loaded.config.output.fail_threshold, 70);
        assert_eq!(loaded.config.weights.test_gap_max_penalty, 35);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn policy_preset_can_be_layered_with_policy_file() {
        let path = write_temp_policy(
            r#"
policy_version = 2
[output]
mode = "warn"
"#,
        );

        let loaded =
            load_effective_from_typed(Some(&path), Some(PolicyPreset::Strict)).expect("load");
        assert_eq!(loaded.config.output.mode, "warn");
        assert!(loaded.config.output.fail_threshold >= 70);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn migrate_policy_from_v1_to_v2_adds_version() {
        let input = r#"
[output]
mode = "warn"
"#;
        let migrated = migrate_policy_text(input, POLICY_VERSION_LEGACY, POLICY_VERSION_CURRENT)
            .expect("migrate");
        assert!(migrated.changed);
        assert!(migrated.migrated_toml.contains("policy_version = 2"));
    }

    #[test]
    fn migration_rejects_version_mismatch() {
        let input = r#"
policy_version = 2
[output]
mode = "warn"
"#;
        let err = migrate_policy_text(input, 1, 2).expect_err("must reject mismatch");
        assert!(format!("{err}").contains("version mismatch"));
    }

    #[test]
    fn migration_rejects_out_of_range_policy_version() {
        let input = r#"
policy_version = 4294967297
[output]
mode = "warn"
"#;
        let err = migrate_policy_text(input, 1, 2).expect_err("must reject invalid version");
        assert!(matches!(err, PolicyMigrationError::InvalidVersionField));
    }

    #[test]
    fn compatibility_warning_is_empty_for_current_version() {
        let cfg = Config {
            policy_version: POLICY_VERSION_CURRENT,
            ..Config::default()
        };
        let warnings = compatibility_warnings(&cfg, PolicyVersionSource::Explicit);
        assert!(warnings.is_empty());
    }
}
