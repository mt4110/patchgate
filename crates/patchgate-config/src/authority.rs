use std::collections::BTreeSet;

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{load_effective_from_typed, Config, ConfigError, LoadedConfig, PolicyPreset};

const AUTHORITY_SCHEMA_VERSION: &str = "patchgate.policy_authority.v1";
const BUNDLE_SCHEMA_VERSION: &str = "patchgate.policy.bundle.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyAuthority {
    pub schema_version: String,
    pub trusted: bool,
    pub digest: String,
    #[serde(default)]
    pub sources: Vec<PolicyAuthoritySource>,
    #[serde(default)]
    pub pr_overlay: PolicyOverlayAuthority,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

impl Default for PolicyAuthority {
    fn default() -> Self {
        Self {
            schema_version: AUTHORITY_SCHEMA_VERSION.to_string(),
            trusted: false,
            digest: "sha256:unresolved".to_string(),
            sources: Vec::new(),
            pr_overlay: PolicyOverlayAuthority::default(),
            diagnostics: vec!["policy authority was not resolved".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyAuthoritySource {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub digest: String,
    pub trusted: bool,
    pub signature_verified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyOverlayAuthority {
    pub present: bool,
    #[serde(default)]
    pub accepted_keys: Vec<String>,
    #[serde(default)]
    pub rejected_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyAuthorityFailure {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyAuthorityArtifact {
    pub schema_version: String,
    pub resolved_policy_digest: String,
    pub policy_authority: PolicyAuthority,
    #[serde(default)]
    pub enforce_failures: Vec<PolicyAuthorityFailure>,
}

#[derive(Debug, Clone)]
pub struct PolicyAuthoritySourceInput {
    pub kind: &'static str,
    pub ref_name: Option<String>,
    pub path: Option<String>,
    pub text: String,
}

impl PolicyAuthoritySourceInput {
    pub fn new(kind: &'static str, text: impl Into<String>) -> Self {
        Self {
            kind,
            ref_name: None,
            path: None,
            text: text.into(),
        }
    }

    pub fn with_ref(mut self, ref_name: Option<String>) -> Self {
        self.ref_name = ref_name;
        self
    }

    pub fn with_path(mut self, path: Option<String>) -> Self {
        self.path = path;
        self
    }
}

#[derive(Debug, Clone)]
pub struct PolicyBundleSourceInput {
    pub path: Option<String>,
    pub text: String,
    pub signature_path: Option<String>,
    pub signature_text: Option<String>,
    pub public_key_base64: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyAuthorityResolverInput {
    pub mode: String,
    pub preset: Option<PolicyPreset>,
    pub base_branch: Option<PolicyAuthoritySourceInput>,
    pub protected_ref: Option<PolicyAuthoritySourceInput>,
    pub local_file: Option<PolicyAuthoritySourceInput>,
    pub org_bundle: Option<PolicyBundleSourceInput>,
    pub enforce_trusted_policy_required: bool,
    pub allow_untrusted_local_enforce: bool,
}

#[derive(Debug, Clone)]
pub struct PolicyAuthorityResolution {
    pub config: Config,
    pub loaded: LoadedConfig,
    pub authority: PolicyAuthority,
    pub artifact: PolicyAuthorityArtifact,
    pub enforce_failures: Vec<PolicyAuthorityFailure>,
}

#[derive(Debug, Error)]
pub enum PolicyAuthorityError {
    #[error("policy source `{kind}` parse failed: {source}")]
    SourceParse {
        kind: &'static str,
        #[source]
        source: ConfigError,
    },

    #[error("policy bundle parse failed: {message}")]
    BundleParse { message: String },

    #[error("policy bundle config parse failed: {source}")]
    BundleConfig {
        #[source]
        source: ConfigError,
    },

    #[error("resolved policy serialization failed: {source}")]
    RenderResolvedPolicy {
        #[source]
        source: toml::ser::Error,
    },
}

#[derive(Debug, Deserialize)]
struct RawPolicyBundle {
    schema_version: String,
    policy: toml::Value,
}

pub fn resolve_policy_authority(
    input: PolicyAuthorityResolverInput,
) -> Result<PolicyAuthorityResolution, PolicyAuthorityError> {
    let mut sources = Vec::new();
    let mut diagnostics = Vec::new();
    let mut enforce_failures = Vec::new();
    let mut trusted_values = Vec::new();

    if let Some(base) = input.base_branch.as_ref() {
        let trusted_source = load_source_policy_value(base, input.preset)?;
        trusted_values.push(TrustedPolicyValue {
            value: trusted_source.value,
        });
        sources.push(source_record(base, true, false));
    }

    if let Some(protected) = input.protected_ref.as_ref() {
        let trusted_source = load_source_policy_value(protected, input.preset)?;
        trusted_values.push(TrustedPolicyValue {
            value: trusted_source.value,
        });
        sources.push(source_record(protected, true, false));
    }

    if let Some(bundle) = input.org_bundle.as_ref() {
        let digest = sha256_digest(bundle.text.as_bytes());
        match verify_policy_bundle_source(bundle) {
            Ok(verified) => {
                let policy_value = parse_policy_bundle_value(bundle.text.as_str())?;
                match load_policy_bundle_value_config(policy_value.clone(), input.preset) {
                    Ok(_) => {
                        trusted_values.push(TrustedPolicyValue {
                            value: policy_value,
                        });
                        sources.push(PolicyAuthoritySource {
                            kind: "org_bundle".to_string(),
                            ref_name: None,
                            path: bundle.path.clone(),
                            digest,
                            trusted: true,
                            signature_verified: true,
                        });
                        diagnostics.push(format!(
                            "org bundle signature verified with key fingerprint {}",
                            verified.public_key_fingerprint
                        ));
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(message) => {
                sources.push(PolicyAuthoritySource {
                    kind: "org_bundle".to_string(),
                    ref_name: None,
                    path: bundle.path.clone(),
                    digest,
                    trusted: false,
                    signature_verified: false,
                });
                enforce_failures.push(PolicyAuthorityFailure {
                    code: "org_bundle_signature_unverified".to_string(),
                    message,
                });
            }
        }
    }

    let mut overlay = PolicyOverlayAuthority::default();
    let local_loaded = match input.local_file.as_ref() {
        Some(local) => match load_source_policy_value(local, input.preset) {
            Ok(loaded_source) => {
                sources.push(source_record(local, false, false));
                Some(loaded_source.loaded)
            }
            Err(err) if !trusted_values.is_empty() => {
                sources.push(source_record(local, false, false));
                let message = format!("PR policy overlay could not be parsed: {err}");
                overlay.present = true;
                overlay.rejected_keys.push("policy.parse".to_string());
                diagnostics.push(message.clone());
                if input.mode == "enforce" {
                    enforce_failures.push(PolicyAuthorityFailure {
                        code: "pr_overlay_invalid".to_string(),
                        message,
                    });
                }
                None
            }
            Err(err) => return Err(err),
        },
        None => None,
    };

    let loaded = if !trusted_values.is_empty() {
        let mut trusted = merge_trusted_policy_values(&trusted_values, input.preset)?;
        if let Some(local) = local_loaded.as_ref() {
            if local.config != trusted.config {
                let overlay_resolution =
                    resolve_pr_overlay(&trusted.config, &local.config, input.mode.as_str());
                overlay = overlay_resolution.authority;
                trusted.config = overlay_resolution.config;
                if input.mode == "enforce" && !overlay.rejected_keys.is_empty() {
                    enforce_failures.push(PolicyAuthorityFailure {
                        code: "pr_overlay_rejected".to_string(),
                        message: format!(
                            "PR policy overlay attempted untrusted changes: {}",
                            overlay.rejected_keys.join(", ")
                        ),
                    });
                }
            }
        }
        trusted
    } else if let Some(local) = local_loaded {
        if input.mode == "enforce"
            && input.enforce_trusted_policy_required
            && !input.allow_untrusted_local_enforce
        {
            enforce_failures.push(PolicyAuthorityFailure {
                code: "untrusted_policy_in_enforce".to_string(),
                message: "enforce mode requires a trusted base, protected ref, or verified org bundle policy".to_string(),
            });
        }
        local
    } else {
        let loaded = load_effective_from_typed(None, input.preset).map_err(|source| {
            PolicyAuthorityError::SourceParse {
                kind: "default",
                source,
            }
        })?;
        if input.mode == "enforce"
            && input.enforce_trusted_policy_required
            && !input.allow_untrusted_local_enforce
        {
            enforce_failures.push(PolicyAuthorityFailure {
                code: "untrusted_policy_in_enforce".to_string(),
                message: "enforce mode requires a trusted policy; no policy source was found"
                    .to_string(),
            });
        }
        sources.push(PolicyAuthoritySource {
            kind: "default".to_string(),
            ref_name: None,
            path: None,
            digest: policy_digest(&loaded.config)?,
            trusted: false,
            signature_verified: false,
        });
        loaded
    };

    let resolved_policy_digest = policy_digest(&loaded.config)?;
    let trusted = sources.iter().any(|source| source.trusted) && enforce_failures.is_empty();
    if !overlay.rejected_keys.is_empty() {
        diagnostics.push("PR overlay contained rejected keys".to_string());
    }
    if !enforce_failures.is_empty() {
        diagnostics.extend(
            enforce_failures
                .iter()
                .map(|failure| format!("{}: {}", failure.code, failure.message)),
        );
    }
    let authority = PolicyAuthority {
        schema_version: AUTHORITY_SCHEMA_VERSION.to_string(),
        trusted,
        digest: resolved_policy_digest.clone(),
        sources,
        pr_overlay: overlay,
        diagnostics,
    };
    let artifact = PolicyAuthorityArtifact {
        schema_version: AUTHORITY_SCHEMA_VERSION.to_string(),
        resolved_policy_digest,
        policy_authority: authority.clone(),
        enforce_failures: enforce_failures.clone(),
    };

    Ok(PolicyAuthorityResolution {
        config: loaded.config.clone(),
        loaded,
        authority,
        artifact,
        enforce_failures,
    })
}

pub fn policy_digest(config: &Config) -> Result<String, PolicyAuthorityError> {
    let rendered = toml::to_string(config)
        .map_err(|source| PolicyAuthorityError::RenderResolvedPolicy { source })?;
    Ok(sha256_digest(rendered.as_bytes()))
}

pub fn source_text_digest(text: &str) -> String {
    sha256_digest(text.as_bytes())
}

pub fn verify_policy_bundle_signature(
    bundle_text: &str,
    signature_text: &str,
    public_key_base64: &str,
) -> Result<PolicyBundleVerification, String> {
    let key_bytes = decode_base64_material(public_key_base64.trim())
        .map_err(|err| format!("failed to decode policy bundle public key (base64): {err}"))?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "policy bundle public key must be 32 bytes (ed25519)".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|err| format!("failed to parse policy bundle public key (ed25519): {err}"))?;
    let signature_bytes = decode_base64_material(signature_text.trim())
        .map_err(|err| format!("failed to decode policy bundle signature (base64): {err}"))?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|err| format!("failed to parse policy bundle signature (ed25519): {err}"))?;
    verifying_key
        .verify(bundle_text.as_bytes(), &signature)
        .map_err(|err| format!("policy bundle signature verification failed: {err}"))?;

    Ok(PolicyBundleVerification {
        public_key_fingerprint: sha256_hex(key_bytes.as_slice()),
    })
}

fn decode_base64_material(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyBundleVerification {
    pub public_key_fingerprint: String,
}

pub fn load_policy_bundle_config(
    bundle_text: &str,
    preset: Option<PolicyPreset>,
) -> Result<LoadedConfig, PolicyAuthorityError> {
    let policy_value = parse_policy_bundle_value(bundle_text)?;
    load_policy_bundle_value_config(policy_value, preset)
}

pub fn build_policy_authority_artifact(
    resolution: &PolicyAuthorityResolution,
) -> PolicyAuthorityArtifact {
    resolution.artifact.clone()
}

struct LoadedPolicyValue {
    loaded: LoadedConfig,
    value: toml::Value,
}

fn load_source_policy_value(
    source: &PolicyAuthoritySourceInput,
    preset: Option<PolicyPreset>,
) -> Result<LoadedPolicyValue, PolicyAuthorityError> {
    let value = parse_source_policy_value(source)?;
    let loaded = load_effective_from_policy_value(value.clone(), preset).map_err(|err| {
        PolicyAuthorityError::SourceParse {
            kind: source.kind,
            source: err,
        }
    })?;
    Ok(LoadedPolicyValue { loaded, value })
}

fn load_policy_bundle_value_config(
    policy_value: toml::Value,
    preset: Option<PolicyPreset>,
) -> Result<LoadedConfig, PolicyAuthorityError> {
    load_effective_from_policy_value(policy_value, preset)
        .map_err(|source| PolicyAuthorityError::BundleConfig { source })
}

struct TrustedPolicyValue {
    value: toml::Value,
}

fn parse_source_policy_value(
    source: &PolicyAuthoritySourceInput,
) -> Result<toml::Value, PolicyAuthorityError> {
    crate::parse_toml_value(source.text.as_str()).map_err(|err| PolicyAuthorityError::SourceParse {
        kind: source.kind,
        source: err,
    })
}

fn parse_policy_bundle_value(bundle_text: &str) -> Result<toml::Value, PolicyAuthorityError> {
    let raw = toml::from_str::<RawPolicyBundle>(bundle_text).map_err(|err| {
        PolicyAuthorityError::BundleParse {
            message: err.to_string(),
        }
    })?;
    if raw.schema_version != BUNDLE_SCHEMA_VERSION {
        return Err(PolicyAuthorityError::BundleParse {
            message: format!(
                "unsupported schema_version `{}` (expected: {BUNDLE_SCHEMA_VERSION})",
                raw.schema_version
            ),
        });
    }
    Ok(raw.policy)
}

fn merge_trusted_policy_values(
    values: &[TrustedPolicyValue],
    preset: Option<PolicyPreset>,
) -> Result<LoadedConfig, PolicyAuthorityError> {
    let mut merged = toml::Value::Table(toml::map::Map::new());
    for value in values {
        crate::deep_merge(&mut merged, value.value.clone());
    }
    load_effective_from_policy_value(merged, preset).map_err(|source| {
        PolicyAuthorityError::SourceParse {
            kind: "trusted_policy_merge",
            source,
        }
    })
}

fn load_effective_from_policy_value(
    policy_value: toml::Value,
    preset: Option<PolicyPreset>,
) -> Result<LoadedConfig, ConfigError> {
    let (config, version_source) = crate::load_effective_from_policy_value(policy_value, preset)?;
    crate::validate_config(&config)?;
    let compatibility_warnings = crate::compatibility_warnings(&config, version_source);
    Ok(LoadedConfig {
        config,
        version_source,
        compatibility_warnings,
    })
}

fn source_record(
    input: &PolicyAuthoritySourceInput,
    trusted: bool,
    signature_verified: bool,
) -> PolicyAuthoritySource {
    PolicyAuthoritySource {
        kind: input.kind.to_string(),
        ref_name: input.ref_name.clone(),
        path: input.path.clone(),
        digest: source_text_digest(input.text.as_str()),
        trusted,
        signature_verified,
    }
}

fn verify_policy_bundle_source(
    bundle: &PolicyBundleSourceInput,
) -> Result<PolicyBundleVerification, String> {
    let signature = bundle
        .signature_text
        .as_deref()
        .ok_or_else(|| "policy bundle signature is missing".to_string())?;
    let public_key = bundle
        .public_key_base64
        .as_deref()
        .ok_or_else(|| "policy bundle public key is missing".to_string())?;
    verify_policy_bundle_signature(bundle.text.as_str(), signature, public_key)
}

struct OverlayResolution {
    config: Config,
    authority: PolicyOverlayAuthority,
}

fn resolve_pr_overlay(base: &Config, overlay: &Config, mode: &str) -> OverlayResolution {
    let mut candidate = base.clone();
    let mut accepted_keys = Vec::new();
    let mut rejected_keys = Vec::new();

    compare_minimum_u8(
        "output.fail_threshold",
        base.output.fail_threshold,
        overlay.output.fail_threshold,
        &mut candidate.output.fail_threshold,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_output_mode(
        base,
        overlay,
        &mut candidate,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_bool_enable_only(
        "test_gap.enabled",
        base.test_gap.enabled,
        overlay.test_gap.enabled,
        &mut candidate.test_gap.enabled,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_bool_enable_only(
        "dangerous_change.enabled",
        base.dangerous_change.enabled,
        overlay.dangerous_change.enabled,
        &mut candidate.dangerous_change.enabled,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_bool_enable_only(
        "dependency_update.enabled",
        base.dependency_update.enabled,
        overlay.dependency_update.enabled,
        &mut candidate.dependency_update.enabled,
        &mut accepted_keys,
        &mut rejected_keys,
    );

    compare_minimum_u8(
        "weights.test_gap_max_penalty",
        base.weights.test_gap_max_penalty,
        overlay.weights.test_gap_max_penalty,
        &mut candidate.weights.test_gap_max_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "weights.dangerous_change_max_penalty",
        base.weights.dangerous_change_max_penalty,
        overlay.weights.dangerous_change_max_penalty,
        &mut candidate.weights.dangerous_change_max_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "weights.dependency_update_max_penalty",
        base.weights.dependency_update_max_penalty,
        overlay.weights.dependency_update_max_penalty,
        &mut candidate.weights.dependency_update_max_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "weights.plugin_max_penalty",
        base.weights.plugin_max_penalty,
        overlay.weights.plugin_max_penalty,
        &mut candidate.weights.plugin_max_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );

    compare_minimum_u8(
        "test_gap.missing_tests_penalty",
        base.test_gap.missing_tests_penalty,
        overlay.test_gap.missing_tests_penalty,
        &mut candidate.test_gap.missing_tests_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "test_gap.large_change_penalty",
        base.test_gap.large_change_penalty,
        overlay.test_gap.large_change_penalty,
        &mut candidate.test_gap.large_change_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_maximum_u32(
        "test_gap.large_change_lines",
        base.test_gap.large_change_lines,
        overlay.test_gap.large_change_lines,
        &mut candidate.test_gap.large_change_lines,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "dangerous_change.per_file_penalty",
        base.dangerous_change.per_file_penalty,
        overlay.dangerous_change.per_file_penalty,
        &mut candidate.dangerous_change.per_file_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "dangerous_change.critical_bonus_penalty",
        base.dangerous_change.critical_bonus_penalty,
        overlay.dangerous_change.critical_bonus_penalty,
        &mut candidate.dangerous_change.critical_bonus_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "dependency_update.manifest_penalty",
        base.dependency_update.manifest_penalty,
        overlay.dependency_update.manifest_penalty,
        &mut candidate.dependency_update.manifest_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "dependency_update.lockfile_penalty",
        base.dependency_update.lockfile_penalty,
        overlay.dependency_update.lockfile_penalty,
        &mut candidate.dependency_update.lockfile_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_minimum_u8(
        "dependency_update.large_lockfile_penalty",
        base.dependency_update.large_lockfile_penalty,
        overlay.dependency_update.large_lockfile_penalty,
        &mut candidate.dependency_update.large_lockfile_penalty,
        &mut accepted_keys,
        &mut rejected_keys,
    );

    compare_language_rules(
        base,
        overlay,
        &mut candidate,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_scope_rules(
        base,
        overlay,
        &mut candidate,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_list_superset_only(
        "dangerous_change.patterns",
        &base.dangerous_change.patterns,
        &overlay.dangerous_change.patterns,
        &mut candidate.dangerous_change.patterns,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_list_superset_only(
        "dangerous_change.critical_patterns",
        &base.dangerous_change.critical_patterns,
        &overlay.dangerous_change.critical_patterns,
        &mut candidate.dangerous_change.critical_patterns,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_list_subset_only(
        "exclude.globs",
        &base.exclude.globs,
        &overlay.exclude.globs,
        &mut candidate.exclude.globs,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_list_subset_only(
        "generated_code.globs",
        &base.generated_code.globs,
        &overlay.generated_code.globs,
        &mut candidate.generated_code.globs,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_generated_mode(
        base,
        overlay,
        &mut candidate,
        &mut accepted_keys,
        &mut rejected_keys,
    );
    compare_plugins(
        base,
        overlay,
        &mut candidate,
        &mut accepted_keys,
        &mut rejected_keys,
    );

    if overlay.waiver.entries != base.waiver.entries {
        rejected_keys.push("waiver.entries".to_string());
    }
    if overlay.policy_authority != base.policy_authority {
        rejected_keys.push("policy_authority".to_string());
    }

    if mode == "enforce" && candidate != *overlay {
        append_unallowlisted_diff_keys(&candidate, overlay, &mut rejected_keys);
    }

    sort_dedup(&mut accepted_keys);
    sort_dedup(&mut rejected_keys);

    OverlayResolution {
        config: candidate,
        authority: PolicyOverlayAuthority {
            present: true,
            accepted_keys,
            rejected_keys,
        },
    }
}

fn compare_minimum_u8(
    key: &str,
    base: u8,
    overlay: u8,
    target: &mut u8,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay == base {
        return;
    }
    if overlay > base {
        *target = overlay;
        accepted.push(key.to_string());
    } else {
        rejected.push(key.to_string());
    }
}

fn compare_maximum_u32(
    key: &str,
    base: u32,
    overlay: u32,
    target: &mut u32,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay == base {
        return;
    }
    if overlay < base {
        *target = overlay;
        accepted.push(key.to_string());
    } else {
        rejected.push(key.to_string());
    }
}

fn compare_bool_enable_only(
    key: &str,
    base: bool,
    overlay: bool,
    target: &mut bool,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay == base {
        return;
    }
    if overlay {
        *target = true;
        accepted.push(key.to_string());
    } else {
        rejected.push(key.to_string());
    }
}

fn compare_output_mode(
    base: &Config,
    overlay: &Config,
    candidate: &mut Config,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay.output.mode == base.output.mode {
        return;
    }
    if base.output.mode == "warn" && overlay.output.mode == "enforce" {
        candidate.output.mode = overlay.output.mode.clone();
        accepted.push("output.mode".to_string());
    } else {
        rejected.push("output.mode".to_string());
    }
}

fn compare_language_rules(
    base: &Config,
    overlay: &Config,
    candidate: &mut Config,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    compare_bool_enable_only(
        "language_rules.rust",
        base.language_rules.rust,
        overlay.language_rules.rust,
        &mut candidate.language_rules.rust,
        accepted,
        rejected,
    );
    compare_bool_enable_only(
        "language_rules.typescript",
        base.language_rules.typescript,
        overlay.language_rules.typescript,
        &mut candidate.language_rules.typescript,
        accepted,
        rejected,
    );
    compare_bool_enable_only(
        "language_rules.python",
        base.language_rules.python,
        overlay.language_rules.python,
        &mut candidate.language_rules.python,
        accepted,
        rejected,
    );
    compare_bool_enable_only(
        "language_rules.go",
        base.language_rules.go,
        overlay.language_rules.go,
        &mut candidate.language_rules.go,
        accepted,
        rejected,
    );
    compare_bool_enable_only(
        "language_rules.java_kotlin",
        base.language_rules.java_kotlin,
        overlay.language_rules.java_kotlin,
        &mut candidate.language_rules.java_kotlin,
        accepted,
        rejected,
    );
}

fn compare_scope_rules(
    base: &Config,
    overlay: &Config,
    candidate: &mut Config,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    compare_maximum_u32(
        "scope.max_changed_files",
        base.scope.max_changed_files,
        overlay.scope.max_changed_files,
        &mut candidate.scope.max_changed_files,
        accepted,
        rejected,
    );
    if overlay.scope.on_exceed != base.scope.on_exceed {
        if base.scope.on_exceed == "fail_open" && overlay.scope.on_exceed == "fail_closed" {
            candidate.scope.on_exceed = overlay.scope.on_exceed.clone();
            accepted.push("scope.on_exceed".to_string());
        } else {
            rejected.push("scope.on_exceed".to_string());
        }
    }
}

fn compare_generated_mode(
    base: &Config,
    overlay: &Config,
    candidate: &mut Config,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay.generated_code.mode == base.generated_code.mode {
        return;
    }
    if base.generated_code.mode == "exclude" && overlay.generated_code.mode == "decay" {
        candidate.generated_code.mode = overlay.generated_code.mode.clone();
        accepted.push("generated_code.mode".to_string());
    } else {
        rejected.push("generated_code.mode".to_string());
    }
}

fn compare_list_superset_only(
    key: &str,
    base: &[String],
    overlay: &[String],
    target: &mut Vec<String>,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay == base {
        return;
    }
    if is_superset(overlay, base) {
        *target = overlay.to_vec();
        accepted.push(key.to_string());
    } else {
        rejected.push(key.to_string());
    }
}

fn compare_list_subset_only(
    key: &str,
    base: &[String],
    overlay: &[String],
    target: &mut Vec<String>,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay == base {
        return;
    }
    if is_subset(overlay, base) {
        *target = overlay.to_vec();
        accepted.push(key.to_string());
    } else {
        rejected.push(key.to_string());
    }
}

fn compare_plugins(
    base: &Config,
    overlay: &Config,
    candidate: &mut Config,
    accepted: &mut Vec<String>,
    rejected: &mut Vec<String>,
) {
    if overlay.plugins == base.plugins {
        return;
    }
    let rejection_start = rejected.len();
    if base.plugins.enabled && !overlay.plugins.enabled {
        rejected.push("plugins.enabled".to_string());
    }
    if base.plugins.signature.required && !overlay.plugins.signature.required {
        rejected.push("plugins.signature.required".to_string());
    }
    if overlay.plugins.signature.public_key_env != base.plugins.signature.public_key_env
        || overlay.plugins.signature.trusted_key_envs != base.plugins.signature.trusted_key_envs
        || overlay.plugins.signature.revoked_key_sha256 != base.plugins.signature.revoked_key_sha256
    {
        rejected.push("plugins.signature.trusted_keys".to_string());
    }
    if overlay.plugins.enabled && !overlay.plugins.signature.required {
        rejected.push("plugins.signature.required".to_string());
    }
    if overlay.plugins.enabled
        && overlay.plugins.entries.iter().any(|plugin| {
            plugin.fail_mode != "fail_closed" || plugin.signature_path.trim().is_empty()
        })
    {
        rejected.push("plugins.entries".to_string());
    }
    if !is_plugin_entry_superset(&overlay.plugins.entries, &base.plugins.entries) {
        rejected.push("plugins.entries".to_string());
    }

    if rejected.len() == rejection_start {
        candidate.plugins = overlay.plugins.clone();
        accepted.push("plugins".to_string());
    }
}

fn append_unallowlisted_diff_keys(
    candidate: &Config,
    overlay: &Config,
    rejected: &mut Vec<String>,
) {
    push_unallowlisted_diff(
        "policy_version",
        &candidate.policy_version,
        &overlay.policy_version,
        rejected,
    );
    push_unallowlisted_diff("output", &candidate.output, &overlay.output, rejected);
    push_unallowlisted_diff("scope", &candidate.scope, &overlay.scope, rejected);
    push_unallowlisted_diff("cache", &candidate.cache, &overlay.cache, rejected);
    push_unallowlisted_diff("exclude", &candidate.exclude, &overlay.exclude, rejected);
    push_unallowlisted_diff(
        "generated_code",
        &candidate.generated_code,
        &overlay.generated_code,
        rejected,
    );
    push_unallowlisted_diff(
        "language_rules",
        &candidate.language_rules,
        &overlay.language_rules,
        rejected,
    );
    push_unallowlisted_diff("weights", &candidate.weights, &overlay.weights, rejected);
    push_unallowlisted_diff("test_gap", &candidate.test_gap, &overlay.test_gap, rejected);
    push_unallowlisted_diff(
        "dangerous_change",
        &candidate.dangerous_change,
        &overlay.dangerous_change,
        rejected,
    );
    push_unallowlisted_diff(
        "dependency_update",
        &candidate.dependency_update,
        &overlay.dependency_update,
        rejected,
    );
    push_unallowlisted_diff(
        "observability",
        &candidate.observability,
        &overlay.observability,
        rejected,
    );
    push_unallowlisted_diff("alerts", &candidate.alerts, &overlay.alerts, rejected);
    push_unallowlisted_diff(
        "policy_authority",
        &candidate.policy_authority,
        &overlay.policy_authority,
        rejected,
    );
    push_unallowlisted_diff("waiver", &candidate.waiver, &overlay.waiver, rejected);
    push_unallowlisted_diff("plugins", &candidate.plugins, &overlay.plugins, rejected);
    push_unallowlisted_diff(
        "integrations",
        &candidate.integrations,
        &overlay.integrations,
        rejected,
    );
    push_unallowlisted_diff("release", &candidate.release, &overlay.release, rejected);
    push_unallowlisted_diff(
        "compatibility",
        &candidate.compatibility,
        &overlay.compatibility,
        rejected,
    );
}

fn push_unallowlisted_diff<T: PartialEq>(
    key: &str,
    candidate: &T,
    overlay: &T,
    rejected: &mut Vec<String>,
) {
    if candidate != overlay {
        rejected.push(format!("policy.unallowlisted.{key}"));
    }
}

fn is_superset(candidate: &[String], required: &[String]) -> bool {
    let candidate: BTreeSet<&String> = candidate.iter().collect();
    required.iter().all(|item| candidate.contains(item))
}

fn is_subset(candidate: &[String], allowed: &[String]) -> bool {
    let allowed: BTreeSet<&String> = allowed.iter().collect();
    candidate.iter().all(|item| allowed.contains(item))
}

fn is_plugin_entry_superset(
    candidate: &[crate::PluginEntry],
    required: &[crate::PluginEntry],
) -> bool {
    required.iter().all(|entry| candidate.contains(entry))
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: &'static str, text: &str) -> PolicyAuthoritySourceInput {
        PolicyAuthoritySourceInput::new(kind, text.to_string())
            .with_path(Some("policy.toml".to_string()))
    }

    #[test]
    fn enforce_local_only_policy_records_untrusted_failure() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "enforce".to_string(),
            preset: None,
            base_branch: None,
            protected_ref: None,
            local_file: Some(source(
                "local_file",
                r#"
policy_version = 2
[output]
fail_threshold = 50
"#,
            )),
            org_bundle: None,
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(!resolution.authority.trusted);
        assert!(resolution
            .enforce_failures
            .iter()
            .any(|failure| failure.code == "untrusted_policy_in_enforce"));
    }

    #[test]
    fn enforce_rejects_pr_overlay_that_lowers_threshold() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "enforce".to_string(),
            preset: None,
            base_branch: Some(source(
                "base_branch",
                r#"
policy_version = 2
[output]
fail_threshold = 80
"#,
            )),
            protected_ref: None,
            local_file: Some(source(
                "local_file",
                r#"
policy_version = 2
[output]
fail_threshold = 50
"#,
            )),
            org_bundle: None,
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(resolution
            .authority
            .pr_overlay
            .rejected_keys
            .contains(&"output.fail_threshold".to_string()));
        assert!(resolution
            .enforce_failures
            .iter()
            .any(|failure| failure.code == "pr_overlay_rejected"));
        assert_eq!(resolution.config.output.fail_threshold, 80);
    }

    #[test]
    fn enforce_rejects_invalid_pr_overlay_without_losing_trusted_policy() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "enforce".to_string(),
            preset: None,
            base_branch: Some(source(
                "base_branch",
                r#"
policy_version = 2
[output]
fail_threshold = 80
"#,
            )),
            protected_ref: None,
            local_file: Some(source(
                "local_file",
                r#"
policy_version = 2
[output
"#,
            )),
            org_bundle: None,
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(!resolution.authority.trusted);
        assert!(resolution
            .enforce_failures
            .iter()
            .any(|failure| failure.code == "pr_overlay_invalid"));
        assert!(resolution.authority.pr_overlay.present);
        assert!(resolution
            .authority
            .pr_overlay
            .rejected_keys
            .contains(&"policy.parse".to_string()));
        assert_eq!(resolution.config.output.fail_threshold, 80);
    }

    #[test]
    fn enforce_accepts_stricter_overlay_keys() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "enforce".to_string(),
            preset: None,
            base_branch: Some(source(
                "base_branch",
                r#"
policy_version = 2
[output]
fail_threshold = 70
"#,
            )),
            protected_ref: None,
            local_file: Some(source(
                "local_file",
                r#"
policy_version = 2
[output]
fail_threshold = 85
[dangerous_change]
patterns = [".github/workflows/**", "infra/**", "terraform/**", "k8s/**", "helm/**", "migrations/**", "db/migrate/**", "**/auth/**", "**/security/**", "Dockerfile", "docker-compose*.yml", "docker-compose*.yaml", "secrets/**"]
critical_patterns = [".github/workflows/**", "infra/**", "terraform/**", "k8s/**", "migrations/**", "secrets/**"]
"#,
            )),
            org_bundle: None,
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(resolution.enforce_failures.is_empty());
        assert!(resolution
            .authority
            .pr_overlay
            .accepted_keys
            .contains(&"output.fail_threshold".to_string()));
        assert!(resolution
            .authority
            .pr_overlay
            .accepted_keys
            .contains(&"dangerous_change.patterns".to_string()));
        assert_eq!(resolution.config.output.fail_threshold, 85);
    }

    #[test]
    fn enforce_accepts_overlay_that_tightens_output_mode() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "enforce".to_string(),
            preset: None,
            base_branch: Some(source(
                "base_branch",
                r#"
policy_version = 2
[output]
mode = "warn"
fail_threshold = 80
"#,
            )),
            protected_ref: None,
            local_file: Some(source(
                "local_file",
                r#"
policy_version = 2
[output]
mode = "enforce"
fail_threshold = 80
"#,
            )),
            org_bundle: None,
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(resolution.enforce_failures.is_empty());
        assert!(resolution
            .authority
            .pr_overlay
            .accepted_keys
            .contains(&"output.mode".to_string()));
        assert!(resolution.authority.pr_overlay.rejected_keys.is_empty());
        assert_eq!(resolution.config.output.mode, "enforce");
    }

    #[test]
    fn trusted_sources_are_deep_merged_in_authority_order() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "enforce".to_string(),
            preset: None,
            base_branch: Some(source(
                "base_branch",
                r#"
policy_version = 2
[language_rules]
java_kotlin = true
"#,
            )),
            protected_ref: Some(source(
                "protected_ref",
                r#"
policy_version = 2
[output]
fail_threshold = 88
"#,
            )),
            local_file: None,
            org_bundle: None,
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(resolution.enforce_failures.is_empty());
        assert!(resolution.authority.trusted);
        assert!(resolution.config.language_rules.java_kotlin);
        assert_eq!(resolution.config.output.fail_threshold, 88);
    }

    #[test]
    fn warn_local_policy_is_marked_untrusted_without_failure() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "warn".to_string(),
            preset: None,
            base_branch: None,
            protected_ref: None,
            local_file: Some(source("local_file", "policy_version = 2\n")),
            org_bundle: None,
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(!resolution.authority.trusted);
        assert!(resolution.enforce_failures.is_empty());
    }

    #[test]
    fn invalid_org_bundle_marks_authority_untrusted_even_with_base_policy() {
        let resolution = resolve_policy_authority(PolicyAuthorityResolverInput {
            mode: "enforce".to_string(),
            preset: None,
            base_branch: Some(source("base_branch", "policy_version = 2\n")),
            protected_ref: None,
            local_file: None,
            org_bundle: Some(PolicyBundleSourceInput {
                path: Some("org-policy.toml".to_string()),
                text: r#"
schema_version = "patchgate.policy.bundle.v1"
[policy]
policy_version = 2
"#
                .to_string(),
                signature_path: Some("org-policy.sig".to_string()),
                signature_text: Some("not-base64".to_string()),
                public_key_base64: Some("also-not-base64".to_string()),
            }),
            enforce_trusted_policy_required: true,
            allow_untrusted_local_enforce: false,
        })
        .expect("resolve authority");

        assert!(!resolution.authority.trusted);
        assert!(resolution
            .enforce_failures
            .iter()
            .any(|failure| failure.code == "org_bundle_signature_unverified"));
    }
}
