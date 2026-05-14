use std::collections::BTreeMap;

use patchgate_config::PolicyAuthority;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    TestGap,
    DangerousChange,
    DependencyUpdate,
    ExternalPlugin,
    PolicyAuthority,
}

impl CheckId {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckId::TestGap => "test_gap",
            CheckId::DangerousChange => "dangerous_change",
            CheckId::DependencyUpdate => "dependency_update",
            CheckId::ExternalPlugin => "external_plugin",
            CheckId::PolicyAuthority => "policy_authority",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CheckId::TestGap => "Test coverage gap",
            CheckId::DangerousChange => "Dangerous file changes",
            CheckId::DependencyUpdate => "Dependency update risk",
            CheckId::ExternalPlugin => "External plugin risk",
            CheckId::PolicyAuthority => "Policy authority",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    pub file: String,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub docs_url: String,
    pub check: CheckId,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub penalty: u8,
    pub location: Option<Location>,
    pub tags: Vec<String>,
}

impl Finding {
    pub fn pr_template_hint(&self) -> String {
        let rule_display = if self.rule_id.is_empty() {
            self.id.as_str()
        } else {
            self.rule_id.as_str()
        };
        if self.category.is_empty() {
            format!("- [ ] `{}` {}", rule_display, self.title)
        } else {
            format!(
                "- [ ] `{}` ({}) {}",
                rule_display, self.category, self.title
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckScore {
    pub check: CheckId,
    pub label: String,
    pub penalty: u8,
    pub max_penalty: u8,
    pub triggered: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPriority {
    P0,
    P1,
    P2,
    P3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub checks: Vec<CheckScore>,
    pub score: u8,
    pub threshold: u8,
    pub should_fail: bool,
    pub mode: String,
    pub scope: String,
    pub review_priority: ReviewPriority,
    pub fingerprint: String,
    pub duration_ms: u128,
    pub skipped_by_cache: bool,
    #[serde(default)]
    pub changed_files: usize,
    #[serde(default)]
    pub check_durations_ms: BTreeMap<String, u128>,
    #[serde(default)]
    pub diagnostic_hints: Vec<String>,
    #[serde(default)]
    pub supply_chain_signals: Vec<SupplyChainSignal>,
    #[serde(default)]
    pub plugin_invocations: Vec<PluginInvocation>,
    #[serde(default)]
    pub policy_authority: PolicyAuthority,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupplyChainSignal {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub message: String,
    pub related_files: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginInvocationStatus {
    Pass,
    Fail,
    Error,
    TimedOut,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginInvocation {
    pub plugin_id: String,
    pub status: PluginInvocationStatus,
    pub duration_ms: u128,
    pub sandbox_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_contract: Option<PluginShadowContract>,
    #[serde(default)]
    pub findings: Vec<PluginFinding>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginShadowContract {
    pub input_api_version: String,
    pub shadow_api_version: String,
    pub shadow_of: String,
    pub bridge_mode: String,
    pub shadow_envelope_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginFinding {
    pub id: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub docs_url: String,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub penalty: u8,
    pub location: Option<Location>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginInput {
    pub schema_version: u8,
    pub api_version: String,
    pub plugin_id: String,
    pub repo_root: String,
    pub mode: String,
    pub scope: String,
    pub changed_files: Vec<PluginChangedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginInputV2Shadow {
    pub schema_version: u8,
    pub api_version: String,
    pub shadow_of: String,
    pub plugin_id: String,
    pub repo_root: String,
    pub mode: String,
    pub scope: String,
    pub changed_files: Vec<PluginChangedFile>,
    pub metadata: PluginShadowMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginShadowMetadata {
    pub bridge_mode: String,
}

impl PluginInputV2Shadow {
    pub fn from_v1(input: &PluginInput, bridge_mode: impl Into<String>) -> Self {
        Self {
            schema_version: 2,
            api_version: "patchgate.plugin.v2-shadow".to_string(),
            shadow_of: input.api_version.clone(),
            plugin_id: input.plugin_id.clone(),
            repo_root: input.repo_root.clone(),
            mode: input.mode.clone(),
            scope: input.scope.clone(),
            changed_files: input.changed_files.clone(),
            metadata: PluginShadowMetadata {
                bridge_mode: bridge_mode.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginChangedFile {
    pub path: String,
    pub status: String,
    pub added: u32,
    pub deleted: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginOutput {
    #[serde(default)]
    pub findings: Vec<PluginFinding>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub threshold: u8,
    pub mode: String,
    pub scope: String,
    pub fingerprint: String,
    pub duration_ms: u128,
    pub skipped_by_cache: bool,
}

impl Report {
    pub fn new(findings: Vec<Finding>, checks: Vec<CheckScore>, meta: ReportMeta) -> Self {
        let total_penalty: u16 = checks.iter().map(|c| c.penalty as u16).sum();
        let capped_penalty = total_penalty.min(100) as u8;
        let score = 100u8.saturating_sub(capped_penalty);
        let should_fail = score < meta.threshold;
        let review_priority = review_priority_from_score(score);

        Self {
            findings,
            checks,
            score,
            threshold: meta.threshold,
            should_fail,
            mode: meta.mode,
            scope: meta.scope,
            review_priority,
            fingerprint: meta.fingerprint,
            duration_ms: meta.duration_ms,
            skipped_by_cache: meta.skipped_by_cache,
            changed_files: 0,
            check_durations_ms: BTreeMap::new(),
            diagnostic_hints: diagnostic_hints_from_score(score, should_fail),
            supply_chain_signals: Vec::new(),
            plugin_invocations: Vec::new(),
            policy_authority: PolicyAuthority::default(),
        }
    }

    pub fn recompute_score(&mut self) {
        let total_penalty: u16 = self.checks.iter().map(|c| c.penalty as u16).sum();
        let capped_penalty = total_penalty.min(100) as u8;
        self.score = 100u8.saturating_sub(capped_penalty);
        self.should_fail = self.score < self.threshold;
        self.review_priority = review_priority_from_score(self.score);
    }
}

fn diagnostic_hints_from_score(score: u8, should_fail: bool) -> Vec<String> {
    let mut hints = Vec::new();
    if should_fail {
        hints.push("Gate failed: prioritize critical/high findings first.".to_string());
    }
    if score <= 40 {
        hints.push(
            "Score is in P0 band (<=40): split PR or add mitigation notes before merge."
                .to_string(),
        );
    } else if score <= 65 {
        hints.push(
            "Score is in P1 band (41-65): assign focused reviewers for risk-heavy files."
                .to_string(),
        );
    }
    hints
}

pub fn review_priority_from_score(score: u8) -> ReviewPriority {
    if score <= 40 {
        ReviewPriority::P0
    } else if score <= 65 {
        ReviewPriority::P1
    } else if score <= 85 {
        ReviewPriority::P2
    } else {
        ReviewPriority::P3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_check(check: CheckId, penalty: u8, max_penalty: u8) -> CheckScore {
        CheckScore {
            check,
            label: check.label().to_string(),
            penalty,
            max_penalty,
            triggered: penalty > 0,
        }
    }

    #[test]
    fn review_priority_boundaries_are_stable() {
        assert_eq!(review_priority_from_score(0), ReviewPriority::P0);
        assert_eq!(review_priority_from_score(40), ReviewPriority::P0);
        assert_eq!(review_priority_from_score(41), ReviewPriority::P1);
        assert_eq!(review_priority_from_score(65), ReviewPriority::P1);
        assert_eq!(review_priority_from_score(66), ReviewPriority::P2);
        assert_eq!(review_priority_from_score(85), ReviewPriority::P2);
        assert_eq!(review_priority_from_score(86), ReviewPriority::P3);
        assert_eq!(review_priority_from_score(100), ReviewPriority::P3);
    }

    #[test]
    fn report_score_is_capped_and_non_negative() {
        let report = Report::new(
            Vec::new(),
            vec![
                sample_check(CheckId::TestGap, 80, 80),
                sample_check(CheckId::DangerousChange, 70, 70),
            ],
            ReportMeta {
                threshold: 70,
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );

        assert_eq!(report.score, 0);
        assert_eq!(report.review_priority, ReviewPriority::P0);
    }

    #[test]
    fn threshold_failure_boundary_is_strictly_less_than() {
        let report_equal_threshold = Report::new(
            Vec::new(),
            vec![sample_check(CheckId::TestGap, 30, 35)],
            ReportMeta {
                threshold: 70,
                mode: "enforce".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );
        assert_eq!(report_equal_threshold.score, 70);
        assert!(!report_equal_threshold.should_fail);

        let report_below_threshold = Report::new(
            Vec::new(),
            vec![sample_check(CheckId::TestGap, 31, 35)],
            ReportMeta {
                threshold: 70,
                mode: "enforce".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );
        assert_eq!(report_below_threshold.score, 69);
        assert!(report_below_threshold.should_fail);
    }

    #[test]
    fn pr_template_hint_uses_rule_id_when_available() {
        let finding = Finding {
            id: "TG-001".to_string(),
            rule_id: "TG-RULE".to_string(),
            category: "test_gap".to_string(),
            docs_url: "https://example.com".to_string(),
            check: CheckId::TestGap,
            title: "Missing tests".to_string(),
            message: "add tests".to_string(),
            severity: Severity::Medium,
            penalty: 10,
            location: None,
            tags: vec![],
        };
        assert_eq!(
            finding.pr_template_hint(),
            "- [ ] `TG-RULE` (test_gap) Missing tests"
        );
    }

    #[test]
    fn pr_template_hint_falls_back_for_legacy_fields() {
        let finding = Finding {
            id: "TG-001".to_string(),
            rule_id: String::new(),
            category: String::new(),
            docs_url: String::new(),
            check: CheckId::TestGap,
            title: "Missing tests".to_string(),
            message: "add tests".to_string(),
            severity: Severity::Medium,
            penalty: 10,
            location: None,
            tags: vec![],
        };
        assert_eq!(finding.pr_template_hint(), "- [ ] `TG-001` Missing tests");
    }
}
