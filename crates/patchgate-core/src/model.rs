use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use patchgate_config::{PolicyAuthority, WaiverEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVIDENCE_SCHEMA_VERSION: &str = "patchgate.evidence.v1";
pub const DECISION_SCHEMA_VERSION: &str = "patchgate.decision.v1";

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
    DiffCorrectness,
    DangerousChange,
    DependencyUpdate,
    SupplyChain,
    ExternalPlugin,
    PolicyAuthority,
    Runtime,
}

impl CheckId {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckId::TestGap => "test_gap",
            CheckId::DiffCorrectness => "diff_correctness",
            CheckId::DangerousChange => "dangerous_change",
            CheckId::DependencyUpdate => "dependency_update",
            CheckId::SupplyChain => "supply_chain",
            CheckId::ExternalPlugin => "external_plugin",
            CheckId::PolicyAuthority => "policy_authority",
            CheckId::Runtime => "runtime",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CheckId::TestGap => "Test coverage gap",
            CheckId::DiffCorrectness => "Diff correctness",
            CheckId::DangerousChange => "Dangerous file changes",
            CheckId::DependencyUpdate => "Dependency update risk",
            CheckId::SupplyChain => "Supply-chain hard gate",
            CheckId::ExternalPlugin => "External plugin risk",
            CheckId::PolicyAuthority => "Policy authority",
            CheckId::Runtime => "Runtime",
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
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub decision: Decision,
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProducerKind {
    #[default]
    Builtin,
    Plugin,
    Scanner,
    Policy,
    Waiver,
    Runtime,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    Low,
    #[default]
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceProducer {
    #[serde(default)]
    pub kind: EvidenceProducerKind,
    pub name: String,
    pub version: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRule {
    pub id: String,
    pub category: String,
    pub docs_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceImpact {
    pub hard_gate_candidate: bool,
    pub score_penalty: u8,
    pub max_penalty: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceLocation {
    pub path_bytes_sha256: String,
    pub path_display: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path_display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub producer: EvidenceProducer,
    pub rule: EvidenceRule,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: EvidenceConfidence,
    pub impact: EvidenceImpact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<EvidenceLocation>,
    pub message: String,
    pub remediation: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionResult {
    #[default]
    Pass,
    Fail,
    Warn,
    Error,
}

impl DecisionResult {
    pub fn as_str(self) -> &'static str {
        match self {
            DecisionResult::Pass => "pass",
            DecisionResult::Fail => "fail",
            DecisionResult::Warn => "warn",
            DecisionResult::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateDecisionResult {
    #[default]
    Pass,
    Fail,
    Waived,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardGateResult {
    pub gate_id: String,
    pub result: GateDecisionResult,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScoreResult {
    pub value: u8,
    pub threshold: u8,
    pub band: ReviewPriority,
    pub failed: bool,
}

impl Default for ScoreResult {
    fn default() -> Self {
        Self {
            value: 100,
            threshold: 70,
            band: ReviewPriority::P3,
            failed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaiverResult {
    pub waiver_id: String,
    pub evidence_id: String,
    pub valid: bool,
    pub expires_at: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub approver: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ticket: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDecisionStatus {
    #[default]
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeDecisionError {
    pub code: String,
    pub category: String,
    pub message: String,
    pub classified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeResult {
    pub result: RuntimeDecisionStatus,
    #[serde(default)]
    pub errors: Vec<RuntimeDecisionError>,
}

impl Default for RuntimeResult {
    fn default() -> Self {
        Self {
            result: RuntimeDecisionStatus::Ok,
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub schema_version: String,
    pub decision_id: String,
    pub result: DecisionResult,
    pub mode: String,
    pub scope: String,
    pub policy_authority_digest: String,
    pub diff_digest: String,
    #[serde(default)]
    pub hard_gates: Vec<HardGateResult>,
    pub score: ScoreResult,
    #[serde(default)]
    pub waivers: Vec<WaiverResult>,
    pub runtime: RuntimeResult,
}

impl Default for Decision {
    fn default() -> Self {
        Self {
            schema_version: DECISION_SCHEMA_VERSION.to_string(),
            decision_id: "dec_unresolved".to_string(),
            result: DecisionResult::Pass,
            mode: String::new(),
            scope: String::new(),
            policy_authority_digest: "sha256:unresolved".to_string(),
            diff_digest: "sha256:unresolved".to_string(),
            hard_gates: Vec::new(),
            score: ScoreResult::default(),
            waivers: Vec::new(),
            runtime: RuntimeResult::default(),
        }
    }
}

impl Decision {
    pub fn has_failed_hard_gate(&self) -> bool {
        self.hard_gates
            .iter()
            .any(|gate| gate.result == GateDecisionResult::Fail)
    }

    pub fn has_failing_conditions(&self) -> bool {
        matches!(self.result, DecisionResult::Fail | DecisionResult::Error)
            || self.score.failed
            || self.has_failed_hard_gate()
    }

    pub fn blocks_merge(&self) -> bool {
        matches!(self.result, DecisionResult::Fail | DecisionResult::Error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginInvocationStatus {
    Pass,
    Fail,
    Error,
    TrustVerificationFailed,
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
    pub trust: Option<PluginTrustReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_contract: Option<PluginShadowContract>,
    #[serde(default)]
    pub findings: Vec<PluginFinding>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginTrustReport {
    pub schema_version: String,
    pub manifest_path: String,
    pub manifest_digest: String,
    pub artifact_digest: String,
    pub lockfile_path: String,
    pub lockfile_digest: String,
    pub signing_key_id: String,
    pub signing_key_fingerprint: String,
    pub permission_set_digest: String,
    pub sandbox_capability: PluginSandboxCapabilityArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginSandboxCapabilityArtifact {
    pub schema_version: String,
    pub profile: String,
    pub network: bool,
    pub env: Vec<String>,
    pub read_paths: Vec<String>,
    pub write_paths: Vec<String>,
    pub stdout_limit_kib: u32,
    pub timeout_ms: u64,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(default)]
    pub path_id: String,
    #[serde(default)]
    pub path_bytes_b64: String,
    #[serde(default)]
    pub file_kind: String,
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

        let mut report = Self {
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
            evidence: Vec::new(),
            decision: Decision::default(),
        };
        report.refresh_decision(&[], Vec::new());
        report
    }

    pub fn recompute_score(&mut self) {
        let total_penalty: u16 = self.checks.iter().map(|c| c.penalty as u16).sum();
        let capped_penalty = total_penalty.min(100) as u8;
        self.score = 100u8.saturating_sub(capped_penalty);
        self.should_fail = self.score < self.threshold;
        self.review_priority = review_priority_from_score(self.score);
        let mut hints = diagnostic_hints_from_score(self.score, self.should_fail);
        for hint in self.diagnostic_hints.drain(..) {
            if !is_score_diagnostic_hint(&hint) && !hints.contains(&hint) {
                hints.push(hint);
            }
        }
        self.diagnostic_hints = hints;
        self.refresh_decision(&[], self.decision.runtime.errors.clone());
    }

    pub fn refresh_decision(
        &mut self,
        waivers: &[WaiverEntry],
        runtime_errors: Vec<RuntimeDecisionError>,
    ) {
        self.evidence = evidence_from_report(self);
        self.decision = evaluate_decision(self, waivers, runtime_errors);
        self.should_fail = self.decision.has_failing_conditions();
    }
}

fn evidence_from_report(report: &Report) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    for finding in &report.findings {
        let max_penalty = report
            .checks
            .iter()
            .find(|check| check.check == finding.check)
            .map(|check| check.max_penalty)
            .unwrap_or(finding.penalty);
        evidence.push(evidence_from_finding(finding, max_penalty));
    }
    for signal in &report.supply_chain_signals {
        evidence.push(evidence_from_supply_chain_signal(signal));
    }
    evidence
}

fn evidence_from_finding(finding: &Finding, max_penalty: u8) -> Evidence {
    let rule_id = non_empty_or(finding.rule_id.as_str(), finding.id.as_str());
    let category = non_empty_or(finding.category.as_str(), finding.check.as_str());
    let path = finding
        .location
        .as_ref()
        .map(|location| location.file.as_str())
        .unwrap_or("");
    let fingerprint = stable_fingerprint(&[
        "finding",
        rule_id,
        category,
        finding.title.as_str(),
        finding.message.as_str(),
        path,
    ]);
    let producer_kind = match finding.check {
        CheckId::ExternalPlugin => EvidenceProducerKind::Plugin,
        CheckId::PolicyAuthority => EvidenceProducerKind::Policy,
        CheckId::Runtime => EvidenceProducerKind::Runtime,
        _ => EvidenceProducerKind::Builtin,
    };
    Evidence {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        evidence_id: stable_prefixed_id("ev", fingerprint.as_str()),
        producer: EvidenceProducer {
            kind: producer_kind,
            name: finding.check.as_str().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            digest: stable_fingerprint(&["producer", finding.check.as_str()]),
        },
        rule: EvidenceRule {
            id: rule_id.to_string(),
            category: category.to_string(),
            docs_url: finding.docs_url.clone(),
        },
        severity: finding.severity,
        confidence: confidence_for_severity(finding.severity),
        impact: EvidenceImpact {
            hard_gate_candidate: finding.severity == Severity::Critical,
            score_penalty: finding.penalty,
            max_penalty,
        },
        location: finding.location.as_ref().map(|location| EvidenceLocation {
            path_bytes_sha256: finding_path_bytes_sha256(finding, location),
            path_display: location.file.clone(),
            old_path_display: None,
            line: location.line,
        }),
        message: finding.message.clone(),
        remediation: remediation_for_finding(finding),
        tags: finding.tags.clone(),
        fingerprint,
    }
}

fn evidence_from_supply_chain_signal(signal: &SupplyChainSignal) -> Evidence {
    let path = signal
        .related_files
        .first()
        .map(String::as_str)
        .unwrap_or("");
    let fingerprint = stable_fingerprint(&[
        "supply_chain",
        signal.id.as_str(),
        signal.title.as_str(),
        signal.message.as_str(),
        path,
    ]);
    Evidence {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        evidence_id: stable_prefixed_id("ev", fingerprint.as_str()),
        producer: EvidenceProducer {
            kind: EvidenceProducerKind::Builtin,
            name: CheckId::SupplyChain.as_str().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            digest: stable_fingerprint(&["producer", CheckId::SupplyChain.as_str()]),
        },
        rule: EvidenceRule {
            id: signal.id.clone(),
            category: CheckId::SupplyChain.as_str().to_string(),
            docs_url: "docs/SECURITY.md".to_string(),
        },
        severity: signal.severity,
        confidence: EvidenceConfidence::High,
        impact: EvidenceImpact {
            hard_gate_candidate: signal.severity == Severity::Critical,
            score_penalty: 0,
            max_penalty: 0,
        },
        location: signal.related_files.first().map(|file| EvidenceLocation {
            path_bytes_sha256: sha256_digest_bytes(file.as_bytes()),
            path_display: file.clone(),
            old_path_display: None,
            line: None,
        }),
        message: signal.message.clone(),
        remediation: if signal.severity == Severity::Critical {
            "Review dependency provenance or revert the coupled lockfile/workflow change."
                .to_string()
        } else {
            "Review dependency provenance and rollback safety.".to_string()
        },
        tags: signal.tags.clone(),
        fingerprint,
    }
}

fn evaluate_decision(
    report: &Report,
    waivers: &[WaiverEntry],
    runtime_errors: Vec<RuntimeDecisionError>,
) -> Decision {
    let runtime = RuntimeResult {
        result: if runtime_errors.is_empty() {
            RuntimeDecisionStatus::Ok
        } else {
            RuntimeDecisionStatus::Error
        },
        errors: runtime_errors,
    };
    let mut waiver_results = Vec::new();
    let mut hard_gate_groups: BTreeMap<String, Vec<&Evidence>> = BTreeMap::new();
    for evidence in &report.evidence {
        if evidence_is_hard_gate_candidate(evidence) {
            hard_gate_groups
                .entry(gate_id_for_evidence(evidence).to_string())
                .or_default()
                .push(evidence);
        }
    }

    let mut hard_gates = Vec::new();
    for (gate_id, evidence_items) in hard_gate_groups {
        let mut unwaived = Vec::new();
        let mut evidence_ids = Vec::new();
        for evidence in evidence_items {
            evidence_ids.push(evidence.evidence_id.clone());
            match valid_waiver_for_evidence(waivers, evidence, gate_id.as_str()) {
                Some(waiver) => waiver_results.push(waiver),
                None => unwaived.push(evidence.evidence_id.clone()),
            }
        }
        hard_gates.push(HardGateResult {
            gate_id,
            result: if unwaived.is_empty() {
                GateDecisionResult::Waived
            } else {
                GateDecisionResult::Fail
            },
            evidence_ids,
        });
    }

    let score = ScoreResult {
        value: report.score,
        threshold: report.threshold,
        band: report.review_priority,
        failed: report.score < report.threshold,
    };
    let hard_gate_failed = hard_gates
        .iter()
        .any(|gate| gate.result == GateDecisionResult::Fail);
    let runtime_failed = runtime.result == RuntimeDecisionStatus::Error
        && (report.mode == "enforce" || runtime.errors.iter().any(|err| !err.classified));
    let result = if runtime_failed {
        DecisionResult::Error
    } else if hard_gate_failed || score.failed {
        if report.mode == "warn" {
            DecisionResult::Warn
        } else {
            DecisionResult::Fail
        }
    } else {
        DecisionResult::Pass
    };

    let mut decision = Decision {
        schema_version: DECISION_SCHEMA_VERSION.to_string(),
        decision_id: String::new(),
        result,
        mode: report.mode.clone(),
        scope: report.scope.clone(),
        policy_authority_digest: report.policy_authority.digest.clone(),
        diff_digest: normalize_digest(report.fingerprint.as_str()),
        hard_gates,
        score,
        waivers: waiver_results,
        runtime,
    };
    decision.decision_id = decision_id(&decision);
    decision
}

fn evidence_is_hard_gate_candidate(evidence: &Evidence) -> bool {
    evidence.impact.hard_gate_candidate || evidence.severity == Severity::Critical
}

fn gate_id_for_evidence(evidence: &Evidence) -> &'static str {
    if evidence.rule.category == CheckId::SupplyChain.as_str()
        && evidence.severity == Severity::Critical
    {
        "critical-supply-chain"
    } else if evidence.rule.category == CheckId::PolicyAuthority.as_str() {
        "policy-authority"
    } else if evidence.rule.category == CheckId::Runtime.as_str()
        || evidence.producer.kind == EvidenceProducerKind::Runtime
    {
        "runtime-error"
    } else {
        "critical-evidence"
    }
}

fn valid_waiver_for_evidence(
    waivers: &[WaiverEntry],
    evidence: &Evidence,
    gate_id: &str,
) -> Option<WaiverResult> {
    waivers.iter().find_map(|entry| {
        if !waiver_matches_evidence(entry, evidence, gate_id) || !waiver_entry_is_valid(entry) {
            return None;
        }
        Some(WaiverResult {
            waiver_id: waiver_id_for_entry(entry, evidence, gate_id),
            evidence_id: evidence.evidence_id.clone(),
            valid: true,
            expires_at: entry.expires_at.clone(),
            reason: entry.reason.clone(),
            approver: entry.approver.clone(),
            ticket: entry.ticket.clone(),
        })
    })
}

fn waiver_matches_evidence(entry: &WaiverEntry, evidence: &Evidence, gate_id: &str) -> bool {
    if !entry.evidence_id.trim().is_empty() && entry.evidence_id != evidence.evidence_id {
        return false;
    }
    if !entry.gate_id.trim().is_empty() && entry.gate_id != gate_id {
        return false;
    }
    let check_id = entry.check_id.trim();
    check_id == gate_id
        || check_id == evidence.rule.category
        || check_id == evidence.producer.name
        || (check_id == "critical_supply_chain" && gate_id == "critical-supply-chain")
        || (check_id == "critical-supply-chain" && gate_id == "critical-supply-chain")
}

fn waiver_entry_is_valid(entry: &WaiverEntry) -> bool {
    if entry.reason.trim().is_empty() || entry.approver.trim().is_empty() {
        return false;
    }
    DateTime::parse_from_rfc3339(entry.expires_at.as_str())
        .map(|expires| expires.with_timezone(&Utc) > Utc::now())
        .unwrap_or(false)
}

fn waiver_id_for_entry(entry: &WaiverEntry, evidence: &Evidence, gate_id: &str) -> String {
    if !entry.waiver_id.trim().is_empty() {
        return entry.waiver_id.clone();
    }
    stable_prefixed_id(
        "wv",
        stable_fingerprint(&[
            entry.check_id.as_str(),
            entry.gate_id.as_str(),
            entry.evidence_id.as_str(),
            gate_id,
            evidence.evidence_id.as_str(),
            entry.expires_at.as_str(),
            entry.approver.as_str(),
        ])
        .as_str(),
    )
}

fn decision_id(decision: &Decision) -> String {
    let mut material = vec![
        decision.result.as_str().to_string(),
        decision.mode.clone(),
        decision.scope.clone(),
        decision.policy_authority_digest.clone(),
        decision.diff_digest.clone(),
        decision.score.value.to_string(),
        decision.score.threshold.to_string(),
        decision.score.failed.to_string(),
        format!("{:?}", decision.runtime.result),
    ];
    for gate in &decision.hard_gates {
        material.push(gate.gate_id.clone());
        material.push(format!("{:?}", gate.result));
        material.extend(gate.evidence_ids.iter().cloned());
    }
    for waiver in &decision.waivers {
        material.push(waiver.waiver_id.clone());
        material.push(waiver.evidence_id.clone());
        material.push(waiver.valid.to_string());
        material.push(waiver.expires_at.clone());
    }
    stable_prefixed_id(
        "dec",
        stable_fingerprint(
            material
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .as_str(),
    )
}

fn normalize_digest(raw: &str) -> String {
    if raw == "sha256:unresolved" {
        raw.to_string()
    } else if let Some(hex) = raw.strip_prefix("sha256:") {
        if is_sha256_hex(hex) {
            raw.to_string()
        } else {
            stable_fingerprint(&["diff", raw])
        }
    } else if is_sha256_hex(raw) {
        format!("sha256:{raw}")
    } else if raw.is_empty() {
        "sha256:unresolved".to_string()
    } else {
        stable_fingerprint(&["diff", raw])
    }
}

fn confidence_for_severity(severity: Severity) -> EvidenceConfidence {
    match severity {
        Severity::Critical | Severity::High => EvidenceConfidence::High,
        Severity::Medium => EvidenceConfidence::Medium,
        Severity::Low => EvidenceConfidence::Low,
    }
}

fn remediation_for_finding(finding: &Finding) -> String {
    if !finding.docs_url.is_empty() {
        match finding.check {
            CheckId::TestGap => "Add or update tests covering the changed package.".to_string(),
            CheckId::DiffCorrectness => {
                "Inspect the raw diff identity and replace unsafe paths or file kinds with reviewable changes.".to_string()
            }
            CheckId::DangerousChange => {
                "Get the required owner review or split the high-risk change.".to_string()
            }
            CheckId::DependencyUpdate => {
                "Review dependency provenance, lockfile integrity and rollback safety.".to_string()
            }
            CheckId::ExternalPlugin => {
                "Fix the plugin finding or document the approved exception.".to_string()
            }
            CheckId::PolicyAuthority => {
                "Restore trusted policy authority before running enforce mode.".to_string()
            }
            CheckId::SupplyChain => {
                "Review dependency provenance and supply-chain control coverage.".to_string()
            }
            CheckId::Runtime => "Resolve the runtime error and replay the decision.".to_string(),
        }
    } else {
        "Review the finding and document the mitigation.".to_string()
    }
}

fn non_empty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

fn finding_path_bytes_sha256(finding: &Finding, location: &Location) -> String {
    for prefix in ["evidence_path_sha256:", "path_sha256:"] {
        if let Some(hex) = finding
            .tags
            .iter()
            .find_map(|tag| tag.strip_prefix(prefix))
            .filter(|hex| is_sha256_hex(hex))
        {
            return format!("sha256:{hex}");
        }
    }
    sha256_digest_bytes(location.file.as_bytes())
}

fn stable_prefixed_id(prefix: &str, material: &str) -> String {
    let normalized =
        if material.strip_prefix("sha256:").is_some_and(is_sha256_hex) || is_sha256_hex(material) {
            material.to_string()
        } else {
            stable_fingerprint(&["id", material])
        };
    format!(
        "{prefix}_{}",
        &normalized.trim_start_matches("sha256:")[..16]
    )
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn sha256_digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn stable_fingerprint(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
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

fn is_score_diagnostic_hint(hint: &str) -> bool {
    hint == "Gate failed: prioritize critical/high findings first."
        || hint.starts_with("Score is in P0 band")
        || hint.starts_with("Score is in P1 band")
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

    fn sample_report(mode: &str, checks: Vec<CheckScore>) -> Report {
        Report::new(
            Vec::new(),
            checks,
            ReportMeta {
                threshold: 80,
                mode: mode.to_string(),
                scope: "pr".to_string(),
                fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        )
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
    fn recompute_score_refreshes_score_hints_and_preserves_custom_hints() {
        let mut report = Report::new(
            Vec::new(),
            vec![sample_check(CheckId::TestGap, 5, 35)],
            ReportMeta {
                threshold: 70,
                mode: "enforce".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );
        assert!(!report.should_fail);
        assert!(report.diagnostic_hints.is_empty());

        report
            .diagnostic_hints
            .push("Policy authority failure blocks enforce mode.".to_string());
        report
            .checks
            .push(sample_check(CheckId::PolicyAuthority, 100, 100));
        report.recompute_score();

        assert_eq!(report.score, 0);
        assert!(report.should_fail);
        assert!(report
            .diagnostic_hints
            .iter()
            .any(|hint| hint.starts_with("Gate failed:")));
        assert!(report
            .diagnostic_hints
            .iter()
            .any(|hint| hint.starts_with("Score is in P0 band")));
        assert!(report
            .diagnostic_hints
            .iter()
            .any(|hint| hint == "Policy authority failure blocks enforce mode."));
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
        assert_eq!(report_below_threshold.decision.result, DecisionResult::Fail);
        assert!(report_below_threshold.decision.score.failed);
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

    #[test]
    fn evidence_location_uses_path_bytes_sha256() {
        let report = Report::new(
            vec![Finding {
                id: "TG-001".to_string(),
                rule_id: "TG-RULE".to_string(),
                category: "test_gap".to_string(),
                docs_url: String::new(),
                check: CheckId::TestGap,
                title: "Missing tests".to_string(),
                message: "add tests".to_string(),
                severity: Severity::Medium,
                penalty: 10,
                location: Some(Location {
                    file: "src/lib.rs".to_string(),
                    line: Some(7),
                }),
                tags: vec![],
            }],
            vec![sample_check(CheckId::TestGap, 10, 35)],
            ReportMeta {
                threshold: 70,
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );

        let location = report.evidence[0]
            .location
            .as_ref()
            .expect("evidence location");
        assert_eq!(
            location.path_bytes_sha256,
            sha256_digest_bytes(b"src/lib.rs")
        );
        assert_ne!(
            location.path_bytes_sha256,
            stable_fingerprint(&["path", "src/lib.rs"])
        );
    }

    #[test]
    fn evidence_location_prefers_raw_path_identity_tag() {
        let raw_digest = sha256_digest_bytes(b"src/bad\nname.rs");
        let raw_tag = format!("path_sha256:{}", raw_digest.trim_start_matches("sha256:"));
        let report = Report::new(
            vec![Finding {
                id: "DIFF-001".to_string(),
                rule_id: "DIFF-001".to_string(),
                category: "diff_correctness".to_string(),
                docs_url: String::new(),
                check: CheckId::DiffCorrectness,
                title: "Path contains control characters".to_string(),
                message: "raw path identity is required".to_string(),
                severity: Severity::Critical,
                penalty: 100,
                location: Some(Location {
                    file: "src/bad\\nname.rs".to_string(),
                    line: None,
                }),
                tags: vec![raw_tag],
            }],
            vec![sample_check(CheckId::DiffCorrectness, 100, 100)],
            ReportMeta {
                threshold: 70,
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );

        let location = report.evidence[0]
            .location
            .as_ref()
            .expect("evidence location");

        assert_eq!(location.path_bytes_sha256, raw_digest);
        assert_ne!(
            location.path_bytes_sha256,
            sha256_digest_bytes(b"src/bad\\nname.rs")
        );
    }

    #[test]
    fn evidence_location_prefers_explicit_evidence_path_identity_tag() {
        let current_digest = sha256_digest_bytes(b"src/new.rs");
        let old_digest = sha256_digest_bytes(b"src/old\nname.rs");
        let current_tag = format!(
            "path_sha256:{}",
            current_digest.trim_start_matches("sha256:")
        );
        let evidence_tag = format!(
            "evidence_path_sha256:{}",
            old_digest.trim_start_matches("sha256:")
        );
        let report = Report::new(
            vec![Finding {
                id: "DIFF-001".to_string(),
                rule_id: "DIFF-001".to_string(),
                category: "diff_correctness".to_string(),
                docs_url: String::new(),
                check: CheckId::DiffCorrectness,
                title: "Path contains control characters".to_string(),
                message: "old path identity is required".to_string(),
                severity: Severity::Critical,
                penalty: 100,
                location: Some(Location {
                    file: "src/new.rs".to_string(),
                    line: None,
                }),
                tags: vec![current_tag, evidence_tag],
            }],
            vec![sample_check(CheckId::DiffCorrectness, 100, 100)],
            ReportMeta {
                threshold: 70,
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );

        let location = report.evidence[0]
            .location
            .as_ref()
            .expect("evidence location");

        assert_eq!(location.path_bytes_sha256, old_digest);
        assert_ne!(location.path_bytes_sha256, current_digest);
    }

    #[test]
    fn normalize_digest_accepts_only_valid_sha256_values() {
        let bare_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let prefixed_hex =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let invalid_prefixed = "sha256:not-a-real-digest";

        assert_eq!(normalize_digest(bare_hex), format!("sha256:{bare_hex}"));
        assert_eq!(normalize_digest(prefixed_hex), prefixed_hex);
        assert_eq!(normalize_digest("sha256:unresolved"), "sha256:unresolved");
        assert_eq!(
            normalize_digest(invalid_prefixed),
            stable_fingerprint(&["diff", invalid_prefixed])
        );
    }

    #[test]
    fn critical_supply_chain_hard_gate_beats_perfect_score() {
        let mut report = sample_report(
            "enforce",
            vec![sample_check(CheckId::DependencyUpdate, 0, 30)],
        );
        report.supply_chain_signals.push(SupplyChainSignal {
            id: "SCM-002".to_string(),
            title: "Lockfile topology changed with workflow modifications".to_string(),
            severity: Severity::Critical,
            message: "Lockfile add/remove combined with CI/workflow edits can bypass dependency controls.".to_string(),
            related_files: vec![
                ".github/workflows/ci.yml".to_string(),
                "package-lock.json".to_string(),
            ],
            tags: vec!["supply-chain".to_string(), "workflow".to_string()],
        });

        report.refresh_decision(&[], Vec::new());

        assert_eq!(report.score, 100);
        assert!(!report.decision.score.failed);
        assert!(report.decision.has_failed_hard_gate());
        assert_eq!(report.decision.result, DecisionResult::Fail);
        assert!(report.should_fail);
    }

    #[test]
    fn warn_decision_conditions_do_not_block_merge() {
        let mut report =
            sample_report("warn", vec![sample_check(CheckId::DependencyUpdate, 0, 30)]);
        report.supply_chain_signals.push(SupplyChainSignal {
            id: "SCM-002".to_string(),
            title: "Lockfile topology changed with workflow modifications".to_string(),
            severity: Severity::Critical,
            message: "Lockfile add/remove combined with CI/workflow edits can bypass dependency controls.".to_string(),
            related_files: vec!["package-lock.json".to_string()],
            tags: vec!["supply-chain".to_string()],
        });

        report.refresh_decision(&[], Vec::new());

        assert_eq!(report.decision.result, DecisionResult::Warn);
        assert!(report.decision.has_failed_hard_gate());
        assert!(report.decision.has_failing_conditions());
        assert!(!report.decision.blocks_merge());
        assert!(report.should_fail);
    }

    #[test]
    fn valid_waiver_allows_critical_when_score_passes() {
        let mut report = sample_report(
            "enforce",
            vec![sample_check(CheckId::DependencyUpdate, 0, 30)],
        );
        report.supply_chain_signals.push(SupplyChainSignal {
            id: "SCM-002".to_string(),
            title: "Lockfile topology changed with workflow modifications".to_string(),
            severity: Severity::Critical,
            message: "Lockfile add/remove combined with CI/workflow edits can bypass dependency controls.".to_string(),
            related_files: vec!["package-lock.json".to_string()],
            tags: vec!["supply-chain".to_string()],
        });
        let waiver = WaiverEntry {
            waiver_id: "wv_supply_chain_exception".to_string(),
            check_id: "critical_supply_chain".to_string(),
            gate_id: "critical-supply-chain".to_string(),
            evidence_id: String::new(),
            ticket: "SEC-1".to_string(),
            reason: "Temporary AppSec-approved migration window".to_string(),
            approver: "appsec".to_string(),
            expires_at: "2999-01-01T00:00:00Z".to_string(),
        };

        report.refresh_decision(&[waiver], Vec::new());

        assert_eq!(report.decision.result, DecisionResult::Pass);
        assert_eq!(report.decision.waivers.len(), 1);
        assert_eq!(
            report.decision.hard_gates[0].result,
            GateDecisionResult::Waived
        );
        assert!(!report.should_fail);
    }

    #[test]
    fn expired_waiver_does_not_clear_hard_gate() {
        let mut report = sample_report(
            "enforce",
            vec![sample_check(CheckId::DependencyUpdate, 0, 30)],
        );
        report.supply_chain_signals.push(SupplyChainSignal {
            id: "SCM-002".to_string(),
            title: "Lockfile topology changed with workflow modifications".to_string(),
            severity: Severity::Critical,
            message: "Lockfile add/remove combined with CI/workflow edits can bypass dependency controls.".to_string(),
            related_files: vec!["package-lock.json".to_string()],
            tags: vec!["supply-chain".to_string()],
        });
        let waiver = WaiverEntry {
            waiver_id: "wv_expired".to_string(),
            check_id: "critical_supply_chain".to_string(),
            gate_id: "critical-supply-chain".to_string(),
            evidence_id: String::new(),
            ticket: "SEC-2".to_string(),
            reason: "Expired exception".to_string(),
            approver: "appsec".to_string(),
            expires_at: "2000-01-01T00:00:00Z".to_string(),
        };

        report.refresh_decision(&[waiver], Vec::new());

        assert_eq!(report.decision.result, DecisionResult::Fail);
        assert!(report.decision.waivers.is_empty());
        assert_eq!(
            report.decision.hard_gates[0].result,
            GateDecisionResult::Fail
        );
    }

    #[test]
    fn runtime_error_in_enforce_is_error_decision() {
        let mut report = sample_report("enforce", vec![sample_check(CheckId::TestGap, 0, 35)]);

        report.refresh_decision(
            &[],
            vec![RuntimeDecisionError {
                code: "PG-RUN-001".to_string(),
                category: "runtime".to_string(),
                message: "critical evaluator failed".to_string(),
                classified: true,
            }],
        );

        assert_eq!(report.decision.result, DecisionResult::Error);
        assert_eq!(report.decision.runtime.result, RuntimeDecisionStatus::Error);
        assert!(report.should_fail);
    }

    #[test]
    fn decision_golden_snapshot_captures_hard_gate_layers() {
        let mut report = sample_report(
            "enforce",
            vec![sample_check(CheckId::DependencyUpdate, 0, 30)],
        );
        report.supply_chain_signals.push(SupplyChainSignal {
            id: "SCM-002".to_string(),
            title: "Lockfile topology changed with workflow modifications".to_string(),
            severity: Severity::Critical,
            message: "Lockfile add/remove combined with CI/workflow edits can bypass dependency controls.".to_string(),
            related_files: vec!["package-lock.json".to_string()],
            tags: vec!["supply-chain".to_string()],
        });

        report.refresh_decision(&[], Vec::new());
        let mut snapshot = serde_json::to_value(&report.decision).expect("decision json");
        snapshot["decision_id"] = serde_json::json!("dec_<stable>");
        snapshot["hard_gates"][0]["evidence_ids"][0] = serde_json::json!("ev_<stable>");

        assert_eq!(
            snapshot,
            serde_json::json!({
                "schema_version": "patchgate.decision.v1",
                "decision_id": "dec_<stable>",
                "result": "fail",
                "mode": "enforce",
                "scope": "pr",
                "policy_authority_digest": "sha256:unresolved",
                "diff_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "hard_gates": [
                    {
                        "gate_id": "critical-supply-chain",
                        "result": "fail",
                        "evidence_ids": ["ev_<stable>"]
                    }
                ],
                "score": {
                    "value": 100,
                    "threshold": 80,
                    "band": "p3",
                    "failed": false
                },
                "waivers": [],
                "runtime": {
                    "result": "ok",
                    "errors": []
                }
            })
        );
    }
}
