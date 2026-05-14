use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _, Result};
use patchgate_core::failure_codes::KNOWN_FAILURE_CODES;
use serde::{Deserialize, Serialize};

const DEFAULT_CASE: &str = "default-worktree";
const DEFAULT_OUTPUT: &str = "target/benchmarks/patchgate_baseline.jsonl";
const DEFAULT_PROFILE_OUTPUT: &str = "target/benchmarks/scan_profile.json";
const DEFAULT_MAX_REGRESSION_PCT: f64 = 30.0;
const DEFAULT_SYNTHETIC_LINES: usize = 1;
const DEFAULT_SLO_AVAILABILITY_TARGET_PCT: u8 = 99;
const DEFAULT_SLO_P95_TARGET_MS: u32 = 1_500;
const DEFAULT_SLO_FALSE_POSITIVE_TARGET_PCT: u8 = 5;
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
enum BenchSubcommand {
    Record,
    Compare,
    Profile,
}

#[derive(Debug, Clone)]
enum OpsSubcommand {
    WeeklySummary,
    AuditReport,
    AuditDriftReport,
    SloReport,
    GaReadiness,
    VerifyV1Calibrate,
    CompatibilityReport,
    FreezeScoreboard,
    FreezeBoundary,
    ReplayNormalize,
    RollbackPacket,
    MigrationDrill,
    ShadowReview,
    FleetReview,
    RcReadiness,
    GaPacket,
    MigrationCompletion,
    DualRunDecommission,
    PostGaTelemetry,
    RetrospectiveCleanup,
    SiemHandoff,
}

#[derive(Debug, Clone)]
struct BenchOptions {
    subcommand: BenchSubcommand,
    case_name: String,
    repo: PathBuf,
    output: PathBuf,
    profile_output: PathBuf,
    report_output: Option<PathBuf>,
    max_regression_pct: f64,
    require_baseline: bool,
    append_on_pass: bool,
    synthetic_files: Option<usize>,
    synthetic_lines: usize,
}

#[derive(Debug, Clone)]
struct OpsOptions {
    subcommand: OpsSubcommand,
    metrics_input: PathBuf,
    audit_input: PathBuf,
    audit_v2_input: Option<PathBuf>,
    output: PathBuf,
    trend_output: Option<PathBuf>,
    replay_summary_input: Option<PathBuf>,
    provider_inputs: Vec<PathBuf>,
    webhook_envelope_inputs: Vec<PathBuf>,
    notification_envelope_inputs: Vec<PathBuf>,
    bundle_catalog_input: Option<PathBuf>,
    registry_input: Option<PathBuf>,
    exceptions_input: Option<PathBuf>,
    benchmark_input: Option<PathBuf>,
    security_review_input: Option<PathBuf>,
    contract_freeze_input: Option<PathBuf>,
    migration_drill_input: Option<PathBuf>,
    rollback_packet_input: Option<PathBuf>,
    fleet_review_input: Option<PathBuf>,
    rc_readiness_input: Option<PathBuf>,
    ga_packet_input: Option<PathBuf>,
    migration_completion_input: Option<PathBuf>,
    dual_run_decommission_input: Option<PathBuf>,
    post_ga_telemetry_input: Option<PathBuf>,
    policy_input: Option<PathBuf>,
    migration_guide_path: Option<PathBuf>,
    provider_rollout_path: Option<PathBuf>,
    candidate_checklist_path: Option<PathBuf>,
    freeze_boundary_path: Option<PathBuf>,
    ops_handbook_path: Option<PathBuf>,
    support_model_path: Option<PathBuf>,
    sunset_notice_path: Option<PathBuf>,
    phase201_backcast_path: Option<PathBuf>,
    go_no_go_path: Option<PathBuf>,
    cost_ceiling_minutes: Option<u64>,
    availability_target_pct: u8,
    p95_target_ms: u32,
    false_positive_target_pct: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BenchSample {
    case_name: String,
    unix_ts: u64,
    duration_ms: u128,
    changed_files: usize,
    score: u64,
    threshold: u64,
    fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchCompareReport {
    case_name: String,
    baseline_duration_ms: u128,
    current_duration_ms: u128,
    duration_delta_pct: f64,
    baseline_changed_files: usize,
    current_changed_files: usize,
    max_regression_pct: f64,
    regressed: bool,
    fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
struct SloReport {
    runs: usize,
    successful_runs: usize,
    gate_failures: usize,
    availability_pct: f64,
    p95_duration_ms: u128,
    gate_failure_rate_pct: f64,
    availability_target_pct: u8,
    p95_target_ms: u32,
    false_positive_target_pct: u8,
    availability_ok: bool,
    p95_ok: bool,
    false_positive_ok: bool,
    ready: bool,
}

#[derive(Debug, Clone, Serialize)]
struct VerifyV1Calibration {
    runs: usize,
    availability_pct: f64,
    gate_failure_rate_pct: f64,
    execution_error_rate_pct: f64,
    recommended_profile: String,
    next_actions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct MetricLogRecord {
    unix_ts: u64,
    repo: String,
    mode: String,
    scope: String,
    duration_ms: u128,
    score: Option<u8>,
    should_fail: Option<bool>,
    failure_code: Option<String>,
}

fn default_audit_v1_schema_version() -> u8 {
    1
}

fn default_audit_v1_format() -> String {
    "patchgate.audit.v1".to_string()
}

fn default_audit_v2_schema_version() -> u8 {
    2
}

fn default_audit_v2_format() -> String {
    "patchgate.audit.v2".to_string()
}

#[derive(Debug, Clone, Deserialize)]
struct AuditLogRecord {
    #[serde(default = "default_audit_v1_schema_version")]
    schema_version: u8,
    #[serde(default = "default_audit_v1_format")]
    audit_format: String,
    unix_ts: u64,
    actor: String,
    repo: String,
    mode: String,
    scope: String,
    result: String,
    failure_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditLogV2Record {
    #[serde(default = "default_audit_v2_schema_version")]
    schema_version: u8,
    #[serde(default = "default_audit_v2_format")]
    audit_format: String,
    emitted_at: u64,
    actor: String,
    repo: String,
    operation: AuditOperationV2,
    gate: AuditGateV2,
    failure: AuditFailureV2,
    diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditOperationV2 {
    target: String,
    mode: String,
    scope: String,
    result: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditGateV2 {
    score: Option<u8>,
    threshold: Option<u8>,
    changed_files: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditFailureV2 {
    code: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SiemHandoffRecord {
    schema_version: u8,
    event_kind: String,
    source_format: String,
    source_schema_version: u8,
    event_time_unix: u64,
    repo: String,
    actor: String,
    target: String,
    mode: String,
    scope: String,
    result: String,
    severity: String,
    score: Option<u8>,
    threshold: Option<u8>,
    changed_files: Option<usize>,
    failure_code: Option<String>,
    failure_category: Option<String>,
    diagnostic_count: usize,
    diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DeadLetterReplaySummaryRecord {
    input_path: String,
    transport_filter: Option<String>,
    selected_records: usize,
    successful_records: usize,
    dry_run_records: usize,
    failed_records: usize,
    skipped_records: usize,
    retained_records: usize,
    dry_run: bool,
    rewrite_input: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompatibilityPosture {
    StabilizeV1,
    HoldV11Line,
    StartV2Seed,
}

impl CompatibilityPosture {
    fn as_str(self) -> &'static str {
        match self {
            Self::StabilizeV1 => "stabilize-v1",
            Self::HoldV11Line => "hold-v1.1-line",
            Self::StartV2Seed => "start-v2-seed",
        }
    }
}

#[derive(Debug, Clone)]
struct CompatibilityAssessment {
    posture: CompatibilityPosture,
    slo: SloReport,
    calibration: VerifyV1Calibration,
    failure_codes: BTreeMap<String, usize>,
    audit_failures: usize,
    replay_evidence_present: bool,
    delivery_recovery_ready: bool,
    replay_summary: Option<DeadLetterReplaySummaryRecord>,
    next_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayEvidencePacket {
    schema_version: u8,
    status: String,
    selected_records: usize,
    successful_records: usize,
    failed_records: usize,
    skipped_records: usize,
    retained_records: usize,
    recovery_ratio_pct: f64,
    dry_run: bool,
    rewrite_input: bool,
}

#[derive(Debug, Clone)]
struct FreezeScoreboard {
    freeze_ready: bool,
    v2_seed_ready: bool,
    has_metrics: bool,
    has_audits: bool,
    ga_ready: bool,
    posture: CompatibilityPosture,
    recommended_profile: String,
    replay_evidence_present: bool,
    next_actions: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct FreezeScopeItem {
    candidate: &'static str,
    decision: &'static str,
    v11_boundary: &'static str,
    evidence_artifact: &'static str,
    release_gate: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct DeferredBacklogItem {
    item: &'static str,
    disposition: &'static str,
    owner_phase: &'static str,
    reconciliation: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct BreakingChangeBoundary {
    surface: &'static str,
    v11_contract: &'static str,
    v2_change_allowed: &'static str,
    guardrail: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct V2Option {
    option: &'static str,
    fit: &'static str,
    tradeoff: &'static str,
    decision: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct V2Risk {
    risk: &'static str,
    trigger: &'static str,
    mitigation: &'static str,
    gate: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct FreezeGateItem<'a> {
    gate: &'static str,
    required_signal: &'static str,
    artifact: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
struct FleetBundleCatalog {
    schema_version: u8,
    #[serde(default)]
    generated_at: String,
    #[serde(default)]
    segments: Vec<FleetSegmentPolicy>,
    #[serde(default)]
    retention_tiers: Vec<AuditRetentionTierPolicy>,
    #[serde(default)]
    rollout_waves: Vec<RolloutWavePolicy>,
    bundles: Vec<FleetBundleEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct FleetBundleEntry {
    repo: String,
    policy_bundle: String,
    wave: String,
    segment: String,
    #[serde(default)]
    providers: Vec<String>,
    #[serde(default)]
    required_provider_modes: Vec<String>,
    #[serde(default)]
    required_provider_capabilities: Vec<String>,
    #[serde(default)]
    retention_tier: String,
    #[serde(default)]
    cost_ceiling_minutes: Option<u64>,
    #[serde(default)]
    phase181_rc_candidate: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct FleetSegmentPolicy {
    segment: String,
    owner: String,
    cost_ceiling_minutes: u64,
    review_cadence: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditRetentionTierPolicy {
    tier: String,
    hot_days: u16,
    warm_days: u16,
    cold_days: u16,
}

#[derive(Debug, Clone, Deserialize)]
struct RolloutWavePolicy {
    wave: String,
    order: u16,
    max_parallel: u16,
    entry_gate: String,
    rollback_trigger: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginRegistryIndex {
    schema_version: u8,
    #[serde(default)]
    trusted_provenance: Vec<String>,
    plugins: Vec<PluginProvenanceEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginProvenanceEntry {
    plugin_id: String,
    version: String,
    owner: String,
    provenance: String,
    verified: bool,
    #[serde(default)]
    source_repo: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    attestation: String,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    sandbox_profile: String,
    #[serde(default)]
    allowed_segments: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GovernanceExceptionsPacket {
    schema_version: u8,
    #[serde(default)]
    reviewed_at: String,
    exceptions: Vec<GovernanceExceptionEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct GovernanceExceptionEntry {
    repo: String,
    kind: String,
    scope: String,
    approved_by: String,
    expires_at: String,
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    segment: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    review_cadence: String,
}

#[derive(Debug, Clone)]
struct AuditDriftSummary {
    unknown_failure_codes: BTreeMap<String, usize>,
    unknown_results: BTreeMap<String, usize>,
    schema_versions: BTreeMap<u8, usize>,
    formats: BTreeMap<String, usize>,
}

#[derive(Debug, Clone)]
struct ShadowAlignment {
    v1_events: usize,
    v2_events: usize,
    v1_failures: usize,
    v2_failures: usize,
    event_delta: isize,
    repo_set_match: bool,
    mode_set_match: bool,
    scope_set_match: bool,
    unique_targets: usize,
    unique_modes: usize,
    unique_scopes: usize,
    diagnostics_emitted: usize,
    aligned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AuditEventIdentity {
    repo: String,
    mode: String,
    scope: String,
    result: String,
    failure_code: Option<String>,
}

#[derive(Debug, Clone)]
struct ProviderArtifactSummary {
    repo: String,
    provider: String,
    schema_mode: String,
    capabilities: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct FleetRepoRow {
    repo: String,
    posture: String,
    runs: usize,
    audit_events_v1: usize,
    audit_events_v2: usize,
    gate_failures: usize,
    average_score: f64,
    ci_minutes: f64,
    segment: String,
    wave: String,
    retention_tier: String,
    repo_cost_ceiling_minutes: Option<u64>,
    repo_cost_ok: bool,
}

#[derive(Debug, Clone)]
struct ProviderNegotiationStatus {
    repo: String,
    required_providers: Vec<String>,
    provided_providers: Vec<String>,
    required_modes: Vec<String>,
    required_capabilities: Vec<String>,
    provided_modes: Vec<String>,
    provided_capabilities: Vec<String>,
    ready: bool,
}

#[derive(Debug, Clone)]
struct SegmentCostStatus {
    segment: String,
    actual_minutes: f64,
    ceiling_minutes: Option<u64>,
    ok: bool,
}

#[derive(Debug, Clone)]
struct ExceptionGovernanceStatus {
    repo: String,
    kind: String,
    scope: String,
    approved_by: String,
    ticket: String,
    owner: String,
    segment: String,
    status: String,
    review_cadence: String,
    expires_at: String,
    expired: Option<bool>,
    valid: bool,
}

#[derive(Debug, Clone)]
struct DeliveryBridgeArtifactSummary {
    kind: String,
    path: String,
    valid: bool,
    bridge_mode: String,
}

#[derive(Debug, Clone)]
struct ReleasePolicySummary {
    lts_active: bool,
    lts_branch: String,
    security_sla_hours: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationDrillReport {
    schema_version: u8,
    generated_at: String,
    drill_id: String,
    repos_total: usize,
    repos_attempted: usize,
    repos_succeeded: usize,
    repos_failed: usize,
    provider_artifacts_checked: usize,
    audit_events_replayed: usize,
    rollback_rehearsed: bool,
    dry_run: bool,
    #[serde(default)]
    owners: Vec<String>,
    #[serde(default)]
    blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RollbackPacket {
    schema_version: u8,
    generated_at: String,
    owner: String,
    #[serde(default)]
    triggers: Vec<String>,
    restore: RollbackRestorePlan,
    verification: RollbackVerification,
    #[serde(default)]
    retained_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RollbackRestorePlan {
    bridge_mode: String,
    generic_schema: String,
    v1_audit_authoritative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RollbackVerification {
    dry_run_completed: bool,
    dual_run_reversible: bool,
    provider_v1_verified: bool,
    audit_v2_retained: bool,
}

#[derive(Debug, Clone)]
struct AuditExportV2Validation {
    ready: bool,
    diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FailureEventKey {
    code: String,
    unix_ts: u64,
    repo: String,
    mode: String,
    scope: String,
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Ok(());
    };

    match command.to_string_lossy().as_ref() {
        "bench" => {
            let options = parse_bench_options(args.collect())?;
            match options.subcommand {
                BenchSubcommand::Record => {
                    let sample = run_bench_sample(&options)?;
                    append_sample(&options.output, &sample)?;
                    println!(
                        "recorded benchmark: case={} duration_ms={} changed_files={} output={}",
                        sample.case_name,
                        sample.duration_ms,
                        sample.changed_files,
                        options.output.display()
                    );
                }
                BenchSubcommand::Compare => {
                    let sample = run_bench_sample(&options)?;
                    let previous = load_latest_sample(&options.output, &sample.case_name)?;
                    if let Some(prev) = previous {
                        validate_workload_identity(&prev, &sample)?;
                        print_comparison(&prev, &sample);
                        let regressed =
                            is_duration_regressed(&prev, &sample, options.max_regression_pct);
                        if let Some(path) = options.report_output.as_ref() {
                            write_compare_report(
                                path,
                                &prev,
                                &sample,
                                options.max_regression_pct,
                                regressed,
                            )?;
                        }
                        if regressed {
                            bail!(
                                "benchmark regression: duration exceeded {:.1}% threshold",
                                options.max_regression_pct
                            );
                        }
                        if options.append_on_pass {
                            append_sample(&options.output, &sample)?;
                        }
                    } else {
                        if options.require_baseline {
                            bail!(
                                "no baseline found for case `{}` in {}",
                                sample.case_name,
                                options.output.display()
                            );
                        }
                        println!(
                            "no baseline found for case `{}` in {}. recording first sample.",
                            sample.case_name,
                            options.output.display()
                        );
                        append_sample(&options.output, &sample)?;
                    }
                }
                BenchSubcommand::Profile => {
                    run_profile_sample(&options)?;
                }
            }
        }
        "ops" => {
            let options = parse_ops_options(args.collect())?;
            run_ops(&options)?;
        }
        other => bail!("unsupported command `{other}`"),
    }

    Ok(())
}

fn print_help() {
    eprintln!(
        concat!(
            "usage:\n",
            "  cargo run -p xtask -- bench record [--case NAME] [--repo PATH] [--output PATH] [--synthetic-files N] [--synthetic-lines N]\n",
            "  cargo run -p xtask -- bench compare [--case NAME] [--repo PATH] [--output PATH] [--max-regression-pct N] [--require-baseline] [--append-on-pass] [--report-output PATH] [--synthetic-files N] [--synthetic-lines N]\n",
            "  cargo run -p xtask -- bench profile [--repo PATH] [--profile-output PATH] [--synthetic-files N] [--synthetic-lines N]\n",
            "  cargo run -p xtask -- ops weekly-summary --metrics-input PATH --audit-input PATH --output PATH [--trend-output PATH]\n",
            "  cargo run -p xtask -- ops audit-report --audit-input PATH --output PATH\n",
            "  cargo run -p xtask -- ops audit-drift-report --audit-input PATH [--audit-v2-input PATH] --output PATH\n",
            "  cargo run -p xtask -- ops siem-handoff --audit-v2-input PATH --output PATH\n",
            "  cargo run -p xtask -- ops slo-report --metrics-input PATH --output PATH [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n",
            "  cargo run -p xtask -- ops ga-readiness --metrics-input PATH --audit-input PATH --output PATH [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n",
            "  cargo run -p xtask -- ops verify-v1-calibrate --metrics-input PATH --output PATH\n",
            "  cargo run -p xtask -- ops compatibility-report --metrics-input PATH --audit-input PATH --output PATH [--replay-summary-input PATH] [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n",
            "  cargo run -p xtask -- ops freeze-scoreboard --metrics-input PATH --audit-input PATH --output PATH [--replay-summary-input PATH] [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n",
            "  cargo run -p xtask -- ops freeze-boundary --output PATH\n",
            "  cargo run -p xtask -- ops replay-normalize --replay-summary-input PATH --output PATH\n",
            "  cargo run -p xtask -- ops rollback-packet --audit-input PATH --audit-v2-input PATH --output PATH [--provider-input PATH ...]\n",
            "  cargo run -p xtask -- ops migration-drill --metrics-input PATH --audit-input PATH --audit-v2-input PATH --rollback-packet-input PATH --output PATH [--provider-input PATH ...]\n",
            "  cargo run -p xtask -- ops shadow-review --audit-input PATH --audit-v2-input PATH --output PATH [--provider-input PATH ...] [--webhook-envelope-input PATH ...] [--notification-envelope-input PATH ...]\n",
            "  cargo run -p xtask -- ops fleet-review --metrics-input PATH --audit-input PATH --output PATH [--audit-v2-input PATH] [--provider-input PATH ...] [--bundle-catalog-input PATH] [--registry-input PATH] [--exceptions-input PATH] [--cost-ceiling-minutes N]\n",
            "  cargo run -p xtask -- ops rc-readiness --metrics-input PATH --audit-input PATH --audit-v2-input PATH --output PATH [--replay-summary-input PATH] [--provider-input PATH ...] [--benchmark-input PATH] [--security-review-input PATH] [--contract-freeze-input PATH] [--migration-drill-input PATH] [--rollback-packet-input PATH] [--fleet-review-input PATH] [--migration-guide-path PATH] [--provider-rollout-path PATH] [--candidate-checklist-path PATH] [--freeze-boundary-path PATH] [--sunset-notice-path PATH]\n",
            "  cargo run -p xtask -- ops ga-packet --metrics-input PATH --audit-input PATH --audit-v2-input PATH --replay-summary-input PATH --policy-input PATH --rc-readiness-input PATH --go-no-go-path PATH --fleet-review-input PATH --migration-guide-path PATH --candidate-checklist-path PATH --ops-handbook-path PATH --support-model-path PATH --sunset-notice-path PATH --phase201-backcast-path PATH --output PATH\n",
            "  cargo run -p xtask -- ops migration-completion --metrics-input PATH --audit-input PATH --audit-v2-input PATH --provider-input PATH ... --fleet-review-input PATH --rc-readiness-input PATH --migration-drill-input PATH --migration-guide-path PATH --candidate-checklist-path PATH --output PATH\n",
            "  cargo run -p xtask -- ops dual-run-decommission --audit-input PATH --audit-v2-input PATH --replay-summary-input PATH --provider-input PATH ... --rollback-packet-input PATH --migration-drill-input PATH --rc-readiness-input PATH --sunset-notice-path PATH --support-model-path PATH --output PATH\n",
            "  cargo run -p xtask -- ops post-ga-telemetry --metrics-input PATH --audit-input PATH --audit-v2-input PATH --replay-summary-input PATH --fleet-review-input PATH --ga-packet-input PATH --support-model-path PATH --output PATH\n",
            "  cargo run -p xtask -- ops retrospective-cleanup --migration-completion-input PATH --dual-run-decommission-input PATH --post-ga-telemetry-input PATH --ops-handbook-path PATH --support-model-path PATH --sunset-notice-path PATH --phase201-backcast-path PATH --output PATH",
        )
    );
}

fn parse_bench_options(args: Vec<OsString>) -> Result<BenchOptions> {
    let mut iter = args.into_iter();
    let Some(sub) = iter.next() else {
        bail!("missing bench subcommand (`record` or `compare`)");
    };
    let subcommand = match sub.to_string_lossy().as_ref() {
        "record" => BenchSubcommand::Record,
        "compare" => BenchSubcommand::Compare,
        "profile" => BenchSubcommand::Profile,
        other => bail!("unsupported bench subcommand `{other}`"),
    };

    let mut case_name = DEFAULT_CASE.to_string();
    let mut repo = std::env::current_dir().context("failed to get current directory")?;
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut profile_output = PathBuf::from(DEFAULT_PROFILE_OUTPUT);
    let mut report_output = None;
    let mut max_regression_pct = DEFAULT_MAX_REGRESSION_PCT;
    let mut require_baseline = false;
    let mut append_on_pass = false;
    let mut synthetic_files = None;
    let mut synthetic_lines = DEFAULT_SYNTHETIC_LINES;

    while let Some(flag) = iter.next() {
        match flag.to_string_lossy().as_ref() {
            "--case" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --case"))?;
                case_name = value.to_string_lossy().to_string();
            }
            "--repo" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --repo"))?;
                repo = PathBuf::from(value);
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --output"))?;
                output = PathBuf::from(value);
            }
            "--max-regression-pct" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --max-regression-pct"))?;
                max_regression_pct = value
                    .to_string_lossy()
                    .parse::<f64>()
                    .context("failed to parse --max-regression-pct")?;
            }
            "--require-baseline" => {
                require_baseline = true;
            }
            "--append-on-pass" => {
                append_on_pass = true;
            }
            "--profile-output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --profile-output"))?;
                profile_output = PathBuf::from(value);
            }
            "--report-output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --report-output"))?;
                report_output = Some(PathBuf::from(value));
            }
            "--synthetic-files" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --synthetic-files"))?;
                synthetic_files = Some(
                    value
                        .to_string_lossy()
                        .parse::<usize>()
                        .context("failed to parse --synthetic-files")?,
                );
            }
            "--synthetic-lines" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --synthetic-lines"))?;
                synthetic_lines = value
                    .to_string_lossy()
                    .parse::<usize>()
                    .context("failed to parse --synthetic-lines")?;
            }
            other => bail!("unsupported flag `{other}`"),
        }
    }

    Ok(BenchOptions {
        subcommand,
        case_name,
        repo,
        output,
        profile_output,
        report_output,
        max_regression_pct,
        require_baseline,
        append_on_pass,
        synthetic_files,
        synthetic_lines,
    })
}

fn parse_ops_options(args: Vec<OsString>) -> Result<OpsOptions> {
    let mut iter = args.into_iter();
    let Some(sub) = iter.next() else {
        bail!("missing ops subcommand (`weekly-summary`, `audit-report`, `audit-drift-report`, `siem-handoff`, `slo-report`, `ga-readiness`, `verify-v1-calibrate`, `compatibility-report`, `freeze-scoreboard`, `freeze-boundary`, `replay-normalize`, `rollback-packet`, `migration-drill`, `shadow-review`, `fleet-review`, `rc-readiness`, `ga-packet`, `migration-completion`, `dual-run-decommission`, `post-ga-telemetry`, or `retrospective-cleanup`)");
    };
    let subcommand = match sub.to_string_lossy().as_ref() {
        "weekly-summary" => OpsSubcommand::WeeklySummary,
        "audit-report" => OpsSubcommand::AuditReport,
        "audit-drift-report" => OpsSubcommand::AuditDriftReport,
        "siem-handoff" => OpsSubcommand::SiemHandoff,
        "slo-report" => OpsSubcommand::SloReport,
        "ga-readiness" => OpsSubcommand::GaReadiness,
        "verify-v1-calibrate" => OpsSubcommand::VerifyV1Calibrate,
        "compatibility-report" => OpsSubcommand::CompatibilityReport,
        "freeze-scoreboard" => OpsSubcommand::FreezeScoreboard,
        "freeze-boundary" => OpsSubcommand::FreezeBoundary,
        "replay-normalize" => OpsSubcommand::ReplayNormalize,
        "rollback-packet" => OpsSubcommand::RollbackPacket,
        "migration-drill" => OpsSubcommand::MigrationDrill,
        "shadow-review" => OpsSubcommand::ShadowReview,
        "fleet-review" => OpsSubcommand::FleetReview,
        "rc-readiness" => OpsSubcommand::RcReadiness,
        "ga-packet" => OpsSubcommand::GaPacket,
        "migration-completion" => OpsSubcommand::MigrationCompletion,
        "dual-run-decommission" => OpsSubcommand::DualRunDecommission,
        "post-ga-telemetry" => OpsSubcommand::PostGaTelemetry,
        "retrospective-cleanup" => OpsSubcommand::RetrospectiveCleanup,
        other => bail!("unsupported ops subcommand `{other}`"),
    };
    let mut metrics_input = PathBuf::from("artifacts/scan-metrics.jsonl");
    let mut audit_input = PathBuf::from("artifacts/scan-audit.jsonl");
    let mut audit_v2_input = None;
    let mut output = PathBuf::from("artifacts/ops-report.md");
    let mut trend_output = None;
    let mut replay_summary_input = None;
    let mut provider_inputs = Vec::new();
    let mut webhook_envelope_inputs = Vec::new();
    let mut notification_envelope_inputs = Vec::new();
    let mut bundle_catalog_input = None;
    let mut registry_input = None;
    let mut exceptions_input = None;
    let mut benchmark_input = None;
    let mut security_review_input = None;
    let mut contract_freeze_input = None;
    let mut migration_drill_input = None;
    let mut rollback_packet_input = None;
    let mut fleet_review_input = None;
    let mut rc_readiness_input = None;
    let mut ga_packet_input = None;
    let mut migration_completion_input = None;
    let mut dual_run_decommission_input = None;
    let mut post_ga_telemetry_input = None;
    let mut policy_input = None;
    let mut migration_guide_path = None;
    let mut provider_rollout_path = None;
    let mut candidate_checklist_path = None;
    let mut freeze_boundary_path = None;
    let mut ops_handbook_path = None;
    let mut support_model_path = None;
    let mut sunset_notice_path = None;
    let mut phase201_backcast_path = None;
    let mut go_no_go_path = None;
    let mut cost_ceiling_minutes = None;
    let mut availability_target_pct = DEFAULT_SLO_AVAILABILITY_TARGET_PCT;
    let mut p95_target_ms = DEFAULT_SLO_P95_TARGET_MS;
    let mut false_positive_target_pct = DEFAULT_SLO_FALSE_POSITIVE_TARGET_PCT;

    while let Some(flag) = iter.next() {
        match flag.to_string_lossy().as_ref() {
            "--metrics-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --metrics-input"))?;
                metrics_input = PathBuf::from(value);
            }
            "--audit-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --audit-input"))?;
                audit_input = PathBuf::from(value);
            }
            "--audit-v2-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --audit-v2-input"))?;
                audit_v2_input = Some(PathBuf::from(value));
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --output"))?;
                output = PathBuf::from(value);
            }
            "--trend-output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --trend-output"))?;
                trend_output = Some(PathBuf::from(value));
            }
            "--replay-summary-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --replay-summary-input"))?;
                replay_summary_input = Some(PathBuf::from(value));
            }
            "--provider-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --provider-input"))?;
                provider_inputs.push(PathBuf::from(value));
            }
            "--webhook-envelope-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --webhook-envelope-input"))?;
                webhook_envelope_inputs.push(PathBuf::from(value));
            }
            "--notification-envelope-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --notification-envelope-input"))?;
                notification_envelope_inputs.push(PathBuf::from(value));
            }
            "--bundle-catalog-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --bundle-catalog-input"))?;
                bundle_catalog_input = Some(PathBuf::from(value));
            }
            "--registry-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --registry-input"))?;
                registry_input = Some(PathBuf::from(value));
            }
            "--exceptions-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --exceptions-input"))?;
                exceptions_input = Some(PathBuf::from(value));
            }
            "--benchmark-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --benchmark-input"))?;
                benchmark_input = Some(PathBuf::from(value));
            }
            "--security-review-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --security-review-input"))?;
                security_review_input = Some(PathBuf::from(value));
            }
            "--contract-freeze-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --contract-freeze-input"))?;
                contract_freeze_input = Some(PathBuf::from(value));
            }
            "--migration-drill-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --migration-drill-input"))?;
                migration_drill_input = Some(PathBuf::from(value));
            }
            "--rollback-packet-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --rollback-packet-input"))?;
                rollback_packet_input = Some(PathBuf::from(value));
            }
            "--fleet-review-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --fleet-review-input"))?;
                fleet_review_input = Some(PathBuf::from(value));
            }
            "--rc-readiness-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --rc-readiness-input"))?;
                rc_readiness_input = Some(PathBuf::from(value));
            }
            "--ga-packet-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --ga-packet-input"))?;
                ga_packet_input = Some(PathBuf::from(value));
            }
            "--migration-completion-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --migration-completion-input"))?;
                migration_completion_input = Some(PathBuf::from(value));
            }
            "--dual-run-decommission-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --dual-run-decommission-input"))?;
                dual_run_decommission_input = Some(PathBuf::from(value));
            }
            "--post-ga-telemetry-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --post-ga-telemetry-input"))?;
                post_ga_telemetry_input = Some(PathBuf::from(value));
            }
            "--policy-input" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --policy-input"))?;
                policy_input = Some(PathBuf::from(value));
            }
            "--migration-guide-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --migration-guide-path"))?;
                migration_guide_path = Some(PathBuf::from(value));
            }
            "--provider-rollout-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --provider-rollout-path"))?;
                provider_rollout_path = Some(PathBuf::from(value));
            }
            "--candidate-checklist-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --candidate-checklist-path"))?;
                candidate_checklist_path = Some(PathBuf::from(value));
            }
            "--freeze-boundary-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --freeze-boundary-path"))?;
                freeze_boundary_path = Some(PathBuf::from(value));
            }
            "--ops-handbook-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --ops-handbook-path"))?;
                ops_handbook_path = Some(PathBuf::from(value));
            }
            "--support-model-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --support-model-path"))?;
                support_model_path = Some(PathBuf::from(value));
            }
            "--sunset-notice-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --sunset-notice-path"))?;
                sunset_notice_path = Some(PathBuf::from(value));
            }
            "--phase201-backcast-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --phase201-backcast-path"))?;
                phase201_backcast_path = Some(PathBuf::from(value));
            }
            "--go-no-go-path" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --go-no-go-path"))?;
                go_no_go_path = Some(PathBuf::from(value));
            }
            "--cost-ceiling-minutes" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --cost-ceiling-minutes"))?;
                cost_ceiling_minutes = Some(
                    value
                        .to_string_lossy()
                        .parse::<u64>()
                        .context("failed to parse --cost-ceiling-minutes")?,
                );
            }
            "--availability-target-pct" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --availability-target-pct"))?;
                availability_target_pct = value
                    .to_string_lossy()
                    .parse::<u8>()
                    .context("failed to parse --availability-target-pct")?;
            }
            "--p95-target-ms" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --p95-target-ms"))?;
                p95_target_ms = value
                    .to_string_lossy()
                    .parse::<u32>()
                    .context("failed to parse --p95-target-ms")?;
            }
            "--false-positive-target-pct" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --false-positive-target-pct"))?;
                false_positive_target_pct = value
                    .to_string_lossy()
                    .parse::<u8>()
                    .context("failed to parse --false-positive-target-pct")?;
            }
            other => bail!("unsupported flag `{other}`"),
        }
    }

    Ok(OpsOptions {
        subcommand,
        metrics_input,
        audit_input,
        audit_v2_input,
        output,
        trend_output,
        replay_summary_input,
        provider_inputs,
        webhook_envelope_inputs,
        notification_envelope_inputs,
        bundle_catalog_input,
        registry_input,
        exceptions_input,
        benchmark_input,
        security_review_input,
        contract_freeze_input,
        migration_drill_input,
        rollback_packet_input,
        fleet_review_input,
        rc_readiness_input,
        ga_packet_input,
        migration_completion_input,
        dual_run_decommission_input,
        post_ga_telemetry_input,
        policy_input,
        migration_guide_path,
        provider_rollout_path,
        candidate_checklist_path,
        freeze_boundary_path,
        ops_handbook_path,
        support_model_path,
        sunset_notice_path,
        phase201_backcast_path,
        go_no_go_path,
        cost_ceiling_minutes,
        availability_target_pct,
        p95_target_ms,
        false_positive_target_pct,
    })
}

fn run_ops(options: &OpsOptions) -> Result<()> {
    match options.subcommand {
        OpsSubcommand::WeeklySummary => run_weekly_summary(options),
        OpsSubcommand::AuditReport => run_audit_report(options),
        OpsSubcommand::AuditDriftReport => run_audit_drift_report(options),
        OpsSubcommand::SiemHandoff => run_siem_handoff(options),
        OpsSubcommand::SloReport => run_slo_report(options),
        OpsSubcommand::GaReadiness => run_ga_readiness(options),
        OpsSubcommand::VerifyV1Calibrate => run_verify_v1_calibrate(options),
        OpsSubcommand::CompatibilityReport => run_compatibility_report(options),
        OpsSubcommand::FreezeScoreboard => run_freeze_scoreboard(options),
        OpsSubcommand::FreezeBoundary => run_freeze_boundary(options),
        OpsSubcommand::ReplayNormalize => run_replay_normalize(options),
        OpsSubcommand::RollbackPacket => run_rollback_packet(options),
        OpsSubcommand::MigrationDrill => run_migration_drill(options),
        OpsSubcommand::ShadowReview => run_shadow_review(options),
        OpsSubcommand::FleetReview => run_fleet_review(options),
        OpsSubcommand::RcReadiness => run_rc_readiness(options),
        OpsSubcommand::GaPacket => run_ga_packet(options),
        OpsSubcommand::MigrationCompletion => run_migration_completion(options),
        OpsSubcommand::DualRunDecommission => run_dual_run_decommission(options),
        OpsSubcommand::PostGaTelemetry => run_post_ga_telemetry(options),
        OpsSubcommand::RetrospectiveCleanup => run_retrospective_cleanup(options),
    }
}

fn run_bench_sample(options: &BenchOptions) -> Result<BenchSample> {
    if let Some(files) = options.synthetic_files {
        return run_synthetic_bench_sample(&options.case_name, files, options.synthetic_lines);
    }
    run_repo_bench_sample(&options.repo, &options.case_name)
}

fn run_synthetic_bench_sample(
    case_name: &str,
    files: usize,
    extra_lines: usize,
) -> Result<BenchSample> {
    let repo = SyntheticRepo::create(files, extra_lines)?;
    run_repo_bench_sample(repo.path(), case_name)
}

fn run_repo_bench_sample(repo: &Path, case_name: &str) -> Result<BenchSample> {
    let changed_files = changed_file_count(repo)?;
    let report = run_patchgate_scan(repo)?;
    let unix_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();

    Ok(BenchSample {
        case_name: case_name.to_string(),
        unix_ts,
        duration_ms: report.duration_ms,
        changed_files,
        score: report.score,
        threshold: report.threshold,
        fingerprint: report.fingerprint,
    })
}

fn run_profile_sample(options: &BenchOptions) -> Result<()> {
    if let Some(files) = options.synthetic_files {
        let repo = SyntheticRepo::create(files, options.synthetic_lines)?;
        run_patchgate_scan_with_profile(repo.path(), &options.profile_output)?;
    } else {
        run_patchgate_scan_with_profile(&options.repo, &options.profile_output)?;
    }
    println!("scan profile written: {}", options.profile_output.display());
    Ok(())
}

fn run_weekly_summary(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;

    let runs = metrics.len();
    let gate_failures = metrics
        .iter()
        .filter(|m| m.should_fail.unwrap_or(false))
        .count();
    let execution_errors = metrics.iter().filter(|m| m.failure_code.is_some()).count();
    let avg_duration = average_duration_for_summary(&metrics);
    let scored: Vec<u8> = metrics.iter().filter_map(|m| m.score).collect();
    let avg_score = if scored.is_empty() {
        0.0
    } else {
        scored.iter().map(|s| *s as f64).sum::<f64>() / scored.len() as f64
    };

    let failure_codes = aggregate_failure_code_counts(&metrics, &audits);

    let mut md = String::new();
    md.push_str("# Weekly Operations Summary\n\n");
    md.push_str(&format!("- runs: {runs}\n"));
    md.push_str(&format!("- gate_failures: {gate_failures}\n"));
    md.push_str(&format!("- execution_errors: {execution_errors}\n"));
    md.push_str(&format!("- avg_duration_ms: {:.2}\n", avg_duration));
    md.push_str(&format!("- avg_score: {:.2}\n", avg_score));
    md.push_str(&format!("- audit_events: {}\n\n", audits.len()));
    md.push_str("## Failure Codes\n");
    if failure_codes.is_empty() {
        md.push_str("- none\n");
    } else {
        for (code, count) in failure_codes {
            md.push_str(&format!("- {code}: {count}\n"));
        }
    }

    write_output(&options.output, md.as_str())?;

    if let Some(path) = options.trend_output.as_ref() {
        let mut by_key = BTreeMap::<String, usize>::new();
        for row in &metrics {
            let day = row.unix_ts / 86_400;
            let key = format!(
                "day:{day}|repo:{}|scope:{}|mode:{}",
                row.repo, row.scope, row.mode
            );
            *by_key.entry(key).or_insert(0) += 1;
        }
        write_output(path, serde_json::to_string_pretty(&by_key)?.as_str())?;
    }

    println!("weekly summary written: {}", options.output.display());
    Ok(())
}

fn average_duration_for_summary(metrics: &[MetricLogRecord]) -> f64 {
    let duration_samples: Vec<&MetricLogRecord> = metrics
        .iter()
        .filter(|m| m.failure_code.is_none())
        .collect();
    if duration_samples.is_empty() {
        0.0
    } else {
        duration_samples
            .iter()
            .map(|m| m.duration_ms as f64)
            .sum::<f64>()
            / duration_samples.len() as f64
    }
}

fn metric_failure_key(row: &MetricLogRecord) -> Option<FailureEventKey> {
    row.failure_code.as_ref().map(|code| FailureEventKey {
        code: code.clone(),
        unix_ts: row.unix_ts,
        repo: row.repo.clone(),
        mode: row.mode.clone(),
        scope: row.scope.clone(),
    })
}

fn audit_failure_key(row: &AuditLogRecord) -> Option<FailureEventKey> {
    row.failure_code.as_ref().map(|code| FailureEventKey {
        code: code.clone(),
        unix_ts: row.unix_ts,
        repo: row.repo.clone(),
        mode: row.mode.clone(),
        scope: row.scope.clone(),
    })
}

fn aggregate_failure_code_counts(
    metrics: &[MetricLogRecord],
    audits: &[AuditLogRecord],
) -> BTreeMap<String, usize> {
    let mut metric_counts = BTreeMap::<FailureEventKey, usize>::new();
    for row in metrics {
        if let Some(key) = metric_failure_key(row) {
            *metric_counts.entry(key).or_insert(0) += 1;
        }
    }

    let mut audit_counts = BTreeMap::<FailureEventKey, usize>::new();
    for row in audits {
        if let Some(key) = audit_failure_key(row) {
            *audit_counts.entry(key).or_insert(0) += 1;
        }
    }

    let mut failure_codes = BTreeMap::<String, usize>::new();
    for (key, metric_count) in &metric_counts {
        let audit_count = audit_counts.get(key).copied().unwrap_or(0);
        *failure_codes.entry(key.code.clone()).or_insert(0) += (*metric_count).max(audit_count);
    }
    for (key, audit_count) in &audit_counts {
        if !metric_counts.contains_key(key) {
            *failure_codes.entry(key.code.clone()).or_insert(0) += *audit_count;
        }
    }

    failure_codes
}

fn is_known_failure_code(code: &str) -> bool {
    KNOWN_FAILURE_CODES.contains(&code)
}

fn run_audit_report(options: &OpsOptions) -> Result<()> {
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let mut by_result = BTreeMap::<String, usize>::new();
    let mut by_actor = BTreeMap::<String, usize>::new();
    let mut by_failure = BTreeMap::<String, usize>::new();

    for row in &audits {
        *by_result.entry(row.result.clone()).or_insert(0) += 1;
        *by_actor.entry(row.actor.clone()).or_insert(0) += 1;
        if let Some(code) = row.failure_code.as_ref() {
            *by_failure.entry(code.clone()).or_insert(0) += 1;
        }
    }

    let mut md = String::new();
    md.push_str("# Audit Report\n\n");
    md.push_str(&format!("- total_events: {}\n", audits.len()));
    md.push_str("## Result Counts\n");
    if by_result.is_empty() {
        md.push_str("- none\n");
    } else {
        for (result, count) in by_result {
            md.push_str(&format!("- {result}: {count}\n"));
        }
    }
    md.push_str("\n## Failure Codes\n");
    if by_failure.is_empty() {
        md.push_str("- none\n");
    } else {
        for (code, count) in by_failure {
            md.push_str(&format!("- {code}: {count}\n"));
        }
    }
    md.push_str("\n## Actors\n");
    if by_actor.is_empty() {
        md.push_str("- none\n");
    } else {
        for (actor, count) in by_actor {
            md.push_str(&format!("- {actor}: {count}\n"));
        }
    }

    write_output(&options.output, md.as_str())?;
    println!("audit report written: {}", options.output.display());
    Ok(())
}

fn run_audit_drift_report(options: &OpsOptions) -> Result<()> {
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audits_v2 = options
        .audit_v2_input
        .as_deref()
        .map(load_jsonl_records::<AuditLogV2Record>)
        .transpose()?
        .unwrap_or_default();
    let drift = build_combined_audit_drift_summary(&audits, &audits_v2);

    let mut md = String::new();
    md.push_str("# Audit Drift Report\n\n");
    md.push_str(&format!(
        "- audit_events: {}\n",
        audits.len() + audits_v2.len()
    ));
    md.push_str(&format!("- audit_v1_events: {}\n", audits.len()));
    md.push_str(&format!("- audit_v2_events: {}\n", audits_v2.len()));
    md.push_str(&format!(
        "- unknown_failure_codes: {}\n",
        drift.unknown_failure_codes.values().copied().sum::<usize>()
    ));
    md.push_str(&format!(
        "- unknown_results: {}\n\n",
        drift.unknown_results.values().copied().sum::<usize>()
    ));

    md.push_str("## Schema Versions\n");
    if drift.schema_versions.is_empty() {
        md.push_str("- none\n");
    } else {
        for (version, count) in &drift.schema_versions {
            md.push_str(&format!("- v{version}: {count}\n"));
        }
    }

    md.push_str("\n## Formats\n");
    if drift.formats.is_empty() {
        md.push_str("- none\n");
    } else {
        for (format, count) in &drift.formats {
            md.push_str(&format!("- {format}: {count}\n"));
        }
    }

    md.push_str("\n## Unknown Failure Codes\n");
    if drift.unknown_failure_codes.is_empty() {
        md.push_str("- none\n");
    } else {
        for (code, count) in &drift.unknown_failure_codes {
            md.push_str(&format!("- {code}: {count}\n"));
        }
    }

    md.push_str("\n## Unknown Results\n");
    if drift.unknown_results.is_empty() {
        md.push_str("- none\n");
    } else {
        for (result, count) in &drift.unknown_results {
            md.push_str(&format!("- {result}: {count}\n"));
        }
    }

    write_output(&options.output, md.as_str())?;
    println!("audit drift report written: {}", options.output.display());
    Ok(())
}

fn run_siem_handoff(options: &OpsOptions) -> Result<()> {
    let audit_v2_input = options
        .audit_v2_input
        .as_deref()
        .ok_or_else(|| anyhow!("siem-handoff requires --audit-v2-input"))?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    validate_siem_handoff_input(&audits_v2)?;
    let records = build_siem_handoff_records(&audits_v2);
    write_jsonl_output(&options.output, &records)?;
    println!(
        "siem handoff written: {} (events={})",
        options.output.display(),
        records.len()
    );
    Ok(())
}

fn validate_siem_handoff_input(audits_v2: &[AuditLogV2Record]) -> Result<()> {
    for (idx, row) in audits_v2.iter().enumerate() {
        let row_number = idx + 1;
        if !(2..=10).contains(&row.schema_version) {
            bail!(
                "siem-handoff input row {row_number} has unsupported audit v2 schema_version {}",
                row.schema_version
            );
        }
        if row.audit_format != "patchgate.audit.v2" {
            bail!(
                "siem-handoff input row {row_number} has unsupported audit_format `{}`",
                row.audit_format
            );
        }
        if !matches!(
            row.operation.result.as_str(),
            "pass" | "gate_fail" | "error"
        ) {
            bail!(
                "siem-handoff input row {row_number} has unsupported result `{}`",
                row.operation.result
            );
        }
        if let Some(code) = row.failure.code.as_ref() {
            if !is_known_failure_code(code) {
                bail!("siem-handoff input row {row_number} has unknown failure_code `{code}`");
            }
        }
        for (field, value) in [
            ("actor", row.actor.as_str()),
            ("repo", row.repo.as_str()),
            ("operation.target", row.operation.target.as_str()),
            ("operation.mode", row.operation.mode.as_str()),
            ("operation.scope", row.operation.scope.as_str()),
        ] {
            if value.trim().is_empty() {
                bail!("siem-handoff input row {row_number} has empty {field}");
            }
        }
    }
    Ok(())
}

fn build_siem_handoff_records(audits_v2: &[AuditLogV2Record]) -> Vec<SiemHandoffRecord> {
    audits_v2.iter().map(siem_handoff_record).collect()
}

fn siem_handoff_record(row: &AuditLogV2Record) -> SiemHandoffRecord {
    SiemHandoffRecord {
        schema_version: 1,
        event_kind: "quality_gate.audit".to_string(),
        source_format: row.audit_format.clone(),
        source_schema_version: row.schema_version,
        event_time_unix: row.emitted_at,
        repo: row.repo.clone(),
        actor: row.actor.clone(),
        target: row.operation.target.clone(),
        mode: row.operation.mode.clone(),
        scope: row.operation.scope.clone(),
        result: row.operation.result.clone(),
        severity: siem_severity(row).to_string(),
        score: row.gate.score,
        threshold: row.gate.threshold,
        changed_files: row.gate.changed_files,
        failure_code: row.failure.code.clone(),
        failure_category: row.failure.category.clone(),
        diagnostic_count: row.diagnostics.len(),
        diagnostics: row.diagnostics.clone(),
    }
}

fn siem_severity(row: &AuditLogV2Record) -> &'static str {
    if row.failure.code.is_some() || row.operation.result == "error" {
        "error"
    } else if row.operation.result == "gate_fail" {
        "warning"
    } else {
        "info"
    }
}

fn run_slo_report(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let report = build_slo_report(
        &metrics,
        options.availability_target_pct,
        options.p95_target_ms,
        options.false_positive_target_pct,
    );

    let mut md = String::new();
    md.push_str("# SLO Report\n\n");
    md.push_str(&format!("- runs: {}\n", report.runs));
    md.push_str(&format!("- successful_runs: {}\n", report.successful_runs));
    md.push_str(&format!("- gate_failures: {}\n", report.gate_failures));
    md.push_str(&format!(
        "- availability_pct: {:.2}%\n",
        report.availability_pct
    ));
    md.push_str(&format!("- p95_duration_ms: {}\n", report.p95_duration_ms));
    md.push_str(&format!(
        "- gate_failure_rate_pct: {:.2}%\n",
        report.gate_failure_rate_pct
    ));
    md.push_str("\n## Targets\n");
    md.push_str(&format!(
        "- availability_target_pct: {} (ok={})\n",
        report.availability_target_pct, report.availability_ok
    ));
    md.push_str(&format!(
        "- p95_target_ms: {} (ok={})\n",
        report.p95_target_ms, report.p95_ok
    ));
    md.push_str(&format!(
        "- false_positive_target_pct: {} (ok={})\n",
        report.false_positive_target_pct, report.false_positive_ok
    ));
    md.push_str(&format!("\n- ready: {}\n", report.ready));

    write_output(&options.output, md.as_str())?;
    println!("slo report written: {}", options.output.display());
    Ok(())
}

fn run_ga_readiness(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let slo = build_slo_report(
        &metrics,
        options.availability_target_pct,
        options.p95_target_ms,
        options.false_positive_target_pct,
    );
    let has_audit_failures = audits.iter().any(audit_v1_is_execution_failure);
    let has_metrics = !metrics.is_empty();
    let has_audits = !audits.is_empty();
    let ga_ready = slo.ready && has_metrics && has_audits && !has_audit_failures;

    let mut md = String::new();
    md.push_str("# GA Readiness\n\n");
    md.push_str(&format!("- ga_ready: {}\n", ga_ready));
    md.push_str("\n## Checklist\n");
    md.push_str(&format!(
        "- {} Metrics present: {} entries\n",
        checklist_box(has_metrics),
        metrics.len()
    ));
    md.push_str(&format!(
        "- {} Audit logs present: {} entries\n",
        checklist_box(has_audits),
        audits.len()
    ));
    md.push_str(&format!(
        "- {} SLO ready: {}\n",
        checklist_box(slo.ready),
        slo.ready
    ));
    md.push_str(&format!(
        "- {} Audit failures absent: {}\n",
        checklist_box(!has_audit_failures),
        !has_audit_failures
    ));
    md.push_str("\n## SLO Snapshot\n");
    md.push_str(&format!(
        "- availability_pct: {:.2}%\n",
        slo.availability_pct
    ));
    md.push_str(&format!("- p95_duration_ms: {}\n", slo.p95_duration_ms));
    md.push_str(&format!(
        "- gate_failure_rate_pct: {:.2}%\n",
        slo.gate_failure_rate_pct
    ));

    write_output(&options.output, md.as_str())?;
    println!("ga readiness report written: {}", options.output.display());
    if !ga_ready {
        bail!(
            "ga readiness check failed (metrics_present={}, audits_present={}, slo_ready={}, audit_failures_absent={})",
            has_metrics,
            has_audits,
            slo.ready,
            !has_audit_failures
        );
    }
    Ok(())
}

fn run_verify_v1_calibrate(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let calibration = build_verify_v1_calibration(&metrics);

    let mut md = String::new();
    md.push_str("# verify-v1 Calibration\n\n");
    md.push_str(&format!("- runs: {}\n", calibration.runs));
    md.push_str(&format!(
        "- availability_pct: {:.2}%\n",
        calibration.availability_pct
    ));
    md.push_str(&format!(
        "- gate_failure_rate_pct: {:.2}%\n",
        calibration.gate_failure_rate_pct
    ));
    md.push_str(&format!(
        "- execution_error_rate_pct: {:.2}%\n",
        calibration.execution_error_rate_pct
    ));
    md.push_str(&format!(
        "- recommended_profile: `{}`\n",
        calibration.recommended_profile
    ));
    md.push_str("\n## Next Actions\n");
    if calibration.next_actions.is_empty() {
        md.push_str("- none\n");
    } else {
        for action in &calibration.next_actions {
            md.push_str(&format!("- {action}\n"));
        }
    }
    md.push_str("\n## Suggested command\n");
    md.push_str(&format!(
        "- `patchgate policy verify-v1 --readiness-profile {} --format text`\n",
        calibration.recommended_profile
    ));

    write_output(&options.output, md.as_str())?;
    println!(
        "verify-v1 calibration report written: {}",
        options.output.display()
    );
    Ok(())
}

fn run_compatibility_report(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let replay_summary = options
        .replay_summary_input
        .as_deref()
        .map(load_json_file::<DeadLetterReplaySummaryRecord>)
        .transpose()?;
    let assessment = build_compatibility_assessment(
        &metrics,
        &audits,
        replay_summary,
        options.availability_target_pct,
        options.p95_target_ms,
        options.false_positive_target_pct,
    );

    let mut md = String::new();
    md.push_str("# Compatibility Report\n\n");
    md.push_str(&format!("- posture: `{}`\n", assessment.posture.as_str()));
    md.push_str(&format!("- metrics_runs: {}\n", assessment.slo.runs));
    md.push_str(&format!("- audit_events: {}\n", audits.len()));
    md.push_str(&format!(
        "- audit_failures: {}\n",
        assessment.audit_failures
    ));
    md.push_str(&format!(
        "- recommended_verify_v1_profile: `{}`\n",
        assessment.calibration.recommended_profile
    ));
    md.push_str(&format!("- slo_ready: {}\n", assessment.slo.ready));
    md.push_str(&format!(
        "- replay_evidence: {}\n\n",
        if assessment.replay_evidence_present {
            "present"
        } else {
            "missing"
        }
    ));

    md.push_str("## Decision Gates\n");
    md.push_str(&format!(
        "- {} SLO targets met: {}\n",
        checklist_box(assessment.slo.ready),
        assessment.slo.ready
    ));
    md.push_str(&format!(
        "- {} Audit failures absent: {}\n",
        checklist_box(assessment.audit_failures == 0),
        assessment.audit_failures == 0
    ));
    md.push_str(&format!(
        "- {} Replay evidence attached: {}\n",
        checklist_box(assessment.replay_evidence_present),
        assessment.replay_evidence_present
    ));
    md.push_str(&format!(
        "- {} Delivery recovery clean: {}\n\n",
        checklist_box(assessment.delivery_recovery_ready),
        assessment.delivery_recovery_ready
    ));

    md.push_str("## SLO Snapshot\n");
    md.push_str(&format!(
        "- availability_pct: {:.2}%\n",
        assessment.slo.availability_pct
    ));
    md.push_str(&format!(
        "- p95_duration_ms: {}\n",
        assessment.slo.p95_duration_ms
    ));
    md.push_str(&format!(
        "- gate_failure_rate_pct: {:.2}%\n\n",
        assessment.slo.gate_failure_rate_pct
    ));

    md.push_str("## Delivery Replay\n");
    if let Some(summary) = assessment.replay_summary.as_ref() {
        md.push_str(&format!("- input_path: {}\n", summary.input_path));
        md.push_str(&format!(
            "- transport_filter: {}\n",
            summary.transport_filter.as_deref().unwrap_or("all")
        ));
        md.push_str(&format!(
            "- selected_records: {}\n",
            summary.selected_records
        ));
        md.push_str(&format!(
            "- successful_records: {}\n",
            summary.successful_records
        ));
        md.push_str(&format!("- dry_run_records: {}\n", summary.dry_run_records));
        md.push_str(&format!("- failed_records: {}\n", summary.failed_records));
        md.push_str(&format!("- skipped_records: {}\n", summary.skipped_records));
        md.push_str(&format!(
            "- retained_records: {}\n",
            summary.retained_records
        ));
        md.push_str(&format!("- dry_run: {}\n", summary.dry_run));
        md.push_str(&format!("- rewrite_input: {}\n\n", summary.rewrite_input));
    } else {
        md.push_str("- none\n\n");
    }

    md.push_str("## Failure Codes\n");
    if assessment.failure_codes.is_empty() {
        md.push_str("- none\n");
    } else {
        for (code, count) in &assessment.failure_codes {
            md.push_str(&format!("- {code}: {count}\n"));
        }
    }

    md.push_str("\n## Next Actions\n");
    if assessment.next_actions.is_empty() {
        md.push_str("- none\n");
    } else {
        for action in &assessment.next_actions {
            md.push_str(&format!("- {action}\n"));
        }
    }

    write_output(&options.output, md.as_str())?;
    println!("compatibility report written: {}", options.output.display());
    Ok(())
}

fn run_freeze_scoreboard(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let replay_summary = options
        .replay_summary_input
        .as_deref()
        .map(load_json_file::<DeadLetterReplaySummaryRecord>)
        .transpose()?;
    let assessment = build_compatibility_assessment(
        &metrics,
        &audits,
        replay_summary,
        options.availability_target_pct,
        options.p95_target_ms,
        options.false_positive_target_pct,
    );
    let scoreboard = build_freeze_scoreboard(&metrics, &audits, &assessment);

    let mut md = String::new();
    md.push_str("# v1.1 Freeze Scoreboard\n\n");
    md.push_str(&format!("- freeze_ready: {}\n", scoreboard.freeze_ready));
    md.push_str(&format!("- v2_seed_ready: {}\n", scoreboard.v2_seed_ready));
    md.push_str(&format!("- ga_ready: {}\n", scoreboard.ga_ready));
    md.push_str(&format!("- posture: `{}`\n", scoreboard.posture.as_str()));
    md.push_str(&format!(
        "- recommended_verify_v1_profile: `{}`\n\n",
        scoreboard.recommended_profile
    ));

    md.push_str("## Checklist\n");
    md.push_str(&format!(
        "- {} Metrics present: {}\n",
        checklist_box(scoreboard.has_metrics),
        scoreboard.has_metrics
    ));
    md.push_str(&format!(
        "- {} Audit logs present: {}\n",
        checklist_box(scoreboard.has_audits),
        scoreboard.has_audits
    ));
    md.push_str(&format!(
        "- {} GA readiness gate passes: {}\n",
        checklist_box(scoreboard.ga_ready),
        scoreboard.ga_ready
    ));
    md.push_str(&format!(
        "- {} Compatibility posture is not stabilize-v1: {}\n",
        checklist_box(scoreboard.freeze_ready),
        scoreboard.freeze_ready
    ));
    md.push_str(&format!(
        "- {} Replay evidence attached for v2 seed: {}\n",
        checklist_box(scoreboard.replay_evidence_present),
        scoreboard.replay_evidence_present
    ));
    md.push_str(&format!(
        "- {} V2 seed gate passes: {}\n\n",
        checklist_box(scoreboard.v2_seed_ready),
        scoreboard.v2_seed_ready
    ));

    md.push_str("## Next Actions\n");
    if scoreboard.next_actions.is_empty() {
        md.push_str("- none\n");
    } else {
        for action in &scoreboard.next_actions {
            md.push_str(&format!("- {action}\n"));
        }
    }

    write_output(&options.output, md.as_str())?;
    println!("freeze scoreboard written: {}", options.output.display());
    Ok(())
}

fn run_freeze_boundary(options: &OpsOptions) -> Result<()> {
    let markdown = build_freeze_boundary_markdown(&options.output);
    write_output(&options.output, markdown.as_str())?;
    println!("freeze boundary written: {}", options.output.display());
    Ok(())
}

fn build_freeze_boundary_markdown(output_path: &Path) -> String {
    let boundary_artifact = output_path.display().to_string();
    let mut md = String::new();
    md.push_str("# v1.1 Freeze Boundary\n\n");
    md.push_str("- artifact_version: 1\n");
    md.push_str("- boundary_status: v1.1-scope-defined, v2-seed-boundary-defined\n");
    md.push_str(&format!("- output_path: `{boundary_artifact}`\n"));
    md.push_str("- recommended_artifact: `artifacts/v1.1-freeze-boundary.md`\n");
    md.push_str("- canonical_doc: docs/24_v11_freeze_boundary.md\n");
    md.push_str(
        "- paired_gate_recommended: `artifacts/v1.1-readiness.md` from `xtask ops freeze-scoreboard`\n\n",
    );

    md.push_str("## v1.1 Scope Candidate Inventory\n\n");
    md.push_str("| Candidate | Decision | v1.1 boundary | Evidence artifact | Release gate |\n");
    md.push_str("| --- | --- | --- | --- | --- |\n");
    for item in freeze_scope_items() {
        md.push_str(&format!(
            "| {} | `{}` | {} | `{}` | {} |\n",
            item.candidate,
            item.decision,
            item.v11_boundary,
            item.evidence_artifact,
            item.release_gate
        ));
    }

    md.push_str("\n## Deferred Backlog / Non-Goal Reconciliation\n\n");
    md.push_str("| Item | Disposition | Owner phase | Reconciliation |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for item in deferred_backlog_items() {
        md.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            item.item, item.disposition, item.owner_phase, item.reconciliation
        ));
    }

    md.push_str("\n## Plugin / Provider Breaking-Change Boundary\n\n");
    md.push_str("| Surface | v1.1 contract | v2 change allowed | Guardrail |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for item in breaking_change_boundaries() {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            item.surface, item.v11_contract, item.v2_change_allowed, item.guardrail
        ));
    }

    md.push_str("\n## Migration Narrative\n\n");
    md.push_str("1. Freeze v1.1 only after verify-v1, compatibility-report, freeze-scoreboard, and this boundary inventory agree.\n");
    md.push_str("2. Keep v1.1 provider, plugin, audit, and docs contracts stable while v2 work runs in shadow or dual mode.\n");
    md.push_str("3. Start v2 seed work from provider and audit bridge surfaces, then widen only after shadow-review and audit-drift evidence remain clean.\n");
    md.push_str("4. Promote RC candidates with migration guide, provider rollout checklist, candidate checklist, benchmark sign-off, and security review attached.\n");
    md.push_str("5. Roll back by returning provider output to v1, disabling bridge mode, and keeping v2 audit artifacts as diagnostic evidence.\n\n");

    md.push_str("## v2 Option Matrix\n\n");
    md.push_str("| Option | Fit | Tradeoff | Decision |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for item in v2_options() {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            item.option, item.fit, item.tradeoff, item.decision
        ));
    }

    md.push_str("\n## v2 Risk Register\n\n");
    md.push_str("| Risk | Trigger | Mitigation | Gate |\n");
    md.push_str("| --- | --- | --- | --- |\n");
    for item in v2_risks() {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            item.risk, item.trigger, item.mitigation, item.gate
        ));
    }

    md.push_str("\n## Release Checklist Freeze Gate\n\n");
    md.push_str("| Gate | Required signal | Artifact |\n");
    md.push_str("| --- | --- | --- |\n");
    for item in freeze_gate_items(boundary_artifact.as_str()) {
        md.push_str(&format!(
            "| {} | {} | `{}` |\n",
            item.gate, item.required_signal, item.artifact
        ));
    }

    md
}

fn freeze_scope_items() -> [FreezeScopeItem; 8] {
    [
        FreezeScopeItem {
            candidate: "verify-v1 strict and lts readiness profiles",
            decision: "v1.1",
            v11_boundary: "Keep as the release-facing compatibility gate.",
            evidence_artifact: "docs/99_release_checklist.md, artifacts/ga-readiness.md",
            release_gate: "strict and lts profile checks are attached.",
        },
        FreezeScopeItem {
            candidate: "dead-letter replay summary and recovery packet",
            decision: "v1.1",
            v11_boundary:
                "Keep replay evidence as the bridge between operations and freeze decisions.",
            evidence_artifact:
                "artifacts/dead-letter-replay-summary.json, artifacts/replay-evidence.json",
            release_gate: "failed and retained replay records are zero or explicitly deferred.",
        },
        FreezeScopeItem {
            candidate: "compatibility report and freeze scoreboard",
            decision: "v1.1",
            v11_boundary: "Use telemetry posture to decide hold versus start-v2-seed.",
            evidence_artifact: "artifacts/compatibility-report.md, artifacts/v1.1-readiness.md",
            release_gate: "posture is not stabilize-v1 and freeze_ready is true.",
        },
        FreezeScopeItem {
            candidate: "plugin signature, sandbox, and provenance trust loop",
            decision: "v1.1",
            v11_boundary: "Preserve patchgate.plugin.v1 command and SDK template compatibility.",
            evidence_artifact: "artifacts/fleet-review.md, docs/SECURITY.md",
            release_gate: "registry provenance and sandbox profile are reviewed.",
        },
        FreezeScopeItem {
            candidate: "generic provider v1 output",
            decision: "v1.1",
            v11_boundary: "Preserve provider, summary, and report fields for downstream CI.",
            evidence_artifact: "docs/15_provider_rollout_checklist.md",
            release_gate: "provider v1 remains readable before dual or v2 output is promoted.",
        },
        FreezeScopeItem {
            candidate: "audit v2 and SIEM handoff",
            decision: "v2-seed",
            v11_boundary: "Keep audit v1 authoritative while v2 is dual-written for evidence.",
            evidence_artifact: "artifacts/shadow-review.md, artifacts/siem-handoff.jsonl",
            release_gate: "shadow alignment and audit drift are clean before RC.",
        },
        FreezeScopeItem {
            candidate: "policy verify-v2 and diff-contract",
            decision: "v2-seed",
            v11_boundary: "Do not make v2 policy semantics required for v1.1 users.",
            evidence_artifact: "docs/16_v2_migration_guide_alpha.md, artifacts/v2-rc-readiness.md",
            release_gate: "v2 checks are preview or bridge gates until RC.",
        },
        FreezeScopeItem {
            candidate: "remote source scanning or high-cost inference in hot path",
            decision: "non-goal",
            v11_boundary: "Keep scan execution local and CI-priced.",
            evidence_artifact: "docs/ROADMAP.md",
            release_gate: "no release blocker depends on remote scanning or hot-path inference.",
        },
    ]
}

fn deferred_backlog_items() -> [DeferredBacklogItem; 6] {
    [
        DeferredBacklogItem {
            item: "fleet registry UI and operator dashboard",
            disposition: "deferred",
            owner_phase: "Phase171-180",
            reconciliation:
                "Keep fleet-review markdown and JSON inputs as the v1.1 artifact boundary.",
        },
        DeferredBacklogItem {
            item: "audit v2 as the sole authoritative stream",
            disposition: "v2-seed",
            owner_phase: "Phase161-170",
            reconciliation:
                "Keep audit v1 authoritative until dual-write shadow evidence is clean.",
        },
        DeferredBacklogItem {
            item: "provider v2 as the default generic output",
            disposition: "v2-seed",
            owner_phase: "Phase161-170",
            reconciliation: "Use dual provider artifacts before switching downstream defaults.",
        },
        DeferredBacklogItem {
            item: "full remote source scan",
            disposition: "non-goal",
            owner_phase: "none",
            reconciliation:
                "It conflicts with the local and CI-first cost model for this release line.",
        },
        DeferredBacklogItem {
            item: "cloud inference in the release hot path",
            disposition: "non-goal",
            owner_phase: "none",
            reconciliation: "It is not required for the deterministic v1.1 freeze gate.",
        },
        DeferredBacklogItem {
            item: "automatic migration of all plugin manifests",
            disposition: "deferred",
            owner_phase: "Phase181-190",
            reconciliation: "Keep SDK compatibility notices and manual rollout checks for v1.1.",
        },
    ]
}

fn breaking_change_boundaries() -> [BreakingChangeBoundary; 5] {
    [
        BreakingChangeBoundary {
            surface: "Plugin command contract",
            v11_contract: "patchgate.plugin.v1 remains callable by existing SDK templates.",
            v2_change_allowed: "Manifest metadata and stronger provenance may be required.",
            guardrail: "Keep v1 templates and contract tests active through v2 seed.",
        },
        BreakingChangeBoundary {
            surface: "Generic provider artifact",
            v11_contract: "v1 provider, summary, and report fields remain stable.",
            v2_change_allowed:
                "publish_format, gate, artifacts, or bridge payloads may be introduced.",
            guardrail: "Use generic_schema dual before making v2 the default.",
        },
        BreakingChangeBoundary {
            surface: "Audit stream",
            v11_contract: "patchgate.audit.v1 JSONL remains the authoritative release signal.",
            v2_change_allowed: "operation, gate, failure, and diagnostics may become structured.",
            guardrail: "Require shadow-review and audit-drift-report before promotion.",
        },
        BreakingChangeBoundary {
            surface: "Policy configuration",
            v11_contract: "policy_version and compatibility.v1 remain accepted.",
            v2_change_allowed:
                "Bridge defaults and stricter compatibility.v2 semantics may change.",
            guardrail: "Run verify-v1, verify-v2, and diff-contract during migration.",
        },
        BreakingChangeBoundary {
            surface: "Docs and SDK templates",
            v11_contract: "v1.1 setup and plugin init flows stay valid.",
            v2_change_allowed: "Parallel v2 examples may be introduced.",
            guardrail: "Keep compatibility notices and migration guide updated together.",
        },
    ]
}

fn v2_options() -> [V2Option; 5] {
    [
        V2Option {
            option: "provider-first bridge",
            fit: "Best first step when downstream CI consumers need schema proof.",
            tradeoff: "Does not prove audit semantics by itself.",
            decision: "Start here for seed work.",
        },
        V2Option {
            option: "audit-first bridge",
            fit: "Best when SIEM and ops diagnostics are the release risk.",
            tradeoff: "Provider consumers still need a separate compatibility pass.",
            decision: "Run in parallel after provider evidence exists.",
        },
        V2Option {
            option: "full dual-contract",
            fit: "Best RC posture once provider and audit shadows are stable.",
            tradeoff: "Higher CI and review cost.",
            decision: "Use for RC readiness.",
        },
        V2Option {
            option: "hold v1.1 line",
            fit: "Best when telemetry is clean enough to release but replay or bridge evidence is missing.",
            tradeoff: "Delays v2 learning.",
            decision: "Valid freeze outcome.",
        },
        V2Option {
            option: "direct v2 cutover",
            fit: "Only acceptable for isolated experiments.",
            tradeoff: "No ecosystem rollback margin.",
            decision: "Do not use for the shared release line.",
        },
    ]
}

fn v2_risks() -> [V2Risk; 7] {
    [
        V2Risk {
            risk: "Provider artifact drift",
            trigger: "Dual or v2 payload cannot be consumed by existing CI readers.",
            mitigation: "Keep v1 output enabled and attach provider rollout evidence.",
            gate: "provider bridge artifact in rc-readiness.",
        },
        V2Risk {
            risk: "Audit stream mismatch",
            trigger: "v2 event counts or failure totals diverge from v1.",
            mitigation: "Keep v1 authoritative and investigate shadow deltas.",
            gate: "shadow-review and audit-drift-report.",
        },
        V2Risk {
            risk: "Plugin trust regression",
            trigger: "Unsigned, unverified, or revoked plugin provenance enters a release wave.",
            mitigation: "Require registry provenance and sandbox profile review.",
            gate: "fleet-review registry provenance.",
        },
        V2Risk {
            risk: "Migration narrative gap",
            trigger: "Checklist, migration guide, and provider rollout docs disagree.",
            mitigation: "Update docs together and block RC until paths resolve.",
            gate: "candidate checklist and migration guide.",
        },
        V2Risk {
            risk: "Replay residue",
            trigger: "Dead-letter replay has failed or retained records.",
            mitigation: "Drain, justify, or defer before v2 seed promotion.",
            gate: "compatibility-report and replay evidence packet.",
        },
        V2Risk {
            risk: "Performance or cost regression",
            trigger: "Benchmark comparison regresses or fleet cost ceiling is exceeded.",
            mitigation: "Hold rollout wave and reduce dual-run scope.",
            gate: "benchmark sign-off and fleet-review cost ceiling.",
        },
        V2Risk {
            risk: "Security review unresolved",
            trigger: "Security review lacks Continue approval or requires mitigation.",
            mitigation: "Keep candidate in hold until reviewer sign-off is clean.",
            gate: "rc-readiness security review.",
        },
    ]
}

fn freeze_gate_items(boundary_artifact: &str) -> [FreezeGateItem<'_>; 7] {
    [
        FreezeGateItem {
            gate: "Scope inventory reviewed",
            required_signal: "Every v1.1 candidate is marked v1.1, deferred, non-goal, or v2-seed.",
            artifact: boundary_artifact,
        },
        FreezeGateItem {
            gate: "Deferred backlog reconciled",
            required_signal: "Every deferred item has an owner phase or a non-goal rationale.",
            artifact: boundary_artifact,
        },
        FreezeGateItem {
            gate: "Breaking-change boundary accepted",
            required_signal:
                "Plugin, provider, audit, policy, docs, and SDK surfaces have v1.1 guardrails.",
            artifact: boundary_artifact,
        },
        FreezeGateItem {
            gate: "Telemetry freeze ready",
            required_signal: "freeze_ready is true and posture is not stabilize-v1.",
            artifact: "artifacts/v1.1-readiness.md",
        },
        FreezeGateItem {
            gate: "Replay evidence clean or explicitly held",
            required_signal:
                "Replay summary is non-dry-run with rewrite enabled, or v2 seed remains blocked.",
            artifact: "artifacts/compatibility-report.md",
        },
        FreezeGateItem {
            gate: "v2 option selected",
            required_signal:
                "Provider-first, audit-first, full dual-contract, or hold-v1.1-line is named.",
            artifact: boundary_artifact,
        },
        FreezeGateItem {
            gate: "Risk register reviewed",
            required_signal: "All v2 risks point to an artifact gate before RC.",
            artifact: boundary_artifact,
        },
    ]
}

fn run_replay_normalize(options: &OpsOptions) -> Result<()> {
    let path = options
        .replay_summary_input
        .as_deref()
        .ok_or_else(|| anyhow!("--replay-summary-input is required for replay-normalize"))?;
    let summary = load_json_file::<DeadLetterReplaySummaryRecord>(path)?;
    let recovered = summary.successful_records + summary.skipped_records;
    let recovery_ratio_pct = if summary.selected_records == 0 {
        100.0
    } else {
        (recovered as f64 / summary.selected_records as f64) * 100.0
    };
    let status = if summary.failed_records > 0 {
        "retrying"
    } else if summary.retained_records > 0 {
        "blocked"
    } else {
        "clean"
    };
    let packet = ReplayEvidencePacket {
        schema_version: 1,
        status: status.to_string(),
        selected_records: summary.selected_records,
        successful_records: summary.successful_records,
        failed_records: summary.failed_records,
        skipped_records: summary.skipped_records,
        retained_records: summary.retained_records,
        recovery_ratio_pct,
        dry_run: summary.dry_run,
        rewrite_input: summary.rewrite_input,
    };
    write_output(
        &options.output,
        serde_json::to_string_pretty(&packet)?.as_str(),
    )?;
    println!(
        "replay evidence packet written: {}",
        options.output.display()
    );
    Ok(())
}

fn run_rollback_packet(options: &OpsOptions) -> Result<()> {
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = options
        .audit_v2_input
        .as_deref()
        .ok_or_else(|| anyhow!("--audit-v2-input is required for rollback-packet"))?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let shadow = build_shadow_alignment(&audits, &audits_v2);
    let rollback_repos = shadow_candidate_repos(&audits, &audits_v2);
    let provider_v1_verified =
        provider_v1_restore_verified(&options.provider_inputs, &rollback_repos)?;
    let audit_v2_retained = !audits_v2.is_empty();
    let audit_event_parity = audit_events_have_strict_parity(&audits, &audits_v2);
    let dual_run_reversible = audit_event_parity && shadow.aligned;
    let dry_run_completed = dual_run_reversible && provider_v1_verified;
    let packet = RollbackPacket {
        schema_version: 1,
        generated_at: current_utc_timestamp_label()?,
        owner: "platform-governance".to_string(),
        triggers: vec![
            "provider artifact drift".to_string(),
            "audit v2 event or failure drift".to_string(),
            "fleet cost ceiling breach".to_string(),
        ],
        restore: RollbackRestorePlan {
            bridge_mode: "off".to_string(),
            generic_schema: "v1".to_string(),
            v1_audit_authoritative: true,
        },
        verification: RollbackVerification {
            dry_run_completed,
            dual_run_reversible,
            provider_v1_verified,
            audit_v2_retained,
        },
        retained_evidence: vec!["audit-v1".to_string(), "audit-v2".to_string()],
    };
    write_output(
        &options.output,
        serde_json::to_string_pretty(&packet)?.as_str(),
    )?;
    println!("rollback packet written: {}", options.output.display());
    if !rollback_packet_input_ready(Some(&options.output))? {
        bail!("rollback packet failed");
    }
    Ok(())
}

fn run_migration_drill(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = options
        .audit_v2_input
        .as_deref()
        .ok_or_else(|| anyhow!("--audit-v2-input is required for migration-drill"))?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let rollback_packet_ready =
        rollback_packet_input_ready(options.rollback_packet_input.as_deref())?;
    let provider_summaries = summarize_provider_inputs(&options.provider_inputs)?;
    let shadow = build_shadow_alignment(&audits, &audits_v2);
    let audit_event_parity = audit_events_have_strict_parity(&audits, &audits_v2);
    let candidate_repos = candidate_repos(&metrics, &audits);
    let metric_repos = metrics
        .iter()
        .map(|row| row.repo.as_str())
        .collect::<BTreeSet<_>>();
    let audit_repos = audits
        .iter()
        .map(|row| row.repo.as_str())
        .collect::<BTreeSet<_>>();
    let audit_v2_repos = audits_v2
        .iter()
        .map(|row| row.repo.as_str())
        .collect::<BTreeSet<_>>();
    let provider_ready_repos = provider_summaries
        .iter()
        .filter(|summary| summary.schema_mode == "dual")
        .map(|summary| summary.repo.as_str())
        .collect::<BTreeSet<_>>();
    let provider_restore_ready_repos = provider_v1_restore_ready_repos(&options.provider_inputs)?;

    let mut blockers = Vec::new();
    if candidate_repos.is_empty() {
        blockers.push("no candidate repos found in metrics or audit inputs".to_string());
    }
    if !shadow.aligned {
        blockers.push("audit v1/v2 shadow alignment failed".to_string());
    }
    if !audit_event_parity {
        blockers.push("audit v1/v2 event identity parity failed".to_string());
    }
    if !rollback_packet_ready {
        blockers.push("rollback packet is missing or incomplete".to_string());
    }
    let repos_succeeded = candidate_repos
        .iter()
        .filter(|repo| {
            metric_repos.contains(repo.as_str())
                && audit_repos.contains(repo.as_str())
                && audit_v2_repos.contains(repo.as_str())
                && provider_ready_repos.contains(repo.as_str())
                && provider_restore_ready_repos.contains(repo.as_str())
                && shadow.aligned
                && audit_event_parity
                && rollback_packet_ready
        })
        .count();
    for repo in &candidate_repos {
        if !metric_repos.contains(repo.as_str()) {
            blockers.push(format!("repo={repo} missing metrics evidence"));
        }
        if !audit_repos.contains(repo.as_str()) {
            blockers.push(format!("repo={repo} missing audit v1 evidence"));
        }
        if !provider_ready_repos.contains(repo.as_str())
            || !provider_restore_ready_repos.contains(repo.as_str())
        {
            blockers.push(format!(
                "repo={repo} missing dual provider artifact with v1 restore evidence"
            ));
        }
        if !audit_v2_repos.contains(repo.as_str()) {
            blockers.push(format!("repo={repo} missing audit v2 evidence"));
        }
    }
    let repos_total = candidate_repos.len();
    let report = MigrationDrillReport {
        schema_version: 1,
        generated_at: current_utc_timestamp_label()?,
        drill_id: "phase181-large-scale-migration-drill".to_string(),
        repos_total,
        repos_attempted: repos_total,
        repos_succeeded,
        repos_failed: repos_total.saturating_sub(repos_succeeded),
        provider_artifacts_checked: provider_summaries.len(),
        audit_events_replayed: audits_v2.len(),
        rollback_rehearsed: rollback_packet_ready,
        dry_run: false,
        owners: vec!["platform-governance".to_string()],
        blockers,
    };
    write_output(
        &options.output,
        serde_json::to_string_pretty(&report)?.as_str(),
    )?;
    println!("migration drill written: {}", options.output.display());
    if report.repos_failed > 0 || !report.blockers.is_empty() {
        bail!("migration drill failed");
    }
    Ok(())
}

fn run_shadow_review(options: &OpsOptions) -> Result<()> {
    let audits_v1 = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = options
        .audit_v2_input
        .as_deref()
        .ok_or_else(|| anyhow!("--audit-v2-input is required for shadow-review"))?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let shadow = build_shadow_alignment(&audits_v1, &audits_v2);
    let drift = build_combined_audit_drift_summary(&audits_v1, &audits_v2);
    let audit_contract_clean = audit_stream_contracts_are_clean(&audits_v1, &audits_v2);
    let audit_drift_clean = audit_drift_is_clean(&drift) && audit_contract_clean;
    let provider_summaries = summarize_provider_inputs(&options.provider_inputs)?;
    let shadow_repos = shadow_candidate_repos(&audits_v1, &audits_v2);
    let provider_bridge_ready = if provider_summaries.is_empty() {
        None
    } else {
        Some(provider_bridge_ready_for_repos(
            &provider_summaries,
            &shadow_repos,
        ))
    };
    let webhook_bridge_summaries = summarize_delivery_bridge_inputs(
        &options.webhook_envelope_inputs,
        "webhook",
        "patchgate.webhook.v2-shadow",
        "scan.completed",
    )?;
    let notification_bridge_summaries = summarize_delivery_bridge_inputs(
        &options.notification_envelope_inputs,
        "notification",
        "patchgate.notification.v2-shadow",
        "scan.completed.notification",
    )?;
    let webhook_bridge_checked = !webhook_bridge_summaries.is_empty();
    let notification_bridge_checked = !notification_bridge_summaries.is_empty();
    let mut delivery_bridge_summaries = webhook_bridge_summaries;
    delivery_bridge_summaries.extend(notification_bridge_summaries);
    let delivery_bridge_ready = if !webhook_bridge_checked && !notification_bridge_checked {
        None
    } else {
        Some(
            webhook_bridge_checked
                && notification_bridge_checked
                && delivery_bridge_summaries
                    .iter()
                    .all(|summary| summary.valid),
        )
    };
    let shadow_traffic_ready = shadow.aligned
        && audit_drift_clean
        && provider_bridge_ready.unwrap_or(true)
        && delivery_bridge_ready.unwrap_or(true);
    let v2_schema_versions = audits_v2
        .iter()
        .map(|row| row.schema_version)
        .collect::<BTreeSet<_>>()
        .len();
    let v2_formats = audits_v2
        .iter()
        .map(|row| row.audit_format.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let v2_emitted_at_min = audits_v2
        .iter()
        .map(|row| row.emitted_at)
        .min()
        .unwrap_or(0);
    let v2_actors = audits_v2
        .iter()
        .map(|row| row.actor.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let v2_repos = audits_v2
        .iter()
        .map(|row| row.repo.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let v2_scored_rows = audits_v2
        .iter()
        .filter(|row| row.gate.score.is_some())
        .count();
    let v2_threshold_rows = audits_v2
        .iter()
        .filter(|row| row.gate.threshold.is_some())
        .count();
    let v2_changed_file_rows = audits_v2
        .iter()
        .filter(|row| row.gate.changed_files.is_some())
        .count();
    let v2_failure_categories = audits_v2
        .iter()
        .filter(|row| row.failure.category.is_some())
        .count();

    let mut md = String::new();
    md.push_str("# Shadow Review\n\n");
    md.push_str(&format!("- audit_v1_events: {}\n", shadow.v1_events));
    md.push_str(&format!("- audit_v2_events: {}\n", shadow.v2_events));
    md.push_str(&format!("- audit_v1_failures: {}\n", shadow.v1_failures));
    md.push_str(&format!("- audit_v2_failures: {}\n", shadow.v2_failures));
    md.push_str(&format!("- event_delta: {}\n", shadow.event_delta));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!(
        "- audit_contract_clean: {}\n",
        audit_contract_clean
    ));
    md.push_str(&format!(
        "- provider_bridge_ready: {}\n",
        optional_bool_label(provider_bridge_ready)
    ));
    md.push_str(&format!(
        "- delivery_bridge_ready: {}\n",
        optional_bool_label(delivery_bridge_ready)
    ));
    md.push_str(&format!(
        "- shadow_traffic_ready: {}\n\n",
        shadow_traffic_ready
    ));

    md.push_str("## V2 Coverage\n");
    md.push_str(&format!("- repo_set_match: {}\n", shadow.repo_set_match));
    md.push_str(&format!("- unique_targets: {}\n", shadow.unique_targets));
    md.push_str(&format!("- unique_modes: {}\n", shadow.unique_modes));
    md.push_str(&format!("- unique_scopes: {}\n", shadow.unique_scopes));
    md.push_str(&format!("- mode_set_match: {}\n", shadow.mode_set_match));
    md.push_str(&format!("- scope_set_match: {}\n", shadow.scope_set_match));
    md.push_str(&format!(
        "- unique_schema_versions: {}\n",
        v2_schema_versions
    ));
    md.push_str(&format!("- unique_formats: {}\n", v2_formats));
    md.push_str(&format!("- earliest_emitted_at: {}\n", v2_emitted_at_min));
    md.push_str(&format!("- unique_actors: {}\n", v2_actors));
    md.push_str(&format!("- unique_repos: {}\n", v2_repos));
    md.push_str(&format!("- rows_with_score: {}\n", v2_scored_rows));
    md.push_str(&format!("- rows_with_threshold: {}\n", v2_threshold_rows));
    md.push_str(&format!(
        "- rows_with_changed_files: {}\n",
        v2_changed_file_rows
    ));
    md.push_str(&format!(
        "- rows_with_failure_category: {}\n",
        v2_failure_categories
    ));
    md.push_str(&format!(
        "- diagnostics_emitted: {}\n",
        shadow.diagnostics_emitted
    ));
    md.push_str(&format!("- aligned: {}\n\n", shadow.aligned));

    md.push_str("## Provider Bridge Artifacts\n");
    if provider_summaries.is_empty() {
        md.push_str("- provider_inputs: none\n");
        md.push_str("- attach `--provider-input` when reviewing provider/audit dual-contract readiness together.\n\n");
    } else {
        md.push_str(&format!(
            "- provider_inputs: {}\n",
            provider_summaries.len()
        ));
        for summary in &provider_summaries {
            md.push_str(&format!(
                "- repo={} schema_mode={}\n",
                summary.repo, summary.schema_mode
            ));
        }
        md.push('\n');
    }

    md.push_str("## Delivery Bridge Artifacts\n");
    if delivery_bridge_summaries.is_empty() {
        md.push_str("- delivery_inputs: none\n");
        md.push_str("- attach `--webhook-envelope-input` and `--notification-envelope-input` to review delivery bridge metadata with shadow traffic.\n\n");
    } else {
        md.push_str(&format!(
            "- delivery_inputs: {}\n",
            delivery_bridge_summaries.len()
        ));
        md.push_str(&format!("- webhook_checked: {}\n", webhook_bridge_checked));
        md.push_str(&format!(
            "- notification_checked: {}\n",
            notification_bridge_checked
        ));
        for summary in &delivery_bridge_summaries {
            md.push_str(&format!(
                "- kind={} valid={} bridge_mode={} path={}\n",
                summary.kind, summary.valid, summary.bridge_mode, summary.path
            ));
        }
        md.push('\n');
    }

    md.push_str("## Review Notes\n");
    md.push_str("- Compare event counts before promoting shadow traffic to wider rollout.\n");
    md.push_str("- Investigate any failure drift where v1 and v2 failure totals differ.\n");
    md.push_str("- Keep dual-write enabled until event counts and failure codes stay aligned.\n");
    if provider_bridge_ready == Some(false) {
        md.push_str("- Attach a dual/v2 provider artifact for at least one repo covered by the audit shadow.\n");
    }
    if delivery_bridge_ready == Some(false) {
        md.push_str("- Attach valid webhook and notification bridge envelopes before widening full shadow traffic.\n");
    }

    write_output(&options.output, md.as_str())?;
    println!("shadow review written: {}", options.output.display());
    Ok(())
}

fn build_audit_drift_summary(audits: &[AuditLogRecord]) -> AuditDriftSummary {
    let known_results = ["pass", "gate_fail", "error"];
    let mut unknown_failure_codes = BTreeMap::<String, usize>::new();
    let mut unknown_results = BTreeMap::<String, usize>::new();
    let mut schema_versions = BTreeMap::<u8, usize>::new();
    let mut formats = BTreeMap::<String, usize>::new();

    for row in audits {
        *schema_versions.entry(row.schema_version).or_insert(0) += 1;
        *formats.entry(row.audit_format.clone()).or_insert(0) += 1;
        if !known_results.contains(&row.result.as_str()) {
            *unknown_results.entry(row.result.clone()).or_insert(0) += 1;
        }
        if let Some(code) = row.failure_code.as_ref() {
            if !is_known_failure_code(code) {
                *unknown_failure_codes.entry(code.clone()).or_insert(0) += 1;
            }
        }
    }

    AuditDriftSummary {
        unknown_failure_codes,
        unknown_results,
        schema_versions,
        formats,
    }
}

fn build_audit_v2_drift_summary(audits: &[AuditLogV2Record]) -> AuditDriftSummary {
    let known_results = ["pass", "gate_fail", "error"];
    let mut unknown_failure_codes = BTreeMap::<String, usize>::new();
    let mut unknown_results = BTreeMap::<String, usize>::new();
    let mut schema_versions = BTreeMap::<u8, usize>::new();
    let mut formats = BTreeMap::<String, usize>::new();

    for row in audits {
        *schema_versions.entry(row.schema_version).or_insert(0) += 1;
        *formats.entry(row.audit_format.clone()).or_insert(0) += 1;
        if !known_results.contains(&row.operation.result.as_str()) {
            *unknown_results
                .entry(row.operation.result.clone())
                .or_insert(0) += 1;
        }
        if let Some(code) = row.failure.code.as_ref() {
            if !is_known_failure_code(code) {
                *unknown_failure_codes.entry(code.clone()).or_insert(0) += 1;
            }
        }
    }

    AuditDriftSummary {
        unknown_failure_codes,
        unknown_results,
        schema_versions,
        formats,
    }
}

fn merge_count_maps<K: Ord>(target: &mut BTreeMap<K, usize>, source: BTreeMap<K, usize>) {
    for (key, count) in source {
        *target.entry(key).or_insert(0) += count;
    }
}

fn build_combined_audit_drift_summary(
    audits: &[AuditLogRecord],
    audits_v2: &[AuditLogV2Record],
) -> AuditDriftSummary {
    let mut combined = build_audit_drift_summary(audits);
    let drift_v2 = build_audit_v2_drift_summary(audits_v2);
    merge_count_maps(
        &mut combined.unknown_failure_codes,
        drift_v2.unknown_failure_codes,
    );
    merge_count_maps(&mut combined.unknown_results, drift_v2.unknown_results);
    merge_count_maps(&mut combined.schema_versions, drift_v2.schema_versions);
    merge_count_maps(&mut combined.formats, drift_v2.formats);
    combined
}

fn audit_v1_is_failure(row: &AuditLogRecord) -> bool {
    row.failure_code.is_some() || matches!(row.result.as_str(), "gate_fail" | "error")
}

fn audit_v1_is_execution_failure(row: &AuditLogRecord) -> bool {
    row.failure_code.is_some() || row.result == "error"
}

fn audit_v2_is_failure(row: &AuditLogV2Record) -> bool {
    row.failure.code.is_some() || matches!(row.operation.result.as_str(), "gate_fail" | "error")
}

fn build_shadow_alignment(
    audits_v1: &[AuditLogRecord],
    audits_v2: &[AuditLogV2Record],
) -> ShadowAlignment {
    let v1_failures = audits_v1
        .iter()
        .filter(|row| audit_v1_is_failure(row))
        .count();
    let v2_failures = audits_v2
        .iter()
        .filter(|row| audit_v2_is_failure(row))
        .count();
    let v1_modes = audits_v1
        .iter()
        .map(|row| row.mode.as_str())
        .collect::<BTreeSet<_>>();
    let v2_modes = audits_v2
        .iter()
        .map(|row| row.operation.mode.as_str())
        .collect::<BTreeSet<_>>();
    let v1_scopes = audits_v1
        .iter()
        .map(|row| row.scope.as_str())
        .collect::<BTreeSet<_>>();
    let v2_scopes = audits_v2
        .iter()
        .map(|row| row.operation.scope.as_str())
        .collect::<BTreeSet<_>>();
    let v1_repos = audits_v1
        .iter()
        .map(|row| row.repo.as_str())
        .collect::<BTreeSet<_>>();
    let v2_repos = audits_v2
        .iter()
        .map(|row| row.repo.as_str())
        .collect::<BTreeSet<_>>();
    let repo_set_match = v1_repos == v2_repos;
    let mode_set_match = v1_modes == v2_modes;
    let scope_set_match = v1_scopes == v2_scopes;
    let unique_targets = audits_v2
        .iter()
        .map(|row| row.operation.target.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let unique_modes = audits_v2
        .iter()
        .map(|row| row.operation.mode.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let unique_scopes = audits_v2
        .iter()
        .map(|row| row.operation.scope.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let diagnostics_emitted = audits_v2
        .iter()
        .map(|row| row.diagnostics.len())
        .sum::<usize>();
    let event_delta = audits_v2.len() as isize - audits_v1.len() as isize;
    let aligned = !audits_v2.is_empty()
        && event_delta.abs() <= 1
        && v2_failures == v1_failures
        && repo_set_match
        && mode_set_match
        && scope_set_match;

    ShadowAlignment {
        v1_events: audits_v1.len(),
        v2_events: audits_v2.len(),
        v1_failures,
        v2_failures,
        event_delta,
        repo_set_match,
        mode_set_match,
        scope_set_match,
        unique_targets,
        unique_modes,
        unique_scopes,
        diagnostics_emitted,
        aligned,
    }
}

fn shadow_candidate_repos(
    audits_v1: &[AuditLogRecord],
    audits_v2: &[AuditLogV2Record],
) -> BTreeSet<String> {
    audits_v1
        .iter()
        .map(|row| row.repo.clone())
        .chain(audits_v2.iter().map(|row| row.repo.clone()))
        .collect()
}

fn optional_bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "not_checked",
    }
}

fn audit_drift_is_clean(drift: &AuditDriftSummary) -> bool {
    drift.unknown_failure_codes.is_empty()
        && drift.unknown_results.is_empty()
        && drift
            .schema_versions
            .keys()
            .all(|version| (1..=10).contains(version))
        && drift
            .formats
            .keys()
            .all(|format| matches!(format.as_str(), "patchgate.audit.v1" | "patchgate.audit.v2"))
}

fn audit_stream_contracts_are_clean(
    audits: &[AuditLogRecord],
    audits_v2: &[AuditLogV2Record],
) -> bool {
    audits.iter().all(|row| {
        (1..=10).contains(&row.schema_version) && row.audit_format == "patchgate.audit.v1"
    }) && audits_v2.iter().all(|row| {
        (2..=10).contains(&row.schema_version) && row.audit_format == "patchgate.audit.v2"
    })
}

fn fleet_repo_posture_label(
    metrics: &[MetricLogRecord],
    audits: &[AuditLogRecord],
    assessment: &CompatibilityAssessment,
) -> String {
    if metrics.is_empty() || audits.is_empty() {
        "telemetry-incomplete".to_string()
    } else {
        assessment.posture.as_str().to_string()
    }
}

fn bundle_retention_tier(entry: &FleetBundleEntry) -> String {
    entry.retention_tier.clone()
}

fn format_csv(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn provider_negotiation_statuses(
    catalog: Option<&FleetBundleCatalog>,
    provider_summaries: &[ProviderArtifactSummary],
) -> Vec<ProviderNegotiationStatus> {
    let Some(catalog) = catalog else {
        return Vec::new();
    };
    catalog
        .bundles
        .iter()
        .map(|entry| {
            let matching = provider_summaries
                .iter()
                .filter(|summary| summary.repo == entry.repo)
                .collect::<Vec<_>>();
            let provided_modes = matching
                .iter()
                .map(|summary| summary.schema_mode.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let provided_providers = matching
                .iter()
                .map(|summary| summary.provider.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let provided_capabilities = matching
                .iter()
                .flat_map(|summary| summary.capabilities.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let required_providers = entry.providers.clone();
            let required_modes = entry.required_provider_modes.clone();
            let required_capabilities = entry.required_provider_capabilities.clone();
            let provider_ready = required_providers.iter().all(|required| {
                provided_providers
                    .iter()
                    .any(|provider| provider == required)
            });
            let mode_ready = required_modes.is_empty()
                || provided_modes
                    .iter()
                    .any(|mode| required_modes.iter().any(|required| required == mode));
            let capability_ready = required_capabilities.iter().all(|required| {
                provided_capabilities
                    .iter()
                    .any(|capability| capability == required)
            });
            ProviderNegotiationStatus {
                repo: entry.repo.clone(),
                required_providers,
                provided_providers,
                required_modes,
                required_capabilities,
                provided_modes,
                provided_capabilities,
                ready: provider_ready && mode_ready && capability_ready,
            }
        })
        .collect()
}

fn segment_cost_statuses(
    segment_duration_ms: &BTreeMap<String, u128>,
    catalog: Option<&FleetBundleCatalog>,
    fallback_ceiling_minutes: Option<u64>,
) -> Vec<SegmentCostStatus> {
    let segment_policies = catalog
        .map(|catalog| {
            catalog
                .segments
                .iter()
                .map(|segment| (segment.segment.as_str(), segment.cost_ceiling_minutes))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    segment_duration_ms
        .iter()
        .map(|(segment, duration_ms)| {
            let ceiling_minutes = segment_policies
                .get(segment.as_str())
                .copied()
                .or(fallback_ceiling_minutes);
            let ceiling_minutes = active_cost_ceiling_minutes(ceiling_minutes);
            let actual_minutes = *duration_ms as f64 / 60_000.0;
            let ok = cost_within_ceiling(actual_minutes, ceiling_minutes);
            SegmentCostStatus {
                segment: segment.clone(),
                actual_minutes,
                ceiling_minutes,
                ok,
            }
        })
        .collect()
}

fn active_cost_ceiling_minutes(ceiling_minutes: Option<u64>) -> Option<u64> {
    ceiling_minutes.filter(|ceiling| *ceiling > 0)
}

fn cost_within_ceiling(actual_minutes: f64, ceiling_minutes: Option<u64>) -> bool {
    active_cost_ceiling_minutes(ceiling_minutes)
        .map_or(true, |ceiling| actual_minutes <= ceiling as f64)
}

fn repo_cost_ceiling_minutes(
    entry: Option<&FleetBundleEntry>,
    segment: &str,
    segment_cost_ceiling_by_name: &BTreeMap<String, u64>,
    fallback_ceiling_minutes: Option<u64>,
) -> Option<u64> {
    active_cost_ceiling_minutes(entry.and_then(|entry| entry.cost_ceiling_minutes))
        .or_else(|| active_cost_ceiling_minutes(segment_cost_ceiling_by_name.get(segment).copied()))
        .or_else(|| active_cost_ceiling_minutes(fallback_ceiling_minutes))
}

fn audit_v2_evidence_ready(repo_rows: &[FleetRepoRow], required: bool) -> bool {
    !required || repo_rows.iter().all(|row| row.audit_events_v2 > 0)
}

fn retention_tier_is_valid(tier: &AuditRetentionTierPolicy) -> bool {
    tier.hot_days > 0 && tier.hot_days <= tier.warm_days && tier.warm_days <= tier.cold_days
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn bundle_catalog_governance_ready(catalog: Option<&FleetBundleCatalog>) -> Option<bool> {
    catalog.map(|catalog| {
        let segment_names = catalog
            .segments
            .iter()
            .map(|segment| segment.segment.as_str())
            .collect::<BTreeSet<_>>();
        let tier_names = catalog
            .retention_tiers
            .iter()
            .map(|tier| tier.tier.as_str())
            .collect::<BTreeSet<_>>();
        let wave_names = catalog
            .rollout_waves
            .iter()
            .map(|wave| wave.wave.as_str())
            .collect::<BTreeSet<_>>();
        let bundle_repo_names = catalog
            .bundles
            .iter()
            .map(|entry| entry.repo.trim())
            .collect::<BTreeSet<_>>();
        let segments_valid = !catalog.segments.is_empty()
            && segment_names.len() == catalog.segments.len()
            && catalog.segments.iter().all(|segment| {
                non_empty(&segment.segment)
                    && non_empty(&segment.owner)
                    && non_empty(&segment.review_cadence)
                    && segment.cost_ceiling_minutes > 0
            });
        let retention_valid = !catalog.retention_tiers.is_empty()
            && tier_names.len() == catalog.retention_tiers.len()
            && catalog.retention_tiers.iter().all(retention_tier_is_valid);
        let waves_valid = !catalog.rollout_waves.is_empty()
            && wave_names.len() == catalog.rollout_waves.len()
            && catalog.rollout_waves.iter().all(|wave| {
                non_empty(&wave.wave)
                    && wave.order > 0
                    && wave.max_parallel > 0
                    && non_empty(&wave.entry_gate)
                    && non_empty(&wave.rollback_trigger)
            });
        let bundles_valid = !catalog.bundles.is_empty()
            && bundle_repo_names.len() == catalog.bundles.len()
            && catalog.bundles.iter().all(|entry| {
                non_empty(&entry.repo)
                    && non_empty(&entry.policy_bundle)
                    && !entry.providers.is_empty()
                    && entry.providers.iter().all(|provider| non_empty(provider))
                    && !entry.required_provider_modes.is_empty()
                    && !entry.required_provider_capabilities.is_empty()
                    && entry
                        .required_provider_capabilities
                        .iter()
                        .all(|capability| non_empty(capability))
                    && non_empty(&entry.retention_tier)
                    && segment_names.contains(entry.segment.as_str())
                    && wave_names.contains(entry.wave.as_str())
                    && tier_names.contains(bundle_retention_tier(entry).as_str())
                    && entry
                        .cost_ceiling_minutes
                        .map_or(true, |ceiling| ceiling > 0)
                    && entry
                        .required_provider_modes
                        .iter()
                        .all(|mode| matches!(mode.as_str(), "v1" | "v2" | "dual"))
            });
        catalog.schema_version > 0
            && ymd_key(&catalog.generated_at).is_some()
            && segments_valid
            && retention_valid
            && waves_valid
            && bundles_valid
    })
}

fn registry_provenance_ready(index: Option<&PluginRegistryIndex>) -> Option<bool> {
    index.map(|index| {
        index.schema_version > 0
            && !index.plugins.is_empty()
            && !index.trusted_provenance.is_empty()
            && index
                .trusted_provenance
                .iter()
                .all(|provenance| !provenance.trim().is_empty())
            && index.plugins.iter().all(|plugin| {
                plugin.verified
                    && !plugin.revoked
                    && !plugin.plugin_id.trim().is_empty()
                    && !plugin.version.trim().is_empty()
                    && !plugin.owner.trim().is_empty()
                    && !plugin.provenance.trim().is_empty()
                    && !plugin.source_repo.trim().is_empty()
                    && !plugin.digest.trim().is_empty()
                    && !plugin.attestation.trim().is_empty()
                    && !plugin.sandbox_profile.trim().is_empty()
                    && !plugin.allowed_segments.is_empty()
                    && plugin
                        .allowed_segments
                        .iter()
                        .all(|segment| !segment.trim().is_empty())
                    && index
                        .trusted_provenance
                        .iter()
                        .any(|trusted| trusted == &plugin.provenance)
            })
    })
}

fn ymd_key(raw: &str) -> Option<(u16, u8, u8)> {
    let trimmed = raw.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() < 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[..10]
            .iter()
            .enumerate()
            .all(|(idx, byte)| idx == 4 || idx == 7 || byte.is_ascii_digit())
    {
        return None;
    }
    let year = parse_ascii_u16(&bytes[0..4])?;
    let month = parse_ascii_u8(&bytes[5..7])?;
    let day = parse_ascii_u8(&bytes[8..10])?;
    if month == 0 || month > 12 {
        return None;
    }
    let max_day = days_in_month(year, month)?;
    if day == 0 || day > max_day {
        return None;
    }
    Some((year, month, day))
}

fn parse_ascii_u16(bytes: &[u8]) -> Option<u16> {
    bytes.iter().try_fold(0u16, |acc, byte| {
        byte.is_ascii_digit()
            .then_some(acc * 10 + u16::from(*byte - b'0'))
    })
}

fn parse_ascii_u8(bytes: &[u8]) -> Option<u8> {
    bytes.iter().try_fold(0u8, |acc, byte| {
        byte.is_ascii_digit().then_some(acc * 10 + (*byte - b'0'))
    })
}

fn days_in_month(year: u16, month: u8) -> Option<u8> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    })
}

fn is_leap_year(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn exception_is_expired(expires_at: &str, reviewed_at: &str) -> Option<bool> {
    let expires = ymd_key(expires_at)?;
    let reviewed = ymd_key(reviewed_at)?;
    Some(expires < reviewed)
}

fn exception_governance_statuses(
    packet: Option<&GovernanceExceptionsPacket>,
) -> Vec<ExceptionGovernanceStatus> {
    let Some(packet) = packet else {
        return Vec::new();
    };
    packet
        .exceptions
        .iter()
        .map(|entry| {
            let status = entry.status.clone();
            let expired = exception_is_expired(&entry.expires_at, &packet.reviewed_at);
            let valid_status = matches!(status.as_str(), "approved" | "active" | "temporary");
            let valid = valid_status
                && expired == Some(false)
                && !entry.repo.trim().is_empty()
                && !entry.kind.trim().is_empty()
                && !entry.scope.trim().is_empty()
                && !entry.approved_by.trim().is_empty()
                && !entry.ticket.trim().is_empty()
                && !entry.owner.trim().is_empty()
                && !entry.segment.trim().is_empty()
                && !entry.review_cadence.trim().is_empty();
            ExceptionGovernanceStatus {
                repo: entry.repo.clone(),
                kind: entry.kind.clone(),
                scope: entry.scope.clone(),
                approved_by: entry.approved_by.clone(),
                ticket: entry.ticket.clone(),
                owner: entry.owner.clone(),
                segment: entry.segment.clone(),
                status,
                review_cadence: entry.review_cadence.clone(),
                expires_at: entry.expires_at.clone(),
                expired,
                valid,
            }
        })
        .collect()
}

fn run_fleet_review(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audits_v2 = options
        .audit_v2_input
        .as_deref()
        .map(load_jsonl_records::<AuditLogV2Record>)
        .transpose()?
        .unwrap_or_default();
    let replay_summary = options
        .replay_summary_input
        .as_deref()
        .map(load_json_file::<DeadLetterReplaySummaryRecord>)
        .transpose()?;
    let bundle_catalog = options
        .bundle_catalog_input
        .as_deref()
        .map(load_json_file::<FleetBundleCatalog>)
        .transpose()?;
    let registry = options
        .registry_input
        .as_deref()
        .map(load_json_file::<PluginRegistryIndex>)
        .transpose()?;
    let exceptions = options
        .exceptions_input
        .as_deref()
        .map(load_json_file::<GovernanceExceptionsPacket>)
        .transpose()?;
    let provider_summaries = summarize_provider_inputs(&options.provider_inputs)?;

    let mut repo_names = BTreeSet::<String>::new();
    repo_names.extend(metrics.iter().map(|row| row.repo.clone()));
    repo_names.extend(audits.iter().map(|row| row.repo.clone()));
    repo_names.extend(audits_v2.iter().map(|row| row.repo.clone()));
    if let Some(catalog) = bundle_catalog.as_ref() {
        repo_names.extend(catalog.bundles.iter().map(|row| row.repo.clone()));
    }
    repo_names.extend(provider_summaries.iter().map(|row| row.repo.clone()));

    let mut posture_counts = BTreeMap::<String, usize>::new();
    let mut segment_duration_ms = BTreeMap::<String, u128>::new();
    let mut repo_rows = Vec::new();
    let mut incomplete_telemetry_repos = 0usize;
    let use_global_replay = repo_names.len() <= 1;
    let mut metrics_by_repo = BTreeMap::<String, Vec<MetricLogRecord>>::new();
    let mut audits_by_repo = BTreeMap::<String, Vec<AuditLogRecord>>::new();
    let mut audits_v2_by_repo = BTreeMap::<String, Vec<AuditLogV2Record>>::new();
    for row in &metrics {
        metrics_by_repo
            .entry(row.repo.clone())
            .or_default()
            .push(row.clone());
    }
    for row in &audits {
        audits_by_repo
            .entry(row.repo.clone())
            .or_default()
            .push(row.clone());
    }
    for row in &audits_v2 {
        audits_v2_by_repo
            .entry(row.repo.clone())
            .or_default()
            .push(row.clone());
    }
    let bundle_map = bundle_catalog
        .as_ref()
        .map(|catalog| {
            catalog
                .bundles
                .iter()
                .map(|entry| (entry.repo.as_str(), entry))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let segment_cost_ceiling_by_name = bundle_catalog
        .as_ref()
        .map(|catalog| {
            catalog
                .segments
                .iter()
                .map(|segment| (segment.segment.clone(), segment.cost_ceiling_minutes))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let empty_metrics: &[MetricLogRecord] = &[];
    let empty_audits: &[AuditLogRecord] = &[];
    let empty_audits_v2: &[AuditLogV2Record] = &[];

    for repo in &repo_names {
        let repo_metrics = metrics_by_repo
            .get(repo)
            .map(Vec::as_slice)
            .unwrap_or(empty_metrics);
        let repo_audits = audits_by_repo
            .get(repo)
            .map(Vec::as_slice)
            .unwrap_or(empty_audits);
        let repo_audits_v2 = audits_v2_by_repo
            .get(repo)
            .map(Vec::as_slice)
            .unwrap_or(empty_audits_v2);
        let assessment = build_compatibility_assessment(
            repo_metrics,
            repo_audits,
            if use_global_replay {
                replay_summary.clone()
            } else {
                None
            },
            options.availability_target_pct,
            options.p95_target_ms,
            options.false_positive_target_pct,
        );
        let posture_label = fleet_repo_posture_label(repo_metrics, repo_audits, &assessment);
        if posture_label == "telemetry-incomplete" {
            incomplete_telemetry_repos += 1;
        }
        *posture_counts.entry(posture_label.clone()).or_insert(0) += 1;
        let total_duration_ms = repo_metrics.iter().map(|row| row.duration_ms).sum::<u128>();
        let ci_minutes = total_duration_ms as f64 / 60_000.0;
        let segment = bundle_map
            .get(repo.as_str())
            .map(|entry| entry.segment.clone())
            .unwrap_or_else(|| "default".to_string());
        *segment_duration_ms.entry(segment.clone()).or_insert(0) += total_duration_ms;
        let average_score = average_metric_score(repo_metrics);
        let gate_failures = repo_metrics
            .iter()
            .filter(|row| row.should_fail.unwrap_or(false))
            .count();
        let (wave, retention_tier) = bundle_map
            .get(repo.as_str())
            .map(|entry| (entry.wave.clone(), bundle_retention_tier(entry)))
            .unwrap_or_else(|| ("unassigned".to_string(), "standard".to_string()));
        let repo_cost_ceiling_minutes = repo_cost_ceiling_minutes(
            bundle_map.get(repo.as_str()).copied(),
            segment.as_str(),
            &segment_cost_ceiling_by_name,
            options.cost_ceiling_minutes,
        );
        let repo_cost_ok = cost_within_ceiling(ci_minutes, repo_cost_ceiling_minutes);
        repo_rows.push(FleetRepoRow {
            repo: repo.clone(),
            posture: posture_label,
            runs: repo_metrics.len(),
            audit_events_v1: repo_audits.len(),
            audit_events_v2: repo_audits_v2.len(),
            gate_failures,
            average_score,
            ci_minutes,
            segment,
            wave,
            retention_tier,
            repo_cost_ceiling_minutes,
            repo_cost_ok,
        });
    }

    let estimated_ci_minutes = metrics
        .iter()
        .map(|row| row.duration_ms as f64)
        .sum::<f64>()
        / 60_000.0;
    let cost_ceiling_minutes = options.cost_ceiling_minutes.unwrap_or(0);
    let cost_ceiling_ok =
        cost_ceiling_minutes == 0 || estimated_ci_minutes <= cost_ceiling_minutes as f64;

    let mut provider_mode_counts = BTreeMap::<String, usize>::new();
    for summary in &provider_summaries {
        *provider_mode_counts
            .entry(summary.schema_mode.clone())
            .or_insert(0) += 1;
    }
    let provider_negotiations =
        provider_negotiation_statuses(bundle_catalog.as_ref(), &provider_summaries);
    let provider_negotiation_ready =
        provider_negotiations.is_empty() || provider_negotiations.iter().all(|status| status.ready);
    let segment_cost_rows = segment_cost_statuses(
        &segment_duration_ms,
        bundle_catalog.as_ref(),
        options.cost_ceiling_minutes,
    );
    let segment_cost_ok = segment_cost_rows.iter().all(|row| row.ok);
    let repo_cost_ok = repo_rows.iter().all(|row| row.repo_cost_ok);
    let audit_v2_ready = audit_v2_evidence_ready(&repo_rows, options.audit_v2_input.is_some());
    let retention_ready = bundle_catalog.as_ref().map(|catalog| {
        let tier_names = catalog
            .retention_tiers
            .iter()
            .map(|tier| tier.tier.as_str())
            .collect::<BTreeSet<_>>();
        let tiers_valid = catalog.retention_tiers.iter().all(retention_tier_is_valid);
        let assignments_valid = catalog.bundles.iter().all(|entry| {
            let tier = bundle_retention_tier(entry);
            tier_names.contains(tier.as_str())
        });
        tiers_valid && assignments_valid
    });
    let catalog_governance_ready = bundle_catalog_governance_ready(bundle_catalog.as_ref());
    let registry_ready = registry_provenance_ready(registry.as_ref());
    let exception_statuses = exception_governance_statuses(exceptions.as_ref());
    let exception_packet_ready = exceptions
        .as_ref()
        .map(|packet| packet.schema_version > 0 && ymd_key(&packet.reviewed_at).is_some())
        .unwrap_or(true);
    let exception_ready = exception_packet_ready
        && (exception_statuses.is_empty() || exception_statuses.iter().all(|status| status.valid));
    let audit_drift_clean = {
        let drift = build_combined_audit_drift_summary(&audits, &audits_v2);
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2)
    };
    let governance_ready = !repo_names.is_empty()
        && incomplete_telemetry_repos == 0
        && cost_ceiling_ok
        && repo_cost_ok
        && segment_cost_ok
        && audit_v2_ready
        && provider_negotiation_ready
        && catalog_governance_ready.unwrap_or(true)
        && retention_ready.unwrap_or(true)
        && registry_ready.unwrap_or(true)
        && exception_ready
        && audit_drift_clean;

    let mut md = String::new();
    md.push_str("# Fleet Ops Review Packet\n\n");
    md.push_str(&format!("- governance_ready: {}\n", governance_ready));
    md.push_str(&format!("- repos_seen: {}\n", repo_names.len()));
    md.push_str(&format!("- metrics_runs: {}\n", metrics.len()));
    md.push_str(&format!("- audit_events_v1: {}\n", audits.len()));
    md.push_str(&format!("- audit_events_v2: {}\n", audits_v2.len()));
    md.push_str(&format!(
        "- provider_artifacts: {}\n",
        provider_summaries.len()
    ));
    md.push_str(&format!(
        "- estimated_ci_minutes: {:.2}\n",
        estimated_ci_minutes
    ));
    if cost_ceiling_minutes > 0 {
        md.push_str(&format!(
            "- cost_ceiling_minutes: {} (ok={})\n",
            cost_ceiling_minutes, cost_ceiling_ok
        ));
    }
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!("- audit_v2_evidence_ready: {}\n", audit_v2_ready));
    md.push_str(&format!(
        "- provider_negotiation_ready: {}\n",
        provider_negotiation_ready
    ));
    md.push_str(&format!("- repo_cost_ok: {}\n", repo_cost_ok));
    md.push_str(&format!("- segment_cost_ok: {}\n", segment_cost_ok));
    md.push_str(&format!(
        "- registry_provenance_ready: {}\n",
        optional_bool_label(registry_ready)
    ));
    md.push_str(&format!(
        "- retention_policy_ready: {}\n",
        optional_bool_label(retention_ready)
    ));
    md.push_str(&format!(
        "- catalog_governance_ready: {}\n",
        optional_bool_label(catalog_governance_ready)
    ));
    md.push_str(&format!(
        "- exception_governance_ready: {}\n",
        exception_ready
    ));
    if let Some(catalog) = bundle_catalog.as_ref() {
        md.push_str(&format!(
            "- bundle_catalog_schema_version: {}\n",
            catalog.schema_version
        ));
    }
    if let Some(index) = registry.as_ref() {
        md.push_str(&format!(
            "- plugin_registry_schema_version: {}\n",
            index.schema_version
        ));
    }
    if let Some(packet) = exceptions.as_ref() {
        md.push_str(&format!(
            "- exceptions_schema_version: {}\n",
            packet.schema_version
        ));
    }
    md.push('\n');

    md.push_str("## Repo Posture\n");
    if repo_rows.is_empty() {
        md.push_str("- none\n");
    } else {
        repo_rows.sort_by(|left, right| left.repo.cmp(&right.repo));
        for row in &repo_rows {
            md.push_str(&format!(
                "- {}: posture=`{}` runs={} audit_v1={} audit_v2={} gate_failures={} avg_score={:.2} ci_minutes={:.2} repo_cost_ceiling={} repo_cost_ok={} segment={} wave={} retention={}\n",
                row.repo,
                row.posture,
                row.runs,
                row.audit_events_v1,
                row.audit_events_v2,
                row.gate_failures,
                row.average_score,
                row.ci_minutes,
                row.repo_cost_ceiling_minutes
                    .map(|ceiling| ceiling.to_string())
                    .unwrap_or_else(|| "segment-default".to_string()),
                row.repo_cost_ok,
                row.segment,
                row.wave,
                row.retention_tier
            ));
        }
    }

    md.push_str("\n## Posture Counts\n");
    if posture_counts.is_empty() {
        md.push_str("- none\n");
    } else {
        for (posture, count) in posture_counts {
            md.push_str(&format!("- {posture}: {count}\n"));
        }
    }

    md.push_str("\n## Bundle Catalog\n");
    if let Some(catalog) = bundle_catalog.as_ref() {
        if !catalog.generated_at.trim().is_empty() {
            md.push_str(&format!("- generated_at: {}\n", catalog.generated_at));
        }
        if catalog.bundles.is_empty() {
            md.push_str("- none\n");
        } else {
            for entry in &catalog.bundles {
                md.push_str(&format!(
                    "- repo={} bundle={} wave={} segment={} retention={} repo_cost_ceiling={} providers={} required_modes={} required_capabilities={} phase181_rc_candidate={}\n",
                    entry.repo,
                    entry.policy_bundle,
                    entry.wave,
                    entry.segment,
                    bundle_retention_tier(entry),
                    entry
                        .cost_ceiling_minutes
                        .map(|ceiling| ceiling.to_string())
                        .unwrap_or_else(|| "segment-default".to_string()),
                    format_csv(&entry.providers),
                    format_csv(&entry.required_provider_modes),
                    format_csv(&entry.required_provider_capabilities),
                    entry.phase181_rc_candidate
                ));
            }
        }
    } else {
        md.push_str("- not provided\n");
    }

    md.push_str("\n## Federated Aggregation\n");
    md.push_str(&format!(
        "- audit_stream_contracts_clean: {}\n",
        audit_stream_contracts_are_clean(&audits, &audits_v2)
    ));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    for row in &repo_rows {
        md.push_str(&format!(
            "- repo={} segment={} wave={} metrics={} audit_v1={} audit_v2={}\n",
            row.repo, row.segment, row.wave, row.runs, row.audit_events_v1, row.audit_events_v2
        ));
    }

    md.push_str("\n## Provider Capability\n");
    if provider_mode_counts.is_empty() {
        md.push_str("- not provided\n");
    } else {
        for (mode, count) in provider_mode_counts {
            md.push_str(&format!("- {mode}: {count}\n"));
        }
        for summary in &provider_summaries {
            let capabilities = summary.capabilities.iter().cloned().collect::<Vec<_>>();
            md.push_str(&format!(
                "- artifact repo={} provider={} schema_mode={} capabilities={}\n",
                summary.repo,
                summary.provider,
                summary.schema_mode,
                format_csv(&capabilities)
            ));
        }
    }
    if !provider_negotiations.is_empty() {
        md.push_str("\n### Negotiation Contract\n");
        for status in &provider_negotiations {
            md.push_str(&format!(
                "- repo={} ready={} required_providers={} provided_providers={} required_modes={} provided_modes={} required_capabilities={} provided_capabilities={}\n",
                status.repo,
                status.ready,
                format_csv(&status.required_providers),
                format_csv(&status.provided_providers),
                format_csv(&status.required_modes),
                format_csv(&status.provided_modes),
                format_csv(&status.required_capabilities),
                format_csv(&status.provided_capabilities)
            ));
        }
    }

    md.push_str("\n## Registry Provenance\n");
    if let Some(index) = registry.as_ref() {
        let verified = index
            .plugins
            .iter()
            .filter(|plugin| plugin.verified)
            .count();
        md.push_str(&format!(
            "- provenance_ready: {}\n",
            registry_ready.unwrap_or(false)
        ));
        if !index.trusted_provenance.is_empty() {
            md.push_str(&format!(
                "- trusted_provenance: {}\n",
                format_csv(&index.trusted_provenance)
            ));
        }
        md.push_str(&format!(
            "- verified_plugins: {}/{}\n",
            verified,
            index.plugins.len()
        ));
        for plugin in &index.plugins {
            let provenance_trusted = index
                .trusted_provenance
                .iter()
                .any(|trusted| trusted == &plugin.provenance);
            md.push_str(&format!(
                "- {}@{} owner={} source_repo={} provenance={} trusted={} verified={} revoked={} digest_present={} attestation_present={} sandbox={} allowed_segments={}\n",
                plugin.plugin_id,
                plugin.version,
                plugin.owner,
                plugin.source_repo,
                plugin.provenance,
                provenance_trusted,
                plugin.verified,
                plugin.revoked,
                !plugin.digest.trim().is_empty(),
                !plugin.attestation.trim().is_empty(),
                if plugin.sandbox_profile.trim().is_empty() {
                    "unspecified"
                } else {
                    plugin.sandbox_profile.as_str()
                },
                format_csv(&plugin.allowed_segments)
            ));
        }
    } else {
        md.push_str("- not provided\n");
    }

    md.push_str("\n## Exception Governance\n");
    if let Some(packet) = exceptions.as_ref() {
        if !packet.reviewed_at.trim().is_empty() {
            md.push_str(&format!("- reviewed_at: {}\n", packet.reviewed_at));
        }
        if packet.exceptions.is_empty() {
            md.push_str("- none\n");
        } else {
            for status in &exception_statuses {
                md.push_str(&format!(
                    "- repo={} kind={} scope={} ticket={} owner={} segment={} approved_by={} status={} review_cadence={} expires_at={} expired={} valid={}\n",
                    status.repo,
                    status.kind,
                    status.scope,
                    status.ticket,
                    status.owner,
                    if status.segment.trim().is_empty() {
                        "unspecified"
                    } else {
                        status.segment.as_str()
                    },
                    status.approved_by,
                    status.status,
                    if status.review_cadence.trim().is_empty() {
                        "unspecified"
                    } else {
                        status.review_cadence.as_str()
                    },
                    status.expires_at,
                    optional_bool_label(status.expired),
                    status.valid
                ));
            }
        }
    } else {
        md.push_str("- not provided\n");
    }

    md.push_str("\n## Audit Retention Tier\n");
    if let Some(catalog) = bundle_catalog.as_ref() {
        if catalog.retention_tiers.is_empty() {
            md.push_str("- not provided\n");
        } else {
            for tier in &catalog.retention_tiers {
                md.push_str(&format!(
                    "- tier={} hot={}d warm={}d cold={}d valid={}\n",
                    tier.tier,
                    tier.hot_days,
                    tier.warm_days,
                    tier.cold_days,
                    retention_tier_is_valid(tier)
                ));
            }
        }
        for entry in &catalog.bundles {
            md.push_str(&format!(
                "- repo={} retention_tier={}\n",
                entry.repo,
                bundle_retention_tier(entry)
            ));
        }
    } else if audits.len() + audits_v2.len() >= 100 {
        md.push_str("- fallback_hot: 7d\n- fallback_warm: 30d\n- fallback_cold: 90d\n");
    } else {
        md.push_str("- fallback_hot: 14d\n- fallback_warm: 60d\n- fallback_cold: 180d\n");
    }

    md.push_str("\n## Segment Cost\n");
    if let Some(catalog) = bundle_catalog.as_ref() {
        for segment in &catalog.segments {
            md.push_str(&format!(
                "- policy segment={} owner={} ceiling={} review_cadence={}\n",
                segment.segment,
                segment.owner,
                segment.cost_ceiling_minutes,
                segment.review_cadence
            ));
        }
    }
    if segment_cost_rows.is_empty() {
        md.push_str("- none\n");
    } else {
        for row in &segment_cost_rows {
            md.push_str(&format!(
                "- {}: actual={:.2} ceiling={} ok={}\n",
                row.segment,
                row.actual_minutes,
                row.ceiling_minutes
                    .map(|ceiling| ceiling.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                row.ok
            ));
        }
    }
    md.push_str("\n## Repo Cost\n");
    if repo_rows.is_empty() {
        md.push_str("- none\n");
    } else {
        for row in &repo_rows {
            md.push_str(&format!(
                "- repo={} actual={:.2} ceiling={} ok={}\n",
                row.repo,
                row.ci_minutes,
                row.repo_cost_ceiling_minutes
                    .map(|ceiling| ceiling.to_string())
                    .unwrap_or_else(|| "segment-default".to_string()),
                row.repo_cost_ok
            ));
        }
    }

    md.push_str("\n## Rollout Waves\n");
    if let Some(catalog) = bundle_catalog.as_ref() {
        if catalog.rollout_waves.is_empty() {
            md.push_str("- not provided\n");
        } else {
            let mut waves = catalog.rollout_waves.clone();
            waves.sort_by_key(|wave| wave.order);
            for wave in &waves {
                let repos = catalog
                    .bundles
                    .iter()
                    .filter(|entry| entry.wave == wave.wave)
                    .map(|entry| entry.repo.clone())
                    .collect::<Vec<_>>();
                md.push_str(&format!(
                    "- wave={} order={} max_parallel={} repos={} entry_gate={} rollback_trigger={}\n",
                    wave.wave,
                    wave.order,
                    wave.max_parallel,
                    format_csv(&repos),
                    wave.entry_gate,
                    wave.rollback_trigger
                ));
            }
            let known_waves = catalog
                .rollout_waves
                .iter()
                .map(|wave| wave.wave.as_str())
                .collect::<BTreeSet<_>>();
            let unknown_waves = catalog
                .bundles
                .iter()
                .filter(|entry| !known_waves.contains(entry.wave.as_str()))
                .map(|entry| entry.wave.clone())
                .collect::<BTreeSet<_>>();
            if !unknown_waves.is_empty() {
                let unknown = unknown_waves.into_iter().collect::<Vec<_>>();
                md.push_str(&format!("- unknown_waves: {}\n", format_csv(&unknown)));
            }
        }
    } else {
        md.push_str("- not provided\n");
    }

    md.push_str("\n## Phase181+ RC Prep Review\n");
    let provider_status_by_repo = provider_negotiations
        .iter()
        .map(|status| (status.repo.as_str(), status.ready))
        .collect::<BTreeMap<_, _>>();
    let segment_cost_by_name = segment_cost_rows
        .iter()
        .map(|row| (row.segment.as_str(), row.ok))
        .collect::<BTreeMap<_, _>>();
    let invalid_exception_repos = exception_statuses
        .iter()
        .filter(|status| !status.valid)
        .map(|status| status.repo.as_str())
        .collect::<BTreeSet<_>>();
    let candidate_repos = bundle_catalog
        .as_ref()
        .map(|catalog| {
            catalog
                .bundles
                .iter()
                .filter(|entry| entry.phase181_rc_candidate)
                .map(|entry| entry.repo.clone())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut phase181_rows = 0usize;
    for row in &repo_rows {
        if !candidate_repos.contains(row.repo.as_str()) && row.posture != "start-v2-seed" {
            continue;
        }
        phase181_rows += 1;
        let provider_ready = provider_status_by_repo
            .get(row.repo.as_str())
            .copied()
            .unwrap_or(provider_negotiations.is_empty());
        let cost_ready = segment_cost_by_name
            .get(row.segment.as_str())
            .copied()
            .unwrap_or(true);
        let mut blockers = Vec::new();
        if row.runs == 0 || row.audit_events_v1 == 0 {
            blockers.push("telemetry-incomplete".to_string());
        }
        if row.audit_events_v2 == 0 {
            blockers.push("audit-v2-missing".to_string());
        }
        if !provider_ready {
            blockers.push("provider-negotiation".to_string());
        }
        if !cost_ready {
            blockers.push("segment-cost".to_string());
        }
        if !row.repo_cost_ok {
            blockers.push("repo-cost".to_string());
        }
        if invalid_exception_repos.contains(row.repo.as_str()) {
            blockers.push("exception-governance".to_string());
        }
        if registry_ready == Some(false) {
            blockers.push("registry-provenance".to_string());
        }
        if catalog_governance_ready == Some(false) {
            blockers.push("bundle-catalog".to_string());
        }
        md.push_str(&format!(
            "- repo={} prep={} next_packet={} blockers={}\n",
            row.repo,
            if blockers.is_empty() {
                "ready"
            } else {
                "blocked"
            },
            if blockers.is_empty() {
                "phase181-rc-hardening"
            } else {
                "fleet-review-remediation"
            },
            format_csv(&blockers)
        ));
    }
    if phase181_rows == 0 {
        md.push_str("- no RC-prep candidate repos yet\n");
    }

    md.push_str("\n## Review Notes\n");
    if !cost_ceiling_ok {
        md.push_str("- Estimated CI minutes exceed the configured fleet cost ceiling.\n");
    }
    if !segment_cost_ok {
        md.push_str("- One or more segments exceed their configured CI cost ceiling.\n");
    }
    if !repo_cost_ok {
        md.push_str("- One or more repos exceed their configured bundle cost ceiling.\n");
    }
    if !provider_negotiation_ready {
        md.push_str(
            "- Provider capability negotiation is incomplete for at least one cataloged repo.\n",
        );
    }
    if registry_ready == Some(false) {
        md.push_str(
            "- Registry provenance has unverified, revoked, or incomplete plugin entries.\n",
        );
    }
    if retention_ready == Some(false) {
        md.push_str(
            "- Audit retention tiers or repo assignments need correction before RC prep.\n",
        );
    }
    if catalog_governance_ready == Some(false) {
        md.push_str("- Bundle catalog has missing segments, retention tiers, rollout waves, or invalid repo assignments.\n");
    }
    if !exception_ready {
        md.push_str("- Exception governance has expired or incomplete approvals.\n");
    }
    if !audit_drift_clean {
        md.push_str("- Federated audit aggregation is not clean; inspect schema, format, result, and failure code drift.\n");
    }
    if !audit_v2_ready {
        md.push_str(
            "- One or more repos are missing audit v2 evidence while audit v2 input is required.\n",
        );
    }
    if provider_summaries.iter().all(|row| row.schema_mode == "v1")
        && !provider_summaries.is_empty()
    {
        md.push_str("- Provider artifacts are still v1-only; keep rollout in canary until dual or v2 payloads appear.\n");
    }
    if repo_names.is_empty() {
        md.push_str("- Collect at least one repo telemetry stream before using this packet for governance.\n");
    } else if incomplete_telemetry_repos > 0 {
        md.push_str("- Some repos have incomplete telemetry; attach both metrics and audit streams before treating posture as a rollout signal.\n");
    } else if governance_ready {
        md.push_str("- Fleet cost remains within ceiling; continue wave-based rollout review.\n");
    }

    write_output(&options.output, md.as_str())?;
    println!("fleet review packet written: {}", options.output.display());
    Ok(())
}

fn run_rc_readiness(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = options
        .audit_v2_input
        .as_deref()
        .ok_or_else(|| anyhow!("--audit-v2-input is required for rc-readiness"))?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let replay_summary = options
        .replay_summary_input
        .as_deref()
        .map(load_json_file::<DeadLetterReplaySummaryRecord>)
        .transpose()?;
    let assessment = build_compatibility_assessment(
        &metrics,
        &audits,
        replay_summary.clone(),
        options.availability_target_pct,
        options.p95_target_ms,
        options.false_positive_target_pct,
    );
    let scoreboard = build_freeze_scoreboard(&metrics, &audits, &assessment);
    let shadow = build_shadow_alignment(&audits, &audits_v2);
    let drift = build_combined_audit_drift_summary(&audits, &audits_v2);
    let audit_export_v2_validation = validate_audit_export_v2(&audits, &audits_v2);
    let benchmark_signoff = options
        .benchmark_input
        .as_deref()
        .map(load_json_file::<BenchCompareReport>)
        .transpose()?
        .map(|report| !report.regressed)
        .unwrap_or(false);
    let security_review_present = path_exists(options.security_review_input.as_deref());
    let security_review_approved =
        security_review_is_approved(options.security_review_input.as_deref())?;
    let security_review_packet_ready =
        security_review_packet_ready(options.security_review_input.as_deref())?;
    let contract_freeze_ready =
        contract_freeze_input_ready(options.contract_freeze_input.as_deref())?;
    let migration_drill_artifact_ready =
        migration_drill_ready(options.migration_drill_input.as_deref())?;
    let rollback_packet_input_ready =
        rollback_packet_input_ready(options.rollback_packet_input.as_deref())?;
    let fleet_cost_signoff =
        fleet_review_cost_signoff_ready(options.fleet_review_input.as_deref())?;
    let benchmark_cost_signoff = benchmark_signoff && fleet_cost_signoff;
    let migration_guide_present = path_exists(options.migration_guide_path.as_deref());
    let provider_rollout_present = path_exists(options.provider_rollout_path.as_deref());
    let candidate_checklist_present = path_exists(options.candidate_checklist_path.as_deref());
    let candidate_checklist_ready =
        candidate_checklist_ready(options.candidate_checklist_path.as_deref())?;
    let freeze_boundary_present = path_exists(options.freeze_boundary_path.as_deref());
    let deprecation_countdown_ready =
        deprecation_countdown_markers_ready(options.sunset_notice_path.as_deref())?;
    let provider_summaries = summarize_provider_inputs(&options.provider_inputs)?;
    let candidate_repos = candidate_repos(&metrics, &audits);
    let provider_bridge_ready =
        provider_bridge_ready_for_repos(&provider_summaries, &candidate_repos);
    let audit_drift_clean =
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2);
    let migration_drill_clean = replay_summary.as_ref().is_some_and(|summary| {
        !summary.dry_run
            && summary.rewrite_input
            && summary.failed_records == 0
            && summary.retained_records == 0
    }) && migration_drill_artifact_ready;
    let rollback_packet_ready = migration_drill_clean
        && shadow.aligned
        && candidate_checklist_ready
        && rollback_packet_input_ready;
    let deprecation_window_days = 90u16;
    let rc_ready = scoreboard.v2_seed_ready
        && contract_freeze_ready
        && audit_drift_clean
        && audit_export_v2_validation.ready
        && shadow.aligned
        && provider_bridge_ready
        && benchmark_cost_signoff
        && security_review_packet_ready
        && migration_guide_present
        && provider_rollout_present
        && candidate_checklist_ready
        && freeze_boundary_present
        && deprecation_countdown_ready
        && rollback_packet_ready;

    let mut next_actions = assessment.next_actions.clone();
    let mut seen_actions = next_actions.iter().cloned().collect::<BTreeSet<_>>();
    if !provider_bridge_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Generate at least one dual/v2 provider artifact for the candidate repo before RC sign-off.".to_string(),
        );
    }
    if !benchmark_signoff {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach a non-regressing benchmark compare artifact for RC sign-off.".to_string(),
        );
    }
    if !fleet_cost_signoff {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach a fleet-review artifact with governance, repo cost, and segment cost green."
                .to_string(),
        );
    }
    if !security_review_present {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach the RC security review packet before promoting the candidate.".to_string(),
        );
    } else if !security_review_packet_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Complete the RC security review packet with inputs, criteria, checked Continue, and unchecked Mitigation required.".to_string(),
        );
    }
    if !contract_freeze_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach an enforced diff-contract JSON artifact with v1 frozen and v2 bridge enabled."
                .to_string(),
        );
    }
    if !audit_export_v2_validation.ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Regenerate audit v2 export until schema, format, event identity, gate fields, and v1/v2 sets validate.".to_string(),
        );
    }
    if !migration_drill_artifact_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach a non-dry-run large-scale migration drill artifact with zero failed repos and rollback rehearsal.".to_string(),
        );
    }
    if !rollback_packet_input_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach a rollback packet that restores bridge_mode=off, generic_schema=v1, and retains audit v1/v2 evidence.".to_string(),
        );
    }
    if !deprecation_countdown_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach the v1 sunset notice with +30/+60/+90 deprecation countdown markers."
                .to_string(),
        );
    }
    if !candidate_checklist_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Update the v2 candidate checklist with PR181-PR190 RC hardening markers.".to_string(),
        );
    }
    if !migration_guide_present
        || !provider_rollout_present
        || !candidate_checklist_present
        || !freeze_boundary_present
    {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Sync migration guide, provider rollout checklist, candidate checklist, and freeze boundary paths.".to_string(),
        );
    }

    let mut md = String::new();
    md.push_str("# V2 RC Readiness Packet\n\n");
    md.push_str(&format!("- rc_ready: {}\n", rc_ready));
    md.push_str(&format!("- posture: `{}`\n", assessment.posture.as_str()));
    md.push_str(&format!(
        "- deprecation_window_days: {}\n",
        deprecation_window_days
    ));
    md.push_str(&format!(
        "- contract_freeze_ready: {}\n",
        contract_freeze_ready
    ));
    md.push_str(&format!("- shadow_aligned: {}\n", shadow.aligned));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!(
        "- audit_export_v2_valid: {}\n",
        audit_export_v2_validation.ready
    ));
    md.push_str(&format!(
        "- provider_bridge_ready: {}\n",
        provider_bridge_ready
    ));
    md.push_str(&format!("- benchmark_signoff: {}\n", benchmark_signoff));
    md.push_str(&format!("- fleet_cost_signoff: {}\n", fleet_cost_signoff));
    md.push_str(&format!(
        "- benchmark_cost_signoff: {}\n",
        benchmark_cost_signoff
    ));
    md.push_str(&format!(
        "- security_review_present: {}\n",
        security_review_present
    ));
    md.push_str(&format!(
        "- security_review_approved: {}\n",
        security_review_approved
    ));
    md.push_str(&format!(
        "- security_review_packet_ready: {}\n",
        security_review_packet_ready
    ));
    md.push_str(&format!(
        "- migration_drill_artifact_ready: {}\n",
        migration_drill_artifact_ready
    ));
    md.push_str(&format!(
        "- migration_drill_clean: {}\n",
        migration_drill_clean
    ));
    md.push_str(&format!(
        "- rollback_packet_input_ready: {}\n",
        rollback_packet_input_ready
    ));
    md.push_str(&format!(
        "- rollback_packet_ready: {}\n",
        rollback_packet_ready
    ));
    md.push_str(&format!(
        "- deprecation_countdown_ready: {}\n",
        deprecation_countdown_ready
    ));
    md.push_str(&format!(
        "- candidate_checklist_ready: {}\n",
        candidate_checklist_ready
    ));
    md.push_str(&format!(
        "- freeze_boundary_present: {}\n\n",
        freeze_boundary_present
    ));

    md.push_str("## Checklist\n");
    md.push_str(&format!(
        "- {} v2 seed readiness passes\n",
        checklist_box(scoreboard.v2_seed_ready)
    ));
    md.push_str(&format!(
        "- {} v2 RC contract freeze is enforced\n",
        checklist_box(contract_freeze_ready)
    ));
    md.push_str(&format!(
        "- {} audit drift is clean\n",
        checklist_box(audit_drift_clean)
    ));
    md.push_str(&format!(
        "- {} audit export v2 validates\n",
        checklist_box(audit_export_v2_validation.ready)
    ));
    md.push_str(&format!(
        "- {} shadow alignment holds\n",
        checklist_box(shadow.aligned)
    ));
    md.push_str(&format!(
        "- {} provider bridge artifact is present\n",
        checklist_box(provider_bridge_ready)
    ));
    md.push_str(&format!(
        "- {} benchmark sign-off is attached\n",
        checklist_box(benchmark_signoff)
    ));
    md.push_str(&format!(
        "- {} cost sign-off is attached\n",
        checklist_box(fleet_cost_signoff)
    ));
    md.push_str(&format!(
        "- {} security review packet is complete and approved\n",
        checklist_box(security_review_packet_ready)
    ));
    md.push_str(&format!(
        "- {} large-scale migration drill is clean\n",
        checklist_box(migration_drill_clean)
    ));
    md.push_str(&format!(
        "- {} migration guide path resolves\n",
        checklist_box(migration_guide_present)
    ));
    md.push_str(&format!(
        "- {} provider rollout checklist path resolves\n",
        checklist_box(provider_rollout_present)
    ));
    md.push_str(&format!(
        "- {} candidate checklist has RC hardening markers\n",
        checklist_box(candidate_checklist_ready)
    ));
    md.push_str(&format!(
        "- {} freeze boundary path resolves\n",
        checklist_box(freeze_boundary_present)
    ));
    md.push_str(&format!(
        "- {} v1 deprecation countdown markers resolve\n",
        checklist_box(deprecation_countdown_ready)
    ));
    md.push_str(&format!(
        "- {} rollback packet is attached and derivable from replay + shadow evidence\n",
        checklist_box(rollback_packet_ready)
    ));
    if !audit_export_v2_validation.diagnostics.is_empty() {
        md.push_str("\n## Audit Export V2 Diagnostics\n");
        for diagnostic in &audit_export_v2_validation.diagnostics {
            md.push_str(&format!("- {diagnostic}\n"));
        }
    }

    md.push_str("\n## Next Actions\n");
    if next_actions.is_empty() {
        md.push_str("- none\n");
    } else {
        for action in &next_actions {
            md.push_str(&format!("- {action}\n"));
        }
    }

    write_output(&options.output, md.as_str())?;
    println!("rc readiness packet written: {}", options.output.display());
    if !rc_ready {
        bail!("v2 rc readiness failed");
    }
    Ok(())
}

fn run_ga_packet(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = required_path(
        options.audit_v2_input.as_deref(),
        "--audit-v2-input",
        "ga-packet",
    )?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let replay_summary_input = required_path(
        options.replay_summary_input.as_deref(),
        "--replay-summary-input",
        "ga-packet",
    )?;
    let replay_summary = Some(load_json_file::<DeadLetterReplaySummaryRecord>(
        replay_summary_input,
    )?);
    let policy_input = required_path(
        options.policy_input.as_deref(),
        "--policy-input",
        "ga-packet",
    )?;
    let release_policy = load_release_policy_summary(policy_input)?;
    let rc_readiness_input = required_path(
        options.rc_readiness_input.as_deref(),
        "--rc-readiness-input",
        "ga-packet",
    )?;
    let go_no_go_path = required_path(
        options.go_no_go_path.as_deref(),
        "--go-no-go-path",
        "ga-packet",
    )?;
    let fleet_review_input = required_path(
        options.fleet_review_input.as_deref(),
        "--fleet-review-input",
        "ga-packet",
    )?;
    let migration_guide_path = required_path(
        options.migration_guide_path.as_deref(),
        "--migration-guide-path",
        "ga-packet",
    )?;
    let candidate_checklist_path = required_path(
        options.candidate_checklist_path.as_deref(),
        "--candidate-checklist-path",
        "ga-packet",
    )?;
    let ops_handbook_path = required_path(
        options.ops_handbook_path.as_deref(),
        "--ops-handbook-path",
        "ga-packet",
    )?;
    let support_model_path = required_path(
        options.support_model_path.as_deref(),
        "--support-model-path",
        "ga-packet",
    )?;
    let sunset_notice_path = required_path(
        options.sunset_notice_path.as_deref(),
        "--sunset-notice-path",
        "ga-packet",
    )?;
    let phase201_backcast_path = required_path(
        options.phase201_backcast_path.as_deref(),
        "--phase201-backcast-path",
        "ga-packet",
    )?;
    let assessment = build_compatibility_assessment(
        &metrics,
        &audits,
        replay_summary.clone(),
        options.availability_target_pct,
        options.p95_target_ms,
        options.false_positive_target_pct,
    );
    let scoreboard = build_freeze_scoreboard(&metrics, &audits, &assessment);
    let shadow = build_shadow_alignment(&audits, &audits_v2);
    let drift = build_combined_audit_drift_summary(&audits, &audits_v2);
    let replay_clean = replay_summary
        .as_ref()
        .is_some_and(|summary| summary.failed_records == 0 && summary.retained_records == 0);
    let migration_guide_present = path_exists(Some(migration_guide_path));
    let candidate_checklist_ready = candidate_checklist_ready(Some(candidate_checklist_path))?;
    let ops_handbook_ready = ops_handbook_ready(Some(ops_handbook_path))?;
    let support_model_ready = support_model_ready(Some(support_model_path))?;
    let sunset_notice_ready = sunset_notice_ready(Some(sunset_notice_path))?;
    let phase201_backcast_ready = phase201_backcast_ready(Some(phase201_backcast_path))?;
    let rc_readiness_ready = rc_readiness_packet_ready(Some(rc_readiness_input))?;
    let go_no_go_ready = go_no_go_review_ready(Some(go_no_go_path))?;
    let fleet_governance_ready = fleet_review_cost_signoff_ready(Some(fleet_review_input))?;
    let lts_ready = release_policy.lts_active
        && release_policy.lts_branch == "lts/v2"
        && release_policy.security_sla_hours <= 72;
    let docs_ready = migration_guide_present
        && candidate_checklist_ready
        && ops_handbook_ready
        && support_model_ready
        && sunset_notice_ready
        && phase201_backcast_ready;
    let dual_run_decommission_ready = replay_clean && shadow.aligned;
    let audit_drift_clean =
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2);
    let post_ga_telemetry_ready = !metrics.is_empty()
        && !audits.is_empty()
        && !audits_v2.is_empty()
        && assessment.slo.ready
        && shadow.aligned
        && audit_drift_clean
        && replay_clean
        && fleet_governance_ready
        && support_model_ready;
    let ga_ready = scoreboard.v2_seed_ready
        && dual_run_decommission_ready
        && audit_drift_clean
        && post_ga_telemetry_ready
        && lts_ready
        && docs_ready;
    let ga_ready = ga_ready && rc_readiness_ready && go_no_go_ready;

    let mut next_actions = assessment.next_actions.clone();
    let mut seen_actions = next_actions.iter().cloned().collect::<BTreeSet<_>>();
    if !lts_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Enable release.lts, set branch to `lts/v2`, and keep security_sla_hours <= 72."
                .to_string(),
        );
    }
    if !docs_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Refresh migration, checklist, ops handbook, support model, sunset notice, and Phase201+ docs with GA/LTS handoff markers.".to_string(),
        );
    }
    if !dual_run_decommission_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Keep dual-run active until replay evidence is clean and shadow alignment stays green."
                .to_string(),
        );
    }
    if !scoreboard.v2_seed_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Promote the compatibility posture to `start-v2-seed`; `freeze_ready` alone is not enough for GA.".to_string(),
        );
    }
    if !audit_drift_clean {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Clear unknown audit failure codes/results before promoting the GA packet.".to_string(),
        );
    }
    if !rc_readiness_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach a green v2 RC readiness packet before the GA review.".to_string(),
        );
    }
    if !go_no_go_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach a go/no-go review with Go checked, No-go unchecked, and rollback/support/sunset evidence referenced.".to_string(),
        );
    }
    if !post_ga_telemetry_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach clean post-GA telemetry prerequisites: SLO, audit parity, replay recovery, fleet governance, and support model.".to_string(),
        );
    }

    let mut md = String::new();
    md.push_str("# V2 GA Packet\n\n");
    md.push_str(&format!("- ga_ready: {}\n", ga_ready));
    md.push_str(&format!("- posture: `{}`\n", assessment.posture.as_str()));
    md.push_str(&format!("- v2_seed_ready: {}\n", scoreboard.v2_seed_ready));
    md.push_str(&format!("- lts_active: {}\n", release_policy.lts_active));
    md.push_str(&format!("- lts_branch: {}\n", release_policy.lts_branch));
    md.push_str(&format!(
        "- security_sla_hours: {}\n",
        release_policy.security_sla_hours
    ));
    md.push_str(&format!(
        "- dual_run_decommission_ready: {}\n",
        dual_run_decommission_ready
    ));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!(
        "- post_ga_telemetry_ready: {}\n",
        post_ga_telemetry_ready
    ));
    md.push_str(&format!(
        "- fleet_governance_ready: {}\n",
        fleet_governance_ready
    ));
    md.push_str(&format!("- rc_readiness_ready: {}\n", rc_readiness_ready));
    md.push_str(&format!("- go_no_go_ready: {}\n", go_no_go_ready));
    md.push_str(&format!(
        "- candidate_checklist_ready: {}\n",
        candidate_checklist_ready
    ));
    md.push_str(&format!("- ops_handbook_ready: {}\n", ops_handbook_ready));
    md.push_str(&format!("- support_model_ready: {}\n", support_model_ready));
    md.push_str(&format!("- sunset_notice_ready: {}\n", sunset_notice_ready));
    md.push_str(&format!(
        "- phase201_backcast_ready: {}\n",
        phase201_backcast_ready
    ));
    md.push_str(&format!("- docs_ready: {}\n\n", docs_ready));

    md.push_str("## Checklist\n");
    md.push_str(&format!(
        "- {} v2 seed readiness remains green\n",
        checklist_box(scoreboard.v2_seed_ready)
    ));
    md.push_str(&format!(
        "- {} dual-run can be decommissioned cleanly\n",
        checklist_box(dual_run_decommission_ready)
    ));
    md.push_str(&format!(
        "- {} audit drift is clean\n",
        checklist_box(audit_drift_clean)
    ));
    md.push_str(&format!(
        "- {} RC readiness packet is green\n",
        checklist_box(rc_readiness_ready)
    ));
    md.push_str(&format!(
        "- {} GA go/no-go review is Go\n",
        checklist_box(go_no_go_ready)
    ));
    md.push_str(&format!(
        "- {} LTS policy is active and within SLA\n",
        checklist_box(lts_ready)
    ));
    md.push_str(&format!(
        "- {} migration guide exists\n",
        checklist_box(migration_guide_present)
    ));
    md.push_str(&format!(
        "- {} candidate checklist has RC/GA markers\n",
        checklist_box(candidate_checklist_ready)
    ));
    md.push_str(&format!(
        "- {} ops handbook has GA handoff commands\n",
        checklist_box(ops_handbook_ready)
    ));
    md.push_str(&format!(
        "- {} support model has escalation owners and SLA bands\n",
        checklist_box(support_model_ready)
    ));
    md.push_str(&format!(
        "- {} v1 sunset notice has countdown and compatibility markers\n",
        checklist_box(sunset_notice_ready)
    ));
    md.push_str(&format!(
        "- {} Phase201+ backcast has entry/packet handoff markers\n",
        checklist_box(phase201_backcast_ready)
    ));
    md.push_str(&format!(
        "- {} post-GA telemetry review can be generated\n",
        checklist_box(post_ga_telemetry_ready)
    ));

    md.push_str("\n## Next Actions\n");
    if next_actions.is_empty() {
        md.push_str("- none\n");
    } else {
        for action in &next_actions {
            md.push_str(&format!("- {action}\n"));
        }
    }

    write_output(&options.output, md.as_str())?;
    println!("ga packet written: {}", options.output.display());
    if !ga_ready {
        bail!("v2 ga packet gate failed");
    }
    Ok(())
}

fn run_migration_completion(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = required_path(
        options.audit_v2_input.as_deref(),
        "--audit-v2-input",
        "migration-completion",
    )?;
    require_non_empty_paths(
        &options.provider_inputs,
        "--provider-input",
        "migration-completion",
    )?;
    let fleet_review_input = required_path(
        options.fleet_review_input.as_deref(),
        "--fleet-review-input",
        "migration-completion",
    )?;
    let rc_readiness_input = required_path(
        options.rc_readiness_input.as_deref(),
        "--rc-readiness-input",
        "migration-completion",
    )?;
    let migration_drill_input = required_path(
        options.migration_drill_input.as_deref(),
        "--migration-drill-input",
        "migration-completion",
    )?;
    let migration_guide_path = required_path(
        options.migration_guide_path.as_deref(),
        "--migration-guide-path",
        "migration-completion",
    )?;
    let candidate_checklist_path = required_path(
        options.candidate_checklist_path.as_deref(),
        "--candidate-checklist-path",
        "migration-completion",
    )?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let provider_summaries = summarize_provider_inputs(&options.provider_inputs)?;
    let shadow = build_shadow_alignment(&audits, &audits_v2);
    let drift = build_combined_audit_drift_summary(&audits, &audits_v2);
    let audit_export = validate_audit_export_v2(&audits, &audits_v2);
    let audit_drift_clean =
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2);
    let mut repos = candidate_repos(&metrics, &audits);
    repos.extend(audits_v2.iter().map(|row| row.repo.clone()));
    let provider_bridge_ready = provider_bridge_ready_for_repos(&provider_summaries, &repos);
    let fleet_governance_ready = fleet_review_cost_signoff_ready(Some(fleet_review_input))?;
    let rc_readiness_ready = rc_readiness_packet_ready(Some(rc_readiness_input))?;
    let migration_drill_ready = migration_drill_ready(Some(migration_drill_input))?;
    let migration_guide_present = path_exists(Some(migration_guide_path));
    let candidate_checklist_ready = candidate_checklist_ready(Some(candidate_checklist_path))?;
    let migration_complete = !repos.is_empty()
        && provider_bridge_ready
        && audit_export.ready
        && audit_drift_clean
        && shadow.aligned
        && fleet_governance_ready
        && rc_readiness_ready
        && migration_drill_ready
        && migration_guide_present
        && candidate_checklist_ready;

    let mut md = String::new();
    md.push_str("# Ecosystem Migration Completion Board\n\n");
    md.push_str(&format!(
        "- generated_at: {}\n",
        current_utc_timestamp_label()?
    ));
    md.push_str(&format!("- migration_complete: {}\n", migration_complete));
    md.push_str(&format!("- repo_count: {}\n", repos.len()));
    md.push_str(&format!(
        "- provider_bridge_ready: {}\n",
        provider_bridge_ready
    ));
    md.push_str(&format!(
        "- audit_export_v2_valid: {}\n",
        audit_export.ready
    ));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!("- shadow_aligned: {}\n", shadow.aligned));
    md.push_str(&format!(
        "- fleet_governance_ready: {}\n",
        fleet_governance_ready
    ));
    md.push_str(&format!("- rc_readiness_ready: {}\n", rc_readiness_ready));
    md.push_str(&format!(
        "- migration_drill_ready: {}\n",
        migration_drill_ready
    ));
    md.push_str(&format!(
        "- migration_guide_present: {}\n",
        migration_guide_present
    ));
    md.push_str(&format!(
        "- candidate_checklist_ready: {}\n\n",
        candidate_checklist_ready
    ));

    md.push_str("## Repo Board\n");
    if repos.is_empty() {
        md.push_str("- no repositories have migration telemetry yet\n");
    } else {
        for repo in &repos {
            let modes = provider_summaries
                .iter()
                .filter(|summary| summary.repo == *repo)
                .map(|summary| summary.schema_mode.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let v1_events = audits.iter().filter(|row| row.repo == *repo).count();
            let v2_events = audits_v2.iter().filter(|row| row.repo == *repo).count();
            md.push_str(&format!(
                "- repo={} provider_modes={} audit_v1_events={} audit_v2_events={}\n",
                repo,
                format_csv(&modes),
                v1_events,
                v2_events
            ));
        }
    }

    md.push_str("\n## Handoff\n");
    if migration_complete {
        md.push_str("- Promote this board with the GA packet and keep it as the migration completion source of truth.\n");
        md.push_str("- Use this board as the input to dual-run decommission review.\n");
    } else {
        md.push_str("- Keep v1/v2 dual-run active until every repo has dual or v2 provider evidence, audit v2 parity, RC readiness, and fleet governance sign-off.\n");
    }

    write_output(&options.output, md.as_str())?;
    println!(
        "migration completion board written: {}",
        options.output.display()
    );
    if !migration_complete {
        bail!("ecosystem migration completion gate failed");
    }
    Ok(())
}

fn run_dual_run_decommission(options: &OpsOptions) -> Result<()> {
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = required_path(
        options.audit_v2_input.as_deref(),
        "--audit-v2-input",
        "dual-run-decommission",
    )?;
    let replay_summary_input = required_path(
        options.replay_summary_input.as_deref(),
        "--replay-summary-input",
        "dual-run-decommission",
    )?;
    require_non_empty_paths(
        &options.provider_inputs,
        "--provider-input",
        "dual-run-decommission",
    )?;
    let rollback_packet_input = required_path(
        options.rollback_packet_input.as_deref(),
        "--rollback-packet-input",
        "dual-run-decommission",
    )?;
    let migration_drill_input = required_path(
        options.migration_drill_input.as_deref(),
        "--migration-drill-input",
        "dual-run-decommission",
    )?;
    let rc_readiness_input = required_path(
        options.rc_readiness_input.as_deref(),
        "--rc-readiness-input",
        "dual-run-decommission",
    )?;
    let sunset_notice_path = required_path(
        options.sunset_notice_path.as_deref(),
        "--sunset-notice-path",
        "dual-run-decommission",
    )?;
    let support_model_path = required_path(
        options.support_model_path.as_deref(),
        "--support-model-path",
        "dual-run-decommission",
    )?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let replay_summary = Some(load_json_file::<DeadLetterReplaySummaryRecord>(
        replay_summary_input,
    )?);
    let shadow = build_shadow_alignment(&audits, &audits_v2);
    let drift = build_combined_audit_drift_summary(&audits, &audits_v2);
    let audit_drift_clean =
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2);
    let replay_clean = replay_summary.as_ref().is_some_and(|summary| {
        !summary.dry_run
            && summary.rewrite_input
            && summary.failed_records == 0
            && summary.retained_records == 0
    });
    let repos = shadow_candidate_repos(&audits, &audits_v2);
    let provider_v1_restore_ready = provider_v1_restore_verified(&options.provider_inputs, &repos)?;
    let rollback_packet_ready = rollback_packet_input_ready(Some(rollback_packet_input))?;
    let migration_drill_ready = migration_drill_ready(Some(migration_drill_input))?;
    let rc_readiness_ready = rc_readiness_packet_ready(Some(rc_readiness_input))?;
    let sunset_notice_ready = sunset_notice_ready(Some(sunset_notice_path))?;
    let support_model_ready = support_model_ready(Some(support_model_path))?;
    let decommission_ready = !repos.is_empty()
        && replay_clean
        && shadow.aligned
        && audit_drift_clean
        && provider_v1_restore_ready
        && rollback_packet_ready
        && migration_drill_ready
        && rc_readiness_ready
        && sunset_notice_ready
        && support_model_ready;

    let mut md = String::new();
    md.push_str("# Dual-Run Decommission Plan\n\n");
    md.push_str(&format!(
        "- generated_at: {}\n",
        current_utc_timestamp_label()?
    ));
    md.push_str(&format!("- decommission_ready: {}\n", decommission_ready));
    md.push_str(&format!("- repo_count: {}\n", repos.len()));
    md.push_str(&format!("- replay_clean: {}\n", replay_clean));
    md.push_str(&format!("- shadow_aligned: {}\n", shadow.aligned));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!(
        "- provider_v1_restore_ready: {}\n",
        provider_v1_restore_ready
    ));
    md.push_str(&format!(
        "- rollback_packet_ready: {}\n",
        rollback_packet_ready
    ));
    md.push_str(&format!(
        "- migration_drill_ready: {}\n",
        migration_drill_ready
    ));
    md.push_str(&format!("- rc_readiness_ready: {}\n", rc_readiness_ready));
    md.push_str(&format!("- sunset_notice_ready: {}\n", sunset_notice_ready));
    md.push_str(&format!(
        "- support_model_ready: {}\n\n",
        support_model_ready
    ));

    md.push_str("## Sequence\n");
    md.push_str("- Freeze writes to dual-run bridge settings during the change window.\n");
    md.push_str("- Preserve audit v1 and audit v2 artifacts before changing provider schema.\n");
    md.push_str(
        "- Switch `compatibility.v2.bridge_mode` to `off` after rollback packet verification.\n",
    );
    md.push_str("- Switch generic provider output to `v2` after downstream readers confirm v1 restore remains available.\n");
    md.push_str(
        "- Keep rollback packet and support escalation open through the +90 review window.\n\n",
    );

    md.push_str("## Rollback Triggers\n");
    md.push_str("- audit v2 event count diverges from v1 during the decommission window\n");
    md.push_str("- downstream provider reader rejects v2-only payloads\n");
    md.push_str("- delivery replay or notification recovery retains failed records\n");
    md.push_str("- support model classifies the incident as critical\n");

    write_output(&options.output, md.as_str())?;
    println!(
        "dual-run decommission plan written: {}",
        options.output.display()
    );
    if !decommission_ready {
        bail!("dual-run decommission gate failed");
    }
    Ok(())
}

fn run_post_ga_telemetry(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = required_path(
        options.audit_v2_input.as_deref(),
        "--audit-v2-input",
        "post-ga-telemetry",
    )?;
    let replay_summary_input = required_path(
        options.replay_summary_input.as_deref(),
        "--replay-summary-input",
        "post-ga-telemetry",
    )?;
    let fleet_review_input = required_path(
        options.fleet_review_input.as_deref(),
        "--fleet-review-input",
        "post-ga-telemetry",
    )?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let replay_summary = Some(load_json_file::<DeadLetterReplaySummaryRecord>(
        replay_summary_input,
    )?);
    let assessment = build_compatibility_assessment(
        &metrics,
        &audits,
        replay_summary.clone(),
        options.availability_target_pct,
        options.p95_target_ms,
        options.false_positive_target_pct,
    );
    let shadow = build_shadow_alignment(&audits, &audits_v2);
    let drift = build_combined_audit_drift_summary(&audits, &audits_v2);
    let audit_drift_clean =
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2);
    let replay_clean = replay_summary.as_ref().is_some_and(|summary| {
        !summary.dry_run
            && summary.rewrite_input
            && summary.failed_records == 0
            && summary.retained_records == 0
    });
    let fleet_governance_ready = fleet_review_cost_signoff_ready(Some(fleet_review_input))?;
    let ga_packet_input = options
        .ga_packet_input
        .as_deref()
        .ok_or_else(|| anyhow!("--ga-packet-input is required for post-ga-telemetry"))?;
    let ga_packet_ready = ga_packet_ready(Some(ga_packet_input))?;
    let support_model_path = options
        .support_model_path
        .as_deref()
        .ok_or_else(|| anyhow!("--support-model-path is required for post-ga-telemetry"))?;
    let support_model_ready = support_model_ready(Some(support_model_path))?;
    let telemetry_review_ready = !metrics.is_empty()
        && !audits.is_empty()
        && !audits_v2.is_empty()
        && assessment.slo.ready
        && shadow.aligned
        && audit_drift_clean
        && replay_clean
        && fleet_governance_ready
        && ga_packet_ready
        && support_model_ready;

    let mut md = String::new();
    md.push_str("# Post-GA Telemetry Review\n\n");
    md.push_str(&format!(
        "- generated_at: {}\n",
        current_utc_timestamp_label()?
    ));
    md.push_str(&format!(
        "- telemetry_review_ready: {}\n",
        telemetry_review_ready
    ));
    md.push_str(&format!("- runs: {}\n", assessment.slo.runs));
    md.push_str(&format!(
        "- availability_pct: {:.2}\n",
        assessment.slo.availability_pct
    ));
    md.push_str(&format!(
        "- p95_duration_ms: {}\n",
        assessment.slo.p95_duration_ms
    ));
    md.push_str(&format!(
        "- gate_failure_rate_pct: {:.2}\n",
        assessment.slo.gate_failure_rate_pct
    ));
    md.push_str(&format!("- slo_ready: {}\n", assessment.slo.ready));
    md.push_str(&format!("- shadow_aligned: {}\n", shadow.aligned));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!("- replay_clean: {}\n", replay_clean));
    md.push_str(&format!(
        "- fleet_governance_ready: {}\n",
        fleet_governance_ready
    ));
    md.push_str(&format!("- ga_packet_ready: {}\n", ga_packet_ready));
    md.push_str(&format!(
        "- support_model_ready: {}\n\n",
        support_model_ready
    ));

    md.push_str("## Review Focus\n");
    md.push_str(
        "- Watch score, duration, and gate failure deltas after the GA packet is promoted.\n",
    );
    md.push_str("- Compare audit v1/v2 parity until the dual-run decommission plan is complete.\n");
    md.push_str("- Escalate through the support model when telemetry changes from steady-state to regression.\n\n");

    md.push_str("## Next Actions\n");
    if telemetry_review_ready {
        md.push_str("- keep the telemetry review cadence attached to Phase201+ planning\n");
        md.push_str("- use this review as the input for retrospective cleanup\n");
    } else {
        for action in &assessment.next_actions {
            md.push_str(&format!("- {action}\n"));
        }
        if !replay_clean {
            md.push_str(
                "- attach a non-dry-run replay summary with zero failed and retained records\n",
            );
        }
        if !fleet_governance_ready {
            md.push_str(
                "- attach a fleet review with governance, repo cost, and segment cost green\n",
            );
        }
    }

    write_output(&options.output, md.as_str())?;
    println!(
        "post-GA telemetry review written: {}",
        options.output.display()
    );
    if !telemetry_review_ready {
        bail!("post-GA telemetry review gate failed");
    }
    Ok(())
}

fn run_retrospective_cleanup(options: &OpsOptions) -> Result<()> {
    let migration_completion_input = required_path(
        options.migration_completion_input.as_deref(),
        "--migration-completion-input",
        "retrospective-cleanup",
    )?;
    let dual_run_decommission_input = required_path(
        options.dual_run_decommission_input.as_deref(),
        "--dual-run-decommission-input",
        "retrospective-cleanup",
    )?;
    let post_ga_telemetry_input = required_path(
        options.post_ga_telemetry_input.as_deref(),
        "--post-ga-telemetry-input",
        "retrospective-cleanup",
    )?;
    let ops_handbook_path = required_path(
        options.ops_handbook_path.as_deref(),
        "--ops-handbook-path",
        "retrospective-cleanup",
    )?;
    let support_model_path = required_path(
        options.support_model_path.as_deref(),
        "--support-model-path",
        "retrospective-cleanup",
    )?;
    let sunset_notice_path = required_path(
        options.sunset_notice_path.as_deref(),
        "--sunset-notice-path",
        "retrospective-cleanup",
    )?;
    let phase201_backcast_path = required_path(
        options.phase201_backcast_path.as_deref(),
        "--phase201-backcast-path",
        "retrospective-cleanup",
    )?;
    let migration_completion_ready =
        migration_completion_board_ready(Some(migration_completion_input))?;
    let dual_run_decommission_ready =
        dual_run_decommission_plan_ready(Some(dual_run_decommission_input))?;
    let post_ga_telemetry_ready = post_ga_telemetry_review_ready(Some(post_ga_telemetry_input))?;
    let ops_handbook_ready = ops_handbook_ready(Some(ops_handbook_path))?;
    let support_model_ready = support_model_ready(Some(support_model_path))?;
    let sunset_notice_ready = sunset_notice_ready(Some(sunset_notice_path))?;
    let phase201_backcast_ready = phase201_backcast_ready(Some(phase201_backcast_path))?;
    let cleanup_queue_ready = migration_completion_ready
        && dual_run_decommission_ready
        && post_ga_telemetry_ready
        && ops_handbook_ready
        && support_model_ready
        && sunset_notice_ready
        && phase201_backcast_ready;

    let mut md = String::new();
    md.push_str("# Retrospective And Cleanup Queue\n\n");
    md.push_str(&format!(
        "- generated_at: {}\n",
        current_utc_timestamp_label()?
    ));
    md.push_str(&format!("- cleanup_queue_ready: {}\n", cleanup_queue_ready));
    md.push_str(&format!(
        "- migration_completion_ready: {}\n",
        migration_completion_ready
    ));
    md.push_str(&format!(
        "- dual_run_decommission_ready: {}\n",
        dual_run_decommission_ready
    ));
    md.push_str(&format!(
        "- post_ga_telemetry_ready: {}\n",
        post_ga_telemetry_ready
    ));
    md.push_str(&format!("- ops_handbook_ready: {}\n", ops_handbook_ready));
    md.push_str(&format!("- support_model_ready: {}\n", support_model_ready));
    md.push_str(&format!("- sunset_notice_ready: {}\n", sunset_notice_ready));
    md.push_str(&format!(
        "- phase201_backcast_ready: {}\n\n",
        phase201_backcast_ready
    ));

    md.push_str("## Cleanup Queue\n");
    md.push_str("- retire v1-only provider fixtures after +90 review closes\n");
    md.push_str(
        "- keep rollback packet fixture until the support model closes the last critical window\n",
    );
    md.push_str(
        "- move dual-run docs from active procedure to historical reference after decommission\n",
    );
    md.push_str("- backcast Phase201+ items from telemetry review, migration board, and support tickets\n\n");

    md.push_str("## Retrospective Prompts\n");
    md.push_str(
        "- Which GA evidence was reviewed by humans instead of only generated by automation?\n",
    );
    md.push_str("- Which support cases changed the LTS or sunset policy?\n");
    md.push_str("- Which dual-run artifacts are still useful after v2-only operation?\n");

    write_output(&options.output, md.as_str())?;
    println!(
        "retrospective cleanup queue written: {}",
        options.output.display()
    );
    let output_packet_ready = retrospective_cleanup_queue_ready(Some(&options.output))?;
    if !cleanup_queue_ready || !output_packet_ready {
        bail!("retrospective cleanup queue gate failed");
    }
    Ok(())
}

fn average_metric_score(metrics: &[MetricLogRecord]) -> f64 {
    let scores = metrics
        .iter()
        .filter_map(|row| row.score)
        .collect::<Vec<_>>();
    if scores.is_empty() {
        return 0.0;
    }
    scores.iter().map(|score| *score as f64).sum::<f64>() / scores.len() as f64
}

fn collect_string_array_field(value: &serde_json::Value, key: &str) -> BTreeSet<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .filter(|item| !item.trim().is_empty())
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default()
}

fn provider_capabilities(value: &serde_json::Value, schema_mode: &str) -> BTreeSet<String> {
    let mut capabilities = collect_string_array_field(value, "capabilities");
    match schema_mode {
        "dual" => {
            capabilities.insert("generic.v1".to_string());
            capabilities.insert("generic.v2".to_string());
            capabilities.insert("generic.dual".to_string());
            capabilities.insert("audit.shadow".to_string());
            if let Some(v2) = value.get("v2") {
                capabilities.extend(collect_string_array_field(v2, "capabilities"));
            }
        }
        "v2" => {
            capabilities.insert("generic.v2".to_string());
            capabilities.insert("audit.shadow".to_string());
        }
        "v1" => {
            capabilities.insert("generic.v1".to_string());
        }
        _ => {}
    }
    capabilities
}

fn provider_identity(value: &serde_json::Value, schema_mode: &str) -> String {
    if let Some(provider) = value.get("provider").and_then(serde_json::Value::as_str) {
        return provider.to_string();
    }
    if let Some(provider) = value
        .get("v1")
        .and_then(|v1| v1.get("provider"))
        .and_then(serde_json::Value::as_str)
    {
        return provider.to_string();
    }
    match schema_mode {
        "dual" | "v2" => "generic".to_string(),
        _ => "unknown".to_string(),
    }
}

fn audit_event_identity_counts_v1(
    audits: &[AuditLogRecord],
) -> BTreeMap<AuditEventIdentity, usize> {
    let mut counts = BTreeMap::new();
    for row in audits {
        let identity = AuditEventIdentity {
            repo: row.repo.clone(),
            mode: row.mode.clone(),
            scope: row.scope.clone(),
            result: row.result.clone(),
            failure_code: row.failure_code.clone(),
        };
        *counts.entry(identity).or_insert(0) += 1;
    }
    counts
}

fn audit_event_identity_counts_v2(
    audits: &[AuditLogV2Record],
) -> BTreeMap<AuditEventIdentity, usize> {
    let mut counts = BTreeMap::new();
    for row in audits {
        let identity = AuditEventIdentity {
            repo: row.repo.clone(),
            mode: row.operation.mode.clone(),
            scope: row.operation.scope.clone(),
            result: row.operation.result.clone(),
            failure_code: row.failure.code.clone(),
        };
        *counts.entry(identity).or_insert(0) += 1;
    }
    counts
}

fn audit_events_have_strict_parity(
    audits_v1: &[AuditLogRecord],
    audits_v2: &[AuditLogV2Record],
) -> bool {
    !audits_v1.is_empty()
        && !audits_v2.is_empty()
        && audit_event_identity_counts_v1(audits_v1) == audit_event_identity_counts_v2(audits_v2)
}

fn summarize_provider_inputs(paths: &[PathBuf]) -> Result<Vec<ProviderArtifactSummary>> {
    let mut out = Vec::new();
    for path in paths {
        let value = load_json_file::<serde_json::Value>(path)?;
        let schema_mode = if value
            .get("bridge_format")
            .and_then(serde_json::Value::as_str)
            == Some("patchgate.provider.generic.bridge.v1")
            && value.get("v1").is_some()
            && value.get("v2").is_some()
        {
            "dual"
        } else if value
            .get("publish_format")
            .and_then(serde_json::Value::as_str)
            == Some("patchgate.provider.generic.v2")
            && value.get("gate").is_some()
            && value.get("artifacts").is_some()
        {
            "v2"
        } else if value.get("provider").and_then(serde_json::Value::as_str) == Some("generic")
            && value.get("summary").is_some()
            && value.get("report").is_some()
        {
            "v1"
        } else {
            "unknown"
        };
        let repo = value
            .get("repo")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        out.push(ProviderArtifactSummary {
            repo: repo.to_string(),
            provider: provider_identity(&value, schema_mode),
            schema_mode: schema_mode.to_string(),
            capabilities: provider_capabilities(&value, schema_mode),
        });
    }
    Ok(out)
}

fn provider_v1_payload_matches(value: &serde_json::Value, repo: &str) -> bool {
    value
        .get("repo")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value_repo| value_repo == repo)
        && value.get("provider").and_then(serde_json::Value::as_str) == Some("generic")
        && value.get("summary").is_some()
        && value.get("report").is_some()
}

fn provider_v1_restore_ready_repos(paths: &[PathBuf]) -> Result<BTreeSet<String>> {
    let mut ready_repos = BTreeSet::new();
    for path in paths {
        let value = load_json_file::<serde_json::Value>(path)?;
        let repo = value
            .get("repo")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let repo_is_valid = repo != "unknown" && !repo.trim().is_empty();
        let dual_bridge_with_v1 = value
            .get("bridge_format")
            .and_then(serde_json::Value::as_str)
            == Some("patchgate.provider.generic.bridge.v1")
            && value.get("v2").is_some()
            && value
                .get("v1")
                .is_some_and(|v1| provider_v1_payload_matches(v1, repo));
        let direct_v1 = provider_v1_payload_matches(&value, repo);
        if repo_is_valid && (dual_bridge_with_v1 || direct_v1) {
            ready_repos.insert(repo.to_string());
        }
    }
    Ok(ready_repos)
}

fn provider_v1_restore_verified(paths: &[PathBuf], repos: &BTreeSet<String>) -> Result<bool> {
    let ready_repos = provider_v1_restore_ready_repos(paths)?;
    Ok(!repos.is_empty() && repos.iter().all(|repo| ready_repos.contains(repo)))
}

fn summarize_delivery_bridge_inputs(
    paths: &[PathBuf],
    kind: &str,
    expected_bridge_format: &str,
    expected_shadow_of: &str,
) -> Result<Vec<DeliveryBridgeArtifactSummary>> {
    let mut out = Vec::new();
    for path in paths {
        let value = load_json_file::<serde_json::Value>(path)?;
        let bridge_mode = value
            .get("bridge")
            .and_then(|bridge| bridge.get("bridge_mode"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let valid =
            delivery_bridge_artifact_is_valid(&value, expected_bridge_format, expected_shadow_of);
        out.push(DeliveryBridgeArtifactSummary {
            kind: kind.to_string(),
            path: path.display().to_string(),
            valid,
            bridge_mode: bridge_mode.to_string(),
        });
    }
    Ok(out)
}

fn delivery_bridge_artifact_is_valid(
    value: &serde_json::Value,
    expected_bridge_format: &str,
    expected_shadow_of: &str,
) -> bool {
    value
        .get("repo")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|repo| !repo.trim().is_empty())
        && value.get("event").and_then(serde_json::Value::as_str) == Some(expected_shadow_of)
        && value.get("bridge").is_some_and(|bridge| {
            bridge
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                == Some(1)
                && bridge
                    .get("bridge_format")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected_bridge_format)
                && bridge.get("shadow_of").and_then(serde_json::Value::as_str)
                    == Some(expected_shadow_of)
                && bridge
                    .get("bridge_mode")
                    .and_then(serde_json::Value::as_str)
                    == Some("full")
        })
        && if expected_shadow_of == "scan.completed" {
            value.get("report").is_some()
        } else {
            value.get("summary").is_some()
        }
}

fn candidate_repos(metrics: &[MetricLogRecord], audits: &[AuditLogRecord]) -> BTreeSet<String> {
    metrics
        .iter()
        .map(|row| row.repo.clone())
        .chain(audits.iter().map(|row| row.repo.clone()))
        .collect()
}

fn provider_bridge_ready_for_repos(
    provider_summaries: &[ProviderArtifactSummary],
    repos: &BTreeSet<String>,
) -> bool {
    let ready_repos = provider_summaries
        .iter()
        .filter(|summary| matches!(summary.schema_mode.as_str(), "dual" | "v2"))
        .map(|summary| summary.repo.as_str())
        .collect::<BTreeSet<_>>();
    !repos.is_empty() && repos.iter().all(|repo| ready_repos.contains(repo.as_str()))
}

fn path_exists(path: Option<&Path>) -> bool {
    path.is_some_and(Path::exists)
}

fn required_path<'a>(path: Option<&'a Path>, flag: &str, command: &str) -> Result<&'a Path> {
    path.ok_or_else(|| anyhow!("{flag} is required for {command}"))
}

fn require_non_empty_paths(paths: &[PathBuf], flag: &str, command: &str) -> Result<()> {
    if paths.is_empty() {
        bail!("{flag} is required for {command}");
    }
    Ok(())
}

fn security_review_is_approved(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path.filter(|path| path.exists()) else {
        return Ok(false);
    };
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let continue_checked = raw.contains("- [x] Continue") || raw.contains("- [X] Continue");
    let mitigation_checked =
        raw.contains("- [x] Mitigation required") || raw.contains("- [X] Mitigation required");
    Ok(continue_checked && !mitigation_checked)
}

fn security_review_packet_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let approved = security_review_is_approved(Some(path))?;
    let mitigation_unchecked = raw.contains("- [ ] Mitigation required");
    let required_criteria = [
        "unknown failure codes",
        "audit v1/v2 event identity",
        "rollback packet restores",
        "cost and provenance",
    ];
    Ok(approved
        && mitigation_unchecked
        && raw.contains("# RC Security Review Packet")
        && raw.contains("## Inputs")
        && raw.contains("## Review Criteria")
        && raw.contains("## Decision")
        && raw.contains("audit-drift")
        && raw.contains("shadow-review")
        && raw.contains("fleet-review")
        && raw.contains("rollback")
        && required_criteria
            .iter()
            .all(|criterion| raw.contains(criterion)))
}

fn contract_freeze_input_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value = serde_json::from_str::<serde_json::Value>(raw.as_str())
        .with_context(|| format!("decode {}", path.display()))?;
    let v1_enabled = value
        .get("v1_contract")
        .and_then(|contract| contract.get("enabled"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    let v2_enabled = value
        .get("v2_contract")
        .and_then(|contract| contract.get("enabled"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    let breaking_gate_ready = value
        .get("breaking_change_gate_ready")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let details = value
        .get("v1_contract")
        .and_then(|contract| contract.get("details"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .chain(
            value
                .get("v2_contract")
                .and_then(|contract| contract.get("details"))
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str),
        )
        .collect::<Vec<_>>();
    let v1_frozen = details.contains(&"compatibility.v1.rc_frozen=true");
    let strict_v1 = details.contains(&"compatibility.v1.allow_legacy_config_names=false");
    let shadow_mode = details.contains(&"compatibility.v2.shadow_mode=true");
    let bridge_enabled = details.iter().any(|detail| {
        detail.starts_with("compatibility.v2.bridge_mode=") && !detail.ends_with("=off")
    });
    let guide_present = details.contains(&"migration_guide_exists=true");
    let audit_v2_present = details.iter().any(|detail| {
        detail.starts_with("observability.audit_v2_jsonl_path=") && !detail.ends_with("=<disabled>")
    });
    v1_enabled
        .then_some(())
        .ok_or_else(|| anyhow!("contract freeze input has v1_contract.enabled=false"))?;
    Ok(v2_enabled
        && breaking_gate_ready
        && v1_frozen
        && strict_v1
        && shadow_mode
        && bridge_enabled
        && guide_present
        && audit_v2_present)
}

fn migration_drill_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    let report = load_json_file::<MigrationDrillReport>(path)?;
    Ok(report.schema_version > 0
        && ymd_key(&report.generated_at).is_some()
        && !report.drill_id.trim().is_empty()
        && report.repos_total > 0
        && report.repos_attempted == report.repos_total
        && report.repos_succeeded == report.repos_total
        && report.repos_failed == 0
        && report.provider_artifacts_checked >= report.repos_total
        && report.audit_events_replayed > 0
        && report.rollback_rehearsed
        && !report.dry_run
        && report.owners.iter().any(|owner| !owner.trim().is_empty())
        && report.blockers.is_empty())
}

fn rollback_packet_input_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    let packet = load_json_file::<RollbackPacket>(path)?;
    let retained = packet
        .retained_evidence
        .iter()
        .map(|item| item.as_str())
        .collect::<BTreeSet<_>>();
    Ok(packet.schema_version > 0
        && ymd_key(&packet.generated_at).is_some()
        && !packet.owner.trim().is_empty()
        && packet
            .triggers
            .iter()
            .any(|trigger| !trigger.trim().is_empty())
        && packet.restore.bridge_mode == "off"
        && packet.restore.generic_schema == "v1"
        && packet.restore.v1_audit_authoritative
        && packet.verification.dry_run_completed
        && packet.verification.dual_run_reversible
        && packet.verification.provider_v1_verified
        && packet.verification.audit_v2_retained
        && retained.contains("audit-v1")
        && retained.contains("audit-v2"))
}

fn deprecation_countdown_markers_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(raw.contains("## Countdown markers")
        && raw.contains("- +30:")
        && raw.contains("- +60:")
        && raw.contains("- +90:")
        && raw.contains("v2-ga-packet")
        && raw.contains("dual-run"))
}

fn markdown_packet_ready(path: Option<&Path>, title: &str, required: &[&str]) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(raw.contains(title) && required.iter().all(|marker| raw.contains(marker)))
}

fn sunset_notice_ready(path: Option<&Path>) -> Result<bool> {
    Ok(deprecation_countdown_markers_ready(path)?
        && markdown_packet_ready(
            path,
            "# V1 Sunset Notice",
            &[
                "## Compatibility Contract",
                "v1.1 compatibility window",
                "security / critical fix",
                "provider compatibility",
                "audit v1",
                "support model",
            ],
        )?)
}

fn support_model_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# V2 Support Model",
        &[
            "## Support bands",
            "## Escalation",
            "## Ownership",
            "critical",
            "standard",
            "advisory",
            "release owner",
            "support owner",
            "security owner",
            "24h",
            "3 business days",
        ],
    )
}

fn ops_handbook_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# V2 Ops Handbook",
        &[
            "## Core artifacts",
            "## Steady-state loop",
            "## GA command",
            "ecosystem-migration-completion.md",
            "dual-run-decommission.md",
            "post-ga-telemetry-review.md",
            "retrospective-cleanup-queue.md",
            "migration-completion",
            "dual-run-decommission",
            "post-ga-telemetry",
            "retrospective-cleanup",
        ],
    )
}

fn phase201_backcast_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# Phase Backcast (201+)",
        &[
            "## Entry conditions",
            "## First planning packets",
            "ecosystem migration completion",
            "dual-run decommission",
            "post-GA telemetry",
            "retrospective cleanup",
            "## Phase201-210 candidates",
        ],
    )
}

fn candidate_checklist_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let required = [
        "v2 RC contract freeze",
        "breaking-change enforcement",
        "v1 deprecation countdown",
        "large-scale migration drill",
        "audit export v2 validation",
        "rollback packet",
        "RC security review",
        "benchmark / cost sign-off",
        "candidate checklist",
        "GA go / no-go",
    ];
    Ok(required.iter().all(|marker| raw.contains(marker)))
}

fn fleet_review_cost_signoff_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(raw.contains("- governance_ready: true")
        && raw.contains("- repo_cost_ok: true")
        && raw.contains("- segment_cost_ok: true")
        && !raw.contains("next_packet=fleet-review-remediation"))
}

fn rc_readiness_packet_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(raw.contains("- rc_ready: true")
        && raw.contains("- contract_freeze_ready: true")
        && raw.contains("- audit_export_v2_valid: true")
        && raw.contains("- security_review_packet_ready: true")
        && raw.contains("- migration_drill_clean: true")
        && raw.contains("- rollback_packet_ready: true")
        && raw.contains("- benchmark_cost_signoff: true")
        && raw.contains("- deprecation_countdown_ready: true"))
}

fn go_no_go_review_ready(path: Option<&Path>) -> Result<bool> {
    let Some(path) = path else {
        return Ok(false);
    };
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let go_checked = raw.contains("- [x] Go") || raw.contains("- [X] Go");
    let no_go_checked = raw.contains("- [x] No-go") || raw.contains("- [X] No-go");
    let no_go_unchecked = raw.contains("- [ ] No-go");
    Ok(go_checked
        && !no_go_checked
        && no_go_unchecked
        && raw.contains("# V2 GA Go / No-Go Review")
        && raw.contains("## Decision")
        && raw.contains("## Required Evidence")
        && raw.contains("RC readiness")
        && raw.contains("rollback")
        && raw.contains("LTS policy")
        && raw.contains("v1 sunset")
        && raw.contains("support"))
}

fn ga_packet_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# V2 GA Packet",
        &[
            "- ga_ready: true",
            "- lts_active: true",
            "- lts_branch: lts/v2",
            "- dual_run_decommission_ready: true",
            "- post_ga_telemetry_ready: true",
            "- fleet_governance_ready: true",
            "- rc_readiness_ready: true",
            "- go_no_go_ready: true",
            "- support_model_ready: true",
            "- sunset_notice_ready: true",
            "- phase201_backcast_ready: true",
            "- docs_ready: true",
            "- [x] LTS policy is active and within SLA",
        ],
    )
}

fn migration_completion_board_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# Ecosystem Migration Completion Board",
        &[
            "- migration_complete: true",
            "- provider_bridge_ready: true",
            "- audit_export_v2_valid: true",
            "- audit_drift_clean: true",
            "- shadow_aligned: true",
            "- fleet_governance_ready: true",
            "- rc_readiness_ready: true",
            "- migration_drill_ready: true",
            "- migration_guide_present: true",
            "- candidate_checklist_ready: true",
        ],
    )
}

fn dual_run_decommission_plan_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# Dual-Run Decommission Plan",
        &[
            "- decommission_ready: true",
            "- replay_clean: true",
            "- shadow_aligned: true",
            "- audit_drift_clean: true",
            "- provider_v1_restore_ready: true",
            "- rollback_packet_ready: true",
            "- migration_drill_ready: true",
            "- rc_readiness_ready: true",
            "- sunset_notice_ready: true",
            "- support_model_ready: true",
        ],
    )
}

fn post_ga_telemetry_review_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# Post-GA Telemetry Review",
        &[
            "- telemetry_review_ready: true",
            "- slo_ready: true",
            "- shadow_aligned: true",
            "- audit_drift_clean: true",
            "- replay_clean: true",
            "- fleet_governance_ready: true",
            "- ga_packet_ready: true",
            "- support_model_ready: true",
        ],
    )
}

fn retrospective_cleanup_queue_ready(path: Option<&Path>) -> Result<bool> {
    markdown_packet_ready(
        path,
        "# Retrospective And Cleanup Queue",
        &[
            "- cleanup_queue_ready: true",
            "- migration_completion_ready: true",
            "- dual_run_decommission_ready: true",
            "- post_ga_telemetry_ready: true",
            "## Cleanup Queue",
            "## Retrospective Prompts",
        ],
    )
}

fn validate_audit_export_v2(
    audits: &[AuditLogRecord],
    audits_v2: &[AuditLogV2Record],
) -> AuditExportV2Validation {
    let shadow = build_shadow_alignment(audits, audits_v2);
    let mut diagnostics = Vec::new();
    if audits_v2.is_empty() {
        diagnostics.push("audit v2 stream is empty".to_string());
    }
    for row in audits_v2 {
        if row.schema_version != 2 {
            diagnostics.push(format!(
                "repo={} emitted_at={} schema_version={}",
                row.repo, row.emitted_at, row.schema_version
            ));
        }
        if row.audit_format != "patchgate.audit.v2" {
            diagnostics.push(format!(
                "repo={} emitted_at={} audit_format={}",
                row.repo, row.emitted_at, row.audit_format
            ));
        }
        if row.emitted_at == 0
            || row.actor.trim().is_empty()
            || row.repo.trim().is_empty()
            || row.operation.target.trim().is_empty()
            || row.operation.mode.trim().is_empty()
            || row.operation.scope.trim().is_empty()
            || !matches!(
                row.operation.result.as_str(),
                "pass" | "gate_fail" | "error"
            )
        {
            diagnostics.push(format!(
                "repo={} emitted_at={} has incomplete operation identity",
                row.repo, row.emitted_at
            ));
        }
        if row.gate.score.is_none()
            || row.gate.threshold.is_none()
            || row.gate.changed_files.is_none()
        {
            diagnostics.push(format!(
                "repo={} emitted_at={} missing gate score, threshold, or changed_files",
                row.repo, row.emitted_at
            ));
        }
        if let Some(code) = row.failure.code.as_ref() {
            if !is_known_failure_code(code) {
                diagnostics.push(format!(
                    "repo={} emitted_at={} unknown failure_code={}",
                    row.repo, row.emitted_at, code
                ));
            }
        }
    }
    if !shadow.repo_set_match {
        diagnostics.push("audit v1/v2 repo sets differ".to_string());
    }
    if !shadow.mode_set_match {
        diagnostics.push("audit v1/v2 mode sets differ".to_string());
    }
    if !shadow.scope_set_match {
        diagnostics.push("audit v1/v2 scope sets differ".to_string());
    }
    if shadow.event_delta != 0 {
        diagnostics.push(format!("audit v1/v2 event_delta={}", shadow.event_delta));
    }
    if !audit_events_have_strict_parity(audits, audits_v2) {
        diagnostics.push("audit v1/v2 event identities differ".to_string());
    }
    AuditExportV2Validation {
        ready: diagnostics.is_empty(),
        diagnostics,
    }
}

fn load_release_policy_summary(path: &Path) -> Result<ReleasePolicySummary> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value = raw
        .parse::<toml::Value>()
        .with_context(|| format!("decode {}", path.display()))?;
    let lts = value
        .get("release")
        .and_then(|release| release.get("lts"))
        .and_then(toml::Value::as_table);
    let lts_active = lts
        .and_then(|table| table.get("active"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(false);
    let lts_branch = lts
        .and_then(|table| table.get("branch"))
        .and_then(toml::Value::as_str)
        .unwrap_or("lts/v1")
        .to_string();
    let security_sla_hours_raw = match lts.and_then(|table| table.get("security_sla_hours")) {
        Some(value) => value.as_integer().ok_or_else(|| {
            anyhow!(
                "release.lts.security_sla_hours must be an integer between 1 and {} in {}",
                24 * 30,
                path.display()
            )
        })?,
        None => 72,
    };
    if !(1..=i64::from(24 * 30)).contains(&security_sla_hours_raw) {
        bail!(
            "release.lts.security_sla_hours must be between 1 and {} in {}",
            24 * 30,
            path.display()
        );
    }
    let security_sla_hours = security_sla_hours_raw as u16;
    Ok(ReleasePolicySummary {
        lts_active,
        lts_branch,
        security_sla_hours,
    })
}

fn build_verify_v1_calibration(metrics: &[MetricLogRecord]) -> VerifyV1Calibration {
    let runs = metrics.len();
    if runs == 0 {
        return VerifyV1Calibration {
            runs: 0,
            availability_pct: 0.0,
            gate_failure_rate_pct: 0.0,
            execution_error_rate_pct: 0.0,
            recommended_profile: "standard".to_string(),
            next_actions: vec!["collect at least one metrics run before calibration".to_string()],
        };
    }

    let execution_errors = metrics.iter().filter(|m| m.failure_code.is_some()).count();
    let successful = runs.saturating_sub(execution_errors);
    let gate_failures = metrics
        .iter()
        .filter(|m| m.should_fail.unwrap_or(false))
        .count();
    let availability_pct = (successful as f64 / runs as f64) * 100.0;
    let gate_failure_rate_pct = (gate_failures as f64 / runs as f64) * 100.0;
    let execution_error_rate_pct = (execution_errors as f64 / runs as f64) * 100.0;

    let mut next_actions = Vec::new();
    let recommended_profile = if availability_pct >= 99.5
        && gate_failure_rate_pct <= 3.0
        && execution_error_rate_pct <= 0.5
    {
        "lts"
    } else if availability_pct >= 99.0
        && gate_failure_rate_pct <= 5.0
        && execution_error_rate_pct <= 1.0
    {
        "strict"
    } else {
        if availability_pct < 99.0 {
            next_actions.push("improve run stability to availability >= 99%".to_string());
        }
        if gate_failure_rate_pct > 5.0 {
            next_actions
                .push("reduce gate failure rate below 5% by tuning rules/threshold".to_string());
        }
        if execution_error_rate_pct > 1.0 {
            next_actions.push("reduce execution errors below 1%".to_string());
        }
        "standard"
    };

    VerifyV1Calibration {
        runs,
        availability_pct,
        gate_failure_rate_pct,
        execution_error_rate_pct,
        recommended_profile: recommended_profile.to_string(),
        next_actions,
    }
}

fn build_compatibility_assessment(
    metrics: &[MetricLogRecord],
    audits: &[AuditLogRecord],
    replay_summary: Option<DeadLetterReplaySummaryRecord>,
    availability_target_pct: u8,
    p95_target_ms: u32,
    false_positive_target_pct: u8,
) -> CompatibilityAssessment {
    let slo = build_slo_report(
        metrics,
        availability_target_pct,
        p95_target_ms,
        false_positive_target_pct,
    );
    let calibration = build_verify_v1_calibration(metrics);
    let failure_codes = aggregate_failure_code_counts(metrics, audits);
    let audit_failures = audits.iter().filter(|row| audit_v1_is_failure(row)).count();
    let replay_evidence_present = replay_summary
        .as_ref()
        .is_some_and(|summary| !summary.dry_run && summary.rewrite_input);
    let delivery_recovery_ready = replay_summary.as_ref().is_some_and(|summary| {
        !summary.dry_run
            && summary.rewrite_input
            && summary.failed_records == 0
            && summary.retained_records == 0
    });

    let posture = if !slo.ready
        || audit_failures > 0
        || replay_summary
            .as_ref()
            .is_some_and(|summary| summary.failed_records > 0 || summary.retained_records > 0)
    {
        CompatibilityPosture::StabilizeV1
    } else if replay_evidence_present
        && matches!(calibration.recommended_profile.as_str(), "strict" | "lts")
    {
        CompatibilityPosture::StartV2Seed
    } else {
        CompatibilityPosture::HoldV11Line
    };

    let mut next_actions = Vec::new();
    let mut seen_actions = BTreeSet::new();
    for action in &calibration.next_actions {
        push_unique_action(&mut next_actions, &mut seen_actions, action.clone());
    }
    if !slo.ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            format!(
                "Recover SLO targets (availability >= {}%, p95 <= {}ms, false positives <= {}%).",
                availability_target_pct, p95_target_ms, false_positive_target_pct
            ),
        );
    }
    if audit_failures > 0 {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            format!(
                "Investigate {} audit failure event(s) before widening the compatibility boundary.",
                audit_failures
            ),
        );
    }
    match replay_summary.as_ref() {
        Some(summary) if summary.failed_records > 0 || summary.retained_records > 0 => {
            push_unique_action(
                &mut next_actions,
                &mut seen_actions,
                format!(
                    "Drain or justify retained dead-letter records (failed={}, retained={}) before dual-track rollout.",
                    summary.failed_records, summary.retained_records
                ),
            );
        }
        Some(summary) if summary.dry_run || !summary.rewrite_input => {
            push_unique_action(
                &mut next_actions,
                &mut seen_actions,
                "Attach a non-dry-run dead-letter replay summary with rewrite enabled before promoting v2 seed work.".to_string(),
            );
            if summary.dry_run {
                push_unique_action(
                    &mut next_actions,
                    &mut seen_actions,
                    "Re-run dead-letter replay without --dry-run to collect real delivery recovery evidence.".to_string(),
                );
            }
            if !summary.rewrite_input {
                push_unique_action(
                    &mut next_actions,
                    &mut seen_actions,
                    "Re-run dead-letter replay with input rewrite enabled so retained records are proven clean.".to_string(),
                );
            }
        }
        Some(_) => {}
        None => {
            push_unique_action(
                &mut next_actions,
                &mut seen_actions,
                "Attach a dead-letter replay summary before promoting v1.1 freeze decisions to v2 seed work.".to_string(),
            );
        }
    }

    match posture {
        CompatibilityPosture::StartV2Seed => push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Keep v1.1 compatibility notices active while prototyping v2 dual-contract surfaces.".to_string(),
        ),
        CompatibilityPosture::HoldV11Line if next_actions.is_empty() => push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Continue collecting steady telemetry until replay evidence and strict/lts readiness are both sustained.".to_string(),
        ),
        CompatibilityPosture::StabilizeV1 if next_actions.is_empty() => push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Stabilize v1 operations before opening v2 migration work.".to_string(),
        ),
        _ => {}
    }

    CompatibilityAssessment {
        posture,
        slo,
        calibration,
        failure_codes,
        audit_failures,
        replay_evidence_present,
        delivery_recovery_ready,
        replay_summary,
        next_actions,
    }
}

fn build_freeze_scoreboard(
    metrics: &[MetricLogRecord],
    audits: &[AuditLogRecord],
    assessment: &CompatibilityAssessment,
) -> FreezeScoreboard {
    let has_metrics = !metrics.is_empty();
    let has_audits = !audits.is_empty();
    let ga_ready =
        assessment.slo.ready && has_metrics && has_audits && assessment.audit_failures == 0;
    let freeze_ready = ga_ready
        && matches!(
            assessment.posture,
            CompatibilityPosture::HoldV11Line | CompatibilityPosture::StartV2Seed
        );
    let v2_seed_ready = ga_ready && assessment.posture == CompatibilityPosture::StartV2Seed;

    FreezeScoreboard {
        freeze_ready,
        v2_seed_ready,
        has_metrics,
        has_audits,
        ga_ready,
        posture: assessment.posture,
        recommended_profile: assessment.calibration.recommended_profile.clone(),
        replay_evidence_present: assessment.replay_evidence_present,
        next_actions: assessment.next_actions.clone(),
    }
}

fn push_unique_action(actions: &mut Vec<String>, seen: &mut BTreeSet<String>, action: String) {
    if seen.insert(action.clone()) {
        actions.push(action);
    }
}

fn checklist_box(condition: bool) -> &'static str {
    if condition {
        "[x]"
    } else {
        "[ ]"
    }
}

fn build_slo_report(
    metrics: &[MetricLogRecord],
    availability_target_pct: u8,
    p95_target_ms: u32,
    false_positive_target_pct: u8,
) -> SloReport {
    let runs = metrics.len();
    let successful_runs = metrics.iter().filter(|m| m.failure_code.is_none()).count();
    let gate_failures = metrics
        .iter()
        .filter(|m| m.should_fail.unwrap_or(false))
        .count();
    let availability_pct = if runs == 0 {
        0.0
    } else {
        (successful_runs as f64 / runs as f64) * 100.0
    };
    let gate_failure_rate_pct = if runs == 0 {
        0.0
    } else {
        (gate_failures as f64 / runs as f64) * 100.0
    };
    let mut durations: Vec<u128> = metrics
        .iter()
        .filter(|m| m.failure_code.is_none())
        .map(|m| m.duration_ms)
        .collect();
    durations.sort_unstable();
    let p95_duration_ms = percentile_u128(&durations, 95);

    let availability_ok = availability_pct >= availability_target_pct as f64;
    let p95_ok = p95_duration_ms <= p95_target_ms as u128;
    let false_positive_ok = gate_failure_rate_pct <= false_positive_target_pct as f64;
    let ready = availability_ok && p95_ok && false_positive_ok;

    SloReport {
        runs,
        successful_runs,
        gate_failures,
        availability_pct,
        p95_duration_ms,
        gate_failure_rate_pct,
        availability_target_pct,
        p95_target_ms,
        false_positive_target_pct,
        availability_ok,
        p95_ok,
        false_positive_ok,
        ready,
    }
}

fn percentile_u128(sorted_values: &[u128], percentile: usize) -> u128 {
    if sorted_values.is_empty() {
        return 0;
    }
    let len = sorted_values.len();
    let rank = len.saturating_mul(percentile).div_ceil(100).max(1);
    let idx = rank.saturating_sub(1).min(len - 1);
    sorted_values[idx]
}

fn load_jsonl_records<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>> {
    if !path.exists() {
        bail!("input JSONL file does not exist: {}", path.display());
    }
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("read line {} from {}", idx + 1, path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str::<T>(&line)
                .with_context(|| format!("decode line {} from {}", idx + 1, path.display()))?,
        );
    }
    Ok(out)
}

fn load_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    if !path.exists() {
        bail!("input JSON file does not exist: {}", path.display());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("decode {}", path.display()))
}

fn current_utc_timestamp_label() -> Result<String> {
    let unix_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    let (year, month, day) = unix_days_to_ymd((unix_ts / 86_400) as i64);
    let second_of_day = unix_ts % 86_400;
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn unix_days_to_ymd(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

fn write_output(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_jsonl_output<T: Serialize>(path: &Path, records: &[T]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let file = fs::File::create(path).with_context(|| format!("write {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for record in records {
        serde_json::to_writer(&mut writer, record)
            .with_context(|| format!("encode JSONL record for {}", path.display()))?;
        writer
            .write_all(b"\n")
            .with_context(|| format!("write {}", path.display()))?;
    }
    writer
        .flush()
        .with_context(|| format!("flush {}", path.display()))
}

struct SyntheticRepo {
    root: PathBuf,
}

impl SyntheticRepo {
    fn create(files: usize, extra_lines: usize) -> Result<Self> {
        let mut root = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        root.push(format!(
            "patchgate-bench-synth-{}-{ts}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;

        init_git_repo(&root)?;
        for i in 0..files {
            let rel = synthetic_file_path(i);
            let abs = root.join(&rel);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&abs, "export const value = 1;\n")?;
        }
        run_git(&root, &["add", "."])?;
        run_git(&root, &["commit", "-qm", "baseline"])?;

        for i in 0..files {
            let rel = synthetic_file_path(i);
            let abs = root.join(&rel);
            let mut content = fs::read_to_string(&abs)?;
            for _ in 0..extra_lines.max(1) {
                content.push_str("export const changed = true;\n");
            }
            fs::write(&abs, content)?;
        }

        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for SyntheticRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn synthetic_file_path(index: usize) -> String {
    let package = index / 200;
    format!("packages/pkg-{package:03}/src/file-{index:05}.ts")
}

fn init_git_repo(path: &Path) -> Result<()> {
    run_git(path, &["init", "-q"])?;
    run_git(
        path,
        &["config", "user.email", "patchgate-bench@example.com"],
    )?;
    run_git(path, &["config", "user.name", "Patchgate Bench"])?;
    Ok(())
}

fn run_git(path: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .with_context(|| format!("failed to run git {:?}", args))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn changed_file_count(repo: &Path) -> Result<usize> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--find-renames", "--no-color"])
        .current_dir(repo)
        .output()
        .context("failed to run git diff --name-only")?;
    if !output.status.success() {
        bail!(
            "git diff --name-only failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

#[derive(Debug, Deserialize)]
struct ScanReport {
    duration_ms: u128,
    score: u64,
    threshold: u64,
    fingerprint: String,
}

fn run_patchgate_scan(repo: &Path) -> Result<ScanReport> {
    let repo = canonical_repo_path(repo)?;
    let repo_arg = repo
        .to_str()
        .ok_or_else(|| anyhow!("invalid repo path utf8 for scan command"))?;
    let output = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "patchgate-cli",
            "--",
            "--repo",
            repo_arg,
            "scan",
            "--mode",
            "warn",
            "--scope",
            "worktree",
            "--format",
            "json",
            "--no-cache",
        ])
        .current_dir(workspace_root())
        .output()
        .context("failed to run patchgate scan")?;

    if !output.status.success() {
        bail!(
            "patchgate scan failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    serde_json::from_slice::<ScanReport>(&output.stdout)
        .context("failed to parse patchgate scan json output")
}

fn run_patchgate_scan_with_profile(repo: &Path, profile_output: &Path) -> Result<()> {
    let repo = canonical_repo_path(repo)?;
    let repo_arg = repo
        .to_str()
        .ok_or_else(|| anyhow!("invalid repo path utf8 for scan command"))?;
    if let Some(parent) = profile_output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let output = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "patchgate-cli",
            "--",
            "--repo",
            repo_arg,
            "scan",
            "--mode",
            "warn",
            "--scope",
            "worktree",
            "--format",
            "json",
            "--no-cache",
            "--profile-output",
            profile_output
                .to_str()
                .ok_or_else(|| anyhow!("invalid profile output path"))?,
        ])
        .current_dir(workspace_root())
        .output()
        .context("failed to run patchgate scan with profile")?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "patchgate scan with profile failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn canonical_repo_path(repo: &Path) -> Result<PathBuf> {
    repo.canonicalize()
        .with_context(|| format!("failed to canonicalize --repo path `{}`", repo.display()))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn append_sample(path: &Path, sample: &BenchSample) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let json = serde_json::to_string(sample).context("encode benchmark sample")?;
    writeln!(file, "{json}").context("append benchmark sample")?;
    Ok(())
}

fn load_latest_sample(path: &Path, case_name: &str) -> Result<Option<BenchSample>> {
    if !path.exists() {
        return Ok(None);
    }

    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut last: Option<BenchSample> = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let sample: BenchSample =
            serde_json::from_str(&line).context("failed to decode benchmark jsonl line")?;
        if sample.case_name == case_name {
            last = Some(sample);
        }
    }
    Ok(last)
}

fn validate_workload_identity(previous: &BenchSample, current: &BenchSample) -> Result<()> {
    if previous.fingerprint != current.fingerprint {
        bail!(
            "benchmark workload mismatch: fingerprint changed (baseline={}, current={})",
            previous.fingerprint,
            current.fingerprint
        );
    }
    if previous.changed_files != current.changed_files {
        bail!(
            "benchmark workload mismatch: changed_files changed (baseline={}, current={})",
            previous.changed_files,
            current.changed_files
        );
    }
    Ok(())
}

fn print_comparison(previous: &BenchSample, current: &BenchSample) {
    let duration_delta = signed_delta(previous.duration_ms as f64, current.duration_ms as f64);
    let file_delta = signed_delta(previous.changed_files as f64, current.changed_files as f64);
    println!(
        "benchmark compare: case={}\n- duration_ms: {} -> {} ({:+.2}%)\n- changed_files: {} -> {} ({:+.2}%)",
        current.case_name,
        previous.duration_ms,
        current.duration_ms,
        duration_delta,
        previous.changed_files,
        current.changed_files,
        file_delta
    );
}

fn write_compare_report(
    path: &Path,
    previous: &BenchSample,
    current: &BenchSample,
    max_regression_pct: f64,
    regressed: bool,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let report = BenchCompareReport {
        case_name: current.case_name.clone(),
        baseline_duration_ms: previous.duration_ms,
        current_duration_ms: current.duration_ms,
        duration_delta_pct: signed_delta(previous.duration_ms as f64, current.duration_ms as f64),
        baseline_changed_files: previous.changed_files,
        current_changed_files: current.changed_files,
        max_regression_pct,
        regressed,
        fingerprint: current.fingerprint.clone(),
    };
    fs::write(path, serde_json::to_string_pretty(&report)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn signed_delta(previous: f64, current: f64) -> f64 {
    if previous == 0.0 {
        return if current == 0.0 { 0.0 } else { 100.0 };
    }
    ((current - previous) / previous) * 100.0
}

fn is_duration_regressed(
    previous: &BenchSample,
    current: &BenchSample,
    max_regression_pct: f64,
) -> bool {
    signed_delta(previous.duration_ms as f64, current.duration_ms as f64) > max_regression_pct
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    use super::{
        active_cost_ceiling_minutes, aggregate_failure_code_counts, audit_drift_is_clean,
        audit_stream_contracts_are_clean, audit_v2_evidence_ready, average_duration_for_summary,
        build_audit_drift_summary, build_combined_audit_drift_summary,
        build_compatibility_assessment, build_freeze_boundary_markdown, build_freeze_scoreboard,
        build_shadow_alignment, build_siem_handoff_records, build_verify_v1_calibration,
        bundle_catalog_governance_ready, candidate_checklist_ready, candidate_repos,
        canonical_repo_path, checklist_box, contract_freeze_input_ready, cost_within_ceiling,
        deprecation_countdown_markers_ready, dual_run_decommission_plan_ready,
        exception_governance_statuses, exception_is_expired, fleet_repo_posture_label,
        fleet_review_cost_signoff_ready, ga_packet_ready, go_no_go_review_ready, load_json_file,
        load_jsonl_records, load_release_policy_summary, migration_completion_board_ready,
        migration_drill_ready, ops_handbook_ready, parse_ops_options, percentile_u128,
        phase201_backcast_ready, post_ga_telemetry_review_ready, provider_bridge_ready_for_repos,
        provider_capabilities, provider_negotiation_statuses, rc_readiness_packet_ready,
        registry_provenance_ready, repo_cost_ceiling_minutes, retention_tier_is_valid,
        retrospective_cleanup_queue_ready, rollback_packet_input_ready, run_ga_readiness,
        run_migration_drill, run_rollback_packet, security_review_is_approved,
        security_review_packet_ready, segment_cost_statuses, summarize_delivery_bridge_inputs,
        summarize_provider_inputs, sunset_notice_ready, support_model_ready, unix_days_to_ymd,
        validate_audit_export_v2, validate_siem_handoff_input, validate_workload_identity,
        workspace_root, AuditFailureV2, AuditGateV2, AuditLogRecord, AuditLogV2Record,
        AuditOperationV2, AuditRetentionTierPolicy, BenchSample, CompatibilityPosture,
        DeadLetterReplaySummaryRecord, FleetBundleCatalog, FleetBundleEntry, FleetRepoRow,
        FleetSegmentPolicy, GovernanceExceptionEntry, GovernanceExceptionsPacket, MetricLogRecord,
        MigrationDrillReport, OpsOptions, OpsSubcommand, PluginProvenanceEntry,
        PluginRegistryIndex, ProviderArtifactSummary, RolloutWavePolicy, TEMP_SEQ,
    };

    fn sample(case_name: &str, changed_files: usize, fingerprint: &str) -> BenchSample {
        BenchSample {
            case_name: case_name.to_string(),
            unix_ts: 0,
            duration_ms: 10,
            changed_files,
            score: 100,
            threshold: 70,
            fingerprint: fingerprint.to_string(),
        }
    }

    #[test]
    fn workload_identity_requires_same_fingerprint_and_changed_files() {
        let prev = sample("ci-worktree", 0, "abc");
        let same = sample("ci-worktree", 0, "abc");
        validate_workload_identity(&prev, &same).expect("same workload must pass");

        let mismatch_fp = sample("ci-worktree", 0, "def");
        assert!(
            validate_workload_identity(&prev, &mismatch_fp).is_err(),
            "fingerprint mismatch should fail"
        );

        let mismatch_files = sample("ci-worktree", 1, "abc");
        assert!(
            validate_workload_identity(&prev, &mismatch_files).is_err(),
            "changed_files mismatch should fail"
        );
    }

    #[test]
    fn canonical_repo_path_resolves_relative_path_against_caller_cwd() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let rel = format!("target/xtask-relative-repo-{seq}");
        let cwd = std::env::current_dir().expect("cwd");
        let abs = cwd.join(&rel);
        std::fs::create_dir_all(&abs).expect("create temp repo dir");

        let resolved = canonical_repo_path(Path::new(&rel)).expect("resolve relative repo path");
        let expected = abs.canonicalize().expect("canonicalized expected path");
        assert_eq!(resolved, expected);

        std::fs::remove_dir_all(&abs).expect("cleanup temp repo dir");
    }

    #[test]
    fn weekly_summary_duration_excludes_execution_errors() {
        let metrics = vec![
            MetricLogRecord {
                unix_ts: 1,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 20,
                score: Some(90),
                should_fail: Some(false),
                failure_code: None,
            },
            MetricLogRecord {
                unix_ts: 2,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 0,
                score: None,
                should_fail: None,
                failure_code: Some("PG-RT-001".to_string()),
            },
        ];

        assert_eq!(average_duration_for_summary(&metrics), 20.0);
    }

    #[test]
    fn failure_code_aggregation_deduplicates_stream_overlap_without_losing_multiplicity() {
        let metrics = vec![
            MetricLogRecord {
                unix_ts: 10,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 0,
                score: None,
                should_fail: None,
                failure_code: Some("PG-RT-001".to_string()),
            },
            MetricLogRecord {
                unix_ts: 10,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 0,
                score: None,
                should_fail: None,
                failure_code: Some("PG-RT-001".to_string()),
            },
        ];
        let audits = vec![
            AuditLogRecord {
                schema_version: 1,
                audit_format: "patchgate.audit.v1".to_string(),
                unix_ts: 10,
                actor: "bot".to_string(),
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "error".to_string(),
                failure_code: Some("PG-RT-001".to_string()),
            },
            AuditLogRecord {
                schema_version: 1,
                audit_format: "patchgate.audit.v1".to_string(),
                unix_ts: 10,
                actor: "bot".to_string(),
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "error".to_string(),
                failure_code: Some("PG-RT-001".to_string()),
            },
            AuditLogRecord {
                schema_version: 1,
                audit_format: "patchgate.audit.v1".to_string(),
                unix_ts: 11,
                actor: "bot".to_string(),
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "error".to_string(),
                failure_code: Some("PG-CFG-001".to_string()),
            },
        ];

        let counts = aggregate_failure_code_counts(&metrics, &audits);
        assert_eq!(counts.get("PG-RT-001"), Some(&2usize));
        assert_eq!(counts.get("PG-CFG-001"), Some(&1usize));
    }

    #[test]
    fn load_jsonl_records_errors_when_file_is_missing() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let missing = std::env::temp_dir().join(format!("xtask-missing-{seq}.jsonl"));
        let err = load_jsonl_records::<MetricLogRecord>(&missing).expect_err("must error");
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn audit_log_record_defaults_missing_contract_fields() {
        let record: AuditLogRecord = serde_json::from_str(
            r#"{"unix_ts":1,"actor":"bot","repo":"repo","mode":"warn","scope":"staged","result":"pass","failure_code":null}"#,
        )
        .expect("decode v1 audit record");

        assert_eq!(record.schema_version, 1);
        assert_eq!(record.audit_format, "patchgate.audit.v1");
    }

    #[test]
    fn audit_log_v2_record_defaults_missing_contract_fields() {
        let record: AuditLogV2Record = serde_json::from_str(
            r#"{"emitted_at":1,"actor":"bot","repo":"repo","operation":{"target":"scan","mode":"warn","scope":"staged","result":"pass"},"gate":{"score":80,"threshold":70,"changed_files":1},"failure":{"code":null,"category":null},"diagnostics":[]}"#,
        )
        .expect("decode v2 audit record");

        assert_eq!(record.schema_version, 2);
        assert_eq!(record.audit_format, "patchgate.audit.v2");
    }

    #[test]
    fn siem_handoff_maps_audit_v2_to_flat_events() {
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 42,
            actor: "ci".to_string(),
            repo: "owner/repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "enforce".to_string(),
                scope: "worktree".to_string(),
                result: "gate_fail".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(64),
                threshold: Some(70),
                changed_files: Some(3),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec!["dangerous_change triggered".to_string()],
        }];

        let records = build_siem_handoff_records(&audits_v2);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event_kind, "quality_gate.audit");
        assert_eq!(records[0].source_schema_version, 2);
        assert_eq!(records[0].event_time_unix, 42);
        assert_eq!(records[0].severity, "warning");
        assert_eq!(records[0].diagnostic_count, 1);
        assert_eq!(records[0].score, Some(64));
    }

    #[test]
    fn siem_handoff_rejects_non_v2_audit_contract() {
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            emitted_at: 42,
            actor: "ci".to_string(),
            repo: "owner/repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "enforce".to_string(),
                scope: "worktree".to_string(),
                result: "gate_fail".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(64),
                threshold: Some(70),
                changed_files: Some(3),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];

        let err = validate_siem_handoff_input(&audits_v2).expect_err("must reject v1 contract");
        assert!(err
            .to_string()
            .contains("unsupported audit v2 schema_version"));
    }

    #[test]
    fn siem_handoff_rejects_unknown_failure_code() {
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 42,
            actor: "ci".to_string(),
            repo: "owner/repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "enforce".to_string(),
                scope: "worktree".to_string(),
                result: "error".to_string(),
            },
            gate: AuditGateV2 {
                score: None,
                threshold: None,
                changed_files: None,
            },
            failure: AuditFailureV2 {
                code: Some("PG-UNKNOWN-001".to_string()),
                category: Some("runtime".to_string()),
            },
            diagnostics: vec![],
        }];

        let err =
            validate_siem_handoff_input(&audits_v2).expect_err("must reject unknown failure code");
        assert!(err.to_string().contains("unknown failure_code"));
    }

    #[test]
    fn checklist_box_marks_condition() {
        assert_eq!(checklist_box(true), "[x]");
        assert_eq!(checklist_box(false), "[ ]");
    }

    #[test]
    fn freeze_boundary_artifact_covers_scope_and_v2_risk_sections() {
        let markdown =
            build_freeze_boundary_markdown(Path::new("artifacts/v1.1-freeze-boundary.md"));

        assert!(markdown.contains("## v1.1 Scope Candidate Inventory"));
        assert!(markdown.contains("## Deferred Backlog / Non-Goal Reconciliation"));
        assert!(markdown.contains("## Plugin / Provider Breaking-Change Boundary"));
        assert!(markdown.contains("## Migration Narrative"));
        assert!(markdown.contains("## v2 Option Matrix"));
        assert!(markdown.contains("## v2 Risk Register"));
        assert!(markdown.contains("## Release Checklist Freeze Gate"));
        assert!(markdown.contains("artifacts/v1.1-freeze-boundary.md"));
        assert!(markdown.contains("direct v2 cutover"));
    }

    #[test]
    fn freeze_boundary_artifact_reports_selected_output_path() {
        let markdown = build_freeze_boundary_markdown(Path::new("target/v1.1-freeze-boundary.md"));

        assert!(markdown.contains("- output_path: `target/v1.1-freeze-boundary.md`"));
        assert!(markdown.contains("| Scope inventory reviewed | Every v1.1 candidate is marked v1.1, deferred, non-goal, or v2-seed. | `target/v1.1-freeze-boundary.md` |"));
        assert!(markdown.contains("- recommended_artifact: `artifacts/v1.1-freeze-boundary.md`"));
    }

    #[test]
    fn freeze_boundary_doc_tracks_generated_artifact_sections() {
        let doc_path = workspace_root().join("docs/24_v11_freeze_boundary.md");
        let doc = fs::read_to_string(&doc_path).expect("read freeze boundary doc");

        for heading in [
            "## v1.1 Scope Candidate Inventory",
            "## Deferred Backlog / Non-Goal Reconciliation",
            "## Plugin / Provider Breaking-Change Boundary",
            "## Migration Narrative",
            "## v2 Option Matrix",
            "## v2 Risk Register",
            "## Release Checklist Freeze Gate",
        ] {
            assert!(
                doc.contains(heading),
                "freeze boundary doc must include generated artifact section `{heading}`"
            );
        }
    }

    #[test]
    fn rc_readiness_accepts_freeze_boundary_path() {
        let options = parse_ops_options(vec![
            "rc-readiness".into(),
            "--freeze-boundary-path".into(),
            "artifacts/v1.1-freeze-boundary.md".into(),
            "--contract-freeze-input".into(),
            "artifacts/diff-contract.json".into(),
            "--migration-drill-input".into(),
            "artifacts/migration-drill.json".into(),
            "--rollback-packet-input".into(),
            "artifacts/rollback-packet.json".into(),
            "--fleet-review-input".into(),
            "artifacts/fleet-review.md".into(),
            "--sunset-notice-path".into(),
            "docs/21_v1_sunset_notice.md".into(),
        ])
        .expect("parse rc readiness options");

        assert_eq!(
            options.freeze_boundary_path.as_deref(),
            Some(Path::new("artifacts/v1.1-freeze-boundary.md"))
        );
        assert_eq!(
            options.contract_freeze_input.as_deref(),
            Some(Path::new("artifacts/diff-contract.json"))
        );
        assert_eq!(
            options.migration_drill_input.as_deref(),
            Some(Path::new("artifacts/migration-drill.json"))
        );
        assert_eq!(
            options.rollback_packet_input.as_deref(),
            Some(Path::new("artifacts/rollback-packet.json"))
        );
        assert_eq!(
            options.fleet_review_input.as_deref(),
            Some(Path::new("artifacts/fleet-review.md"))
        );
        assert_eq!(
            options.sunset_notice_path.as_deref(),
            Some(Path::new("docs/21_v1_sunset_notice.md"))
        );
    }

    #[test]
    fn ga_packet_accepts_rc_and_go_no_go_paths() {
        let options = parse_ops_options(vec![
            "ga-packet".into(),
            "--rc-readiness-input".into(),
            "artifacts/v2-rc-readiness.md".into(),
            "--go-no-go-path".into(),
            "docs/25_v2_ga_go_no_go.md".into(),
        ])
        .expect("parse ga packet options");

        assert_eq!(
            options.rc_readiness_input.as_deref(),
            Some(Path::new("artifacts/v2-rc-readiness.md"))
        );
        assert_eq!(
            options.go_no_go_path.as_deref(),
            Some(Path::new("docs/25_v2_ga_go_no_go.md"))
        );
    }

    #[test]
    fn percentile_uses_ceiling_rank_for_small_samples() {
        let values = vec![100u128, 200u128];
        assert_eq!(percentile_u128(&values, 95), 200);
    }

    #[test]
    fn ga_readiness_fails_when_not_ready_and_writes_report() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("xtask-ga-readiness-{seq}"));
        fs::create_dir_all(&base).expect("create temp dir");
        let metrics_input = base.join("metrics.jsonl");
        let audit_input = base.join("audit.jsonl");
        let output = base.join("ga-readiness.md");
        fs::write(&metrics_input, "").expect("write metrics");
        fs::write(&audit_input, "").expect("write audits");
        let options = OpsOptions {
            subcommand: OpsSubcommand::GaReadiness,
            metrics_input,
            audit_input,
            audit_v2_input: None,
            output: output.clone(),
            trend_output: None,
            replay_summary_input: None,
            provider_inputs: Vec::new(),
            webhook_envelope_inputs: Vec::new(),
            notification_envelope_inputs: Vec::new(),
            bundle_catalog_input: None,
            registry_input: None,
            exceptions_input: None,
            benchmark_input: None,
            security_review_input: None,
            contract_freeze_input: None,
            migration_drill_input: None,
            rollback_packet_input: None,
            fleet_review_input: None,
            rc_readiness_input: None,
            ga_packet_input: None,
            migration_completion_input: None,
            dual_run_decommission_input: None,
            post_ga_telemetry_input: None,
            policy_input: None,
            migration_guide_path: None,
            provider_rollout_path: None,
            candidate_checklist_path: None,
            freeze_boundary_path: None,
            ops_handbook_path: None,
            support_model_path: None,
            sunset_notice_path: None,
            phase201_backcast_path: None,
            go_no_go_path: None,
            cost_ceiling_minutes: None,
            availability_target_pct: 99,
            p95_target_ms: 1_500,
            false_positive_target_pct: 5,
        };

        let err = run_ga_readiness(&options).expect_err("ga readiness must fail");
        assert!(format!("{err:#}").contains("ga readiness check failed"));

        let markdown = fs::read_to_string(PathBuf::from(&output)).expect("read output");
        assert!(markdown.contains("- ga_ready: false"));
        assert!(markdown.contains("- [ ] Metrics present: 0 entries"));
        assert!(markdown.contains("- [ ] Audit logs present: 0 entries"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn ga_readiness_ignores_gate_fail_outcomes() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("xtask-ga-readiness-gate-fail-{seq}"));
        fs::create_dir_all(&base).expect("create temp dir");
        let metrics_input = base.join("metrics.jsonl");
        let audit_input = base.join("audit.jsonl");
        let output = base.join("ga-readiness.md");
        fs::write(
            &metrics_input,
            concat!(
                "{\"unix_ts\":1,\"repo\":\"repo\",\"mode\":\"warn\",\"scope\":\"staged\",\"duration_ms\":10,\"score\":95,\"should_fail\":false,\"failure_code\":null}\n",
                "{\"unix_ts\":2,\"repo\":\"repo\",\"mode\":\"warn\",\"scope\":\"staged\",\"duration_ms\":12,\"score\":94,\"should_fail\":false,\"failure_code\":null}\n"
            ),
        )
        .expect("write metrics");
        fs::write(
            &audit_input,
            "{\"schema_version\":1,\"audit_format\":\"patchgate.audit.v1\",\"unix_ts\":2,\"actor\":\"bot\",\"repo\":\"repo\",\"mode\":\"warn\",\"scope\":\"staged\",\"result\":\"gate_fail\",\"failure_code\":null}\n",
        )
        .expect("write audits");
        let options = OpsOptions {
            subcommand: OpsSubcommand::GaReadiness,
            metrics_input,
            audit_input,
            audit_v2_input: None,
            output: output.clone(),
            trend_output: None,
            replay_summary_input: None,
            provider_inputs: Vec::new(),
            webhook_envelope_inputs: Vec::new(),
            notification_envelope_inputs: Vec::new(),
            bundle_catalog_input: None,
            registry_input: None,
            exceptions_input: None,
            benchmark_input: None,
            security_review_input: None,
            contract_freeze_input: None,
            migration_drill_input: None,
            rollback_packet_input: None,
            fleet_review_input: None,
            rc_readiness_input: None,
            ga_packet_input: None,
            migration_completion_input: None,
            dual_run_decommission_input: None,
            post_ga_telemetry_input: None,
            policy_input: None,
            migration_guide_path: None,
            provider_rollout_path: None,
            candidate_checklist_path: None,
            freeze_boundary_path: None,
            ops_handbook_path: None,
            support_model_path: None,
            sunset_notice_path: None,
            phase201_backcast_path: None,
            go_no_go_path: None,
            cost_ceiling_minutes: None,
            availability_target_pct: 99,
            p95_target_ms: 1_500,
            false_positive_target_pct: 5,
        };

        run_ga_readiness(&options).expect("ga readiness should ignore gate_fail outcomes");

        let markdown = fs::read_to_string(PathBuf::from(&output)).expect("read output");
        assert!(markdown.contains("- ga_ready: true"));
        assert!(markdown.contains("- [x] Audit failures absent: true"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn verify_v1_calibration_recommends_lts_for_high_stability() {
        let metrics = vec![
            MetricLogRecord {
                unix_ts: 1,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 10,
                score: Some(95),
                should_fail: Some(false),
                failure_code: None,
            },
            MetricLogRecord {
                unix_ts: 2,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 12,
                score: Some(93),
                should_fail: Some(false),
                failure_code: None,
            },
        ];
        let calibration = build_verify_v1_calibration(&metrics);
        assert_eq!(calibration.recommended_profile, "lts");
    }

    #[test]
    fn compatibility_assessment_requires_replay_evidence_before_v2_seed() {
        let metrics = vec![
            MetricLogRecord {
                unix_ts: 1,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 10,
                score: Some(95),
                should_fail: Some(false),
                failure_code: None,
            },
            MetricLogRecord {
                unix_ts: 2,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 12,
                score: Some(94),
                should_fail: Some(false),
                failure_code: None,
            },
        ];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 2,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];

        let assessment = build_compatibility_assessment(&metrics, &audits, None, 99, 1_500, 5);
        assert_eq!(assessment.posture, CompatibilityPosture::HoldV11Line);
        assert!(!assessment.replay_evidence_present);
    }

    #[test]
    fn compatibility_assessment_can_start_v2_seed_when_inputs_are_clean() {
        let metrics = vec![
            MetricLogRecord {
                unix_ts: 1,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 10,
                score: Some(95),
                should_fail: Some(false),
                failure_code: None,
            },
            MetricLogRecord {
                unix_ts: 2,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 12,
                score: Some(94),
                should_fail: Some(false),
                failure_code: None,
            },
        ];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 2,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let replay = DeadLetterReplaySummaryRecord {
            input_path: "artifacts/dead-letter-replay-summary.json".to_string(),
            transport_filter: Some("notification".to_string()),
            selected_records: 0,
            successful_records: 0,
            dry_run_records: 0,
            failed_records: 0,
            skipped_records: 0,
            retained_records: 0,
            dry_run: false,
            rewrite_input: true,
        };

        let assessment =
            build_compatibility_assessment(&metrics, &audits, Some(replay), 99, 1_500, 5);
        assert_eq!(assessment.posture, CompatibilityPosture::StartV2Seed);
        assert!(assessment.delivery_recovery_ready);
    }

    #[test]
    fn compatibility_assessment_rejects_dry_run_replay_evidence() {
        let metrics = vec![
            MetricLogRecord {
                unix_ts: 1,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 10,
                score: Some(95),
                should_fail: Some(false),
                failure_code: None,
            },
            MetricLogRecord {
                unix_ts: 2,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 12,
                score: Some(94),
                should_fail: Some(false),
                failure_code: None,
            },
        ];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 2,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let replay = DeadLetterReplaySummaryRecord {
            input_path: "artifacts/dead-letter-replay-summary.json".to_string(),
            transport_filter: Some("notification".to_string()),
            selected_records: 0,
            successful_records: 0,
            dry_run_records: 0,
            failed_records: 0,
            skipped_records: 0,
            retained_records: 0,
            dry_run: true,
            rewrite_input: true,
        };

        let assessment =
            build_compatibility_assessment(&metrics, &audits, Some(replay), 99, 1_500, 5);
        assert_eq!(assessment.posture, CompatibilityPosture::HoldV11Line);
        assert!(!assessment.replay_evidence_present);
        assert!(!assessment.delivery_recovery_ready);
    }

    #[test]
    fn compatibility_assessment_requires_rewrite_enabled_replay_evidence() {
        let metrics = vec![
            MetricLogRecord {
                unix_ts: 1,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 10,
                score: Some(95),
                should_fail: Some(false),
                failure_code: None,
            },
            MetricLogRecord {
                unix_ts: 2,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 12,
                score: Some(94),
                should_fail: Some(false),
                failure_code: None,
            },
        ];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 2,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let replay = DeadLetterReplaySummaryRecord {
            input_path: "artifacts/dead-letter-replay-summary.json".to_string(),
            transport_filter: Some("notification".to_string()),
            selected_records: 0,
            successful_records: 0,
            dry_run_records: 0,
            failed_records: 0,
            skipped_records: 0,
            retained_records: 0,
            dry_run: false,
            rewrite_input: false,
        };

        let assessment =
            build_compatibility_assessment(&metrics, &audits, Some(replay), 99, 1_500, 5);
        assert_eq!(assessment.posture, CompatibilityPosture::HoldV11Line);
        assert!(!assessment.replay_evidence_present);
        assert!(!assessment.delivery_recovery_ready);
    }

    #[test]
    fn compatibility_assessment_counts_gate_fail_as_audit_failure() {
        let metrics = vec![MetricLogRecord {
            unix_ts: 1,
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 10,
            score: Some(95),
            should_fail: Some(false),
            failure_code: None,
        }];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "gate_fail".to_string(),
            failure_code: None,
        }];

        let assessment = build_compatibility_assessment(&metrics, &audits, None, 99, 1_500, 5);
        assert_eq!(assessment.audit_failures, 1);
        assert_eq!(assessment.posture, CompatibilityPosture::StabilizeV1);
    }

    #[test]
    fn freeze_scoreboard_allows_v11_freeze_before_v2_seed() {
        let metrics = vec![MetricLogRecord {
            unix_ts: 1,
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 10,
            score: Some(95),
            should_fail: Some(false),
            failure_code: None,
        }];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];

        let assessment = build_compatibility_assessment(&metrics, &audits, None, 99, 1_500, 5);
        let scoreboard = build_freeze_scoreboard(&metrics, &audits, &assessment);
        assert!(scoreboard.freeze_ready);
        assert!(!scoreboard.v2_seed_ready);
        assert_eq!(scoreboard.posture, CompatibilityPosture::HoldV11Line);
    }

    #[test]
    fn freeze_scoreboard_allows_v2_seed_only_when_posture_is_start_v2_seed() {
        let metrics = vec![MetricLogRecord {
            unix_ts: 1,
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 10,
            score: Some(95),
            should_fail: Some(false),
            failure_code: None,
        }];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let replay = DeadLetterReplaySummaryRecord {
            input_path: "artifacts/dead-letter-replay-summary.json".to_string(),
            transport_filter: None,
            selected_records: 0,
            successful_records: 0,
            dry_run_records: 0,
            failed_records: 0,
            skipped_records: 0,
            retained_records: 0,
            dry_run: false,
            rewrite_input: true,
        };

        let assessment =
            build_compatibility_assessment(&metrics, &audits, Some(replay), 99, 1_500, 5);
        let scoreboard = build_freeze_scoreboard(&metrics, &audits, &assessment);
        assert!(scoreboard.freeze_ready);
        assert!(scoreboard.v2_seed_ready);
        assert_eq!(scoreboard.posture, CompatibilityPosture::StartV2Seed);
    }

    #[test]
    fn audit_drift_summary_tracks_unknown_codes_and_results() {
        let audits = vec![AuditLogRecord {
            schema_version: 3,
            audit_format: "patchgate.audit.experimental".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "deferred".to_string(),
            failure_code: Some("PG-NEW-001".to_string()),
        }];

        let drift = build_audit_drift_summary(&audits);
        assert_eq!(drift.unknown_failure_codes.get("PG-NEW-001"), Some(&1usize));
        assert_eq!(drift.unknown_results.get("deferred"), Some(&1usize));
        assert_eq!(drift.schema_versions.get(&3), Some(&1usize));
        assert!(!audit_drift_is_clean(&drift));
    }

    #[test]
    fn audit_drift_accepts_supported_schema_version_bumps() {
        let audits = vec![AuditLogRecord {
            schema_version: 3,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];

        let drift = build_audit_drift_summary(&audits);
        assert!(audit_drift_is_clean(&drift));
    }

    #[test]
    fn combined_audit_drift_summary_includes_v2_unknowns() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 9,
            audit_format: "patchgate.audit.future".to_string(),
            emitted_at: 2,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "deferred".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(80),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: Some("PG-NEW-002".to_string()),
                category: Some("runtime".to_string()),
            },
            diagnostics: vec![],
        }];

        let drift = build_combined_audit_drift_summary(&audits_v1, &audits_v2);
        assert_eq!(drift.unknown_failure_codes.get("PG-NEW-002"), Some(&1usize));
        assert_eq!(drift.unknown_results.get("deferred"), Some(&1usize));
        assert_eq!(drift.schema_versions.get(&9), Some(&1usize));
        assert_eq!(drift.formats.get("patchgate.audit.future"), Some(&1usize));
        assert!(!audit_drift_is_clean(&drift));
    }

    #[test]
    fn fleet_repo_posture_label_marks_missing_telemetry_as_incomplete() {
        let metrics = Vec::new();
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];

        let assessment = build_compatibility_assessment(&metrics, &audits, None, 99, 1_500, 5);
        let posture = fleet_repo_posture_label(&metrics, &audits, &assessment);
        assert_eq!(posture, "telemetry-incomplete");
    }

    #[test]
    fn shadow_alignment_rejects_more_v2_failures_than_v1() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "error".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(80),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: Some("PG-RT-001".to_string()),
                category: Some("runtime".to_string()),
            },
            diagnostics: vec!["boom".to_string()],
        }];

        let alignment = build_shadow_alignment(&audits_v1, &audits_v2);
        assert!(!alignment.aligned);
        assert_eq!(alignment.v2_failures, 1);
        assert_eq!(alignment.diagnostics_emitted, 1);
    }

    #[test]
    fn shadow_alignment_counts_gate_fail_as_failure() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "gate_fail".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "gate_fail".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(60),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];

        let alignment = build_shadow_alignment(&audits_v1, &audits_v2);
        assert_eq!(alignment.v1_failures, 1);
        assert_eq!(alignment.v2_failures, 1);
        assert!(alignment.aligned);
    }

    #[test]
    fn shadow_alignment_rejects_failure_total_drift() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "gate_fail".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "pass".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(80),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];

        let alignment = build_shadow_alignment(&audits_v1, &audits_v2);
        assert_eq!(alignment.v1_failures, 1);
        assert_eq!(alignment.v2_failures, 0);
        assert!(!alignment.aligned);
    }

    #[test]
    fn shadow_alignment_rejects_mode_or_scope_drift() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "enforce".to_string(),
                scope: "repo".to_string(),
                result: "pass".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(95),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];

        let alignment = build_shadow_alignment(&audits_v1, &audits_v2);
        assert!(!alignment.mode_set_match);
        assert!(!alignment.scope_set_match);
        assert!(!alignment.aligned);
    }

    #[test]
    fn shadow_alignment_rejects_repo_drift() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo-a".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo-b".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "pass".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(95),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];

        let alignment = build_shadow_alignment(&audits_v1, &audits_v2);
        assert!(!alignment.repo_set_match);
        assert!(!alignment.aligned);
    }

    #[test]
    fn audit_stream_contracts_require_expected_versions_and_formats() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 2,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 1,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "pass".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(95),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];

        assert!(!audit_stream_contracts_are_clean(&audits_v1, &audits_v2));
    }

    #[test]
    fn audit_stream_contracts_accept_configured_schema_bumps() {
        let audits_v1 = vec![AuditLogRecord {
            schema_version: 3,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let audits_v2 = vec![AuditLogV2Record {
            schema_version: 4,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "pass".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(95),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];

        assert!(audit_stream_contracts_are_clean(&audits_v1, &audits_v2));
    }

    #[test]
    fn provider_bridge_ready_requires_candidate_repo_match() {
        let metrics = vec![MetricLogRecord {
            unix_ts: 1,
            repo: "repo-a".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 10,
            score: Some(95),
            should_fail: Some(false),
            failure_code: None,
        }];
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo-a".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let repos = candidate_repos(&metrics, &audits);
        let summaries = vec![
            ProviderArtifactSummary {
                repo: "repo-b".to_string(),
                provider: "generic".to_string(),
                schema_mode: "dual".to_string(),
                capabilities: std::collections::BTreeSet::new(),
            },
            ProviderArtifactSummary {
                repo: "repo-a".to_string(),
                provider: "generic".to_string(),
                schema_mode: "v1".to_string(),
                capabilities: std::collections::BTreeSet::new(),
            },
        ];

        assert!(!provider_bridge_ready_for_repos(&summaries, &repos));
    }

    #[test]
    fn provider_bridge_ready_requires_every_candidate_repo() {
        let repos = ["repo-a".to_string(), "repo-b".to_string()]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let mut summaries = vec![ProviderArtifactSummary {
            repo: "repo-a".to_string(),
            provider: "generic".to_string(),
            schema_mode: "dual".to_string(),
            capabilities: std::collections::BTreeSet::new(),
        }];

        assert!(!provider_bridge_ready_for_repos(&summaries, &repos));

        summaries.push(ProviderArtifactSummary {
            repo: "repo-b".to_string(),
            provider: "generic".to_string(),
            schema_mode: "v2".to_string(),
            capabilities: std::collections::BTreeSet::new(),
        });
        assert!(provider_bridge_ready_for_repos(&summaries, &repos));
    }

    #[test]
    fn rollback_packet_generates_from_dual_run_evidence() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("xtask-rollback-packet-{seq}"));
        fs::create_dir_all(&base).expect("create temp dir");

        let audit = base.join("audit.jsonl");
        let audit_v2 = base.join("audit-v2.jsonl");
        let provider = base.join("provider-dual.json");
        let output = base.join("rollback-packet.json");
        fs::write(
            &audit,
            r#"{"schema_version":1,"audit_format":"patchgate.audit.v1","unix_ts":1,"actor":"bot","repo":"repo-a","mode":"warn","scope":"staged","result":"pass","failure_code":null}
"#,
        )
        .expect("write audit");
        fs::write(
            &audit_v2,
            r#"{"schema_version":2,"audit_format":"patchgate.audit.v2","emitted_at":1,"actor":"bot","repo":"repo-a","operation":{"target":"scan","mode":"warn","scope":"staged","result":"pass"},"gate":{"score":95,"threshold":70,"changed_files":1},"failure":{"code":null,"category":null},"diagnostics":[]}
"#,
        )
        .expect("write audit v2");
        fs::write(
            &provider,
            r#"{"bridge_format":"patchgate.provider.generic.bridge.v1","repo":"repo-a","v1":{"provider":"generic","repo":"repo-a","summary":{},"report":{}},"v2":{}}
"#,
        )
        .expect("write provider");

        let options = parse_ops_options(vec![
            "rollback-packet".into(),
            "--audit-input".into(),
            audit.into_os_string(),
            "--audit-v2-input".into(),
            audit_v2.into_os_string(),
            "--provider-input".into(),
            provider.into_os_string(),
            "--output".into(),
            output.clone().into_os_string(),
        ])
        .expect("parse rollback packet options");

        run_rollback_packet(&options).expect("rollback packet should pass");
        assert!(rollback_packet_input_ready(Some(&output)).expect("rollback packet ready"));

        let mismatched_provider = base.join("provider-mismatch.json");
        let blocked_output = base.join("rollback-packet-blocked.json");
        fs::write(
            &mismatched_provider,
            r#"{"bridge_format":"patchgate.provider.generic.bridge.v1","repo":"repo-b","v1":{"provider":"generic","repo":"repo-b","summary":{},"report":{}},"v2":{}}
"#,
        )
        .expect("write mismatched provider");
        let blocked_options = parse_ops_options(vec![
            "rollback-packet".into(),
            "--audit-input".into(),
            options.audit_input.clone().into_os_string(),
            "--audit-v2-input".into(),
            options
                .audit_v2_input
                .clone()
                .expect("audit v2 input")
                .into_os_string(),
            "--provider-input".into(),
            mismatched_provider.into_os_string(),
            "--output".into(),
            blocked_output.into_os_string(),
        ])
        .expect("parse blocked rollback options");
        let err = run_rollback_packet(&blocked_options).expect_err("repo mismatch must block");
        assert!(err.to_string().contains("rollback packet failed"));

        let malformed_provider = base.join("provider-malformed.json");
        let malformed_output = base.join("rollback-packet-malformed.json");
        fs::write(
            &malformed_provider,
            r#"{"bridge_format":"patchgate.provider.generic.bridge.v1","repo":"repo-a","v1":{"repo":"repo-a"},"v2":{}}
"#,
        )
        .expect("write malformed provider");
        let malformed_options = parse_ops_options(vec![
            "rollback-packet".into(),
            "--audit-input".into(),
            options.audit_input.clone().into_os_string(),
            "--audit-v2-input".into(),
            options
                .audit_v2_input
                .clone()
                .expect("audit v2 input")
                .into_os_string(),
            "--provider-input".into(),
            malformed_provider.into_os_string(),
            "--output".into(),
            malformed_output.into_os_string(),
        ])
        .expect("parse malformed rollback options");
        let err =
            run_rollback_packet(&malformed_options).expect_err("malformed v1 restore must block");
        assert!(err.to_string().contains("rollback packet failed"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn migration_drill_generates_report_from_current_evidence() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("xtask-migration-drill-{seq}"));
        fs::create_dir_all(&base).expect("create temp dir");

        let metrics = base.join("metrics.jsonl");
        let audit = base.join("audit.jsonl");
        let audit_v2 = base.join("audit-v2.jsonl");
        let provider = base.join("provider-dual.json");
        let rollback = base.join("rollback-packet.json");
        let output = base.join("migration-drill.json");
        fs::write(
            &metrics,
            r#"{"unix_ts":1,"repo":"repo-a","mode":"warn","scope":"staged","duration_ms":10,"score":95,"should_fail":false,"failure_code":null}
"#,
        )
        .expect("write metrics");
        fs::write(
            &audit,
            r#"{"schema_version":1,"audit_format":"patchgate.audit.v1","unix_ts":1,"actor":"bot","repo":"repo-a","mode":"warn","scope":"staged","result":"pass","failure_code":null}
"#,
        )
        .expect("write audit");
        fs::write(
            &audit_v2,
            r#"{"schema_version":2,"audit_format":"patchgate.audit.v2","emitted_at":1,"actor":"bot","repo":"repo-a","operation":{"target":"scan","mode":"warn","scope":"staged","result":"pass"},"gate":{"score":95,"threshold":70,"changed_files":1},"failure":{"code":null,"category":null},"diagnostics":[]}
"#,
        )
        .expect("write audit v2");
        fs::write(
            &provider,
            r#"{"bridge_format":"patchgate.provider.generic.bridge.v1","repo":"repo-a","v1":{"provider":"generic","repo":"repo-a","summary":{},"report":{}},"v2":{}}
"#,
        )
        .expect("write provider");
        fs::write(
            &rollback,
            r#"{"schema_version":1,"generated_at":"2026-05-14T00:00:00Z","owner":"platform","triggers":["provider drift"],"restore":{"bridge_mode":"off","generic_schema":"v1","v1_audit_authoritative":true},"verification":{"dry_run_completed":true,"dual_run_reversible":true,"provider_v1_verified":true,"audit_v2_retained":true},"retained_evidence":["audit-v1","audit-v2"]}"#,
        )
        .expect("write rollback");

        let options = parse_ops_options(vec![
            "migration-drill".into(),
            "--metrics-input".into(),
            metrics.into_os_string(),
            "--audit-input".into(),
            audit.into_os_string(),
            "--audit-v2-input".into(),
            audit_v2.into_os_string(),
            "--provider-input".into(),
            provider.into_os_string(),
            "--rollback-packet-input".into(),
            rollback.into_os_string(),
            "--output".into(),
            output.clone().into_os_string(),
        ])
        .expect("parse migration drill options");

        run_migration_drill(&options).expect("migration drill should pass");
        let report = load_json_file::<MigrationDrillReport>(&output).expect("load drill report");
        assert_eq!(report.repos_total, 1);
        assert_eq!(report.repos_succeeded, 1);
        assert_eq!(report.provider_artifacts_checked, 1);
        assert_eq!(report.audit_events_replayed, 1);
        assert!(report.rollback_rehearsed);
        assert!(!report.dry_run);
        assert!(report.blockers.is_empty());
        assert!(super::ymd_key(&report.generated_at).is_some());

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn unix_days_to_ymd_covers_epoch_boundary() {
        assert_eq!(unix_days_to_ymd(0), (1970, 1, 1));
        assert_eq!(unix_days_to_ymd(1), (1970, 1, 2));
        assert_eq!(unix_days_to_ymd(-1), (1969, 12, 31));
    }

    #[test]
    fn summarize_provider_inputs_detects_dual_payload() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-provider-{seq}.json"));
        fs::write(
            &path,
            r#"{"schema_version":1,"bridge_format":"patchgate.provider.generic.bridge.v1","repo":"example/repo","v1":{"provider":"generic"},"v2":{"publish_format":"patchgate.provider.generic.v2"}}"#,
        )
        .expect("write provider payload");

        let summaries = summarize_provider_inputs(std::slice::from_ref(&path))
            .expect("summarize provider inputs");
        assert_eq!(summaries[0].schema_mode, "dual");
        assert_eq!(summaries[0].repo, "example/repo");
        assert_eq!(summaries[0].provider, "generic");
        assert!(summaries[0].capabilities.contains("generic.dual"));
        assert!(summaries[0].capabilities.contains("audit.shadow"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn native_provider_capabilities_include_shadow_audit() {
        let dual_value = serde_json::json!({
            "schema_version": 1,
            "bridge_format": "patchgate.provider.generic.bridge.v1",
            "repo": "example/repo",
            "v1": {"provider": "generic"},
            "v2": {"publish_format": "patchgate.provider.generic.v2"}
        });
        let v2_value = serde_json::json!({
            "schema_version": 2,
            "publish_format": "patchgate.provider.generic.v2",
            "repo": "example/repo",
            "gate": {},
            "artifacts": {}
        });

        assert!(provider_capabilities(&dual_value, "dual").contains("audit.shadow"));
        assert!(provider_capabilities(&v2_value, "v2").contains("audit.shadow"));
        assert!(!provider_capabilities(&dual_value, "v1").contains("audit.shadow"));
    }

    #[test]
    fn summarize_provider_inputs_rejects_invalid_v2_contract_shape() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-provider-invalid-{seq}.json"));
        fs::write(
            &path,
            r#"{"publish_format":"not-a-patchgate-contract","repo":"example/repo"}"#,
        )
        .expect("write malformed provider payload");

        let summaries = summarize_provider_inputs(std::slice::from_ref(&path))
            .expect("summarize provider inputs");
        assert_eq!(summaries[0].schema_mode, "unknown");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn provider_negotiation_requires_catalog_modes_and_capabilities() {
        let catalog = FleetBundleCatalog {
            schema_version: 1,
            generated_at: "2026-03-23T00:00:00Z".to_string(),
            segments: Vec::new(),
            retention_tiers: Vec::new(),
            rollout_waves: Vec::new(),
            bundles: vec![FleetBundleEntry {
                repo: "example/repo".to_string(),
                policy_bundle: "core-strict".to_string(),
                wave: "canary".to_string(),
                segment: "prod".to_string(),
                providers: vec!["generic".to_string()],
                required_provider_modes: vec!["dual".to_string()],
                required_provider_capabilities: vec!["audit.shadow".to_string()],
                retention_tier: "regulated".to_string(),
                cost_ceiling_minutes: Some(20),
                phase181_rc_candidate: true,
            }],
        };
        let mut capabilities = std::collections::BTreeSet::new();
        capabilities.insert("generic.dual".to_string());
        capabilities.insert("audit.shadow".to_string());
        let summaries = vec![ProviderArtifactSummary {
            repo: "example/repo".to_string(),
            provider: "generic".to_string(),
            schema_mode: "dual".to_string(),
            capabilities,
        }];

        let statuses = provider_negotiation_statuses(Some(&catalog), &summaries);
        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].ready);

        let mut wrong_provider = summaries.clone();
        wrong_provider[0].provider = "other".to_string();
        let statuses = provider_negotiation_statuses(Some(&catalog), &wrong_provider);
        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].ready);

        let mut multi_provider_catalog = catalog.clone();
        multi_provider_catalog.bundles[0]
            .providers
            .push("internal".to_string());
        let statuses = provider_negotiation_statuses(Some(&multi_provider_catalog), &summaries);
        assert_eq!(statuses.len(), 1);
        assert!(!statuses[0].ready);

        let mut complete_provider_set = summaries.clone();
        complete_provider_set.push(ProviderArtifactSummary {
            repo: "example/repo".to_string(),
            provider: "internal".to_string(),
            schema_mode: "dual".to_string(),
            capabilities: std::collections::BTreeSet::new(),
        });
        let statuses =
            provider_negotiation_statuses(Some(&multi_provider_catalog), &complete_provider_set);
        assert_eq!(statuses.len(), 1);
        assert!(statuses[0].ready);
    }

    #[test]
    fn retention_and_segment_cost_policies_are_validated() {
        let valid = AuditRetentionTierPolicy {
            tier: "regulated".to_string(),
            hot_days: 14,
            warm_days: 90,
            cold_days: 365,
        };
        let invalid = AuditRetentionTierPolicy {
            tier: "broken".to_string(),
            hot_days: 90,
            warm_days: 30,
            cold_days: 365,
        };
        assert!(retention_tier_is_valid(&valid));
        assert!(!retention_tier_is_valid(&invalid));

        let mut durations = std::collections::BTreeMap::new();
        durations.insert("prod".to_string(), 31 * 60_000);
        let catalog = FleetBundleCatalog {
            schema_version: 1,
            generated_at: String::new(),
            segments: vec![FleetSegmentPolicy {
                segment: "prod".to_string(),
                owner: "platform".to_string(),
                cost_ceiling_minutes: 30,
                review_cadence: "weekly".to_string(),
            }],
            retention_tiers: vec![valid],
            rollout_waves: Vec::new(),
            bundles: Vec::new(),
        };
        let rows = segment_cost_statuses(&durations, Some(&catalog), None);
        assert_eq!(rows[0].segment, "prod");
        assert!(!rows[0].ok);
        let rows = segment_cost_statuses(&durations, None, Some(0));
        assert_eq!(rows[0].ceiling_minutes, None);
        assert!(rows[0].ok);
        assert_eq!(bundle_catalog_governance_ready(Some(&catalog)), Some(false));
        assert!(cost_within_ceiling(20.0, Some(20)));
        assert!(!cost_within_ceiling(20.1, Some(20)));
        assert_eq!(active_cost_ceiling_minutes(Some(0)), None);
        assert!(cost_within_ceiling(20.1, Some(0)));
        let mut segment_ceilings = std::collections::BTreeMap::new();
        segment_ceilings.insert("prod".to_string(), 30);
        assert_eq!(
            repo_cost_ceiling_minutes(None, "prod", &segment_ceilings, Some(60)),
            Some(30)
        );
        assert_eq!(
            repo_cost_ceiling_minutes(None, "unknown", &segment_ceilings, Some(60)),
            Some(60)
        );
        assert_eq!(
            repo_cost_ceiling_minutes(None, "unknown", &segment_ceilings, Some(0)),
            None
        );

        let complete_catalog = FleetBundleCatalog {
            schema_version: 1,
            generated_at: "2026-05-13T00:00:00Z".to_string(),
            segments: vec![FleetSegmentPolicy {
                segment: "prod".to_string(),
                owner: "platform".to_string(),
                cost_ceiling_minutes: 30,
                review_cadence: "weekly".to_string(),
            }],
            retention_tiers: vec![AuditRetentionTierPolicy {
                tier: "regulated".to_string(),
                hot_days: 14,
                warm_days: 90,
                cold_days: 365,
            }],
            rollout_waves: vec![RolloutWavePolicy {
                wave: "canary".to_string(),
                order: 1,
                max_parallel: 1,
                entry_gate: "shadow clean".to_string(),
                rollback_trigger: "provider drift".to_string(),
            }],
            bundles: vec![FleetBundleEntry {
                repo: "example/repo".to_string(),
                policy_bundle: "core-strict".to_string(),
                wave: "canary".to_string(),
                segment: "prod".to_string(),
                providers: vec!["generic".to_string()],
                required_provider_modes: vec!["dual".to_string()],
                required_provider_capabilities: vec!["audit.shadow".to_string()],
                retention_tier: "regulated".to_string(),
                cost_ceiling_minutes: Some(20),
                phase181_rc_candidate: true,
            }],
        };
        assert_eq!(
            bundle_catalog_governance_ready(Some(&complete_catalog)),
            Some(true)
        );
        let mut duplicate_repo_catalog = complete_catalog.clone();
        duplicate_repo_catalog
            .bundles
            .push(duplicate_repo_catalog.bundles[0].clone());
        assert_eq!(
            bundle_catalog_governance_ready(Some(&duplicate_repo_catalog)),
            Some(false)
        );
        assert_eq!(
            repo_cost_ceiling_minutes(
                complete_catalog.bundles.first(),
                "prod",
                &segment_ceilings,
                Some(60)
            ),
            Some(20)
        );
        let mut missing_provider_contract = complete_catalog.clone();
        missing_provider_contract.bundles[0]
            .required_provider_capabilities
            .clear();
        assert_eq!(
            bundle_catalog_governance_ready(Some(&missing_provider_contract)),
            Some(false)
        );
    }

    #[test]
    fn audit_v2_evidence_is_required_when_input_is_present() {
        let rows = vec![
            FleetRepoRow {
                repo: "example/repo".to_string(),
                posture: "stabilize-v1".to_string(),
                runs: 1,
                audit_events_v1: 1,
                audit_events_v2: 1,
                gate_failures: 0,
                average_score: 90.0,
                ci_minutes: 1.0,
                segment: "prod".to_string(),
                wave: "canary".to_string(),
                retention_tier: "regulated".to_string(),
                repo_cost_ceiling_minutes: Some(10),
                repo_cost_ok: true,
            },
            FleetRepoRow {
                repo: "example/without-v2".to_string(),
                posture: "stabilize-v1".to_string(),
                runs: 1,
                audit_events_v1: 1,
                audit_events_v2: 0,
                gate_failures: 0,
                average_score: 90.0,
                ci_minutes: 1.0,
                segment: "prod".to_string(),
                wave: "canary".to_string(),
                retention_tier: "regulated".to_string(),
                repo_cost_ceiling_minutes: Some(10),
                repo_cost_ok: true,
            },
        ];

        assert!(audit_v2_evidence_ready(&rows, false));
        assert!(!audit_v2_evidence_ready(&rows, true));
    }

    #[test]
    fn registry_and_exception_governance_require_complete_evidence() {
        let registry = PluginRegistryIndex {
            schema_version: 1,
            trusted_provenance: vec!["sigstore".to_string()],
            plugins: vec![PluginProvenanceEntry {
                plugin_id: "example/security-rules".to_string(),
                version: "0.3.0".to_string(),
                owner: "security".to_string(),
                provenance: "sigstore".to_string(),
                verified: true,
                source_repo: "example/security-rules".to_string(),
                digest: "sha256:abc".to_string(),
                attestation: "https://attestations.example/security-rules".to_string(),
                revoked: false,
                sandbox_profile: "isolated".to_string(),
                allowed_segments: vec!["prod".to_string()],
            }],
        };
        assert_eq!(registry_provenance_ready(Some(&registry)), Some(true));
        let mut incomplete_registry = registry.clone();
        incomplete_registry.plugins[0].sandbox_profile.clear();
        assert_eq!(
            registry_provenance_ready(Some(&incomplete_registry)),
            Some(false)
        );
        let mut untrusted_registry = registry.clone();
        untrusted_registry.trusted_provenance.clear();
        assert_eq!(
            registry_provenance_ready(Some(&untrusted_registry)),
            Some(false)
        );

        assert_eq!(
            exception_is_expired("2026-04-30T00:00:00Z", "2026-05-13T00:00:00Z"),
            Some(true)
        );
        assert_eq!(
            exception_is_expired("2026-99-99T00:00:00Z", "2026-05-13T00:00:00Z"),
            None
        );
        assert_eq!(
            exception_is_expired("2026-05-1é", "2026-05-13T00:00:00Z"),
            None
        );
        let packet = GovernanceExceptionsPacket {
            schema_version: 1,
            reviewed_at: "2026-05-13T00:00:00Z".to_string(),
            exceptions: vec![GovernanceExceptionEntry {
                repo: "example/repo".to_string(),
                kind: "waiver".to_string(),
                scope: "provider-bridge".to_string(),
                approved_by: "ops-lead".to_string(),
                expires_at: "2026-05-30T00:00:00Z".to_string(),
                ticket: "SEC-1".to_string(),
                owner: "platform".to_string(),
                segment: "prod".to_string(),
                status: "approved".to_string(),
                review_cadence: "weekly".to_string(),
            }],
        };
        let statuses = exception_governance_statuses(Some(&packet));
        assert!(statuses[0].valid);

        let mut invalid_packet = packet.clone();
        invalid_packet.exceptions[0].expires_at = "not-a-date".to_string();
        let statuses = exception_governance_statuses(Some(&invalid_packet));
        assert!(!statuses[0].valid);

        let mut incomplete_exception = packet.clone();
        incomplete_exception.exceptions[0].review_cadence.clear();
        let statuses = exception_governance_statuses(Some(&incomplete_exception));
        assert!(!statuses[0].valid);
    }

    #[test]
    fn summarize_delivery_bridge_inputs_validates_shadow_metadata() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-webhook-bridge-{seq}.json"));
        fs::write(
            &path,
            r#"{"event":"scan.completed","repo":"example/repo","report":{},"bridge":{"schema_version":1,"bridge_format":"patchgate.webhook.v2-shadow","shadow_of":"scan.completed","bridge_mode":"full"}}"#,
        )
        .expect("write webhook bridge payload");

        let summaries = summarize_delivery_bridge_inputs(
            std::slice::from_ref(&path),
            "webhook",
            "patchgate.webhook.v2-shadow",
            "scan.completed",
        )
        .expect("summarize delivery inputs");
        assert!(summaries[0].valid);
        assert_eq!(summaries[0].bridge_mode, "full");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn summarize_delivery_bridge_inputs_rejects_non_full_bridge_mode() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-webhook-bridge-invalid-{seq}.json"));
        fs::write(
            &path,
            r#"{"event":"scan.completed","repo":"example/repo","report":{},"bridge":{"schema_version":1,"bridge_format":"patchgate.webhook.v2-shadow","shadow_of":"scan.completed","bridge_mode":"provider"}}"#,
        )
        .expect("write webhook bridge payload");

        let summaries = summarize_delivery_bridge_inputs(
            std::slice::from_ref(&path),
            "webhook",
            "patchgate.webhook.v2-shadow",
            "scan.completed",
        )
        .expect("summarize delivery inputs");
        assert!(!summaries[0].valid);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_release_policy_summary_reads_lts_fields() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-policy-{seq}.toml"));
        fs::write(
            &path,
            r#"[release.lts]
active = true
branch = "lts/v2"
security_sla_hours = 48
"#,
        )
        .expect("write policy file");

        let summary = load_release_policy_summary(&path).expect("load release policy summary");
        assert!(summary.lts_active);
        assert_eq!(summary.lts_branch, "lts/v2");
        assert_eq!(summary.security_sla_hours, 48);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_release_policy_summary_uses_config_defaults_when_missing_lts_fields() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-policy-defaults-{seq}.toml"));
        fs::write(
            &path,
            r#"[release.lts]
active = true
"#,
        )
        .expect("write policy file");

        let summary = load_release_policy_summary(&path).expect("load release policy summary");
        assert!(summary.lts_active);
        assert_eq!(summary.lts_branch, "lts/v1");
        assert_eq!(summary.security_sla_hours, 72);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_release_policy_summary_rejects_negative_security_sla_hours() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-policy-negative-sla-{seq}.toml"));
        fs::write(
            &path,
            r#"[release.lts]
active = true
security_sla_hours = -1
"#,
        )
        .expect("write policy file");

        let err = load_release_policy_summary(&path).expect_err("negative SLA hours should fail");
        assert!(format!("{err:#}").contains("release.lts.security_sla_hours must be between 1"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_release_policy_summary_rejects_non_integer_security_sla_hours() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-policy-string-sla-{seq}.toml"));
        fs::write(
            &path,
            r#"[release.lts]
active = true
security_sla_hours = "72"
"#,
        )
        .expect("write policy file");

        let err =
            load_release_policy_summary(&path).expect_err("non-integer SLA hours should fail");
        assert!(format!("{err:#}").contains("release.lts.security_sla_hours must be an integer"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn security_review_requires_checked_continue() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pending = std::env::temp_dir().join(format!("xtask-security-pending-{seq}.md"));
        let approved = std::env::temp_dir().join(format!("xtask-security-approved-{seq}.md"));
        fs::write(
            &pending,
            "# RC Security Review Packet\n\n## Decision\n- [ ] Continue\n- [ ] Mitigation required\n",
        )
        .expect("write pending review");
        fs::write(
            &approved,
            "# RC Security Review Packet\n\n## Decision\n- [x] Continue\n- [ ] Mitigation required\n",
        )
        .expect("write approved review");

        assert!(!security_review_is_approved(Some(&pending)).expect("pending review state"));
        assert!(security_review_is_approved(Some(&approved)).expect("approved review state"));

        let _ = fs::remove_file(pending);
        let _ = fs::remove_file(approved);
    }

    #[test]
    fn rc_hardening_artifact_validators_reject_thin_inputs() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("xtask-rc-hardening-{seq}"));
        fs::create_dir_all(&base).expect("create temp dir");

        let contract = base.join("diff-contract.json");
        fs::write(
            &contract,
            r#"{"policy_path":"policy.toml","breaking_change_gate_ready":true,"v1_contract":{"enabled":true,"details":["policy_version=2","compatibility.v1.rc_frozen=true","compatibility.v1.allow_legacy_config_names=false"]},"v2_contract":{"enabled":true,"details":["compatibility.v2.shadow_mode=true","compatibility.v2.bridge_mode=full","observability.audit_v2_jsonl_path=artifacts/scan-audit-v2.jsonl","migration_guide_exists=true"]},"migration_delta":["provider payload schema: v1 -> dual","audit export: v1 -> v2"]}"#,
        )
        .expect("write contract freeze");
        assert!(contract_freeze_input_ready(Some(&contract)).expect("contract ready"));

        let drill = base.join("migration-drill.json");
        fs::write(
            &drill,
            r#"{"schema_version":1,"generated_at":"2026-05-14T00:00:00Z","drill_id":"phase181-drill","repos_total":2,"repos_attempted":2,"repos_succeeded":2,"repos_failed":0,"provider_artifacts_checked":2,"audit_events_replayed":4,"rollback_rehearsed":true,"dry_run":false,"owners":["platform"],"blockers":[]}"#,
        )
        .expect("write drill");
        assert!(migration_drill_ready(Some(&drill)).expect("drill ready"));

        let rollback = base.join("rollback-packet.json");
        fs::write(
            &rollback,
            r#"{"schema_version":1,"generated_at":"2026-05-14T00:00:00Z","owner":"platform","triggers":["provider drift"],"restore":{"bridge_mode":"off","generic_schema":"v1","v1_audit_authoritative":true},"verification":{"dry_run_completed":true,"dual_run_reversible":true,"provider_v1_verified":true,"audit_v2_retained":true},"retained_evidence":["audit-v1","audit-v2"]}"#,
        )
        .expect("write rollback");
        assert!(rollback_packet_input_ready(Some(&rollback)).expect("rollback ready"));

        let security = base.join("security-review.md");
        fs::write(
            &security,
            "# RC Security Review Packet\n\n## Inputs\n- audit-drift\n- shadow-review\n- fleet-review\n- rollback packet\n\n## Review Criteria\n- unknown failure codes are absent\n- audit v1/v2 event identity and failure counts match\n- rollback packet restores provider and audit authority to v1\n- cost and provenance signals have no open blockers\n\n## Decision\n- [x] Continue\n- [ ] Mitigation required\n",
        )
        .expect("write security");
        assert!(security_review_packet_ready(Some(&security)).expect("security ready"));
        fs::write(
            &security,
            "# RC Security Review Packet\n\n## Inputs\n- audit-drift\n- shadow-review\n- fleet-review\n- rollback packet\n\n## Review Criteria\n- unknown failure codes are absent\n- audit v1/v2 event identity and failure counts match\n- rollback packet restores provider and audit authority to v1\n- cost and provenance signals have no open blockers\n\n## Decision\n- [x] Continue\n",
        )
        .expect("write thin security");
        assert!(!security_review_packet_ready(Some(&security)).expect("security should parse"));
        fs::write(
            &security,
            "# RC Security Review Packet\n\n## Inputs\n- audit-drift\n- shadow-review\n- fleet-review\n- rollback packet\n\n## Review Criteria\n- unknown failure codes are absent\n- audit v1/v2 event identity and failure counts match\n- rollback packet restores provider and audit authority to v1\n- cost and provenance signals have no open blockers\n\n## Decision\n- [x] Continue\n- [ ] Mitigation required\n",
        )
        .expect("restore security");

        let sunset = base.join("sunset.md");
        fs::write(
            &sunset,
            "# V1 Sunset Notice\n\n## Countdown markers\n- +30: verify-v2\n- +60: v1-only warning\n- +90: dual-run decommission with `v2-ga-packet.md`\n",
        )
        .expect("write sunset");
        assert!(deprecation_countdown_markers_ready(Some(&sunset)).expect("sunset ready"));

        let checklist = base.join("candidate.md");
        fs::write(
            &checklist,
            [
                "v2 RC contract freeze",
                "breaking-change enforcement",
                "v1 deprecation countdown",
                "large-scale migration drill",
                "audit export v2 validation",
                "rollback packet",
                "RC security review",
                "benchmark / cost sign-off",
                "candidate checklist",
                "GA go / no-go",
            ]
            .join("\n"),
        )
        .expect("write checklist");
        assert!(candidate_checklist_ready(Some(&checklist)).expect("checklist ready"));

        let fleet = base.join("fleet-review.md");
        fs::write(
            &fleet,
            "# Fleet\n- governance_ready: true\n- repo_cost_ok: true\n- segment_cost_ok: true\n",
        )
        .expect("write fleet");
        assert!(fleet_review_cost_signoff_ready(Some(&fleet)).expect("fleet ready"));

        let rc = base.join("v2-rc-readiness.md");
        fs::write(
            &rc,
            "# V2 RC Readiness Packet\n- rc_ready: true\n- contract_freeze_ready: true\n- audit_export_v2_valid: true\n- security_review_packet_ready: true\n- migration_drill_clean: true\n- rollback_packet_ready: true\n- benchmark_cost_signoff: true\n- deprecation_countdown_ready: true\n",
        )
        .expect("write rc packet");
        assert!(rc_readiness_packet_ready(Some(&rc)).expect("rc ready"));

        let go = base.join("go-no-go.md");
        fs::write(
            &go,
            "# V2 GA Go / No-Go Review\n\n## Required Evidence\n- RC readiness: artifacts/v2-rc-readiness.md\n- rollback packet: artifacts/rollback-packet.json\n- LTS policy: artifacts/policy.v2.toml\n- v1 sunset notice: docs/21_v1_sunset_notice.md\n- support path: docs/22_v2_support_model.md\n\n## Decision\n- [x] Go\n- [ ] No-go\n",
        )
        .expect("write go no-go");
        assert!(go_no_go_review_ready(Some(&go)).expect("go no-go ready"));
        fs::write(
            &go,
            "# V2 GA Go / No-Go Review\n\n## Required Evidence\n- RC readiness: artifacts/v2-rc-readiness.md\n- rollback packet: artifacts/rollback-packet.json\n- v1 sunset notice: docs/21_v1_sunset_notice.md\n- support path: docs/22_v2_support_model.md\n\n## Decision\n- [x] Go\n- [ ] No-go\n",
        )
        .expect("write thin go no-go");
        assert!(!go_no_go_review_ready(Some(&go)).expect("thin go no-go should parse"));

        fs::write(
            &drill,
            r#"{"schema_version":1,"generated_at":"2026-05-14T00:00:00Z","drill_id":"phase181-drill","repos_total":2,"repos_attempted":2,"repos_succeeded":1,"repos_failed":1,"provider_artifacts_checked":2,"audit_events_replayed":4,"rollback_rehearsed":false,"dry_run":false,"owners":["platform"],"blockers":["repo failed"]}"#,
        )
        .expect("write failed drill");
        assert!(!migration_drill_ready(Some(&drill)).expect("drill should parse"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn ga_handoff_validators_reject_thin_docs_and_artifacts() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("xtask-ga-handoff-{seq}"));
        fs::create_dir_all(&base).expect("create temp dir");

        let sunset = base.join("sunset.md");
        fs::write(
            &sunset,
            "# V1 Sunset Notice\n\n## Countdown markers\n- +30: verify-v2\n- +60: v1-only warning\n- +90: dual-run decommission with `v2-ga-packet.md`\n\n## Compatibility Contract\n- v1.1 compatibility window stays open\n- security / critical fix only\n- provider compatibility is restored through rollback\n- audit v1 is authoritative fallback\n- support model owns escalation\n",
        )
        .expect("write sunset");
        assert!(sunset_notice_ready(Some(&sunset)).expect("sunset ready"));

        let support = base.join("support.md");
        fs::write(
            &support,
            "# V2 Support Model\n\n## Support bands\n- critical\n- standard\n- advisory\n\n## Escalation\n- use GA packet\n\n## Ownership\n- release owner: platform\n- support owner: support\n- security owner: security\n\n## Response expectations\n- critical: 24h\n- standard: 3 business days\n",
        )
        .expect("write support");
        assert!(support_model_ready(Some(&support)).expect("support ready"));

        let ops = base.join("ops.md");
        fs::write(
            &ops,
            "# V2 Ops Handbook\n\n## Core artifacts\n- ecosystem-migration-completion.md\n- dual-run-decommission.md\n- post-ga-telemetry-review.md\n- retrospective-cleanup-queue.md\n\n## Steady-state loop\n- migration-completion\n- dual-run-decommission\n- post-ga-telemetry\n- retrospective-cleanup\n\n## GA command\ncargo run -p xtask -- ops ga-packet\n",
        )
        .expect("write ops");
        assert!(ops_handbook_ready(Some(&ops)).expect("ops ready"));

        let phase201 = base.join("phase201.md");
        fs::write(
            &phase201,
            "# Phase Backcast (201+)\n\n## Entry conditions\n- v2 GA\n\n## First planning packets\n- ecosystem migration completion\n- dual-run decommission\n- post-GA telemetry\n- retrospective cleanup\n\n## Phase201-210 candidates\n- v2 only\n",
        )
        .expect("write phase201");
        assert!(phase201_backcast_ready(Some(&phase201)).expect("phase201 ready"));

        let ga = base.join("ga.md");
        fs::write(
            &ga,
            "# V2 GA Packet\n\n- ga_ready: true\n- lts_active: true\n- lts_branch: lts/v2\n- dual_run_decommission_ready: true\n- post_ga_telemetry_ready: true\n- fleet_governance_ready: true\n- rc_readiness_ready: true\n- go_no_go_ready: true\n- support_model_ready: true\n- sunset_notice_ready: true\n- phase201_backcast_ready: true\n- docs_ready: true\n\n## Checklist\n- [x] LTS policy is active and within SLA\n",
        )
        .expect("write ga");
        assert!(ga_packet_ready(Some(&ga)).expect("ga ready"));
        fs::write(
            &ga,
            "# V2 GA Packet\n\n- ga_ready: true\n- lts_active: true\n- lts_branch: lts/v1\n- dual_run_decommission_ready: true\n- post_ga_telemetry_ready: true\n- fleet_governance_ready: true\n- rc_readiness_ready: true\n- go_no_go_ready: true\n- support_model_ready: true\n- sunset_notice_ready: true\n- phase201_backcast_ready: true\n- docs_ready: true\n\n## Checklist\n- [x] LTS policy is active and within SLA\n",
        )
        .expect("write thin ga");
        assert!(!ga_packet_ready(Some(&ga)).expect("ga should parse"));

        let migration = base.join("migration.md");
        fs::write(
            &migration,
            "# Ecosystem Migration Completion Board\n\n- migration_complete: true\n- provider_bridge_ready: true\n- audit_export_v2_valid: true\n- audit_drift_clean: true\n- shadow_aligned: true\n- fleet_governance_ready: true\n- rc_readiness_ready: true\n- migration_drill_ready: true\n- migration_guide_present: true\n- candidate_checklist_ready: true\n",
        )
        .expect("write migration board");
        assert!(migration_completion_board_ready(Some(&migration)).expect("migration ready"));

        let decommission = base.join("decommission.md");
        fs::write(
            &decommission,
            "# Dual-Run Decommission Plan\n\n- decommission_ready: true\n- replay_clean: true\n- shadow_aligned: true\n- audit_drift_clean: true\n- provider_v1_restore_ready: true\n- rollback_packet_ready: true\n- migration_drill_ready: true\n- rc_readiness_ready: true\n- sunset_notice_ready: true\n- support_model_ready: true\n",
        )
        .expect("write decommission");
        assert!(dual_run_decommission_plan_ready(Some(&decommission)).expect("decommission ready"));

        let telemetry = base.join("telemetry.md");
        fs::write(
            &telemetry,
            "# Post-GA Telemetry Review\n\n- telemetry_review_ready: true\n- slo_ready: true\n- shadow_aligned: true\n- audit_drift_clean: true\n- replay_clean: true\n- fleet_governance_ready: true\n- ga_packet_ready: true\n- support_model_ready: true\n",
        )
        .expect("write telemetry");
        assert!(post_ga_telemetry_review_ready(Some(&telemetry)).expect("telemetry ready"));

        let cleanup = base.join("cleanup.md");
        fs::write(
            &cleanup,
            "# Retrospective And Cleanup Queue\n\n- cleanup_queue_ready: true\n- migration_completion_ready: true\n- dual_run_decommission_ready: true\n- post_ga_telemetry_ready: true\n\n## Cleanup Queue\n- item\n\n## Retrospective Prompts\n- prompt\n",
        )
        .expect("write cleanup");
        assert!(retrospective_cleanup_queue_ready(Some(&cleanup)).expect("cleanup ready"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn audit_export_v2_validation_requires_strict_v2_contract() {
        let audits = vec![AuditLogRecord {
            schema_version: 1,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            result: "pass".to_string(),
            failure_code: None,
        }];
        let valid_v2 = vec![AuditLogV2Record {
            schema_version: 2,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: 1,
            actor: "bot".to_string(),
            repo: "repo".to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "pass".to_string(),
            },
            gate: AuditGateV2 {
                score: Some(90),
                threshold: Some(70),
                changed_files: Some(1),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: vec![],
        }];
        assert!(validate_audit_export_v2(&audits, &valid_v2).ready);

        let mut invalid_v2 = valid_v2;
        invalid_v2[0].schema_version = 3;
        invalid_v2[0].gate.score = None;
        let validation = validate_audit_export_v2(&audits, &invalid_v2);
        assert!(!validation.ready);
        assert!(validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("schema_version=3")));

        let mut extra_v2 = invalid_v2;
        extra_v2[0].schema_version = 2;
        extra_v2[0].gate.score = Some(90);
        extra_v2.push(extra_v2[0].clone());
        let validation = validate_audit_export_v2(&audits, &extra_v2);
        assert!(!validation.ready);
        assert!(validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("event_delta=1")));
        assert!(validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("event identities differ")));
    }

    #[test]
    fn load_json_file_parses_compact_json() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-json-{seq}.json"));
        fs::write(
            &path,
            "{\"input_path\":\"artifacts/dead-letter.jsonl\",\"transport_filter\":null,\"selected_records\":1,\"successful_records\":1,\"dry_run_records\":0,\"failed_records\":0,\"skipped_records\":0,\"retained_records\":0,\"dry_run\":false,\"rewrite_input\":true}",
        )
        .expect("write json");

        let summary =
            load_json_file::<DeadLetterReplaySummaryRecord>(&path).expect("load json file");
        assert_eq!(summary.successful_records, 1);
        assert!(summary.rewrite_input);

        let _ = fs::remove_file(path);
    }
}
