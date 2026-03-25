use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _, Result};
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
    ReplayNormalize,
    ShadowReview,
    FleetReview,
    RcReadiness,
    GaPacket,
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
    bundle_catalog_input: Option<PathBuf>,
    registry_input: Option<PathBuf>,
    exceptions_input: Option<PathBuf>,
    benchmark_input: Option<PathBuf>,
    security_review_input: Option<PathBuf>,
    policy_input: Option<PathBuf>,
    migration_guide_path: Option<PathBuf>,
    provider_rollout_path: Option<PathBuf>,
    candidate_checklist_path: Option<PathBuf>,
    ops_handbook_path: Option<PathBuf>,
    support_model_path: Option<PathBuf>,
    sunset_notice_path: Option<PathBuf>,
    phase201_backcast_path: Option<PathBuf>,
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

#[derive(Debug, Clone, Deserialize)]
struct FleetBundleCatalog {
    schema_version: u8,
    bundles: Vec<FleetBundleEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct FleetBundleEntry {
    repo: String,
    policy_bundle: String,
    wave: String,
    segment: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginRegistryIndex {
    schema_version: u8,
    plugins: Vec<PluginProvenanceEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginProvenanceEntry {
    plugin_id: String,
    version: String,
    owner: String,
    provenance: String,
    verified: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct GovernanceExceptionsPacket {
    schema_version: u8,
    exceptions: Vec<GovernanceExceptionEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct GovernanceExceptionEntry {
    repo: String,
    kind: String,
    scope: String,
    approved_by: String,
    expires_at: String,
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

#[derive(Debug, Clone)]
struct ProviderArtifactSummary {
    repo: String,
    schema_mode: String,
}

#[derive(Debug, Clone)]
struct ReleasePolicySummary {
    lts_active: bool,
    lts_branch: String,
    security_sla_hours: u16,
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
        "usage:\n  cargo run -p xtask -- bench record [--case NAME] [--repo PATH] [--output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- bench compare [--case NAME] [--repo PATH] [--output PATH] [--max-regression-pct N] [--require-baseline] [--append-on-pass] [--report-output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- bench profile [--repo PATH] [--profile-output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- ops weekly-summary --metrics-input PATH --audit-input PATH --output PATH [--trend-output PATH]\n  cargo run -p xtask -- ops audit-report --audit-input PATH --output PATH\n  cargo run -p xtask -- ops audit-drift-report --audit-input PATH [--audit-v2-input PATH] --output PATH\n  cargo run -p xtask -- ops slo-report --metrics-input PATH --output PATH [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n  cargo run -p xtask -- ops ga-readiness --metrics-input PATH --audit-input PATH --output PATH [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n  cargo run -p xtask -- ops verify-v1-calibrate --metrics-input PATH --output PATH\n  cargo run -p xtask -- ops compatibility-report --metrics-input PATH --audit-input PATH --output PATH [--replay-summary-input PATH] [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n  cargo run -p xtask -- ops freeze-scoreboard --metrics-input PATH --audit-input PATH --output PATH [--replay-summary-input PATH] [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n  cargo run -p xtask -- ops replay-normalize --replay-summary-input PATH --output PATH\n  cargo run -p xtask -- ops shadow-review --audit-input PATH --audit-v2-input PATH --output PATH\n  cargo run -p xtask -- ops fleet-review --metrics-input PATH --audit-input PATH --output PATH [--audit-v2-input PATH] [--provider-input PATH ...] [--bundle-catalog-input PATH] [--registry-input PATH] [--exceptions-input PATH] [--cost-ceiling-minutes N]\n  cargo run -p xtask -- ops rc-readiness --metrics-input PATH --audit-input PATH --audit-v2-input PATH --output PATH [--replay-summary-input PATH] [--provider-input PATH ...] [--benchmark-input PATH] [--security-review-input PATH] [--migration-guide-path PATH] [--provider-rollout-path PATH] [--candidate-checklist-path PATH]\n  cargo run -p xtask -- ops ga-packet --metrics-input PATH --audit-input PATH --audit-v2-input PATH --output PATH [--replay-summary-input PATH] [--policy-input PATH] [--migration-guide-path PATH] [--candidate-checklist-path PATH] [--ops-handbook-path PATH] [--support-model-path PATH] [--sunset-notice-path PATH] [--phase201-backcast-path PATH]"
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
        bail!("missing ops subcommand (`weekly-summary`, `audit-report`, `audit-drift-report`, `slo-report`, `ga-readiness`, `verify-v1-calibrate`, `compatibility-report`, `freeze-scoreboard`, `replay-normalize`, `shadow-review`, `fleet-review`, `rc-readiness`, or `ga-packet`)");
    };
    let subcommand = match sub.to_string_lossy().as_ref() {
        "weekly-summary" => OpsSubcommand::WeeklySummary,
        "audit-report" => OpsSubcommand::AuditReport,
        "audit-drift-report" => OpsSubcommand::AuditDriftReport,
        "slo-report" => OpsSubcommand::SloReport,
        "ga-readiness" => OpsSubcommand::GaReadiness,
        "verify-v1-calibrate" => OpsSubcommand::VerifyV1Calibrate,
        "compatibility-report" => OpsSubcommand::CompatibilityReport,
        "freeze-scoreboard" => OpsSubcommand::FreezeScoreboard,
        "replay-normalize" => OpsSubcommand::ReplayNormalize,
        "shadow-review" => OpsSubcommand::ShadowReview,
        "fleet-review" => OpsSubcommand::FleetReview,
        "rc-readiness" => OpsSubcommand::RcReadiness,
        "ga-packet" => OpsSubcommand::GaPacket,
        other => bail!("unsupported ops subcommand `{other}`"),
    };
    let mut metrics_input = PathBuf::from("artifacts/scan-metrics.jsonl");
    let mut audit_input = PathBuf::from("artifacts/scan-audit.jsonl");
    let mut audit_v2_input = None;
    let mut output = PathBuf::from("artifacts/ops-report.md");
    let mut trend_output = None;
    let mut replay_summary_input = None;
    let mut provider_inputs = Vec::new();
    let mut bundle_catalog_input = None;
    let mut registry_input = None;
    let mut exceptions_input = None;
    let mut benchmark_input = None;
    let mut security_review_input = None;
    let mut policy_input = None;
    let mut migration_guide_path = None;
    let mut provider_rollout_path = None;
    let mut candidate_checklist_path = None;
    let mut ops_handbook_path = None;
    let mut support_model_path = None;
    let mut sunset_notice_path = None;
    let mut phase201_backcast_path = None;
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
        bundle_catalog_input,
        registry_input,
        exceptions_input,
        benchmark_input,
        security_review_input,
        policy_input,
        migration_guide_path,
        provider_rollout_path,
        candidate_checklist_path,
        ops_handbook_path,
        support_model_path,
        sunset_notice_path,
        phase201_backcast_path,
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
        OpsSubcommand::SloReport => run_slo_report(options),
        OpsSubcommand::GaReadiness => run_ga_readiness(options),
        OpsSubcommand::VerifyV1Calibrate => run_verify_v1_calibrate(options),
        OpsSubcommand::CompatibilityReport => run_compatibility_report(options),
        OpsSubcommand::FreezeScoreboard => run_freeze_scoreboard(options),
        OpsSubcommand::ReplayNormalize => run_replay_normalize(options),
        OpsSubcommand::ShadowReview => run_shadow_review(options),
        OpsSubcommand::FleetReview => run_fleet_review(options),
        OpsSubcommand::RcReadiness => run_rc_readiness(options),
        OpsSubcommand::GaPacket => run_ga_packet(options),
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

const KNOWN_FAILURE_CODES: &[&str] = &[
    "PG-IN-001",
    "PG-CFG-001",
    "PG-GIT-001",
    "PG-RT-001",
    "PG-OUT-001",
    "PG-PUB-001",
    "PG-PUB-002",
    "PG-PUB-SSO-001",
    "PG-PUB-ORG-001",
    "PG-PUB-WEB-001",
    "PG-NOT-001",
    "PG-GOV-001",
];

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
    let has_audit_failures = audits.iter().any(audit_v1_is_failure);
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

fn run_shadow_review(options: &OpsOptions) -> Result<()> {
    let audits_v1 = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = options
        .audit_v2_input
        .as_deref()
        .ok_or_else(|| anyhow!("--audit-v2-input is required for shadow-review"))?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let shadow = build_shadow_alignment(&audits_v1, &audits_v2);
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
    md.push_str(&format!("- event_delta: {}\n\n", shadow.event_delta));

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

    md.push_str("## Review Notes\n");
    md.push_str("- Compare event counts before promoting shadow traffic to wider rollout.\n");
    md.push_str("- Investigate any failure drift where v1 and v2 failure totals differ.\n");
    md.push_str("- Keep dual-write enabled until event counts and failure codes stay aligned.\n");

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
    let empty_metrics: &[MetricLogRecord] = &[];
    let empty_audits: &[AuditLogRecord] = &[];

    for repo in &repo_names {
        let repo_metrics = metrics_by_repo
            .get(repo)
            .map(Vec::as_slice)
            .unwrap_or(empty_metrics);
        let repo_audits = audits_by_repo
            .get(repo)
            .map(Vec::as_slice)
            .unwrap_or(empty_audits);
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
        repo_rows.push((
            repo.clone(),
            posture_label,
            repo_metrics.len(),
            repo_audits.len(),
            gate_failures,
            average_score,
            segment,
        ));
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

    let mut md = String::new();
    md.push_str("# Fleet Ops Review Packet\n\n");
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
        repo_rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (repo, posture, runs, audit_events, gate_failures, average_score, segment) in repo_rows
        {
            md.push_str(&format!(
                "- {repo}: posture=`{posture}` runs={runs} audits={audit_events} gate_failures={gate_failures} avg_score={average_score:.2} segment={segment}\n"
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
        if catalog.bundles.is_empty() {
            md.push_str("- none\n");
        } else {
            for entry in &catalog.bundles {
                md.push_str(&format!(
                    "- repo={} bundle={} wave={} segment={}\n",
                    entry.repo, entry.policy_bundle, entry.wave, entry.segment
                ));
            }
        }
    } else {
        md.push_str("- not provided\n");
    }

    md.push_str("\n## Provider Capability\n");
    if provider_mode_counts.is_empty() {
        md.push_str("- not provided\n");
    } else {
        for (mode, count) in provider_mode_counts {
            md.push_str(&format!("- {mode}: {count}\n"));
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
            "- verified_plugins: {}/{}\n",
            verified,
            index.plugins.len()
        ));
        for plugin in &index.plugins {
            md.push_str(&format!(
                "- {}@{} owner={} provenance={} verified={}\n",
                plugin.plugin_id, plugin.version, plugin.owner, plugin.provenance, plugin.verified
            ));
        }
    } else {
        md.push_str("- not provided\n");
    }

    md.push_str("\n## Exception Governance\n");
    if let Some(packet) = exceptions.as_ref() {
        if packet.exceptions.is_empty() {
            md.push_str("- none\n");
        } else {
            for entry in &packet.exceptions {
                md.push_str(&format!(
                    "- repo={} kind={} scope={} approved_by={} expires_at={}\n",
                    entry.repo, entry.kind, entry.scope, entry.approved_by, entry.expires_at
                ));
            }
        }
    } else {
        md.push_str("- not provided\n");
    }

    md.push_str("\n## Audit Retention Tier\n");
    if audits.len() + audits_v2.len() >= 100 {
        md.push_str("- hot: 7d\n- warm: 30d\n- cold: 90d\n");
    } else {
        md.push_str("- hot: 14d\n- warm: 60d\n- cold: 180d\n");
    }

    md.push_str("\n## Segment Cost\n");
    if segment_duration_ms.is_empty() {
        md.push_str("- none\n");
    } else {
        for (segment, duration_ms) in segment_duration_ms {
            md.push_str(&format!(
                "- {segment}: {:.2} minutes\n",
                duration_ms as f64 / 60_000.0
            ));
        }
    }

    md.push_str("\n## Review Notes\n");
    if !cost_ceiling_ok {
        md.push_str("- Estimated CI minutes exceed the configured fleet cost ceiling.\n");
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
    } else if cost_ceiling_ok {
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
    let migration_guide_present = path_exists(options.migration_guide_path.as_deref());
    let provider_rollout_present = path_exists(options.provider_rollout_path.as_deref());
    let candidate_checklist_present = path_exists(options.candidate_checklist_path.as_deref());
    let provider_summaries = summarize_provider_inputs(&options.provider_inputs)?;
    let candidate_repos = candidate_repos(&metrics, &audits);
    let provider_bridge_ready =
        provider_bridge_ready_for_repos(&provider_summaries, &candidate_repos);
    let audit_drift_clean =
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2);
    let migration_drill_clean = replay_summary
        .as_ref()
        .is_some_and(|summary| summary.failed_records == 0 && summary.retained_records == 0);
    let rollback_packet_ready =
        migration_drill_clean && shadow.aligned && candidate_checklist_present;
    let deprecation_window_days = 90u16;
    let rc_ready = scoreboard.v2_seed_ready
        && audit_drift_clean
        && shadow.aligned
        && provider_bridge_ready
        && benchmark_signoff
        && security_review_approved
        && migration_guide_present
        && provider_rollout_present
        && candidate_checklist_present
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
    if !security_review_present {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Attach the RC security review packet before promoting the candidate.".to_string(),
        );
    } else if !security_review_approved {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Mark the RC security review packet with `- [x] Continue` and keep `Mitigation required` unchecked after reviewer sign-off.".to_string(),
        );
    }
    if !migration_guide_present || !provider_rollout_present || !candidate_checklist_present {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Sync migration guide, provider rollout checklist, and candidate checklist paths."
                .to_string(),
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
    md.push_str(&format!("- shadow_aligned: {}\n", shadow.aligned));
    md.push_str(&format!("- audit_drift_clean: {}\n", audit_drift_clean));
    md.push_str(&format!(
        "- provider_bridge_ready: {}\n",
        provider_bridge_ready
    ));
    md.push_str(&format!("- benchmark_signoff: {}\n", benchmark_signoff));
    md.push_str(&format!(
        "- security_review_present: {}\n",
        security_review_present
    ));
    md.push_str(&format!(
        "- security_review_approved: {}\n",
        security_review_approved
    ));
    md.push_str(&format!(
        "- migration_drill_clean: {}\n",
        migration_drill_clean
    ));
    md.push_str(&format!(
        "- rollback_packet_ready: {}\n\n",
        rollback_packet_ready
    ));

    md.push_str("## Checklist\n");
    md.push_str(&format!(
        "- {} v2 seed readiness passes\n",
        checklist_box(scoreboard.v2_seed_ready)
    ));
    md.push_str(&format!(
        "- {} audit drift is clean\n",
        checklist_box(audit_drift_clean)
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
        "- {} security review packet is approved\n",
        checklist_box(security_review_approved)
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
        "- {} candidate checklist path resolves\n",
        checklist_box(candidate_checklist_present)
    ));
    md.push_str(&format!(
        "- {} rollback packet is derivable from replay + shadow evidence\n",
        checklist_box(rollback_packet_ready)
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
    println!("rc readiness packet written: {}", options.output.display());
    if !rc_ready {
        bail!("v2 rc readiness failed");
    }
    Ok(())
}

fn run_ga_packet(options: &OpsOptions) -> Result<()> {
    let metrics = load_jsonl_records::<MetricLogRecord>(&options.metrics_input)?;
    let audits = load_jsonl_records::<AuditLogRecord>(&options.audit_input)?;
    let audit_v2_input = options
        .audit_v2_input
        .as_deref()
        .ok_or_else(|| anyhow!("--audit-v2-input is required for ga-packet"))?;
    let audits_v2 = load_jsonl_records::<AuditLogV2Record>(audit_v2_input)?;
    let replay_summary = options
        .replay_summary_input
        .as_deref()
        .map(load_json_file::<DeadLetterReplaySummaryRecord>)
        .transpose()?;
    let policy_input = options
        .policy_input
        .as_deref()
        .ok_or_else(|| anyhow!("--policy-input is required for ga-packet"))?;
    let release_policy = load_release_policy_summary(policy_input)?;
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
    let migration_guide_present = path_exists(options.migration_guide_path.as_deref());
    let candidate_checklist_present = path_exists(options.candidate_checklist_path.as_deref());
    let ops_handbook_present = path_exists(options.ops_handbook_path.as_deref());
    let support_model_present = path_exists(options.support_model_path.as_deref());
    let sunset_notice_present = path_exists(options.sunset_notice_path.as_deref());
    let phase201_backcast_present = path_exists(options.phase201_backcast_path.as_deref());
    let lts_ready = release_policy.lts_active
        && !release_policy.lts_branch.trim().is_empty()
        && release_policy.security_sla_hours <= 72;
    let docs_ready = migration_guide_present
        && candidate_checklist_present
        && ops_handbook_present
        && support_model_present
        && sunset_notice_present
        && phase201_backcast_present;
    let dual_run_decommission_ready = replay_clean && shadow.aligned;
    let audit_drift_clean =
        audit_drift_is_clean(&drift) && audit_stream_contracts_are_clean(&audits, &audits_v2);
    let ga_ready = scoreboard.v2_seed_ready
        && dual_run_decommission_ready
        && audit_drift_clean
        && lts_ready
        && docs_ready;

    let mut next_actions = assessment.next_actions.clone();
    let mut seen_actions = next_actions.iter().cloned().collect::<BTreeSet<_>>();
    if !lts_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Enable release.lts, set the branch name, and keep security_sla_hours <= 72."
                .to_string(),
        );
    }
    if !docs_ready {
        push_unique_action(
            &mut next_actions,
            &mut seen_actions,
            "Refresh migration, checklist, ops handbook, support model, sunset notice, and Phase201+ docs.".to_string(),
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
        "- {} LTS policy is active and within SLA\n",
        checklist_box(lts_ready)
    ));
    md.push_str(&format!(
        "- {} migration guide exists\n",
        checklist_box(migration_guide_present)
    ));
    md.push_str(&format!(
        "- {} candidate checklist exists\n",
        checklist_box(candidate_checklist_present)
    ));
    md.push_str(&format!(
        "- {} ops handbook exists\n",
        checklist_box(ops_handbook_present)
    ));
    md.push_str(&format!(
        "- {} support model exists\n",
        checklist_box(support_model_present)
    ));
    md.push_str(&format!(
        "- {} v1 sunset notice exists\n",
        checklist_box(sunset_notice_present)
    ));
    md.push_str(&format!(
        "- {} Phase201+ backcast exists\n",
        checklist_box(phase201_backcast_present)
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

fn summarize_provider_inputs(paths: &[PathBuf]) -> Result<Vec<ProviderArtifactSummary>> {
    let mut out = Vec::new();
    for path in paths {
        let value = load_json_file::<serde_json::Value>(path)?;
        let schema_mode = if value.get("bridge_format").is_some() {
            "dual"
        } else if value.get("publish_format").is_some() {
            "v2"
        } else if value.get("provider").is_some() {
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
            schema_mode: schema_mode.to_string(),
        });
    }
    Ok(out)
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
    !repos.is_empty()
        && provider_summaries.iter().any(|summary| {
            repos.contains(summary.repo.as_str())
                && matches!(summary.schema_mode.as_str(), "dual" | "v2")
        })
}

fn path_exists(path: Option<&Path>) -> bool {
    path.is_some_and(Path::exists)
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

fn write_output(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
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
        aggregate_failure_code_counts, audit_drift_is_clean, audit_stream_contracts_are_clean,
        average_duration_for_summary, build_audit_drift_summary,
        build_combined_audit_drift_summary, build_compatibility_assessment,
        build_freeze_scoreboard, build_shadow_alignment, build_verify_v1_calibration,
        candidate_repos, canonical_repo_path, checklist_box, fleet_repo_posture_label,
        load_json_file, load_jsonl_records, load_release_policy_summary, percentile_u128,
        provider_bridge_ready_for_repos, run_ga_readiness, security_review_is_approved,
        summarize_provider_inputs, validate_workload_identity, AuditFailureV2, AuditGateV2,
        AuditLogRecord, AuditLogV2Record, AuditOperationV2, BenchSample, CompatibilityPosture,
        DeadLetterReplaySummaryRecord, MetricLogRecord, OpsOptions, OpsSubcommand,
        ProviderArtifactSummary, TEMP_SEQ,
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
    fn checklist_box_marks_condition() {
        assert_eq!(checklist_box(true), "[x]");
        assert_eq!(checklist_box(false), "[ ]");
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
            bundle_catalog_input: None,
            registry_input: None,
            exceptions_input: None,
            benchmark_input: None,
            security_review_input: None,
            policy_input: None,
            migration_guide_path: None,
            provider_rollout_path: None,
            candidate_checklist_path: None,
            ops_handbook_path: None,
            support_model_path: None,
            sunset_notice_path: None,
            phase201_backcast_path: None,
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
                schema_mode: "dual".to_string(),
            },
            ProviderArtifactSummary {
                repo: "repo-a".to_string(),
                schema_mode: "v1".to_string(),
            },
        ];

        assert!(!provider_bridge_ready_for_repos(&summaries, &repos));
    }

    #[test]
    fn summarize_provider_inputs_detects_dual_payload() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("xtask-provider-{seq}.json"));
        fs::write(
            &path,
            r#"{"schema_version":1,"bridge_format":"patchgate.provider.generic.bridge.v1","repo":"example/repo"}"#,
        )
        .expect("write provider payload");

        let summaries = summarize_provider_inputs(std::slice::from_ref(&path))
            .expect("summarize provider inputs");
        assert_eq!(summaries[0].schema_mode, "dual");
        assert_eq!(summaries[0].repo, "example/repo");

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
