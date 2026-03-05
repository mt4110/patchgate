use std::collections::BTreeMap;
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
    SloReport,
    GaReadiness,
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
    output: PathBuf,
    trend_output: Option<PathBuf>,
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Deserialize)]
struct AuditLogRecord {
    unix_ts: u64,
    actor: String,
    repo: String,
    mode: String,
    scope: String,
    result: String,
    failure_code: Option<String>,
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
        "usage:\n  cargo run -p xtask -- bench record [--case NAME] [--repo PATH] [--output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- bench compare [--case NAME] [--repo PATH] [--output PATH] [--max-regression-pct N] [--require-baseline] [--append-on-pass] [--report-output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- bench profile [--repo PATH] [--profile-output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- ops weekly-summary --metrics-input PATH --audit-input PATH --output PATH [--trend-output PATH]\n  cargo run -p xtask -- ops audit-report --audit-input PATH --output PATH\n  cargo run -p xtask -- ops slo-report --metrics-input PATH --output PATH [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]\n  cargo run -p xtask -- ops ga-readiness --metrics-input PATH --audit-input PATH --output PATH [--availability-target-pct N] [--p95-target-ms N] [--false-positive-target-pct N]"
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
        bail!("missing ops subcommand (`weekly-summary`, `audit-report`, `slo-report`, or `ga-readiness`)");
    };
    let subcommand = match sub.to_string_lossy().as_ref() {
        "weekly-summary" => OpsSubcommand::WeeklySummary,
        "audit-report" => OpsSubcommand::AuditReport,
        "slo-report" => OpsSubcommand::SloReport,
        "ga-readiness" => OpsSubcommand::GaReadiness,
        other => bail!("unsupported ops subcommand `{other}`"),
    };
    let mut metrics_input = PathBuf::from("artifacts/scan-metrics.jsonl");
    let mut audit_input = PathBuf::from("artifacts/scan-audit.jsonl");
    let mut output = PathBuf::from("artifacts/ops-report.md");
    let mut trend_output = None;
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
        output,
        trend_output,
        availability_target_pct,
        p95_target_ms,
        false_positive_target_pct,
    })
}

fn run_ops(options: &OpsOptions) -> Result<()> {
    match options.subcommand {
        OpsSubcommand::WeeklySummary => run_weekly_summary(options),
        OpsSubcommand::AuditReport => run_audit_report(options),
        OpsSubcommand::SloReport => run_slo_report(options),
        OpsSubcommand::GaReadiness => run_ga_readiness(options),
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
    let has_audit_failures = audits
        .iter()
        .any(|row| row.failure_code.is_some() || row.result == "error");
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
        aggregate_failure_code_counts, average_duration_for_summary, canonical_repo_path,
        checklist_box, load_jsonl_records, percentile_u128, run_ga_readiness,
        validate_workload_identity, AuditLogRecord, BenchSample, MetricLogRecord, OpsOptions,
        OpsSubcommand, TEMP_SEQ,
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
                unix_ts: 10,
                actor: "bot".to_string(),
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "error".to_string(),
                failure_code: Some("PG-RT-001".to_string()),
            },
            AuditLogRecord {
                unix_ts: 10,
                actor: "bot".to_string(),
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                result: "error".to_string(),
                failure_code: Some("PG-RT-001".to_string()),
            },
            AuditLogRecord {
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
            output: output.clone(),
            trend_output: None,
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
}
