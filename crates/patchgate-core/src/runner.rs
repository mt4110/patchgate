use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context as _, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use patchgate_config::Config;
use sha2::{Digest, Sha256};

use crate::model::{
    CheckId, CheckScore, Finding, Location, PluginChangedFile, PluginFinding, PluginInput,
    PluginInvocation, PluginInvocationStatus, PluginOutput, Report, ReportMeta, Severity,
    SupplyChainSignal,
};

const MAX_STORED_LINE_SAMPLES: usize = 32;
const MAX_STORED_LINE_CHARS: usize = 240;

#[derive(Debug, Clone, Copy)]
pub enum ScopeMode {
    Staged,
    Worktree,
    Repo,
}

impl ScopeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeMode::Staged => "staged",
            ScopeMode::Worktree => "worktree",
            ScopeMode::Repo => "repo",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Context {
    pub repo_root: PathBuf,
    pub scope: ScopeMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
    TypeChanged,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ChangedFile {
    pub path: String,
    pub status: ChangeStatus,
    pub old_path: Option<String>,
    pub added: u32,
    pub deleted: u32,
    pub added_lines: Vec<String>,
    pub removed_lines: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DiffData {
    pub files: Vec<ChangedFile>,
    pub fingerprint: String,
}

impl DiffData {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

pub struct Runner {
    policy: Config,
}

impl Runner {
    pub fn new(policy: Config) -> Self {
        Self { policy }
    }

    pub fn collect_diff(&self, ctx: &Context) -> Result<DiffData> {
        collect_diff(ctx)
    }

    pub fn evaluate(&self, ctx: &Context, diff: DiffData, mode: &str) -> Result<Report> {
        let start = Instant::now();

        let exclude_set =
            compile_globs(&self.policy.exclude.globs).context("failed to compile exclude globs")?;
        let generated_set = compile_globs(&self.policy.generated_code.globs)
            .context("failed to compile generated_code.globs")?;

        let (
            (test_gap, test_gap_ms),
            (dangerous_change, dangerous_change_ms),
            (dependency_update, dependency_update_ms),
        ) = std::thread::scope(|scope| {
            let test_gap_handle = scope.spawn(|| {
                let check_start = Instant::now();
                let result = evaluate_test_gap(&self.policy, &diff, &exclude_set, &generated_set);
                (result, check_start.elapsed().as_millis())
            });
            let dangerous_change_handle = scope.spawn(|| {
                let check_start = Instant::now();
                let result =
                    evaluate_dangerous_change(&self.policy, &diff, &exclude_set, &generated_set);
                (result, check_start.elapsed().as_millis())
            });
            let dependency_update_handle = scope.spawn(|| {
                let check_start = Instant::now();
                let result =
                    evaluate_dependency_update(&self.policy, &diff, &exclude_set, &generated_set);
                (result, check_start.elapsed().as_millis())
            });

            let (test_gap_result, test_gap_ms) = test_gap_handle
                .join()
                .map_err(|_| anyhow::anyhow!("test_gap worker thread panicked"))?;
            let (dangerous_change_result, dangerous_change_ms) = dangerous_change_handle
                .join()
                .map_err(|_| anyhow::anyhow!("dangerous_change worker thread panicked"))?;
            let (dependency_update_result, dependency_update_ms) = dependency_update_handle
                .join()
                .map_err(|_| anyhow::anyhow!("dependency_update worker thread panicked"))?;

            Ok::<_, anyhow::Error>((
                (test_gap_result?, test_gap_ms),
                (dangerous_change_result?, dangerous_change_ms),
                (dependency_update_result?, dependency_update_ms),
            ))
        })?;

        let plugin_outcome = evaluate_plugins(&self.policy, ctx, &diff, mode)?;

        let mut findings = Vec::new();
        findings.extend(test_gap.findings);
        findings.extend(dangerous_change.findings);
        findings.extend(dependency_update.findings);
        findings.extend(plugin_outcome.findings);

        let mut checks = vec![
            test_gap.score,
            dangerous_change.score,
            dependency_update.score,
        ];
        if let Some(plugin_score) = plugin_outcome.score {
            checks.push(plugin_score);
        }

        let changed_files = diff.files.len();
        let fingerprint = diff.fingerprint.clone();
        let mut report = Report::new(
            findings,
            checks,
            ReportMeta {
                threshold: self.policy.output.fail_threshold,
                mode: mode.to_string(),
                scope: ctx.scope.as_str().to_string(),
                fingerprint,
                duration_ms: start.elapsed().as_millis(),
                skipped_by_cache: false,
            },
        );
        report.changed_files = changed_files;
        report
            .check_durations_ms
            .insert(CheckId::TestGap.as_str().to_string(), test_gap_ms);
        report.check_durations_ms.insert(
            CheckId::DangerousChange.as_str().to_string(),
            dangerous_change_ms,
        );
        report.check_durations_ms.insert(
            CheckId::DependencyUpdate.as_str().to_string(),
            dependency_update_ms,
        );
        if let Some(plugin_duration_ms) = plugin_outcome.total_duration_ms {
            report.check_durations_ms.insert(
                CheckId::ExternalPlugin.as_str().to_string(),
                plugin_duration_ms,
            );
        }
        report.supply_chain_signals = build_supply_chain_signals(&diff);
        if !report.supply_chain_signals.is_empty() {
            report.diagnostic_hints.push(
                "Supply-chain signal detected: require dependency integrity review.".to_string(),
            );
        }
        if !plugin_outcome.diagnostics.is_empty() {
            report.diagnostic_hints.extend(plugin_outcome.diagnostics);
        }
        report.plugin_invocations = plugin_outcome.invocations;
        Ok(report)
    }

    pub fn run(&self, ctx: &Context, mode: &str) -> Result<Report> {
        let diff = self.collect_diff(ctx)?;
        self.evaluate(ctx, diff, mode)
    }
}

struct CheckEvaluation {
    score: CheckScore,
    findings: Vec<Finding>,
}

#[derive(Debug, Default)]
struct PluginEvaluationOutcome {
    score: Option<CheckScore>,
    findings: Vec<Finding>,
    invocations: Vec<PluginInvocation>,
    diagnostics: Vec<String>,
    total_duration_ms: Option<u128>,
}

fn evaluate_plugins(
    policy: &Config,
    ctx: &Context,
    diff: &DiffData,
    mode: &str,
) -> Result<PluginEvaluationOutcome> {
    if !policy.plugins.enabled || policy.plugins.entries.is_empty() {
        return Ok(PluginEvaluationOutcome::default());
    }

    let mut outcome = PluginEvaluationOutcome::default();
    let mut total_penalty: u16 = 0;
    let mut total_duration_ms = 0u128;
    let mut triggered = false;

    for plugin in &policy.plugins.entries {
        let start = Instant::now();
        let result = execute_plugin(policy, ctx, diff, mode, plugin);
        total_duration_ms = total_duration_ms.saturating_add(start.elapsed().as_millis());
        match result {
            Ok(invocation) => {
                if invocation.status != PluginInvocationStatus::Pass {
                    triggered = true;
                }
                if plugin.fail_mode == "fail_closed"
                    && plugin_invocation_is_execution_failure(&invocation.status)
                {
                    let message = invocation
                        .error
                        .as_deref()
                        .unwrap_or("plugin execution failed");
                    return Err(anyhow::anyhow!(
                        "plugin `{}` failed with fail_closed policy: {message}",
                        plugin.id
                    ));
                }
                for finding in &invocation.findings {
                    total_penalty = total_penalty.saturating_add(finding.penalty as u16);
                }
                outcome.findings.extend(
                    invocation
                        .findings
                        .iter()
                        .map(|f| plugin_to_core_finding(plugin.id.as_str(), f)),
                );
                outcome.diagnostics.extend(
                    invocation
                        .diagnostics
                        .iter()
                        .map(|d| format!("plugin:{}: {d}", plugin.id)),
                );
                outcome.invocations.push(invocation);
            }
            Err(err) => {
                let message = format!("{err:#}");
                triggered = true;
                if plugin.fail_mode == "fail_closed" {
                    return Err(anyhow::anyhow!(
                        "plugin `{}` failed with fail_closed policy: {message}",
                        plugin.id
                    ));
                }
                outcome.diagnostics.push(format!(
                    "plugin:{} failed (fail_open): {message}",
                    plugin.id
                ));
                outcome.invocations.push(PluginInvocation {
                    plugin_id: plugin.id.clone(),
                    status: PluginInvocationStatus::Error,
                    duration_ms: start.elapsed().as_millis(),
                    sandbox_profile: policy.plugins.sandbox.profile.clone(),
                    findings: Vec::new(),
                    diagnostics: vec!["execution failed".to_string()],
                    error: Some(message),
                });
            }
        }
    }

    let max_penalty = policy.weights.plugin_max_penalty;
    let penalty = total_penalty.min(max_penalty as u16) as u8;
    if !outcome.invocations.is_empty() {
        outcome.score = Some(CheckScore {
            check: CheckId::ExternalPlugin,
            label: CheckId::ExternalPlugin.label().to_string(),
            penalty,
            max_penalty,
            triggered: triggered || penalty > 0 || !outcome.findings.is_empty(),
        });
        outcome.total_duration_ms = Some(total_duration_ms);
    }

    Ok(outcome)
}

fn plugin_invocation_is_execution_failure(status: &PluginInvocationStatus) -> bool {
    matches!(
        status,
        PluginInvocationStatus::Error | PluginInvocationStatus::TimedOut
    )
}

fn execute_plugin(
    policy: &Config,
    ctx: &Context,
    diff: &DiffData,
    mode: &str,
    plugin: &patchgate_config::PluginEntry,
) -> Result<PluginInvocation> {
    let input = PluginInput {
        schema_version: 1,
        api_version: "patchgate.plugin.v1".to_string(),
        plugin_id: plugin.id.clone(),
        repo_root: ctx.repo_root.to_string_lossy().to_string(),
        mode: mode.to_string(),
        scope: ctx.scope.as_str().to_string(),
        changed_files: diff
            .files
            .iter()
            .map(|f| PluginChangedFile {
                path: f.path.clone(),
                status: change_status_as_str(f.status).to_string(),
                added: f.added,
                deleted: f.deleted,
            })
            .collect(),
    };
    let input_json = serde_json::to_vec(&input).context("failed to encode plugin input")?;
    let max_output_bytes = (policy.plugins.sandbox.max_stdout_kib as usize).saturating_mul(1024);
    let sandbox_profile = policy.plugins.sandbox.profile.as_str();
    let timeout = Duration::from_millis(plugin.timeout_ms);

    let start = Instant::now();
    let mut command = Command::new(plugin.command.as_str());
    command.args(&plugin.args);
    command.current_dir(&ctx.repo_root);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if sandbox_profile == "restricted" {
        command.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
        for key in &policy.plugins.sandbox.env_allowlist {
            if let Ok(value) = std::env::var(key) {
                command.env(key, value);
            }
        }
    }
    command.env("PATCHGATE_PLUGIN_ID", plugin.id.as_str());
    command.env("PATCHGATE_SANDBOX_PROFILE", sandbox_profile);
    command.env(
        "PATCHGATE_SANDBOX_NETWORK",
        if policy.plugins.sandbox.allow_network {
            "allow"
        } else {
            "deny"
        },
    );

    let mut child = command.spawn().with_context(|| {
        format!(
            "failed to start plugin `{}` command `{}`",
            plugin.id, plugin.command
        )
    })?;
    let stdin_writer = child.stdin.take().map(|mut stdin| {
        thread::spawn(move || -> std::io::Result<()> {
            stdin.write_all(&input_json)?;
            Ok(())
        })
    });

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture plugin stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture plugin stderr"))?;
    let stdout_limit_exceeded = Arc::new(AtomicBool::new(false));
    let stderr_limit_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_limit_probe = Arc::clone(&stdout_limit_exceeded);
    let stderr_limit_probe = Arc::clone(&stderr_limit_exceeded);
    let stdout_reader = thread::spawn(move || {
        read_stream_with_limit(stdout, max_output_bytes, Some(stdout_limit_probe))
    });
    let stderr_reader = thread::spawn(move || {
        read_stream_with_limit(stderr, max_output_bytes, Some(stderr_limit_probe))
    });

    let termination = wait_for_child_with_timeout(
        &mut child,
        timeout,
        stdout_limit_exceeded.as_ref(),
        stderr_limit_exceeded.as_ref(),
    )?;
    if !matches!(termination, ChildTermination::Exited(_)) {
        let _ = child.kill();
        let _ = child.wait();
    }
    if let Some(stdin_writer) = stdin_writer {
        join_stdin_writer(stdin_writer, &termination)?;
    }
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    let duration_ms = start.elapsed().as_millis();

    if matches!(termination, ChildTermination::TimedOut) {
        return Ok(PluginInvocation {
            plugin_id: plugin.id.clone(),
            status: PluginInvocationStatus::TimedOut,
            duration_ms,
            sandbox_profile: sandbox_profile.to_string(),
            findings: Vec::new(),
            diagnostics: vec![format!("timeout after {}ms", plugin.timeout_ms)],
            error: Some(format!("plugin timed out after {}ms", plugin.timeout_ms)),
        });
    }

    if stdout_limit_exceeded.load(Ordering::Relaxed)
        || stderr_limit_exceeded.load(Ordering::Relaxed)
        || matches!(termination, ChildTermination::OutputLimitExceeded)
    {
        let mut exceeded_streams = Vec::new();
        if stdout_limit_exceeded.load(Ordering::Relaxed) {
            exceeded_streams.push("stdout");
        }
        if stderr_limit_exceeded.load(Ordering::Relaxed) {
            exceeded_streams.push("stderr");
        }
        let stream_label = if exceeded_streams.is_empty() {
            "output".to_string()
        } else {
            exceeded_streams.join(",")
        };
        let message = format!(
            "plugin `{}` {} exceeded sandbox.max_stdout_kib ({} KiB)",
            plugin.id, stream_label, policy.plugins.sandbox.max_stdout_kib
        );
        return Ok(PluginInvocation {
            plugin_id: plugin.id.clone(),
            status: PluginInvocationStatus::Error,
            duration_ms,
            sandbox_profile: sandbox_profile.to_string(),
            findings: Vec::new(),
            diagnostics: vec![message.clone()],
            error: Some(message),
        });
    }

    let exit_status = match termination {
        ChildTermination::Exited(status) => status,
        ChildTermination::TimedOut | ChildTermination::OutputLimitExceeded => unreachable!(),
    };

    let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
    if !exit_status.success() {
        let reason = if stderr.is_empty() {
            format!("exit status: {exit_status}")
        } else {
            stderr
        };
        return Ok(PluginInvocation {
            plugin_id: plugin.id.clone(),
            status: PluginInvocationStatus::Error,
            duration_ms,
            sandbox_profile: sandbox_profile.to_string(),
            findings: Vec::new(),
            diagnostics: vec!["plugin process returned non-zero exit".to_string()],
            error: Some(reason),
        });
    }

    let stdout = String::from_utf8(stdout).context("plugin stdout was not utf8")?;
    let mut plugin_output: PluginOutput =
        serde_json::from_str(stdout.as_str()).context("failed to decode plugin output json")?;
    for finding in &mut plugin_output.findings {
        if finding.rule_id.trim().is_empty() {
            finding.rule_id = finding.id.clone();
        }
        if finding.category.trim().is_empty() {
            finding.category = "plugin".to_string();
        }
    }
    let status = if plugin_output.findings.is_empty() {
        PluginInvocationStatus::Pass
    } else {
        PluginInvocationStatus::Fail
    };
    let mut diagnostics = plugin_output.diagnostics;
    if !stderr.is_empty() {
        diagnostics.push(format!("stderr: {stderr}"));
    }
    Ok(PluginInvocation {
        plugin_id: plugin.id.clone(),
        status,
        duration_ms,
        sandbox_profile: sandbox_profile.to_string(),
        findings: plugin_output.findings,
        diagnostics,
        error: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildTermination {
    Exited(std::process::ExitStatus),
    TimedOut,
    OutputLimitExceeded,
}

fn wait_for_child_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    stdout_limit_exceeded: &AtomicBool,
    stderr_limit_exceeded: &AtomicBool,
) -> Result<ChildTermination> {
    let start = Instant::now();
    loop {
        if stdout_limit_exceeded.load(Ordering::Relaxed)
            || stderr_limit_exceeded.load(Ordering::Relaxed)
        {
            return Ok(ChildTermination::OutputLimitExceeded);
        }
        if let Some(status) = child.try_wait()? {
            return Ok(ChildTermination::Exited(status));
        }
        if start.elapsed() >= timeout {
            return Ok(ChildTermination::TimedOut);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_stream_with_limit<R: Read>(
    mut reader: R,
    max_bytes: usize,
    overflow_flag: Option<Arc<AtomicBool>>,
) -> std::io::Result<Vec<u8>> {
    let mut stored = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut overflowed = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if overflowed {
            continue;
        }
        let remaining = max_bytes.saturating_sub(stored.len());
        if read <= remaining {
            stored.extend_from_slice(&buffer[..read]);
            continue;
        }
        if remaining > 0 {
            stored.extend_from_slice(&buffer[..remaining]);
        }
        overflowed = true;
        if let Some(flag) = overflow_flag.as_ref() {
            flag.store(true, Ordering::Relaxed);
        }
    }
    Ok(stored)
}

fn join_reader(
    handle: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream_name: &str,
) -> Result<Vec<u8>> {
    let output = handle
        .join()
        .map_err(|_| anyhow::anyhow!("plugin {stream_name} reader thread panicked"))?;
    output.with_context(|| format!("failed to read plugin {stream_name}"))
}

fn join_stdin_writer(
    handle: thread::JoinHandle<std::io::Result<()>>,
    termination: &ChildTermination,
) -> Result<()> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            if matches!(termination, ChildTermination::Exited(_)) {
                return Err(err).context("failed to write plugin input");
            }
            Ok(())
        }
        Err(_) => Err(anyhow::anyhow!("plugin stdin writer thread panicked")),
    }
}

fn plugin_to_core_finding(plugin_id: &str, finding: &PluginFinding) -> Finding {
    let mut tags = finding.tags.clone();
    tags.push(format!("plugin:{plugin_id}"));
    let core_id = if finding.id.trim().is_empty() {
        format!("PLG-{plugin_id}-001")
    } else {
        finding.id.clone()
    };
    Finding {
        id: core_id.clone(),
        rule_id: if finding.rule_id.trim().is_empty() {
            core_id
        } else {
            finding.rule_id.clone()
        },
        category: if finding.category.trim().is_empty() {
            "plugin".to_string()
        } else {
            finding.category.clone()
        },
        docs_url: finding.docs_url.clone(),
        check: CheckId::ExternalPlugin,
        title: finding.title.clone(),
        message: finding.message.clone(),
        severity: finding.severity,
        penalty: finding.penalty,
        location: finding.location.clone(),
        tags,
    }
}

fn change_status_as_str(status: ChangeStatus) -> &'static str {
    match status {
        ChangeStatus::Added => "added",
        ChangeStatus::Modified => "modified",
        ChangeStatus::Deleted => "deleted",
        ChangeStatus::Renamed => "renamed",
        ChangeStatus::Copied => "copied",
        ChangeStatus::TypeChanged => "type_changed",
        ChangeStatus::Unknown => "unknown",
    }
}

fn evaluate_test_gap(
    policy: &Config,
    diff: &DiffData,
    exclude_set: &GlobSet,
    generated_set: &GlobSet,
) -> Result<CheckEvaluation> {
    let max_penalty = policy.weights.test_gap_max_penalty;
    if !policy.test_gap.enabled {
        return Ok(CheckEvaluation {
            score: CheckScore {
                check: CheckId::TestGap,
                label: CheckId::TestGap.label().to_string(),
                penalty: 0,
                max_penalty,
                triggered: false,
            },
            findings: Vec::new(),
        });
    }

    let test_set = compile_globs(&policy.test_gap.test_globs)
        .context("failed to compile test_gap.test_globs")?;
    let ignore_set = compile_globs(&policy.test_gap.production_ignore_globs)
        .context("failed to compile test_gap.production_ignore_globs")?;
    let manifest_set = compile_globs(&policy.dependency_update.manifest_globs)
        .context("failed to compile dependency_update.manifest_globs")?;
    let lock_set = compile_globs(&policy.dependency_update.lockfile_globs)
        .context("failed to compile dependency_update.lockfile_globs")?;

    let mut package_markers = BTreeSet::new();
    for file in &diff.files {
        if manifest_set.is_match(&file.path) {
            package_markers.insert(parent_dir(&file.path));
        }
    }
    let mut package_markers: Vec<String> = package_markers
        .into_iter()
        .filter(|marker| marker.as_str() != ".")
        .collect();
    package_markers.sort_by_key(|marker| std::cmp::Reverse(marker.len()));

    let mut tests_by_package: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut production_files_by_package: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut production_churn_by_package: BTreeMap<String, u32> = BTreeMap::new();

    for file in &diff.files {
        if exclude_set.is_match(&file.path) {
            continue;
        }
        if file.status == ChangeStatus::Deleted {
            continue;
        }
        // Skip metadata-only changes (e.g. pure rename/mode change) to reduce false positives.
        if is_metadata_only_change(file) {
            continue;
        }
        let generated_factor = generated_penalty_factor(policy, generated_set, &file.path);
        if generated_factor == 0 {
            continue;
        }
        if is_test_related_file(policy, file, &test_set) {
            let package = infer_package_root(&file.path, &package_markers);
            tests_by_package
                .entry(package)
                .or_default()
                .insert(file.path.clone());
            continue;
        }
        if ignore_set.is_match(&file.path)
            || manifest_set.is_match(&file.path)
            || lock_set.is_match(&file.path)
        {
            continue;
        }
        let churn = scale_u32_by_factor(file.added.saturating_add(file.deleted), generated_factor);
        let package = infer_package_root(&file.path, &package_markers);
        *production_churn_by_package
            .entry(package.clone())
            .or_insert(0) = production_churn_by_package
            .get(&package)
            .copied()
            .unwrap_or(0)
            .saturating_add(churn);
        production_files_by_package
            .entry(package)
            .or_default()
            .push(file.path.clone());
    }

    let mut findings = Vec::new();
    let mut penalty = 0u8;

    let global_test_files = tests_by_package.get(".").cloned().unwrap_or_default();
    let empty_test_files = BTreeSet::new();
    let mut uncovered_packages = Vec::new();
    let mut uncovered_files = Vec::new();
    let mut under_tested_packages = Vec::new();
    let mut under_tested_files = Vec::new();
    let mut under_tested_churn = 0u32;
    let mut under_tested_matching_test_files = BTreeSet::new();
    for (package, files) in &production_files_by_package {
        let package_test_files = tests_by_package.get(package).unwrap_or(&empty_test_files);
        let matching_test_updates = if package == "." {
            package_test_files.len()
        } else {
            package_test_files.union(&global_test_files).count()
        };
        if matching_test_updates == 0 {
            uncovered_packages.push(package.clone());
            uncovered_files.extend(files.iter().cloned());
        }
        if matching_test_updates <= 1 {
            under_tested_packages.push(package.clone());
            under_tested_files.extend(files.iter().cloned());
            under_tested_churn = under_tested_churn.saturating_add(
                production_churn_by_package
                    .get(package)
                    .copied()
                    .unwrap_or_default(),
            );
            under_tested_matching_test_files.extend(package_test_files.iter().cloned());
            if package != "." {
                under_tested_matching_test_files.extend(global_test_files.iter().cloned());
            }
        }
    }

    if !uncovered_files.is_empty() {
        penalty = penalty.saturating_add(policy.test_gap.missing_tests_penalty);
        let package_note = if !uncovered_packages.is_empty() {
            format!(
                " Uncovered package roots: {}.",
                uncovered_packages
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            String::new()
        };
        findings.push(Finding {
            id: "TG-001".to_string(),
            rule_id: "TG-001".to_string(),
            category: "test_coverage".to_string(),
            docs_url:
                "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                    .to_string(),
            check: CheckId::TestGap,
            title: "No test changes detected".to_string(),
            message: format!(
                "{} production file(s) changed without matching test coverage updates.{} Example: {}",
                uncovered_files.len(),
                package_note,
                uncovered_files
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::High,
            penalty: policy.test_gap.missing_tests_penalty,
            location: Some(Location {
                file: uncovered_files[0].clone(),
                line: None,
            }),
            tags: vec!["test-gap".to_string(), "package-boundary".to_string()],
        });
    }

    if !under_tested_files.is_empty() && under_tested_churn >= policy.test_gap.large_change_lines {
        penalty = penalty.saturating_add(policy.test_gap.large_change_penalty);
        findings.push(Finding {
            id: "TG-002".to_string(),
            rule_id: "TG-002".to_string(),
            category: "test_coverage".to_string(),
            docs_url:
                "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                    .to_string(),
            check: CheckId::TestGap,
            title: "Large code change with limited test updates".to_string(),
            message: format!(
                "Changed {} lines across under-tested production files with only {} matching test file(s) updated. Under-tested packages: {}",
                under_tested_churn,
                under_tested_matching_test_files.len(),
                under_tested_packages
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::Medium,
            penalty: policy.test_gap.large_change_penalty,
            location: Some(Location {
                file: under_tested_files[0].clone(),
                line: None,
            }),
            tags: vec![
                "test-gap".to_string(),
                "large-change".to_string(),
                "package-boundary".to_string(),
            ],
        });
    }

    let penalty = penalty.min(max_penalty);
    Ok(CheckEvaluation {
        score: CheckScore {
            check: CheckId::TestGap,
            label: CheckId::TestGap.label().to_string(),
            penalty,
            max_penalty,
            triggered: penalty > 0,
        },
        findings,
    })
}

fn evaluate_dangerous_change(
    policy: &Config,
    diff: &DiffData,
    exclude_set: &GlobSet,
    generated_set: &GlobSet,
) -> Result<CheckEvaluation> {
    let max_penalty = policy.weights.dangerous_change_max_penalty;
    if !policy.dangerous_change.enabled {
        return Ok(CheckEvaluation {
            score: CheckScore {
                check: CheckId::DangerousChange,
                label: CheckId::DangerousChange.label().to_string(),
                penalty: 0,
                max_penalty,
                triggered: false,
            },
            findings: Vec::new(),
        });
    }

    let pattern_set = compile_globs(&policy.dangerous_change.patterns)
        .context("failed to compile dangerous_change.patterns")?;
    let critical_set = compile_globs(&policy.dangerous_change.critical_patterns)
        .context("failed to compile dangerous_change.critical_patterns")?;

    let mut findings = Vec::new();
    let mut penalty = 0u8;

    for file in &diff.files {
        if exclude_set.is_match(&file.path) {
            continue;
        }
        if !pattern_set.is_match(&file.path) {
            continue;
        }

        let mut file_penalty = policy.dangerous_change.per_file_penalty;
        let is_critical = critical_set.is_match(&file.path);
        if is_critical {
            file_penalty =
                file_penalty.saturating_add(policy.dangerous_change.critical_bonus_penalty);
        }
        let generated_factor = generated_penalty_factor(policy, generated_set, &file.path);
        if generated_factor == 0 {
            continue;
        }
        file_penalty = scale_penalty(file_penalty, generated_factor);

        penalty = penalty.saturating_add(file_penalty);
        let mut tags = vec!["dangerous-change".to_string()];
        tags.push(if is_critical {
            "critical".to_string()
        } else {
            "non-critical".to_string()
        });
        if generated_factor < 100 {
            tags.push("generated-decay".to_string());
        }

        findings.push(Finding {
            id: if is_critical {
                "DC-002".to_string()
            } else {
                "DC-001".to_string()
            },
            rule_id: if is_critical {
                "DC-002".to_string()
            } else {
                "DC-001".to_string()
            },
            category: "change_risk".to_string(),
            docs_url:
                "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                    .to_string(),
            check: CheckId::DangerousChange,
            title: if is_critical {
                "Critical infrastructure path changed".to_string()
            } else {
                "High-risk path changed".to_string()
            },
            message: format!(
                "{} was changed (status: {:?}, classification:{}, generated_factor:{}%).",
                file.path,
                file.status,
                if is_critical {
                    "critical (matched dangerous_change.critical_patterns)"
                } else {
                    "non-critical (matched dangerous_change.patterns only)"
                },
                generated_factor
            ),
            severity: if is_critical {
                Severity::Critical
            } else {
                Severity::High
            },
            penalty: file_penalty,
            location: Some(Location {
                file: file.path.clone(),
                line: None,
            }),
            tags,
        });
    }

    let penalty = penalty.min(max_penalty);
    Ok(CheckEvaluation {
        score: CheckScore {
            check: CheckId::DangerousChange,
            label: CheckId::DangerousChange.label().to_string(),
            penalty,
            max_penalty,
            triggered: penalty > 0,
        },
        findings,
    })
}

fn evaluate_dependency_update(
    policy: &Config,
    diff: &DiffData,
    exclude_set: &GlobSet,
    generated_set: &GlobSet,
) -> Result<CheckEvaluation> {
    let max_penalty = policy.weights.dependency_update_max_penalty;
    if !policy.dependency_update.enabled {
        return Ok(CheckEvaluation {
            score: CheckScore {
                check: CheckId::DependencyUpdate,
                label: CheckId::DependencyUpdate.label().to_string(),
                penalty: 0,
                max_penalty,
                triggered: false,
            },
            findings: Vec::new(),
        });
    }

    let manifest_set = compile_globs(&policy.dependency_update.manifest_globs)
        .context("failed to compile dependency_update.manifest_globs")?;
    let lock_set = compile_globs(&policy.dependency_update.lockfile_globs)
        .context("failed to compile dependency_update.lockfile_globs")?;

    let mut manifests: Vec<(String, DependencyEcosystem, u8)> = Vec::new();
    let mut lockfiles: Vec<(ChangedFile, DependencyEcosystem, u8)> = Vec::new();
    let mut total_lockfile_churn = 0u32;

    for file in &diff.files {
        if exclude_set.is_match(&file.path) {
            continue;
        }
        // Ignore metadata-only diffs to avoid manifest/lock false positives.
        if is_metadata_only_change(file) {
            continue;
        }
        let generated_factor = generated_penalty_factor(policy, generated_set, &file.path);
        if generated_factor == 0 {
            continue;
        }
        if manifest_set.is_match(&file.path) {
            manifests.push((
                file.path.clone(),
                dependency_ecosystem_for_manifest(&file.path),
                generated_factor,
            ));
        }
        if lock_set.is_match(&file.path) {
            total_lockfile_churn = total_lockfile_churn.saturating_add(scale_u32_by_factor(
                file.added.saturating_add(file.deleted),
                generated_factor,
            ));
            lockfiles.push((
                file.clone(),
                dependency_ecosystem_for_lockfile(&file.path),
                generated_factor,
            ));
        }
    }

    let mut findings = Vec::new();
    let mut penalty = 0u8;

    if !manifests.is_empty() {
        let manifest_bonus = manifests
            .iter()
            .map(|(_, ecosystem, _)| {
                ecosystem_penalty_config(policy, *ecosystem).manifest_bonus_penalty
            })
            .max()
            .unwrap_or(0);
        let generated_factor = manifests
            .iter()
            .map(|(_, _, factor)| *factor)
            .max()
            .unwrap_or(100);
        let manifest_penalty = scale_penalty(
            policy
                .dependency_update
                .manifest_penalty
                .saturating_add(manifest_bonus),
            generated_factor,
        );
        penalty = penalty.saturating_add(manifest_penalty);
        findings.push(Finding {
            id: "DU-001".to_string(),
            rule_id: "DU-001".to_string(),
            category: "dependency".to_string(),
            docs_url:
                "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                    .to_string(),
            check: CheckId::DependencyUpdate,
            title: "Dependency manifest updated".to_string(),
            message: format!(
                "Dependency manifest changed (ecosystem bonus +{}, generated_factor {}%): {}",
                manifest_bonus,
                generated_factor,
                manifests
                    .iter()
                    .take(4)
                    .map(|(path, _, _)| path.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::Medium,
            penalty: manifest_penalty,
            location: Some(Location {
                file: manifests[0].0.clone(),
                line: None,
            }),
            tags: vec!["dependencies".to_string(), "manifest".to_string()],
        });
    }

    if !lockfiles.is_empty() {
        let lockfile_bonus = lockfiles
            .iter()
            .map(|(_, ecosystem, _)| {
                ecosystem_penalty_config(policy, *ecosystem).lockfile_bonus_penalty
            })
            .max()
            .unwrap_or(0);
        let generated_factor = lockfiles
            .iter()
            .map(|(_, _, factor)| *factor)
            .max()
            .unwrap_or(100);
        let lockfile_penalty = scale_penalty(
            policy
                .dependency_update
                .lockfile_penalty
                .saturating_add(lockfile_bonus),
            generated_factor,
        );
        penalty = penalty.saturating_add(lockfile_penalty);
        findings.push(Finding {
            id: "DU-002".to_string(),
            rule_id: "DU-002".to_string(),
            category: "dependency".to_string(),
            docs_url:
                "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                    .to_string(),
            check: CheckId::DependencyUpdate,
            title: "Dependency lockfile updated".to_string(),
            message: format!(
                "Dependency lockfile changed (ecosystem bonus +{}, generated_factor {}%): {}",
                lockfile_bonus,
                generated_factor,
                lockfiles
                    .iter()
                    .take(4)
                    .map(|(file, _, _)| file.path.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::Low,
            penalty: lockfile_penalty,
            location: Some(Location {
                file: lockfiles[0].0.path.clone(),
                line: None,
            }),
            tags: vec!["dependencies".to_string(), "lockfile".to_string()],
        });
    }

    if total_lockfile_churn >= policy.dependency_update.large_lockfile_churn
        && !lockfiles.is_empty()
    {
        let large_bonus = lockfiles
            .iter()
            .map(|(_, ecosystem, _)| {
                ecosystem_penalty_config(policy, *ecosystem).large_lockfile_bonus_penalty
            })
            .max()
            .unwrap_or(0);
        let generated_factor = lockfiles
            .iter()
            .map(|(_, _, factor)| *factor)
            .max()
            .unwrap_or(100);
        let large_lockfile_penalty = scale_penalty(
            policy
                .dependency_update
                .large_lockfile_penalty
                .saturating_add(large_bonus),
            generated_factor,
        );
        penalty = penalty.saturating_add(large_lockfile_penalty);
        findings.push(Finding {
            id: "DU-003".to_string(),
            rule_id: "DU-003".to_string(),
            category: "dependency".to_string(),
            docs_url:
                "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                    .to_string(),
            check: CheckId::DependencyUpdate,
            title: "Large lockfile churn".to_string(),
            message: format!(
                "Lockfile churn is high ({} changed lines). Prioritize review.",
                total_lockfile_churn
            ),
            severity: Severity::High,
            penalty: large_lockfile_penalty,
            location: Some(Location {
                file: lockfiles[0].0.path.clone(),
                line: None,
            }),
            tags: vec!["dependencies".to_string(), "large-churn".to_string()],
        });
    }

    for (lockfile, _ecosystem, generated_factor) in &lockfiles {
        if matches!(lockfile.status, ChangeStatus::Added | ChangeStatus::Deleted) {
            let add_remove_penalty = scale_penalty(
                policy.dependency_update.lockfile_added_or_removed_penalty,
                *generated_factor,
            );
            penalty = penalty.saturating_add(add_remove_penalty);
            findings.push(Finding {
                id: "DU-004".to_string(),
                rule_id: "DU-004".to_string(),
                category: "dependency".to_string(),
                docs_url:
                    "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                        .to_string(),
                check: CheckId::DependencyUpdate,
                title: "Lockfile was added or removed".to_string(),
                message: format!(
                    "{} was {:?}. Validate resolver/source integrity.",
                    lockfile.path, lockfile.status
                ),
                severity: Severity::Critical,
                penalty: add_remove_penalty,
                location: Some(Location {
                    file: lockfile.path.clone(),
                    line: None,
                }),
                tags: vec![
                    "dependencies".to_string(),
                    "lockfile-change-type".to_string(),
                    "added-removed".to_string(),
                ],
            });
        }
        let churn = lockfile.added.saturating_add(lockfile.deleted);
        if lockfile.added > 0
            && lockfile.deleted > 0
            && churn >= policy.dependency_update.lockfile_mass_update_lines
        {
            let mass_update_penalty = scale_penalty(
                policy.dependency_update.lockfile_mass_update_penalty,
                *generated_factor,
            );
            penalty = penalty.saturating_add(mass_update_penalty);
            findings.push(Finding {
                id: "DU-005".to_string(),
                rule_id: "DU-005".to_string(),
                category: "dependency".to_string(),
                docs_url:
                    "https://github.com/mt4110/patchgate/blob/main/docs/01_concepts.md#core-concepts"
                        .to_string(),
                check: CheckId::DependencyUpdate,
                title: "Lockfile mass update detected".to_string(),
                message: format!(
                    "{} changed by {} lines ({} additions / {} deletions).",
                    lockfile.path, churn, lockfile.added, lockfile.deleted
                ),
                severity: Severity::High,
                penalty: mass_update_penalty,
                location: Some(Location {
                    file: lockfile.path.clone(),
                    line: None,
                }),
                tags: vec![
                    "dependencies".to_string(),
                    "lockfile-change-type".to_string(),
                    "mass-update".to_string(),
                ],
            });
        }
    }

    let penalty = penalty.min(max_penalty);
    Ok(CheckEvaluation {
        score: CheckScore {
            check: CheckId::DependencyUpdate,
            label: CheckId::DependencyUpdate.label().to_string(),
            penalty,
            max_penalty,
            triggered: penalty > 0,
        },
        findings,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DependencyEcosystem {
    Cargo,
    Npm,
    Python,
    Go,
    Jvm,
    Unknown,
}

fn dependency_ecosystem_for_manifest(path: &str) -> DependencyEcosystem {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("cargo.toml") {
        DependencyEcosystem::Cargo
    } else if lower.ends_with("package.json") {
        DependencyEcosystem::Npm
    } else if lower.ends_with("requirements.txt")
        || lower.ends_with("requirements-dev.txt")
        || lower.ends_with("pyproject.toml")
        || lower.ends_with("pipfile")
    {
        DependencyEcosystem::Python
    } else if lower.ends_with("go.mod") {
        DependencyEcosystem::Go
    } else if lower.ends_with("pom.xml")
        || lower.ends_with("build.gradle")
        || lower.ends_with("build.gradle.kts")
    {
        DependencyEcosystem::Jvm
    } else {
        DependencyEcosystem::Unknown
    }
}

fn build_supply_chain_signals(diff: &DiffData) -> Vec<SupplyChainSignal> {
    let dependency_files: Vec<String> = diff
        .files
        .iter()
        .filter(|f| is_dependency_path(&f.path))
        .map(|f| f.path.clone())
        .collect();
    let infra_files: Vec<String> = diff
        .files
        .iter()
        .filter(|f| is_infra_or_ci_path(&f.path))
        .map(|f| f.path.clone())
        .collect();
    let lockfile_add_or_remove = diff.files.iter().any(|f| {
        is_lockfile_path(&f.path) && matches!(f.status, ChangeStatus::Added | ChangeStatus::Deleted)
    });

    let mut signals = Vec::new();
    if !dependency_files.is_empty() && !infra_files.is_empty() {
        let mut related_files = Vec::new();
        related_files.extend(dependency_files.iter().take(3).cloned());
        related_files.extend(infra_files.iter().take(3).cloned());
        signals.push(SupplyChainSignal {
            id: "SCM-001".to_string(),
            title: "Dependency and infrastructure changed together".to_string(),
            severity: Severity::High,
            message: "Dependency updates and CI/infra changes are bundled in one diff. Validate provenance and rollback safety.".to_string(),
            related_files,
            tags: vec![
                "supply-chain".to_string(),
                "dependency".to_string(),
                "infra".to_string(),
            ],
        });
    }

    if lockfile_add_or_remove && !infra_files.is_empty() {
        let mut related_files = Vec::new();
        related_files.extend(infra_files.iter().take(2).cloned());
        related_files.extend(
            diff.files
                .iter()
                .filter(|f| is_lockfile_path(&f.path))
                .map(|f| f.path.clone())
                .take(2),
        );
        signals.push(SupplyChainSignal {
            id: "SCM-002".to_string(),
            title: "Lockfile topology changed with workflow modifications".to_string(),
            severity: Severity::Critical,
            message: "Lockfile add/remove combined with CI/workflow edits can bypass dependency controls. Require security sign-off.".to_string(),
            related_files,
            tags: vec![
                "supply-chain".to_string(),
                "lockfile".to_string(),
                "workflow".to_string(),
            ],
        });
    }

    signals
}

fn is_dependency_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with("cargo.toml")
        || lower.ends_with("cargo.lock")
        || lower.ends_with("package.json")
        || lower.ends_with("package-lock.json")
        || lower.ends_with("yarn.lock")
        || lower.ends_with("pnpm-lock.yaml")
        || lower.ends_with("go.mod")
        || lower.ends_with("go.sum")
        || lower.ends_with("requirements.txt")
        || lower.ends_with("requirements-dev.txt")
        || lower.ends_with("pyproject.toml")
        || lower.ends_with("pipfile")
        || lower.ends_with("pipfile.lock")
        || lower.ends_with("poetry.lock")
        || lower.ends_with("pom.xml")
        || lower.ends_with("build.gradle")
        || lower.ends_with("build.gradle.kts")
        || lower.ends_with("gemfile")
        || lower.ends_with("gemfile.lock")
}

fn is_lockfile_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with("cargo.lock")
        || lower.ends_with("package-lock.json")
        || lower.ends_with("yarn.lock")
        || lower.ends_with("pnpm-lock.yaml")
        || lower.ends_with("go.sum")
        || lower.ends_with("pipfile.lock")
        || lower.ends_with("poetry.lock")
        || lower.ends_with("gemfile.lock")
        || lower.ends_with("requirements.lock")
}

fn is_infra_or_ci_path(path: &str) -> bool {
    path.starts_with(".github/workflows/")
        || path.starts_with("infra/")
        || path.starts_with("terraform/")
        || path.starts_with("k8s/")
        || path.starts_with("helm/")
        || path.starts_with("migrations/")
}

fn dependency_ecosystem_for_lockfile(path: &str) -> DependencyEcosystem {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("cargo.lock") {
        DependencyEcosystem::Cargo
    } else if lower.ends_with("package-lock.json")
        || lower.ends_with("yarn.lock")
        || lower.ends_with("pnpm-lock.yaml")
    {
        DependencyEcosystem::Npm
    } else if lower.ends_with("poetry.lock")
        || lower.ends_with("pipfile.lock")
        || lower.ends_with("requirements.lock")
    {
        DependencyEcosystem::Python
    } else if lower.ends_with("go.sum") {
        DependencyEcosystem::Go
    } else {
        DependencyEcosystem::Unknown
    }
}

fn ecosystem_penalty_config(
    policy: &Config,
    ecosystem: DependencyEcosystem,
) -> patchgate_config::DependencyEcosystemPenalty {
    match ecosystem {
        DependencyEcosystem::Cargo => policy.dependency_update.ecosystem_penalties.cargo,
        DependencyEcosystem::Npm => policy.dependency_update.ecosystem_penalties.npm,
        DependencyEcosystem::Python => policy.dependency_update.ecosystem_penalties.python,
        DependencyEcosystem::Go => policy.dependency_update.ecosystem_penalties.go,
        DependencyEcosystem::Jvm => policy.dependency_update.ecosystem_penalties.jvm,
        DependencyEcosystem::Unknown => patchgate_config::DependencyEcosystemPenalty {
            manifest_bonus_penalty: 0,
            lockfile_bonus_penalty: 0,
            large_lockfile_bonus_penalty: 0,
        },
    }
}

fn collect_diff(ctx: &Context) -> Result<DiffData> {
    let args = diff_args(ctx.scope);
    let output =
        run_git(&ctx.repo_root, &args).with_context(|| format!("git {:?} failed", args))?;

    let mut files = parse_raw_status(&output);
    apply_patch_stats(&mut files, &output);

    let fingerprint = format!("{:x}", Sha256::digest(output.as_bytes()));

    Ok(DiffData {
        files: files.into_values().collect(),
        fingerprint,
    })
}

fn diff_args(scope: ScopeMode) -> Vec<String> {
    match scope {
        ScopeMode::Staged => vec![
            "diff".to_string(),
            "--cached".to_string(),
            "--find-renames".to_string(),
            "--no-color".to_string(),
            "--patch-with-raw".to_string(),
            "--unified=0".to_string(),
        ],
        ScopeMode::Worktree => vec![
            "diff".to_string(),
            "--find-renames".to_string(),
            "--no-color".to_string(),
            "--patch-with-raw".to_string(),
            "--unified=0".to_string(),
        ],
        ScopeMode::Repo => vec![
            "diff".to_string(),
            "HEAD".to_string(),
            "--find-renames".to_string(),
            "--no-color".to_string(),
            "--patch-with-raw".to_string(),
            "--unified=0".to_string(),
        ],
    }
}

fn run_git(repo_root: &PathBuf, args: &[String]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .context("failed to invoke git")?;

    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }

    String::from_utf8(output.stdout).context("git output was not utf8")
}

fn parse_raw_status(input: &str) -> BTreeMap<String, ChangedFile> {
    let mut files = BTreeMap::new();

    for line in input.lines() {
        if !line.starts_with(':') {
            continue;
        }
        let mut parts = line.split('\t');
        let Some(prefix) = parts.next() else {
            continue;
        };
        let Some(first_path) = parts.next() else {
            continue;
        };
        let second_path = parts.next();

        let status_token = prefix.split_whitespace().last().unwrap_or_default();
        let status = parse_status(status_token);

        let (old_path, path) = match status {
            ChangeStatus::Renamed | ChangeStatus::Copied => {
                let Some(new_path) = second_path else {
                    continue;
                };
                (Some(first_path.to_string()), new_path.to_string())
            }
            _ => (None, first_path.to_string()),
        };

        files.insert(
            path.clone(),
            ChangedFile {
                path,
                status,
                old_path,
                added: 0,
                deleted: 0,
                added_lines: Vec::new(),
                removed_lines: Vec::new(),
            },
        );
    }

    files
}

#[cfg(test)]
fn parse_name_status(input: &str) -> BTreeMap<String, ChangedFile> {
    let mut files = BTreeMap::new();

    for line in input.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            continue;
        }

        let status_raw = parts[0];
        let status = parse_status(status_raw);

        let (old_path, path) = match status {
            ChangeStatus::Renamed | ChangeStatus::Copied if parts.len() >= 3 => {
                (Some(parts[1].to_string()), parts[2].to_string())
            }
            _ => (None, parts[1].to_string()),
        };

        files.insert(
            path.clone(),
            ChangedFile {
                path,
                status,
                old_path,
                added: 0,
                deleted: 0,
                added_lines: Vec::new(),
                removed_lines: Vec::new(),
            },
        );
    }

    files
}

fn parse_status(status_raw: &str) -> ChangeStatus {
    match status_raw.chars().next() {
        Some('A') => ChangeStatus::Added,
        Some('M') => ChangeStatus::Modified,
        Some('D') => ChangeStatus::Deleted,
        Some('R') => ChangeStatus::Renamed,
        Some('C') => ChangeStatus::Copied,
        Some('T') => ChangeStatus::TypeChanged,
        _ => ChangeStatus::Unknown,
    }
}

fn apply_patch_stats(files: &mut BTreeMap<String, ChangedFile>, patch: &str) {
    let mut current_path: Option<String> = None;

    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            current_path = None;
            continue;
        }

        if let Some(path) = parse_patch_file_header_path(line, "+++ b/") {
            current_path = Some(path.clone());
            files.entry(path.clone()).or_insert_with(|| ChangedFile {
                path,
                status: ChangeStatus::Unknown,
                old_path: None,
                added: 0,
                deleted: 0,
                added_lines: Vec::new(),
                removed_lines: Vec::new(),
            });
            continue;
        }

        if let Some(path) = parse_patch_file_header_path(line, "--- a/") {
            current_path = Some(path);
            continue;
        }

        if line.starts_with("+++ /dev/null")
            || line.starts_with("--- /dev/null")
            || line.starts_with("@@")
        {
            continue;
        }

        let Some(path) = &current_path else {
            continue;
        };

        let Some(file) = files.get_mut(path) else {
            continue;
        };

        if let Some(stripped) = line.strip_prefix('+') {
            file.added = file.added.saturating_add(1);
            if file.added_lines.len() < MAX_STORED_LINE_SAMPLES {
                file.added_lines.push(truncate_line_sample(stripped));
            }
        } else if let Some(stripped) = line.strip_prefix('-') {
            file.deleted = file.deleted.saturating_add(1);
            if file.removed_lines.len() < MAX_STORED_LINE_SAMPLES {
                file.removed_lines.push(truncate_line_sample(stripped));
            }
        }
    }
}

fn truncate_line_sample(line: &str) -> String {
    if line.chars().count() <= MAX_STORED_LINE_CHARS {
        return line.to_string();
    }
    let mut trimmed = String::new();
    for ch in line.chars().take(MAX_STORED_LINE_CHARS) {
        trimmed.push(ch);
    }
    trimmed.push_str("...");
    trimmed
}

fn parse_patch_file_header_path(line: &str, prefix: &str) -> Option<String> {
    let rest = line.strip_prefix(prefix)?;
    let path = rest
        .split_once('\t')
        .map(|(p, _)| p)
        .unwrap_or(rest)
        .to_string();
    Some(path)
}

fn is_metadata_only_change(file: &ChangedFile) -> bool {
    file.added == 0 && file.deleted == 0
}

fn generated_penalty_factor(policy: &Config, generated_set: &GlobSet, path: &str) -> u8 {
    if !generated_set.is_match(path) {
        return 100;
    }
    match policy.generated_code.mode.as_str() {
        "exclude" => 0,
        "decay" => 100u8.saturating_sub(policy.generated_code.penalty_decay_percent),
        _ => 100,
    }
}

fn scale_penalty(base: u8, factor_percent: u8) -> u8 {
    if base == 0 || factor_percent == 0 {
        return 0;
    }
    if factor_percent >= 100 {
        return base;
    }
    let scaled = ((base as u16) * (factor_percent as u16)).div_ceil(100);
    scaled.max(1).min(u8::MAX as u16) as u8
}

fn scale_u32_by_factor(base: u32, factor_percent: u8) -> u32 {
    if base == 0 || factor_percent == 0 {
        return 0;
    }
    if factor_percent >= 100 {
        return base;
    }
    ((base as u64) * (factor_percent as u64)).div_ceil(100) as u32
}

fn is_test_related_file(policy: &Config, file: &ChangedFile, test_set: &GlobSet) -> bool {
    if test_set.is_match(&file.path) {
        return true;
    }
    let raw_path = file.path.as_str();
    let path = raw_path.to_ascii_lowercase();

    if policy.language_rules.rust
        && path.ends_with(".rs")
        && (path.starts_with("tests/")
            || path.contains("/tests/")
            || path.ends_with("_test.rs")
            || has_any_token(
                &file.added_lines,
                &["#[cfg(test)]", "mod tests", "#[test]", "#[tokio::test]"],
            )
            || has_any_token(
                &file.removed_lines,
                &["#[cfg(test)]", "mod tests", "#[test]", "#[tokio::test]"],
            ))
    {
        return true;
    }

    if policy.language_rules.typescript
        && (path.contains("/__tests__/")
            || path.starts_with("__tests__/")
            || path.ends_with(".test.ts")
            || path.ends_with(".test.tsx")
            || path.ends_with(".spec.ts")
            || path.ends_with(".spec.tsx")
            || path.ends_with(".test.js")
            || path.ends_with(".spec.js")
            || path.ends_with("vitest.config.ts")
            || path.ends_with("vitest.config.js")
            || path.ends_with("jest.config.ts")
            || path.ends_with("jest.config.js"))
    {
        return true;
    }

    if policy.language_rules.python {
        let file_name = path.rsplit('/').next().unwrap_or(path.as_str());
        let is_python_file = path.ends_with(".py");
        if (is_python_file
            && (path.starts_with("tests/")
                || path.contains("/tests/")
                || file_name.starts_with("test_")
                || file_name.ends_with("_test.py")))
            || file_name == "conftest.py"
        {
            return true;
        }
    }

    if policy.language_rules.go && path.ends_with("_test.go") {
        return true;
    }

    if policy.language_rules.java_kotlin
        && (path.contains("/src/test/java/")
            || path.contains("/src/test/kotlin/")
            || is_java_or_kotlin_test_filename(raw_path))
    {
        return true;
    }

    false
}

fn has_any_token(lines: &[String], tokens: &[&str]) -> bool {
    lines
        .iter()
        .any(|line| tokens.iter().any(|needle| line.contains(needle)))
}

fn is_java_or_kotlin_test_filename(path: &str) -> bool {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    let canonical = file_name.to_ascii_lowercase();

    let suffix_patterns = [
        "_test.java",
        "_test.kt",
        ".test.java",
        ".test.kt",
        "-test.java",
        "-test.kt",
        "_it.java",
        "_it.kt",
        ".it.java",
        ".it.kt",
        "-it.java",
        "-it.kt",
    ];
    if suffix_patterns
        .iter()
        .any(|suffix| canonical.ends_with(suffix))
    {
        return true;
    }

    // Camel-case conventions like FooTest.java / FooIT.kt
    let exact_suffixes = ["Test.java", "Test.kt", "IT.java", "IT.kt"];
    exact_suffixes
        .iter()
        .any(|suffix| file_name.ends_with(suffix))
}

fn parent_dir(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(dir, _)| dir.to_string())
        .unwrap_or_else(|| ".".to_string())
}

fn infer_package_root(path: &str, package_markers: &[String]) -> String {
    for marker in package_markers {
        if path == marker.as_str() || path.starts_with(&format!("{}/", marker)) {
            return marker.clone();
        }
    }
    let mut parts = path.split('/');
    let first = parts.next().unwrap_or(".");
    let second = parts.next();
    if matches!(
        first,
        "src" | "tests" | "test" | "docs" | ".github" | "infra"
    ) {
        return ".".to_string();
    }
    if matches!(
        first,
        "packages" | "apps" | "services" | "modules" | "libs" | "crates"
    ) && second.is_some()
    {
        return format!("{}/{}", first, second.unwrap_or_default());
    }
    first.to_string()
}

fn compile_globs(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder
            .add(Glob::new(pattern).with_context(|| format!("invalid glob pattern: {pattern}"))?);
    }
    builder.build().context("failed to build globset")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_status_supports_rename() {
        let parsed = parse_name_status("R100\told.txt\tnew.txt\nM\tsrc/main.rs\n");
        let renamed = parsed.get("new.txt").expect("missing renamed file");
        assert_eq!(renamed.status, ChangeStatus::Renamed);
        assert_eq!(renamed.old_path.as_deref(), Some("old.txt"));
        let modified = parsed.get("src/main.rs").expect("missing modified file");
        assert_eq!(modified.status, ChangeStatus::Modified);
    }

    #[test]
    fn parse_raw_status_supports_rename_and_copy() {
        let raw = ":100644 100644 abcdef1 abcdef2 R100\told.txt\tnew.txt\n:100644 100644 abcdef1 abcdef2 C100\ta.txt\tb.txt\n:100644 100644 abcdef1 abcdef2 M\tm.txt\n";
        let parsed = parse_raw_status(raw);
        let renamed = parsed.get("new.txt").expect("missing renamed path");
        assert_eq!(renamed.status, ChangeStatus::Renamed);
        assert_eq!(renamed.old_path.as_deref(), Some("old.txt"));
        let copied = parsed.get("b.txt").expect("missing copied path");
        assert_eq!(copied.status, ChangeStatus::Copied);
        assert_eq!(copied.old_path.as_deref(), Some("a.txt"));
        let modified = parsed.get("m.txt").expect("missing modified path");
        assert_eq!(modified.status, ChangeStatus::Modified);
    }

    #[test]
    fn apply_patch_stats_counts_lines() {
        let mut files = parse_name_status("M\tsrc/lib.rs\n");
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,2 @@\n-old\n+new\n+more\n";
        apply_patch_stats(&mut files, patch);
        let file = files.get("src/lib.rs").expect("missing file");
        assert_eq!(file.added, 2);
        assert_eq!(file.deleted, 1);
    }

    #[test]
    fn parse_patch_file_header_path_supports_spaces() {
        let line = "+++ b/dir with/file name.txt\t";
        let path = parse_patch_file_header_path(line, "+++ b/").expect("path");
        assert_eq!(path, "dir with/file name.txt");
    }

    #[test]
    fn apply_patch_stats_counts_lines_starting_with_plusplus_or_minusminus() {
        let mut files = parse_name_status("M\tsrc/lib.rs\n");
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,2 @@\n---old\n+++new\n";
        apply_patch_stats(&mut files, patch);
        let file = files.get("src/lib.rs").expect("missing file");
        assert_eq!(file.added, 1);
        assert_eq!(file.deleted, 1);
        assert_eq!(file.added_lines.first().map(String::as_str), Some("++new"));
        assert_eq!(
            file.removed_lines.first().map(String::as_str),
            Some("--old")
        );
    }

    #[test]
    fn apply_patch_stats_does_not_create_old_rename_path_entry() {
        let mut files = parse_raw_status(":100644 100644 abcdef1 abcdef2 R100\told.txt\tnew.txt\n");
        let patch = "diff --git a/old.txt b/new.txt\nsimilarity index 80%\nrename from old.txt\nrename to new.txt\n--- a/old.txt\n+++ b/new.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n";
        apply_patch_stats(&mut files, patch);
        assert!(files.contains_key("new.txt"));
        assert!(
            !files.contains_key("old.txt"),
            "old rename path must not be inserted as a changed file entry"
        );
        let new_file = files.get("new.txt").expect("new path");
        assert_eq!(new_file.added, 1);
        assert_eq!(new_file.deleted, 1);
    }

    #[test]
    fn test_gap_penalizes_when_production_changes_without_tests() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/lib.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 5,
                deleted: 2,
                added_lines: vec!["new".to_string()],
                removed_lines: vec!["old".to_string()],
            }],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        assert!(eval.score.triggered);
        assert!(
            eval.findings.iter().any(|f| f.id == "TG-001"),
            "expected missing test finding"
        );
    }

    #[test]
    fn test_gap_no_penalty_when_test_files_changed() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "src/lib.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 10,
                    deleted: 1,
                    added_lines: vec!["new".to_string()],
                    removed_lines: vec!["old".to_string()],
                },
                ChangedFile {
                    path: "tests/lib_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 4,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        assert!(
            !eval.findings.iter().any(|f| f.id == "TG-001"),
            "missing test finding should not be reported"
        );
    }

    #[test]
    fn test_gap_ignores_rename_without_content_changes() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/new_name.rs".to_string(),
                status: ChangeStatus::Renamed,
                old_path: Some("src/old_name.rs".to_string()),
                added: 0,
                deleted: 0,
                added_lines: vec![],
                removed_lines: vec![],
            }],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        assert_eq!(eval.score.penalty, 0);
        assert!(
            eval.findings.is_empty(),
            "metadata-only rename should not trigger test_gap"
        );
    }

    #[test]
    fn test_gap_does_not_count_metadata_only_test_rename() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "src/lib.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 12,
                    deleted: 3,
                    added_lines: vec!["new".to_string()],
                    removed_lines: vec!["old".to_string()],
                },
                ChangedFile {
                    path: "tests/new_name.rs".to_string(),
                    status: ChangeStatus::Renamed,
                    old_path: Some("tests/old_name.rs".to_string()),
                    added: 0,
                    deleted: 0,
                    added_lines: vec![],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        assert!(
            eval.findings.iter().any(|f| f.id == "TG-001"),
            "metadata-only test rename must not suppress missing test finding"
        );
    }

    #[test]
    fn test_gap_ignores_generated_file_when_generated_mode_is_exclude() {
        let mut policy = Config::default();
        policy.generated_code.mode = "exclude".to_string();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated globs");
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/generated/client.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 120,
                deleted: 20,
                added_lines: vec!["new".to_string()],
                removed_lines: vec!["old".to_string()],
            }],
            fingerprint: "dummy".to_string(),
        };

        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        assert_eq!(eval.score.penalty, 0);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn test_gap_large_change_not_suppressed_by_unrelated_test_updates() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let mut added_lines = Vec::new();
        let mut removed_lines = Vec::new();
        for i in 0..260 {
            added_lines.push(format!("add-{i}"));
            removed_lines.push(format!("del-{i}"));
        }
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "packages/a/src/lib.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 260,
                    deleted: 260,
                    added_lines,
                    removed_lines,
                },
                ChangedFile {
                    path: "packages/b/tests/b_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 3,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                },
                ChangedFile {
                    path: "packages/c/tests/c_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 3,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        assert!(
            eval.findings.iter().any(|f| f.id == "TG-002"),
            "uncovered large change should still trigger TG-002 even with unrelated tests"
        );
    }

    #[test]
    fn test_gap_large_change_with_single_matching_test_still_triggers_tg002() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "packages/a/src/service.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 210,
                    deleted: 10,
                    added_lines: vec!["line".to_string()],
                    removed_lines: vec!["line".to_string()],
                },
                ChangedFile {
                    path: "packages/a/tests/service_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };
        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        assert!(
            !eval.findings.iter().any(|f| f.id == "TG-001"),
            "TG-001 should not fire when at least one matching test exists"
        );
        assert!(
            eval.findings.iter().any(|f| f.id == "TG-002"),
            "TG-002 should fire for large changes with only one matching test file"
        );
    }

    #[test]
    fn test_gap_tg002_message_uses_unique_matching_test_file_count() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "packages/a/src/service.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 120,
                    deleted: 10,
                    added_lines: vec!["line".to_string()],
                    removed_lines: vec!["line".to_string()],
                },
                ChangedFile {
                    path: "packages/b/src/service.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 120,
                    deleted: 10,
                    added_lines: vec!["line".to_string()],
                    removed_lines: vec!["line".to_string()],
                },
                ChangedFile {
                    path: "tests/global_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let eval =
            evaluate_test_gap(&policy, &diff, &exclude_set, &generated_set).expect("evaluate");
        let finding = eval
            .findings
            .iter()
            .find(|f| f.id == "TG-002")
            .expect("TG-002 finding");
        assert!(
            finding
                .message
                .contains("only 1 matching test file(s) updated"),
            "global test file should not be counted once per under-tested package"
        );
    }

    #[test]
    fn dangerous_change_classifies_non_critical_path() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/auth/service.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 3,
                deleted: 1,
                added_lines: vec!["new".to_string()],
                removed_lines: vec!["old".to_string()],
            }],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval = evaluate_dangerous_change(&policy, &diff, &exclude_set, &generated_set)
            .expect("evaluate");
        assert_eq!(eval.score.penalty, policy.dangerous_change.per_file_penalty);
        let finding = eval.findings.first().expect("finding");
        assert_eq!(finding.id, "DC-001");
        assert_eq!(finding.severity, Severity::High);
        assert!(
            finding.tags.iter().any(|tag| tag == "non-critical"),
            "expected non-critical tag"
        );
    }

    #[test]
    fn dangerous_change_classifies_critical_path() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![ChangedFile {
                path: ".github/workflows/ci.yml".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 2,
                deleted: 2,
                added_lines: vec!["new".to_string()],
                removed_lines: vec!["old".to_string()],
            }],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval = evaluate_dangerous_change(&policy, &diff, &exclude_set, &generated_set)
            .expect("evaluate");
        assert_eq!(
            eval.score.penalty,
            policy.dangerous_change.per_file_penalty
                + policy.dangerous_change.critical_bonus_penalty
        );
        let finding = eval.findings.first().expect("finding");
        assert_eq!(finding.id, "DC-002");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(
            finding.tags.iter().any(|tag| tag == "critical"),
            "expected critical tag"
        );
    }

    #[test]
    fn dangerous_change_detects_metadata_only_critical_rename() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![ChangedFile {
                path: ".github/workflows/ci-main.yml".to_string(),
                status: ChangeStatus::Renamed,
                old_path: Some(".github/workflows/ci.yml".to_string()),
                added: 0,
                deleted: 0,
                added_lines: vec![],
                removed_lines: vec![],
            }],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval = evaluate_dangerous_change(&policy, &diff, &exclude_set, &generated_set)
            .expect("evaluate");
        assert_eq!(
            eval.score.penalty,
            policy.dangerous_change.per_file_penalty
                + policy.dangerous_change.critical_bonus_penalty
        );
        let finding = eval.findings.first().expect("finding");
        assert_eq!(finding.id, "DC-002");
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn java_kotlin_heuristic_avoids_contest_false_positive() {
        let mut policy = Config::default();
        policy.language_rules.java_kotlin = true;
        let test_set = compile_globs(&policy.test_gap.test_globs).expect("test globs");
        let contest = ChangedFile {
            path: "src/main/java/com/example/Contest.java".to_string(),
            status: ChangeStatus::Modified,
            old_path: None,
            added: 3,
            deleted: 1,
            added_lines: vec!["line".to_string()],
            removed_lines: vec!["line".to_string()],
        };
        assert!(
            !is_test_related_file(&policy, &contest, &test_set),
            "Contest.java must not be treated as a test file"
        );

        let test_file = ChangedFile {
            path: "src/test/java/com/example/OrderServiceTest.java".to_string(),
            status: ChangeStatus::Modified,
            old_path: None,
            added: 2,
            deleted: 0,
            added_lines: vec!["line".to_string()],
            removed_lines: vec![],
        };
        assert!(is_test_related_file(&policy, &test_file, &test_set));
    }

    #[test]
    fn dependency_update_detects_manifest_and_lockfile_changes() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "Cargo.toml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 1,
                    added_lines: vec!["dep = \"1\"".to_string()],
                    removed_lines: vec!["dep = \"0\"".to_string()],
                },
                ChangedFile {
                    path: "Cargo.lock".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 20,
                    deleted: 10,
                    added_lines: vec!["pkg".to_string()],
                    removed_lines: vec!["old".to_string()],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval = evaluate_dependency_update(&policy, &diff, &exclude_set, &generated_set)
            .expect("evaluate");
        assert!(eval.findings.iter().any(|f| f.id == "DU-001"));
        assert!(eval.findings.iter().any(|f| f.id == "DU-002"));
        assert!(eval.score.penalty >= policy.dependency_update.manifest_penalty);
        assert!(eval.score.penalty >= policy.dependency_update.lockfile_penalty);
    }

    #[test]
    fn dependency_update_ignores_metadata_only_manifest_or_lockfile_changes() {
        let policy = Config::default();
        let exclude_set = compile_globs(&policy.exclude.globs).expect("exclude globs");
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "Cargo.toml".to_string(),
                    status: ChangeStatus::Renamed,
                    old_path: Some("Cargo.old.toml".to_string()),
                    added: 0,
                    deleted: 0,
                    added_lines: vec![],
                    removed_lines: vec![],
                },
                ChangedFile {
                    path: "Cargo.lock".to_string(),
                    status: ChangeStatus::Renamed,
                    old_path: Some("Cargo.old.lock".to_string()),
                    added: 0,
                    deleted: 0,
                    added_lines: vec![],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let generated_set = compile_globs(&policy.generated_code.globs).expect("generated");
        let eval = evaluate_dependency_update(&policy, &diff, &exclude_set, &generated_set)
            .expect("evaluate");
        assert_eq!(eval.score.penalty, 0);
        assert!(eval.findings.is_empty());
    }

    #[test]
    fn supply_chain_signal_detects_dependency_plus_infra_bundle() {
        let policy = Config::default();
        let runner = Runner::new(policy);
        let ctx = Context {
            repo_root: PathBuf::from("."),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "Cargo.toml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 1,
                    added_lines: vec!["dep = \"1\"".to_string()],
                    removed_lines: vec!["dep = \"0\"".to_string()],
                },
                ChangedFile {
                    path: ".github/workflows/ci.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 2,
                    added_lines: vec!["permissions: write-all".to_string()],
                    removed_lines: vec!["permissions: read-all".to_string()],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(
            report
                .supply_chain_signals
                .iter()
                .any(|s| s.id == "SCM-001"),
            "dependency + infra change should trigger SCM-001"
        );
    }

    #[test]
    fn supply_chain_signal_escalates_lockfile_add_remove_with_ci_change() {
        let policy = Config::default();
        let runner = Runner::new(policy);
        let ctx = Context {
            repo_root: PathBuf::from("."),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "Cargo.lock".to_string(),
                    status: ChangeStatus::Added,
                    old_path: None,
                    added: 10,
                    deleted: 0,
                    added_lines: vec!["[[package]]".to_string()],
                    removed_lines: vec![],
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["run: cargo test".to_string()],
                    removed_lines: vec!["run: cargo check".to_string()],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(
            report
                .supply_chain_signals
                .iter()
                .any(|s| s.id == "SCM-002"),
            "lockfile add/remove with CI change should trigger SCM-002"
        );
    }

    #[test]
    fn supply_chain_signal_detects_jvm_manifest_plus_infra_bundle() {
        let policy = Config::default();
        let runner = Runner::new(policy);
        let ctx = Context {
            repo_root: PathBuf::from("."),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "service/build.gradle.kts".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["implementation(\"org.example:lib:1.0\")".to_string()],
                    removed_lines: vec!["implementation(\"org.example:lib:0.9\")".to_string()],
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["permissions: write-all".to_string()],
                    removed_lines: vec!["permissions: read-all".to_string()],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(report
            .supply_chain_signals
            .iter()
            .any(|s| s.id == "SCM-001"));
    }

    #[test]
    fn supply_chain_signal_detects_ruby_manifest_plus_infra_bundle() {
        let policy = Config::default();
        let runner = Runner::new(policy);
        let ctx = Context {
            repo_root: PathBuf::from("."),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "Gemfile".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["gem \"rails\", \"7.2.0\"".to_string()],
                    removed_lines: vec!["gem \"rails\", \"7.1.5\"".to_string()],
                },
                ChangedFile {
                    path: "infra/main.tf".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 0,
                    added_lines: vec!["resource \"aws_s3_bucket\" \"logs\" {}".to_string()],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(report
            .supply_chain_signals
            .iter()
            .any(|s| s.id == "SCM-001"));
    }

    #[test]
    fn supply_chain_signal_scm002_works_when_dependency_update_is_disabled() {
        let mut policy = Config::default();
        policy.dependency_update.enabled = false;
        let runner = Runner::new(policy);
        let ctx = Context {
            repo_root: PathBuf::from("."),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "Cargo.lock".to_string(),
                    status: ChangeStatus::Added,
                    old_path: None,
                    added: 10,
                    deleted: 0,
                    added_lines: vec!["[[package]]".to_string()],
                    removed_lines: vec![],
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["permissions: write-all".to_string()],
                    removed_lines: vec!["permissions: read-all".to_string()],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(
            report
                .supply_chain_signals
                .iter()
                .any(|s| s.id == "SCM-002"),
            "SCM-002 should be derived from diff topology, independent of dependency_update flag"
        );
    }

    #[test]
    fn supply_chain_signal_scm002_detects_gemfile_lock_add_remove() {
        let policy = Config::default();
        let runner = Runner::new(policy);
        let ctx = Context {
            repo_root: PathBuf::from("."),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![
                ChangedFile {
                    path: "Gemfile.lock".to_string(),
                    status: ChangeStatus::Added,
                    old_path: None,
                    added: 10,
                    deleted: 0,
                    added_lines: vec!["GEM".to_string()],
                    removed_lines: vec![],
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 0,
                    added_lines: vec!["run: bundle install".to_string()],
                    removed_lines: vec![],
                },
            ],
            fingerprint: "dummy".to_string(),
        };

        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(report
            .supply_chain_signals
            .iter()
            .any(|s| s.id == "SCM-002"));
    }

    #[test]
    fn plugin_to_core_finding_fills_defaults() {
        let plugin_finding = PluginFinding {
            id: String::new(),
            rule_id: String::new(),
            category: String::new(),
            docs_url: String::new(),
            title: "Plugin finding".to_string(),
            message: "details".to_string(),
            severity: Severity::Medium,
            penalty: 3,
            location: None,
            tags: vec!["sample".to_string()],
        };
        let finding = plugin_to_core_finding("sample-plugin", &plugin_finding);
        assert_eq!(finding.check, CheckId::ExternalPlugin);
        assert_eq!(finding.id, "PLG-sample-plugin-001");
        assert_eq!(finding.rule_id, "PLG-sample-plugin-001");
        assert_eq!(finding.category, "plugin");
        assert!(finding.tags.iter().any(|t| t == "plugin:sample-plugin"));
    }

    #[test]
    fn plugin_execution_failure_status_detection() {
        assert!(plugin_invocation_is_execution_failure(
            &PluginInvocationStatus::Error
        ));
        assert!(plugin_invocation_is_execution_failure(
            &PluginInvocationStatus::TimedOut
        ));
        assert!(!plugin_invocation_is_execution_failure(
            &PluginInvocationStatus::Pass
        ));
        assert!(!plugin_invocation_is_execution_failure(
            &PluginInvocationStatus::Fail
        ));
        assert!(!plugin_invocation_is_execution_failure(
            &PluginInvocationStatus::Skipped
        ));
    }

    #[test]
    fn read_stream_with_limit_truncates_and_marks_overflow() {
        let overflow = Arc::new(AtomicBool::new(false));
        let output = read_stream_with_limit(
            std::io::Cursor::new(vec![b'x'; 64]),
            8,
            Some(Arc::clone(&overflow)),
        )
        .expect("read stream");
        assert_eq!(output.len(), 8);
        assert!(overflow.load(Ordering::Relaxed));
    }

    #[test]
    fn read_stream_with_limit_without_overflow_keeps_all_bytes() {
        let overflow = Arc::new(AtomicBool::new(false));
        let output = read_stream_with_limit(
            std::io::Cursor::new(vec![b'x'; 16]),
            64,
            Some(Arc::clone(&overflow)),
        )
        .expect("read stream");
        assert_eq!(output.len(), 16);
        assert!(!overflow.load(Ordering::Relaxed));
    }

    #[test]
    fn join_stdin_writer_ignores_broken_pipe_on_timeout() {
        let handle = thread::spawn(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            ))
        });
        let result = join_stdin_writer(handle, &ChildTermination::TimedOut);
        assert!(result.is_ok());
    }

    #[test]
    fn join_stdin_writer_reports_error_when_process_exited() {
        #[cfg(windows)]
        let status = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .status()
            .expect("status");
        #[cfg(not(windows))]
        let status = std::process::Command::new("sh")
            .args(["-c", "true"])
            .status()
            .expect("status");
        let handle = thread::spawn(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            ))
        });
        let result = join_stdin_writer(handle, &ChildTermination::Exited(status));
        assert!(result.is_err());
    }

    #[test]
    fn evaluate_plugins_returns_empty_when_disabled() {
        let policy = Config::default();
        let ctx = Context {
            repo_root: PathBuf::from("."),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![],
            fingerprint: "dummy".to_string(),
        };
        let outcome = evaluate_plugins(&policy, &ctx, &diff, "warn").expect("evaluate");
        assert!(outcome.score.is_none());
        assert!(outcome.findings.is_empty());
        assert!(outcome.invocations.is_empty());
    }
}
