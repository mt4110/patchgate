use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context as _, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use globset::{Glob, GlobSet, GlobSetBuilder};
use patchgate_config::Config;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::model::{
    CheckId, CheckScore, Finding, Location, PluginChangedFile, PluginFinding, PluginInput,
    PluginInputV2Shadow, PluginInvocation, PluginInvocationStatus, PluginOutput,
    PluginShadowContract, Report, ReportMeta, Severity, SupplyChainSignal,
};

const MAX_STORED_LINE_SAMPLES: usize = 32;
const MAX_STORED_LINE_CHARS: usize = 240;
const PLUGIN_SHADOW_BRIDGE_MODE: &str = "shadow";
const DIFF_SCHEMA_VERSION: &str = "patchgate.diff.v1";

#[derive(Debug, Clone, Copy)]
pub enum ScopeMode {
    Staged,
    Worktree,
    Repo,
    Pr,
}

impl ScopeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeMode::Staged => "staged",
            ScopeMode::Worktree => "worktree",
            ScopeMode::Repo => "repo",
            ScopeMode::Pr => "pr",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Context {
    pub repo_root: PathBuf,
    pub scope: ScopeMode,
}

#[derive(Debug, Clone, Default)]
pub struct DiffOptions {
    /// PR base ref used when scope is `pr`.
    pub base_ref: Option<String>,
    /// PR head ref used when scope is `pr`; defaults to `HEAD`.
    pub head_ref: Option<String>,
    /// Large-diff preflight limit. When exceeded after raw identity collection,
    /// line stats and patch samples are intentionally skipped.
    pub stop_after_raw_file_limit: Option<usize>,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FileKind {
    #[default]
    Text,
    Binary,
    Symlink,
    Submodule,
    Lfs,
    Unknown,
}

impl FileKind {
    fn as_str(self) -> &'static str {
        match self {
            FileKind::Text => "text",
            FileKind::Binary => "binary",
            FileKind::Symlink => "symlink",
            FileKind::Submodule => "submodule",
            FileKind::Lfs => "lfs",
            FileKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSafetyFlag {
    ControlCharacter,
    NonUtf8,
    RejectedRepositoryPath,
    CaseInsensitiveCollision,
}

#[derive(Debug, Clone, Default)]
pub struct DiffFileMetadata {
    pub path_id: String,
    pub path_bytes_b64: String,
    pub old_path_id: Option<String>,
    pub old_path_bytes_b64: Option<String>,
    pub file_kind: FileKind,
    pub old_mode: Option<String>,
    pub new_mode: Option<String>,
    pub old_oid: Option<String>,
    pub new_oid: Option<String>,
    pub symlink_target: Option<String>,
    pub symlink_target_escapes_repo: bool,
    pub path_flags: Vec<PathSafetyFlag>,
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
    pub metadata: DiffFileMetadata,
}

#[derive(Debug, Clone)]
pub struct DiffData {
    pub files: Vec<ChangedFile>,
    pub fingerprint: String,
    pub base_ref: Option<String>,
    pub head_ref: Option<String>,
    pub merge_base: Option<String>,
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
        collect_diff(ctx, &DiffOptions::default())
    }

    pub fn collect_diff_with_options(
        &self,
        ctx: &Context,
        options: &DiffOptions,
    ) -> Result<DiffData> {
        collect_diff(ctx, options)
    }

    pub fn evaluate(&self, ctx: &Context, diff: DiffData, mode: &str) -> Result<Report> {
        let start = Instant::now();

        let exclude_set =
            compile_globs(&self.policy.exclude.globs).context("failed to compile exclude globs")?;
        let generated_set = compile_globs(&self.policy.generated_code.globs)
            .context("failed to compile generated_code.globs")?;

        let (
            (diff_correctness, diff_correctness_ms),
            (test_gap, test_gap_ms),
            (dangerous_change, dangerous_change_ms),
            (dependency_update, dependency_update_ms),
        ) = std::thread::scope(|scope| {
            let diff_correctness_handle = scope.spawn(|| {
                let check_start = Instant::now();
                let result = evaluate_diff_correctness(&diff);
                (result, check_start.elapsed().as_millis())
            });
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

            let (diff_correctness_result, diff_correctness_ms) = diff_correctness_handle
                .join()
                .map_err(|_| anyhow::anyhow!("diff_correctness worker thread panicked"))?;
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
                (diff_correctness_result, diff_correctness_ms),
                (test_gap_result?, test_gap_ms),
                (dangerous_change_result?, dangerous_change_ms),
                (dependency_update_result?, dependency_update_ms),
            ))
        })?;

        let plugin_outcome = evaluate_plugins(&self.policy, ctx, &diff, mode)?;

        let mut findings = Vec::new();
        findings.extend(diff_correctness.findings);
        findings.extend(test_gap.findings);
        findings.extend(dangerous_change.findings);
        findings.extend(dependency_update.findings);
        findings.extend(plugin_outcome.findings);

        let mut checks = vec![
            diff_correctness.score,
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
        report.check_durations_ms.insert(
            CheckId::DiffCorrectness.as_str().to_string(),
            diff_correctness_ms,
        );
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
        report.refresh_decision(&self.policy.waiver.entries, Vec::new());
        if report.decision.has_failed_hard_gate() {
            report
                .diagnostic_hints
                .push("Hard gate failure blocks the decision independently of score.".to_string());
        }
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

fn evaluate_diff_correctness(diff: &DiffData) -> CheckEvaluation {
    let max_penalty = 100;
    let mut findings = Vec::new();
    let mut penalty = 0u8;

    for file in &diff.files {
        for flag in &file.metadata.path_flags {
            let (rule_id, title, message, severity) = match flag {
                PathSafetyFlag::ControlCharacter => (
                    "DIFF-001",
                    "Path contains control characters",
                    format!(
                        "{} has a current or previous path containing a tab, newline, or other control character. Review it by raw path identity: {}.",
                        path_context(file), file.metadata.path_id
                    ),
                    Severity::Critical,
                ),
                PathSafetyFlag::NonUtf8 => (
                    "DIFF-002",
                    "Path is not valid UTF-8",
                    format!(
                        "{} has a current or previous path that cannot be represented losslessly as UTF-8. Review it by raw path identity: {}.",
                        path_context(file), file.metadata.path_id
                    ),
                    Severity::Critical,
                ),
                PathSafetyFlag::RejectedRepositoryPath => (
                    "DIFF-003",
                    "Path is not a safe repository-relative path",
                    format!(
                        "{} has a current or previous path that is absolute, escapes the repository, or uses an unsafe separator.",
                        path_context(file)
                    ),
                    Severity::Critical,
                ),
                PathSafetyFlag::CaseInsensitiveCollision => (
                    "DIFF-007",
                    "Case-insensitive path collision",
                    format!(
                        "{} collides with another changed path on case-insensitive filesystems.",
                        file.path
                    ),
                    Severity::Critical,
                ),
            };
            let finding_penalty = if severity == Severity::Critical {
                100
            } else {
                10
            };
            penalty = penalty.saturating_add(finding_penalty);
            findings.push(diff_correctness_finding(
                rule_id,
                title,
                message,
                severity,
                finding_penalty,
                file,
                vec!["diff-correctness".to_string(), "path-safety".to_string()],
            ));
        }

        match file.metadata.file_kind {
            FileKind::Binary => {
                penalty = penalty.saturating_add(100);
                findings.push(diff_correctness_finding(
                    "DIFF-004",
                    "Binary diff requires explicit review",
                    format!(
                        "{} changed as binary content. Text-only patch parsing cannot prove this is safe.",
                        file.path
                    ),
                    Severity::Critical,
                    100,
                    file,
                    vec!["diff-correctness".to_string(), "binary".to_string()],
                ));
            }
            FileKind::Submodule => {
                penalty = penalty.saturating_add(100);
                findings.push(diff_correctness_finding(
                    "DIFF-005",
                    "Submodule pointer changed",
                    format!(
                        "{} changed a gitlink from {} to {}.",
                        file.path,
                        file.metadata.old_oid.as_deref().unwrap_or("unknown"),
                        file.metadata.new_oid.as_deref().unwrap_or("unknown")
                    ),
                    Severity::Critical,
                    100,
                    file,
                    vec!["diff-correctness".to_string(), "submodule".to_string()],
                ));
            }
            FileKind::Symlink if file.metadata.symlink_target_escapes_repo => {
                penalty = penalty.saturating_add(100);
                findings.push(diff_correctness_finding(
                    "DIFF-006",
                    "Symlink target escapes repository",
                    format!(
                        "{} points outside the repository boundary (target: {}).",
                        file.path,
                        file.metadata
                            .symlink_target
                            .as_deref()
                            .unwrap_or("unresolved")
                    ),
                    Severity::Critical,
                    100,
                    file,
                    vec!["diff-correctness".to_string(), "symlink".to_string()],
                ));
            }
            FileKind::Symlink => {
                let finding_penalty = 12;
                penalty = penalty.saturating_add(finding_penalty);
                findings.push(diff_correctness_finding(
                    "DIFF-008",
                    "Symlink changed",
                    format!(
                        "{} changed a symlink target (target: {}).",
                        file.path,
                        file.metadata
                            .symlink_target
                            .as_deref()
                            .unwrap_or("unresolved")
                    ),
                    Severity::High,
                    finding_penalty,
                    file,
                    vec!["diff-correctness".to_string(), "symlink".to_string()],
                ));
            }
            FileKind::Lfs => {
                let finding_penalty = 8;
                penalty = penalty.saturating_add(finding_penalty);
                findings.push(diff_correctness_finding(
                    "DIFF-009",
                    "Git LFS pointer changed",
                    format!("{} changed as a Git LFS pointer.", file.path),
                    Severity::Medium,
                    finding_penalty,
                    file,
                    vec!["diff-correctness".to_string(), "lfs".to_string()],
                ));
            }
            FileKind::Text | FileKind::Unknown => {}
        }
    }

    let penalty = penalty.min(max_penalty);
    CheckEvaluation {
        score: CheckScore {
            check: CheckId::DiffCorrectness,
            label: CheckId::DiffCorrectness.label().to_string(),
            penalty,
            max_penalty,
            triggered: penalty > 0,
        },
        findings,
    }
}

fn diff_correctness_finding(
    rule_id: &str,
    title: &str,
    message: String,
    severity: Severity,
    penalty: u8,
    file: &ChangedFile,
    mut tags: Vec<String>,
) -> Finding {
    tags.push(file.metadata.file_kind.as_str().to_string());
    tags.push(file.metadata.path_id.clone());
    if let Some(old_path_id) = &file.metadata.old_path_id {
        tags.push(format!("old_{old_path_id}"));
    }
    Finding {
        id: rule_id.to_string(),
        rule_id: rule_id.to_string(),
        category: "diff_correctness".to_string(),
        docs_url:
            "https://github.com/mt4110/patchgate/blob/main/docs/03_cli_reference.md#patchgate-scan"
                .to_string(),
        check: CheckId::DiffCorrectness,
        title: title.to_string(),
        message,
        severity,
        penalty,
        location: Some(Location {
            file: file.path.clone(),
            line: None,
        }),
        tags,
    }
}

fn path_context(file: &ChangedFile) -> String {
    file.old_path
        .as_ref()
        .map(|old_path| format!("{} (previously {})", file.path, old_path))
        .unwrap_or_else(|| file.path.clone())
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
                    shadow_contract: plugin_shadow_contract(policy, ctx, diff, mode, plugin)?,
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
    let start = Instant::now();
    let input = build_plugin_input(ctx, diff, mode, plugin);
    let shadow_contract = plugin_shadow_contract_from_input(policy, &input)?;
    if let Err(err) = verify_plugin_signature(policy, ctx, plugin) {
        return Ok(PluginInvocation {
            plugin_id: plugin.id.clone(),
            status: PluginInvocationStatus::Error,
            duration_ms: start.elapsed().as_millis(),
            sandbox_profile: policy.plugins.sandbox.profile.clone(),
            shadow_contract,
            findings: Vec::new(),
            diagnostics: vec![format!("signature verification failed: {err:#}")],
            error: Some(format!("signature verification failed: {err:#}")),
        });
    }

    let input_json = serde_json::to_vec(&input).context("failed to encode plugin input")?;
    let max_output_bytes = (policy.plugins.sandbox.max_stdout_kib as usize).saturating_mul(1024);
    let sandbox_profile = policy.plugins.sandbox.profile.as_str();
    let timeout = Duration::from_millis(plugin.timeout_ms);

    let mut command = match sandbox_profile {
        "isolated" => match build_isolated_plugin_command(policy, ctx, plugin) {
            Ok(command) => command,
            Err(message) => {
                return Ok(PluginInvocation {
                    plugin_id: plugin.id.clone(),
                    status: PluginInvocationStatus::Error,
                    duration_ms: start.elapsed().as_millis(),
                    sandbox_profile: sandbox_profile.to_string(),
                    shadow_contract,
                    findings: Vec::new(),
                    diagnostics: vec![message.clone()],
                    error: Some(message),
                });
            }
        },
        _ => {
            let mut command = Command::new(plugin.command.as_str());
            command.args(&plugin.args);
            command
        }
    };
    command.current_dir(&ctx.repo_root);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if sandbox_profile == "restricted" || sandbox_profile == "isolated" {
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
    let stdin_writer = child.stdin.take().map(|mut stdin| {
        thread::spawn(move || -> std::io::Result<()> {
            stdin.write_all(&input_json)?;
            Ok(())
        })
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
            shadow_contract,
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
            shadow_contract,
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
            shadow_contract,
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
        shadow_contract,
        findings: plugin_output.findings,
        diagnostics,
        error: None,
    })
}

fn build_plugin_input(
    ctx: &Context,
    diff: &DiffData,
    mode: &str,
    plugin: &patchgate_config::PluginEntry,
) -> PluginInput {
    PluginInput {
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
                old_path: f.old_path.clone(),
                path_id: f.metadata.path_id.clone(),
                path_bytes_b64: f.metadata.path_bytes_b64.clone(),
                file_kind: f.metadata.file_kind.as_str().to_string(),
                status: change_status_as_str(f.status).to_string(),
                added: f.added,
                deleted: f.deleted,
            })
            .collect(),
    }
}

fn plugin_shadow_contract(
    policy: &Config,
    ctx: &Context,
    diff: &DiffData,
    mode: &str,
    plugin: &patchgate_config::PluginEntry,
) -> Result<Option<PluginShadowContract>> {
    let input = build_plugin_input(ctx, diff, mode, plugin);
    plugin_shadow_contract_from_input(policy, &input)
}

fn plugin_shadow_contract_from_input(
    policy: &Config,
    input: &PluginInput,
) -> Result<Option<PluginShadowContract>> {
    if !policy.compatibility.v2.shadow_mode {
        return Ok(None);
    }
    let bridge_mode = PLUGIN_SHADOW_BRIDGE_MODE.to_string();
    let shadow_input = PluginInputV2Shadow::from_v1(input, bridge_mode.clone());
    let shadow_json =
        serde_json::to_vec(&shadow_input).context("failed to encode plugin shadow input")?;
    Ok(Some(PluginShadowContract {
        input_api_version: input.api_version.clone(),
        shadow_api_version: shadow_input.api_version,
        shadow_of: shadow_input.shadow_of,
        bridge_mode,
        shadow_envelope_sha256: format!("{:x}", Sha256::digest(shadow_json.as_slice())),
    }))
}

fn verify_plugin_signature(
    policy: &Config,
    ctx: &Context,
    plugin: &patchgate_config::PluginEntry,
) -> Result<()> {
    if !policy.plugins.signature.required {
        return Ok(());
    }
    let key_envs = plugin_signature_key_envs(&policy.plugins.signature);
    if key_envs.is_empty() {
        anyhow::bail!("plugins.signature.public_key_env or trusted_key_envs is empty");
    }

    let command_path = resolve_signed_plugin_artifact_path(ctx, plugin);
    let signature_path = if PathBuf::from(plugin.signature_path.as_str()).is_absolute() {
        PathBuf::from(plugin.signature_path.as_str())
    } else {
        ctx.repo_root.join(plugin.signature_path.as_str())
    };
    let command_bytes = fs::read(&command_path).with_context(|| {
        format!(
            "failed to read plugin command file {}",
            command_path.display()
        )
    })?;
    let signature_text = fs::read_to_string(&signature_path).with_context(|| {
        format!(
            "failed to read plugin signature file {}",
            signature_path.display()
        )
    })?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_text.trim())
        .context("failed to decode plugin signature (base64)")?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .context("failed to parse plugin signature (ed25519)")?;

    let revoked_key_sha256 = policy
        .plugins
        .signature
        .revoked_key_sha256
        .iter()
        .map(|fingerprint| fingerprint.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut attempts = Vec::new();
    for key_env in key_envs {
        let (fingerprint, verifying_key) = match load_plugin_public_key_from_env(key_env.as_str()) {
            Ok(key) => key,
            Err(err) => {
                attempts.push(format!("{key_env}: {err:#}"));
                continue;
            }
        };
        if revoked_key_sha256.contains(fingerprint.as_str()) {
            attempts.push(format!(
                "{key_env}: plugin public key fingerprint {fingerprint} is revoked"
            ));
            continue;
        }
        if verifying_key
            .verify(command_bytes.as_slice(), &signature)
            .is_ok()
        {
            return Ok(());
        }
        attempts.push(format!(
            "{key_env}: signature mismatch for key fingerprint {fingerprint}"
        ));
    }

    anyhow::bail!(
        "plugin signature verification failed with configured keyring: {}",
        attempts.join("; ")
    )
}

fn plugin_signature_key_envs(signature: &patchgate_config::PluginSignatureConfig) -> Vec<String> {
    let mut envs = Vec::new();
    let mut seen = BTreeSet::new();
    let primary = signature.public_key_env.trim();
    if !primary.is_empty() && seen.insert(primary.to_string()) {
        envs.push(primary.to_string());
    }
    for env in &signature.trusted_key_envs {
        let trimmed = env.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            envs.push(trimmed.to_string());
        }
    }
    envs
}

fn load_plugin_public_key_from_env(env_name: &str) -> Result<(String, VerifyingKey)> {
    let key_b64 = std::env::var(env_name)
        .with_context(|| format!("missing plugin public key env var: {env_name}"))?;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64.trim())
        .context("failed to decode plugin public key (base64)")?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("plugin public key must be 32 bytes (ed25519)"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .context("failed to parse plugin public key (ed25519)")?;
    let fingerprint = plugin_public_key_fingerprint(&key_bytes);
    Ok((fingerprint, verifying_key))
}

fn plugin_public_key_fingerprint(key_bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(key_bytes))
}

fn resolve_signed_plugin_artifact_path(
    ctx: &Context,
    plugin: &patchgate_config::PluginEntry,
) -> PathBuf {
    let command_candidate = PathBuf::from(plugin.command.as_str());
    let resolved_command = if command_candidate.is_absolute() {
        command_candidate
    } else {
        ctx.repo_root.join(plugin.command.as_str())
    };
    if let Some(script_artifact) = resolve_interpreter_script_artifact_path(ctx, plugin) {
        return script_artifact;
    }
    if resolved_command.is_file() {
        return resolved_command;
    }

    for arg in &plugin.args {
        let candidate = PathBuf::from(arg);
        let resolved = if candidate.is_absolute() {
            candidate
        } else {
            ctx.repo_root.join(arg)
        };
        if resolved.is_file() {
            return resolved;
        }
    }

    resolved_command
}

fn resolve_interpreter_script_artifact_path(
    ctx: &Context,
    plugin: &patchgate_config::PluginEntry,
) -> Option<PathBuf> {
    if !command_looks_like_interpreter(plugin.command.as_str()) {
        return None;
    }

    for arg in &plugin.args {
        let candidate = PathBuf::from(arg);
        let resolved = if candidate.is_absolute() {
            candidate
        } else {
            ctx.repo_root.join(arg)
        };
        if resolved.is_file() && is_probably_script_artifact(resolved.as_path()) {
            return Some(resolved);
        }
    }

    None
}

fn command_looks_like_interpreter(command: &str) -> bool {
    let command_name = PathBuf::from(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
        .trim_end_matches(".exe")
        .to_ascii_lowercase();
    matches!(
        command_name.as_str(),
        "python"
            | "python3"
            | "python3.11"
            | "python3.12"
            | "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "env"
            | "ruby"
            | "perl"
            | "pwsh"
            | "powershell"
    )
}

fn is_probably_script_artifact(path: &std::path::Path) -> bool {
    let looks_like_script_extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "py" | "pyw"
                    | "js"
                    | "cjs"
                    | "mjs"
                    | "ts"
                    | "tsx"
                    | "sh"
                    | "bash"
                    | "zsh"
                    | "fish"
                    | "rb"
                    | "pl"
                    | "ps1"
            )
        })
        .unwrap_or(false);
    if looks_like_script_extension {
        return true;
    }

    fs::read(path)
        .map(|bytes| bytes.starts_with(b"#!"))
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn append_isolated_runtime_mounts(command: &mut Command, allow_network: bool) {
    let mut mounted_paths = BTreeSet::new();
    for raw in [
        "/usr",
        "/usr/local",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/nix",
        "/run/current-system",
        "/run/current-system/sw",
    ] {
        maybe_append_readonly_bind(command, &mut mounted_paths, std::path::Path::new(raw));
    }
    if let Some(path) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path) {
            maybe_append_readonly_bind(command, &mut mounted_paths, entry.as_path());
        }
    }

    if allow_network {
        command.arg("--share-net");
        command.arg("--dir").arg("/etc");
        for raw in [
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/etc/ssl",
            "/etc/pki",
            "/etc/ca-certificates",
        ] {
            maybe_append_readonly_bind(command, &mut mounted_paths, std::path::Path::new(raw));
        }
    } else {
        command.arg("--unshare-net");
    }
}

#[cfg(target_os = "linux")]
fn maybe_append_readonly_bind(
    command: &mut Command,
    mounted_paths: &mut BTreeSet<PathBuf>,
    path: &std::path::Path,
) {
    if !path.is_absolute() || !path.exists() {
        return;
    }
    if !mounted_paths.insert(path.to_path_buf()) {
        return;
    }
    command.arg("--ro-bind").arg(path).arg(path);
}

fn build_isolated_plugin_command(
    policy: &Config,
    ctx: &Context,
    plugin: &patchgate_config::PluginEntry,
) -> std::result::Result<Command, String> {
    #[cfg(target_os = "linux")]
    {
        if !command_exists("bwrap") {
            return Err(
                "sandbox profile `isolated` requires `bwrap` (bubblewrap) on Linux".to_string(),
            );
        }
        let repo = ctx.repo_root.to_string_lossy().to_string();
        let mut command = Command::new("bwrap");
        command
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--unshare-user")
            .arg("--unshare-pid")
            .arg("--unshare-ipc")
            .arg("--unshare-uts")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--ro-bind")
            .arg(repo.as_str())
            .arg(repo.as_str())
            .arg("--chdir")
            .arg(repo.as_str());
        append_isolated_runtime_mounts(&mut command, policy.plugins.sandbox.allow_network);
        command.arg("--").arg(plugin.command.as_str());
        command.args(&plugin.args);
        Ok(command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        let _ = ctx;
        let _ = plugin;
        Err("sandbox profile `isolated` is currently supported only on Linux".to_string())
    }
}

#[cfg(target_os = "linux")]
fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

#[derive(Debug)]
struct DiffCommandPlan {
    raw_args: Vec<String>,
    numstat_args: Vec<String>,
    patch_args: Vec<String>,
    base_ref: Option<String>,
    head_ref: Option<String>,
    merge_base: Option<String>,
}

fn collect_diff(ctx: &Context, options: &DiffOptions) -> Result<DiffData> {
    let plan = diff_command_plan(ctx, options)?;
    let raw_output = run_git_bytes(&ctx.repo_root, &plan.raw_args)
        .with_context(|| format!("git {:?} failed", plan.raw_args))?;
    let mut files = parse_raw_status_z(raw_output.as_slice());
    if options
        .stop_after_raw_file_limit
        .is_some_and(|limit| files.len() > limit)
    {
        let fingerprint = diff_fingerprint(&plan, raw_output.as_slice(), &[], &[]);
        return Ok(DiffData {
            files: files.into_values().collect(),
            fingerprint,
            base_ref: plan.base_ref,
            head_ref: plan.head_ref,
            merge_base: plan.merge_base,
        });
    }

    let numstat_output = run_git_bytes(&ctx.repo_root, &plan.numstat_args)
        .with_context(|| format!("git {:?} failed", plan.numstat_args))?;
    let patch_output = run_git_bytes(&ctx.repo_root, &plan.patch_args)
        .with_context(|| format!("git {:?} failed", plan.patch_args))?;

    apply_numstat_z(&mut files, numstat_output.as_slice());
    apply_patch_line_samples(&mut files, patch_output.as_slice());
    classify_symlink_targets(&ctx.repo_root, &mut files)?;
    classify_lfs_pointers(&ctx.repo_root, &mut files)?;
    mark_case_insensitive_collisions(&mut files);

    let fingerprint = diff_fingerprint(
        &plan,
        raw_output.as_slice(),
        numstat_output.as_slice(),
        patch_output.as_slice(),
    );

    Ok(DiffData {
        files: files.into_values().collect(),
        fingerprint,
        base_ref: plan.base_ref,
        head_ref: plan.head_ref,
        merge_base: plan.merge_base,
    })
}

fn diff_command_plan(ctx: &Context, options: &DiffOptions) -> Result<DiffCommandPlan> {
    let common_raw = [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--raw",
        "-z",
        "--find-renames",
        "--find-copies",
    ];
    let common_numstat = ["diff", "--no-ext-diff", "--no-textconv", "--numstat", "-z"];
    let common_patch = [
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--patch",
        "--binary",
        "--no-color",
        "--unified=0",
    ];

    let build = |extra: &[String],
                 base_ref: Option<String>,
                 head_ref: Option<String>,
                 merge_base: Option<String>| {
        DiffCommandPlan {
            raw_args: git_args(&common_raw, extra),
            numstat_args: git_args(&common_numstat, extra),
            patch_args: git_args(&common_patch, extra),
            base_ref,
            head_ref,
            merge_base,
        }
    };

    match ctx.scope {
        ScopeMode::Staged => Ok(build(&["--cached".to_string()], None, None, None)),
        ScopeMode::Worktree => Ok(build(&[], None, None, None)),
        ScopeMode::Repo => Ok(build(&["HEAD".to_string()], None, None, None)),
        ScopeMode::Pr => {
            let base_ref = options
                .base_ref
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--base-ref is required when --scope pr"))?;
            let head_ref = options
                .head_ref
                .clone()
                .unwrap_or_else(|| "HEAD".to_string());
            let resolved_base_ref = ensure_ref_resolvable(&ctx.repo_root, base_ref.as_str())
                .with_context(|| format!("resolve PR base ref `{base_ref}`"))?;
            let resolved_head_ref = ensure_ref_resolvable(&ctx.repo_root, head_ref.as_str())
                .with_context(|| format!("resolve PR head ref `{head_ref}`"))?;
            let merge_base = run_git_string(
                &ctx.repo_root,
                &[
                    "merge-base".to_string(),
                    resolved_base_ref,
                    resolved_head_ref.clone(),
                ],
            )
            .context("resolve PR merge-base")?
            .trim()
            .to_string();
            if merge_base.is_empty() {
                anyhow::bail!("git merge-base returned an empty SHA");
            }
            Ok(build(
                &[merge_base.clone(), resolved_head_ref],
                Some(base_ref),
                Some(head_ref),
                Some(merge_base),
            ))
        }
    }
}

fn git_args(prefix: &[&str], extra: &[String]) -> Vec<String> {
    prefix
        .iter()
        .map(|arg| (*arg).to_string())
        .chain(extra.iter().cloned())
        .collect()
}

fn ensure_ref_resolvable(repo_root: &Path, reference: &str) -> Result<String> {
    if git_ref_resolves(repo_root, reference) {
        return Ok(reference.to_string());
    }
    let fetched_ref = fetch_ref(repo_root, reference)?;
    if git_ref_resolves(repo_root, reference) {
        return Ok(reference.to_string());
    }
    if let Some(fetched_ref) = fetched_ref {
        if git_ref_resolves(repo_root, fetched_ref.as_str()) {
            return Ok(fetched_ref);
        }
    }
    anyhow::bail!("git ref `{reference}` could not be resolved after fetch")
}

fn git_ref_resolves(repo_root: &Path, reference: &str) -> bool {
    let verify_ref = format!("{reference}^{{commit}}");
    Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", verify_ref.as_str()])
        .current_dir(repo_root)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn fetch_ref(repo_root: &Path, reference: &str) -> Result<Option<String>> {
    let mut args = vec![
        "fetch".to_string(),
        "--no-tags".to_string(),
        "origin".to_string(),
    ];
    let fetched_ref = if let Some(branch) = reference.strip_prefix("origin/") {
        let remote_ref = format!("refs/remotes/origin/{branch}");
        args.push(format!("+refs/heads/{branch}:{remote_ref}"));
        Some(remote_ref)
    } else if let Some(branch) = reference.strip_prefix("refs/heads/") {
        let remote_ref = format!("refs/remotes/origin/{branch}");
        args.push(format!("+refs/heads/{branch}:{remote_ref}"));
        Some(remote_ref)
    } else if let Some(remote_path) = reference.strip_prefix("refs/") {
        let remote_ref = format!("refs/remotes/origin/{remote_path}");
        args.push(format!("+{reference}:{remote_ref}"));
        Some(remote_ref)
    } else {
        args.push(reference.to_string());
        None
    };
    run_git_bytes(repo_root, &args).with_context(|| format!("git {:?} failed", args))?;
    Ok(fetched_ref)
}

fn diff_fingerprint(
    plan: &DiffCommandPlan,
    raw_output: &[u8],
    numstat_output: &[u8],
    patch_output: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    update_fingerprint_chunk(&mut hasher, DIFF_SCHEMA_VERSION.as_bytes());
    update_fingerprint_chunk(
        &mut hasher,
        plan.base_ref.as_deref().unwrap_or("").as_bytes(),
    );
    update_fingerprint_chunk(
        &mut hasher,
        plan.head_ref.as_deref().unwrap_or("").as_bytes(),
    );
    update_fingerprint_chunk(
        &mut hasher,
        plan.merge_base.as_deref().unwrap_or("").as_bytes(),
    );
    update_fingerprint_chunk(&mut hasher, raw_output);
    update_fingerprint_chunk(&mut hasher, numstat_output);
    update_fingerprint_chunk(&mut hasher, patch_output);
    format!("sha256:{:x}", hasher.finalize())
}

fn update_fingerprint_chunk(hasher: &mut Sha256, chunk: &[u8]) {
    hasher.update((chunk.len() as u64).to_be_bytes());
    hasher.update(chunk);
}

fn run_git_bytes(repo_root: &Path, args: &[String]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .context("failed to invoke git")?;

    if !output.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }

    Ok(output.stdout)
}

fn run_git_string(repo_root: &Path, args: &[String]) -> Result<String> {
    let output = run_git_bytes(repo_root, args)?;
    String::from_utf8(output).context("git output was not utf8")
}

#[cfg(test)]
fn parse_raw_status(input: &str) -> BTreeMap<String, ChangedFile> {
    if input.as_bytes().contains(&0) {
        return parse_raw_status_z(input.as_bytes());
    }

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
        let prefix_parts: Vec<&str> = prefix.split_whitespace().collect();
        if prefix_parts.len() < 5 {
            continue;
        }
        let status = parse_status(prefix_parts[4]);
        let (old_path, path) = match status {
            ChangeStatus::Renamed | ChangeStatus::Copied => {
                let Some(new_path) = second_path else {
                    continue;
                };
                (Some(first_path.as_bytes()), new_path.as_bytes())
            }
            _ => (None, first_path.as_bytes()),
        };
        let file = changed_file_from_raw(
            path,
            old_path,
            status,
            prefix_parts[0].trim_start_matches(':').to_string(),
            prefix_parts[1].to_string(),
            prefix_parts[2].to_string(),
            prefix_parts[3].to_string(),
        );
        insert_changed_file(&mut files, file);
    }
    files
}

fn parse_raw_status_z(input: &[u8]) -> BTreeMap<String, ChangedFile> {
    let mut files = BTreeMap::new();

    let mut parts = input.split(|byte| *byte == 0);
    while let Some(prefix_bytes) = parts.next() {
        if prefix_bytes.is_empty() || !prefix_bytes.starts_with(b":") {
            continue;
        }
        let Some(first_path) = parts.next() else {
            continue;
        };
        let prefix = String::from_utf8_lossy(prefix_bytes);
        let prefix_parts: Vec<&str> = prefix.split_whitespace().collect();
        if prefix_parts.len() < 5 {
            continue;
        }
        let old_mode = prefix_parts[0].trim_start_matches(':').to_string();
        let new_mode = prefix_parts[1].to_string();
        let old_oid = prefix_parts[2].to_string();
        let new_oid = prefix_parts[3].to_string();
        let status_token = prefix_parts[4];
        let status = parse_status(status_token);

        let (old_path, path) = match status {
            ChangeStatus::Renamed | ChangeStatus::Copied => {
                let Some(new_path) = parts.next() else {
                    continue;
                };
                (Some(first_path), new_path)
            }
            _ => (None, first_path),
        };

        let file =
            changed_file_from_raw(path, old_path, status, old_mode, new_mode, old_oid, new_oid);
        insert_changed_file(&mut files, file);
    }

    files
}

fn insert_changed_file(files: &mut BTreeMap<String, ChangedFile>, file: ChangedFile) -> String {
    let key = unique_file_key(files, file.path.as_str(), file.metadata.path_id.as_str());
    files.insert(key.clone(), file);
    key
}

fn unique_file_key(
    files: &BTreeMap<String, ChangedFile>,
    display_path: &str,
    path_id: &str,
) -> String {
    match files.get(display_path) {
        None => display_path.to_string(),
        Some(existing) if existing.metadata.path_id == path_id => display_path.to_string(),
        Some(_) => format!("{display_path}#{path_id}"),
    }
}

fn changed_file_from_raw(
    path_bytes: &[u8],
    old_path_bytes: Option<&[u8]>,
    status: ChangeStatus,
    old_mode: String,
    new_mode: String,
    old_oid: String,
    new_oid: String,
) -> ChangedFile {
    let path = display_path(path_bytes);
    let old_path = old_path_bytes.map(display_path);
    let mut metadata = metadata_for_path(path_bytes);
    if let Some(old_path_bytes) = old_path_bytes {
        let old_metadata = metadata_for_path(old_path_bytes);
        metadata.old_path_id = Some(path_id(old_path_bytes));
        metadata.old_path_bytes_b64 = Some(path_bytes_b64(old_path_bytes));
        merge_path_flags(&mut metadata.path_flags, old_metadata.path_flags);
    }
    metadata.old_mode = Some(old_mode.clone());
    metadata.new_mode = Some(new_mode.clone());
    metadata.old_oid = Some(old_oid);
    metadata.new_oid = Some(new_oid);
    metadata.file_kind = classify_file_kind_from_modes(old_mode.as_str(), new_mode.as_str());

    ChangedFile {
        path,
        status,
        old_path,
        added: 0,
        deleted: 0,
        added_lines: Vec::new(),
        removed_lines: Vec::new(),
        metadata,
    }
}

fn merge_path_flags(target: &mut Vec<PathSafetyFlag>, source: Vec<PathSafetyFlag>) {
    for flag in source {
        if !target.contains(&flag) {
            target.push(flag);
        }
    }
}

fn metadata_for_path(path_bytes: &[u8]) -> DiffFileMetadata {
    let mut path_flags = Vec::new();
    if std::str::from_utf8(path_bytes).is_err() {
        path_flags.push(PathSafetyFlag::NonUtf8);
    }
    if path_bytes
        .iter()
        .any(|byte| matches!(*byte, b'\n' | b'\r' | b'\t') || *byte < 0x20)
    {
        path_flags.push(PathSafetyFlag::ControlCharacter);
    }
    if !is_repository_relative_path(path_bytes) {
        path_flags.push(PathSafetyFlag::RejectedRepositoryPath);
    }
    DiffFileMetadata {
        path_id: path_id(path_bytes),
        path_bytes_b64: path_bytes_b64(path_bytes),
        old_path_id: None,
        old_path_bytes_b64: None,
        file_kind: FileKind::Text,
        old_mode: None,
        new_mode: None,
        old_oid: None,
        new_oid: None,
        symlink_target: None,
        symlink_target_escapes_repo: false,
        path_flags,
    }
}

fn classify_file_kind_from_modes(old_mode: &str, new_mode: &str) -> FileKind {
    if old_mode == "160000" || new_mode == "160000" {
        FileKind::Submodule
    } else if old_mode == "120000" || new_mode == "120000" {
        FileKind::Symlink
    } else if new_mode == "000000" && old_mode == "000000" {
        FileKind::Unknown
    } else {
        FileKind::Text
    }
}

fn display_path(path_bytes: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(path_bytes);
    let mut display = String::new();
    for ch in lossy.chars() {
        match ch {
            '\n' => display.push_str("\\n"),
            '\r' => display.push_str("\\r"),
            '\t' => display.push_str("\\t"),
            '\0' => display.push_str("\\0"),
            ch if ch.is_control() => {
                for escaped in ch.escape_default() {
                    display.push(escaped);
                }
            }
            ch => display.push(ch),
        }
    }
    display
}

fn path_id(path_bytes: &[u8]) -> String {
    format!("path_sha256:{:x}", Sha256::digest(path_bytes))
}

fn path_bytes_b64(path_bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(path_bytes)
}

fn is_repository_relative_path(path_bytes: &[u8]) -> bool {
    if path_bytes.is_empty()
        || path_bytes.starts_with(b"/")
        || path_bytes.starts_with(b"\\")
        || path_bytes.contains(&b'\\')
    {
        return false;
    }
    if path_bytes.len() >= 2 && path_bytes[1] == b':' && path_bytes[0].is_ascii_alphabetic() {
        return false;
    }
    path_bytes
        .split(|byte| *byte == b'/')
        .all(|part| !part.is_empty() && part != b"." && part != b"..")
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
                metadata: DiffFileMetadata::default(),
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

fn apply_numstat_z(files: &mut BTreeMap<String, ChangedFile>, input: &[u8]) {
    let mut path_id_to_key: BTreeMap<String, String> = files
        .iter()
        .map(|(key, file)| (file.metadata.path_id.clone(), key.clone()))
        .collect();
    let mut parts = input.split(|byte| *byte == 0);
    while let Some(header) = parts.next() {
        if header.is_empty() {
            continue;
        }
        let Some((added_raw, deleted_raw, path_field)) = split_numstat_header(header) else {
            continue;
        };
        let path_bytes = if path_field.is_empty() {
            let _old_path = parts.next();
            let Some(new_path) = parts.next() else {
                continue;
            };
            new_path
        } else {
            path_field
        };
        let path = display_path(path_bytes);
        let path_metadata = metadata_for_path(path_bytes);
        let key = if let Some(key) = path_id_to_key.get(path_metadata.path_id.as_str()).cloned() {
            key
        } else {
            let file = ChangedFile {
                path: path.clone(),
                status: ChangeStatus::Unknown,
                old_path: None,
                added: 0,
                deleted: 0,
                added_lines: Vec::new(),
                removed_lines: Vec::new(),
                metadata: path_metadata.clone(),
            };
            let key = insert_changed_file(files, file);
            path_id_to_key.insert(path_metadata.path_id.clone(), key.clone());
            key
        };
        let Some(file) = files.get_mut(key.as_str()) else {
            continue;
        };

        match (
            parse_numstat_count(added_raw),
            parse_numstat_count(deleted_raw),
        ) {
            (Some(added), Some(deleted)) => {
                file.added = added;
                file.deleted = deleted;
            }
            _ => {
                if !matches!(
                    file.metadata.file_kind,
                    FileKind::Symlink | FileKind::Submodule
                ) {
                    file.metadata.file_kind = FileKind::Binary;
                }
            }
        }
    }
}

fn split_numstat_header(header: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let first_tab = header.iter().position(|byte| *byte == b'\t')?;
    let second_tab = header[first_tab + 1..]
        .iter()
        .position(|byte| *byte == b'\t')?
        + first_tab
        + 1;
    Some((
        &header[..first_tab],
        &header[first_tab + 1..second_tab],
        &header[second_tab + 1..],
    ))
}

fn parse_numstat_count(raw: &[u8]) -> Option<u32> {
    if raw == b"-" {
        return None;
    }
    let text = std::str::from_utf8(raw).ok()?;
    text.parse::<u32>().ok()
}

fn apply_patch_line_samples(files: &mut BTreeMap<String, ChangedFile>, patch: &[u8]) {
    let display_path_keys = unambiguous_display_path_keys(files);
    let mut current_key: Option<String> = None;

    for line in patch.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = String::from_utf8_lossy(line);
        if line.starts_with("diff --git ") {
            current_key = None;
            continue;
        }

        if let Some(path) = parse_patch_file_header_path(&line, "+++ b/") {
            current_key = display_path_keys.get(path.as_str()).and_then(Clone::clone);
            continue;
        }

        if let Some(path) = parse_patch_file_header_path(&line, "--- a/") {
            current_key = display_path_keys.get(path.as_str()).and_then(Clone::clone);
            continue;
        }

        if line.starts_with("+++ /dev/null")
            || line.starts_with("--- /dev/null")
            || line.starts_with("@@")
        {
            continue;
        }

        let Some(key) = &current_key else {
            continue;
        };
        let Some(file) = files.get_mut(key.as_str()) else {
            continue;
        };

        if let Some(stripped) = line.strip_prefix('+') {
            if file.added_lines.len() < MAX_STORED_LINE_SAMPLES {
                file.added_lines.push(truncate_line_sample(stripped));
            }
        } else if let Some(stripped) = line.strip_prefix('-') {
            if file.removed_lines.len() < MAX_STORED_LINE_SAMPLES {
                file.removed_lines.push(truncate_line_sample(stripped));
            }
        }
    }
}

fn unambiguous_display_path_keys(
    files: &BTreeMap<String, ChangedFile>,
) -> BTreeMap<String, Option<String>> {
    let mut display_path_keys = BTreeMap::new();
    for (key, file) in files {
        display_path_keys
            .entry(file.path.clone())
            .and_modify(|entry| *entry = None)
            .or_insert_with(|| Some(key.clone()));
    }
    display_path_keys
}

fn classify_symlink_targets(
    repo_root: &Path,
    files: &mut BTreeMap<String, ChangedFile>,
) -> Result<()> {
    for file in files.values_mut() {
        if file.metadata.file_kind != FileKind::Symlink {
            continue;
        }
        let oid = if file.status == ChangeStatus::Deleted {
            file.metadata.old_oid.as_deref()
        } else {
            file.metadata.new_oid.as_deref()
        };
        let target = if let Some(oid) = oid.filter(|oid| !oid.chars().all(|ch| ch == '0')) {
            run_git_bytes(
                repo_root,
                &["cat-file".to_string(), "-p".to_string(), oid.to_string()],
            )
            .with_context(|| format!("read symlink target for {}", file.path))?
        } else if file.status != ChangeStatus::Deleted {
            let Some(target) = read_worktree_symlink_target(repo_root, file) else {
                file.metadata.symlink_target_escapes_repo = true;
                continue;
            };
            target
        } else {
            file.metadata.symlink_target_escapes_repo = true;
            continue;
        };
        let target_display = display_path(target.as_slice());
        file.metadata.symlink_target = Some(target_display);
        file.metadata.symlink_target_escapes_repo =
            !symlink_target_stays_in_repo(file.path.as_str(), target.as_slice());
    }
    Ok(())
}

fn read_worktree_symlink_target(repo_root: &Path, file: &ChangedFile) -> Option<Vec<u8>> {
    if !file.metadata.path_flags.is_empty() {
        return None;
    }
    let target = fs::read_link(repo_root.join(file.path.as_str())).ok()?;
    target.to_str().map(|target| target.as_bytes().to_vec())
}

fn classify_lfs_pointers(
    repo_root: &Path,
    files: &mut BTreeMap<String, ChangedFile>,
) -> Result<()> {
    for file in files.values_mut() {
        if file.metadata.file_kind != FileKind::Text || file.status == ChangeStatus::Deleted {
            continue;
        }
        let blob = if let Some(oid) = file
            .metadata
            .new_oid
            .as_deref()
            .filter(|oid| !oid.chars().all(|ch| ch == '0'))
        {
            let size = run_git_string(
                repo_root,
                &["cat-file".to_string(), "-s".to_string(), oid.to_string()],
            )
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(usize::MAX);
            if size > 1024 {
                continue;
            }
            run_git_bytes(
                repo_root,
                &["cat-file".to_string(), "-p".to_string(), oid.to_string()],
            )
            .with_context(|| format!("read blob for {}", file.path))?
        } else {
            let Some(blob) = read_small_worktree_file(repo_root, file, 1024) else {
                continue;
            };
            blob
        };
        if is_lfs_pointer(blob.as_slice()) {
            file.metadata.file_kind = FileKind::Lfs;
        }
    }
    Ok(())
}

fn read_small_worktree_file(
    repo_root: &Path,
    file: &ChangedFile,
    max_bytes: u64,
) -> Option<Vec<u8>> {
    if !file.metadata.path_flags.is_empty() {
        return None;
    }
    let path = repo_root.join(file.path.as_str());
    let metadata = fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    fs::read(path).ok()
}

fn is_lfs_pointer(blob: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(blob) else {
        return false;
    };
    let mut lines = text.lines();
    matches!(
        lines.next(),
        Some("version https://git-lfs.github.com/spec/v1")
    ) && text.lines().any(|line| line.starts_with("oid sha256:"))
        && text.lines().any(|line| line.starts_with("size "))
}

fn symlink_target_stays_in_repo(link_path: &str, target: &[u8]) -> bool {
    if !is_repository_relative_symlink_target(target) {
        return false;
    }
    let Ok(target) = std::str::from_utf8(target) else {
        return false;
    };
    let mut stack: Vec<&str> = link_path.rsplit_once('/').map_or(Vec::new(), |(dir, _)| {
        dir.split('/').filter(|part| !part.is_empty()).collect()
    });
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return false;
                }
            }
            part => stack.push(part),
        }
    }
    true
}

fn is_repository_relative_symlink_target(target: &[u8]) -> bool {
    if target.is_empty()
        || target.starts_with(b"/")
        || target.starts_with(b"\\")
        || target.contains(&b'\\')
        || std::str::from_utf8(target).is_err()
    {
        return false;
    }
    !(target.len() >= 2 && target[1] == b':' && target[0].is_ascii_alphabetic())
}

fn mark_case_insensitive_collisions(files: &mut BTreeMap<String, ChangedFile>) {
    let mut by_folded_path: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, file) in files.iter() {
        by_folded_path
            .entry(normalized_case_collision_key(file.path.as_str()))
            .or_default()
            .push(key.clone());
    }
    for keys in by_folded_path.into_values().filter(|keys| keys.len() > 1) {
        let path_ids: BTreeSet<String> = keys
            .iter()
            .filter_map(|key| files.get(key))
            .map(|file| file.metadata.path_id.clone())
            .collect();
        if path_ids.len() <= 1 {
            continue;
        }
        for key in keys {
            if let Some(file) = files.get_mut(&key) {
                if !file
                    .metadata
                    .path_flags
                    .contains(&PathSafetyFlag::CaseInsensitiveCollision)
                {
                    file.metadata
                        .path_flags
                        .push(PathSafetyFlag::CaseInsensitiveCollision);
                }
            }
        }
    }
}

fn normalized_case_collision_key(path: &str) -> String {
    path.nfc().flat_map(|ch| ch.to_lowercase()).collect()
}

#[cfg(test)]
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
                metadata: DiffFileMetadata::default(),
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
    use ed25519_dalek::Signer;

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
    fn nul_raw_parser_preserves_special_path_identity() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b":100644 100644 abcdef1 abcdef2 M\0");
        raw.extend_from_slice(b"dir\twith\nnewline-\xff.rs\0");

        let parsed = parse_raw_status_z(raw.as_slice());
        let file = parsed.values().next().expect("file");

        assert!(file.path.contains("\\t"));
        assert!(file.path.contains("\\n"));
        assert!(file
            .metadata
            .path_flags
            .contains(&PathSafetyFlag::ControlCharacter));
        assert!(file.metadata.path_flags.contains(&PathSafetyFlag::NonUtf8));
        assert!(file.metadata.path_id.starts_with("path_sha256:"));
        assert!(!file.metadata.path_bytes_b64.is_empty());
    }

    #[test]
    fn raw_display_collision_preserves_both_path_identities() {
        let raw = b":100644 100644 abcdef1 abcdef2 A\0dir/a\nb.rs\0:100644 100644 abcdef1 abcdef2 A\0dir/a\\nb.rs\0";

        let parsed = parse_raw_status_z(raw);
        let path_ids: BTreeSet<String> = parsed
            .values()
            .map(|file| file.metadata.path_id.clone())
            .collect();

        assert_eq!(parsed.len(), 2);
        assert_eq!(path_ids.len(), 2);
        assert!(parsed.contains_key("dir/a\\nb.rs"));
        assert!(parsed.keys().any(|key| key.starts_with("dir/a\\nb.rs#")));
    }

    #[test]
    fn raw_rename_old_path_safety_flags_are_preserved() {
        let raw = b":100644 100644 abcdef1 abcdef2 R100\0dir/old\tname.rs\0dir/new-name.rs\0";
        let parsed = parse_raw_status_z(raw);
        let file = parsed.get("dir/new-name.rs").expect("renamed file");

        assert_eq!(file.old_path.as_deref(), Some("dir/old\\tname.rs"));
        assert!(file
            .metadata
            .path_flags
            .contains(&PathSafetyFlag::ControlCharacter));

        let eval = evaluate_diff_correctness(&DiffData {
            files: parsed.into_values().collect(),
            fingerprint: "fixture".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        });
        assert!(eval.findings.iter().any(|finding| finding.id == "DIFF-001"));
    }

    #[test]
    fn numstat_z_classifies_binary_without_tab_splitting_path() {
        let raw = b":100644 100644 abcdef1 abcdef2 M\0assets/a\tb.png\0";
        let mut parsed = parse_raw_status_z(raw);
        apply_numstat_z(&mut parsed, b"-\t-\tassets/a\tb.png\0");

        let file = parsed.get("assets/a\\tb.png").expect("binary file");
        assert_eq!(file.metadata.file_kind, FileKind::Binary);
    }

    #[test]
    fn patch_line_sampling_survives_non_utf8_lines() {
        let mut files = parse_name_status("M\tbin.dat\nM\tsrc/lib.rs\n");
        let patch = b"diff --git a/bin.dat b/bin.dat\n--- a/bin.dat\n+++ b/bin.dat\n@@ -1,1 +1,1 @@\n-old\n+\xff\n\
diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,1 +1,1 @@\n-old\n+safe\n";

        apply_patch_line_samples(&mut files, patch);

        let file = files.get("src/lib.rs").expect("src file");
        assert_eq!(file.added_lines.first().map(String::as_str), Some("safe"));
    }

    #[test]
    fn diff_correctness_blocks_binary_submodule_and_special_paths() {
        let mut binary = ChangedFile {
            path: "assets/logo.png".to_string(),
            status: ChangeStatus::Modified,
            old_path: None,
            added: 0,
            deleted: 0,
            added_lines: vec![],
            removed_lines: vec![],
            metadata: DiffFileMetadata::default(),
        };
        binary.metadata.file_kind = FileKind::Binary;

        let mut submodule = ChangedFile {
            path: "vendor/lib".to_string(),
            status: ChangeStatus::Modified,
            old_path: None,
            added: 0,
            deleted: 0,
            added_lines: vec![],
            removed_lines: vec![],
            metadata: DiffFileMetadata::default(),
        };
        submodule.metadata.file_kind = FileKind::Submodule;
        submodule.metadata.old_oid = Some("1111111111111111111111111111111111111111".to_string());
        submodule.metadata.new_oid = Some("2222222222222222222222222222222222222222".to_string());

        let mut special = ChangedFile {
            path: "src/bad\\nname.rs".to_string(),
            status: ChangeStatus::Added,
            old_path: None,
            added: 1,
            deleted: 0,
            added_lines: vec![],
            removed_lines: vec![],
            metadata: DiffFileMetadata::default(),
        };
        special
            .metadata
            .path_flags
            .push(PathSafetyFlag::ControlCharacter);

        let diff = DiffData {
            files: vec![binary, submodule, special],
            fingerprint: "fixture".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };
        let eval = evaluate_diff_correctness(&diff);
        let ids: BTreeSet<String> = eval.findings.iter().map(|f| f.id.clone()).collect();

        assert_eq!(eval.score.penalty, 100);
        assert!(ids.contains("DIFF-001"));
        assert!(ids.contains("DIFF-004"));
        assert!(ids.contains("DIFF-005"));
        assert!(eval
            .findings
            .iter()
            .all(|finding| finding.severity == Severity::Critical));
    }

    #[test]
    fn symlink_containment_rejects_repo_escape() {
        assert!(symlink_target_stays_in_repo("docs/link", b"guide.md"));
        assert!(symlink_target_stays_in_repo(
            "docs/nested/link",
            b"../guide.md"
        ));
        assert!(!symlink_target_stays_in_repo("docs/link", b"../../secret"));
        assert!(!symlink_target_stays_in_repo("docs/link", b"/etc/passwd"));
    }

    #[test]
    fn case_insensitive_collision_marks_both_paths() {
        let raw = b":100644 100644 abcdef1 abcdef2 A\0Src/Foo.rs\0:100644 100644 abcdef1 abcdef2 A\0src/foo.rs\0";
        let mut parsed = parse_raw_status_z(raw);
        mark_case_insensitive_collisions(&mut parsed);

        assert!(parsed
            .get("Src/Foo.rs")
            .expect("upper path")
            .metadata
            .path_flags
            .contains(&PathSafetyFlag::CaseInsensitiveCollision));
        assert!(parsed
            .get("src/foo.rs")
            .expect("lower path")
            .metadata
            .path_flags
            .contains(&PathSafetyFlag::CaseInsensitiveCollision));
    }

    #[test]
    fn unicode_normalization_collision_marks_both_paths() {
        let composed = "src/caf\u{00e9}.rs";
        let decomposed = "src/cafe\u{0301}.rs";
        let mut raw = Vec::new();
        raw.extend_from_slice(b":100644 100644 abcdef1 abcdef2 A\0");
        raw.extend_from_slice(composed.as_bytes());
        raw.push(0);
        raw.extend_from_slice(b":100644 100644 abcdef1 abcdef2 A\0");
        raw.extend_from_slice(decomposed.as_bytes());
        raw.push(0);

        let mut parsed = parse_raw_status_z(raw.as_slice());
        mark_case_insensitive_collisions(&mut parsed);

        assert!(parsed
            .get(composed)
            .expect("composed path")
            .metadata
            .path_flags
            .contains(&PathSafetyFlag::CaseInsensitiveCollision));
        assert!(parsed
            .get(decomposed)
            .expect("decomposed path")
            .metadata
            .path_flags
            .contains(&PathSafetyFlag::CaseInsensitiveCollision));
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
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "tests/lib_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 4,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "tests/new_name.rs".to_string(),
                    status: ChangeStatus::Renamed,
                    old_path: Some("tests/old_name.rs".to_string()),
                    added: 0,
                    deleted: 0,
                    added_lines: vec![],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "packages/b/tests/b_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 3,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "packages/c/tests/c_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 3,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "packages/a/tests/service_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "packages/b/src/service.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 120,
                    deleted: 10,
                    added_lines: vec!["line".to_string()],
                    removed_lines: vec!["line".to_string()],
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "tests/global_test.rs".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 0,
                    added_lines: vec!["assert".to_string()],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
            metadata: DiffFileMetadata::default(),
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
            metadata: DiffFileMetadata::default(),
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "Cargo.lock".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 20,
                    deleted: 10,
                    added_lines: vec!["pkg".to_string()],
                    removed_lines: vec!["old".to_string()],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "Cargo.lock".to_string(),
                    status: ChangeStatus::Renamed,
                    old_path: Some("Cargo.old.lock".to_string()),
                    added: 0,
                    deleted: 0,
                    added_lines: vec![],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: ".github/workflows/ci.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 2,
                    deleted: 2,
                    added_lines: vec!["permissions: write-all".to_string()],
                    removed_lines: vec!["permissions: read-all".to_string()],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["run: cargo test".to_string()],
                    removed_lines: vec!["run: cargo check".to_string()],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };

        let report = runner.evaluate(&ctx, diff, "enforce").expect("evaluate");
        assert!(
            report
                .supply_chain_signals
                .iter()
                .any(|s| s.id == "SCM-002"),
            "lockfile add/remove with CI change should trigger SCM-002"
        );
        assert!(
            report.decision.hard_gates.iter().any(|gate| {
                gate.gate_id == "critical-supply-chain"
                    && gate.result == crate::model::GateDecisionResult::Fail
            }),
            "critical supply-chain evidence should become an unwaived hard gate"
        );
        assert_eq!(report.decision.result, crate::model::DecisionResult::Fail);
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["permissions: write-all".to_string()],
                    removed_lines: vec!["permissions: read-all".to_string()],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: "infra/main.tf".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 0,
                    added_lines: vec!["resource \"aws_s3_bucket\" \"logs\" {}".to_string()],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 1,
                    added_lines: vec!["permissions: write-all".to_string()],
                    removed_lines: vec!["permissions: read-all".to_string()],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
                    metadata: DiffFileMetadata::default(),
                },
                ChangedFile {
                    path: ".github/workflows/release.yml".to_string(),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 0,
                    added_lines: vec!["run: bundle install".to_string()],
                    removed_lines: vec![],
                    metadata: DiffFileMetadata::default(),
                },
            ],
            fingerprint: "dummy".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
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
    fn plugin_shadow_contract_hashes_v2_envelope_without_changing_v1_input() {
        let mut policy = Config::default();
        policy.compatibility.v2.shadow_mode = true;
        policy.compatibility.v2.bridge_mode = "full".to_string();
        let input = PluginInput {
            schema_version: 1,
            api_version: "patchgate.plugin.v1".to_string(),
            plugin_id: "sample".to_string(),
            repo_root: ".".to_string(),
            mode: "warn".to_string(),
            scope: "worktree".to_string(),
            changed_files: vec![PluginChangedFile {
                path: "src/lib.rs".to_string(),
                old_path: None,
                path_id: "path_sha256:test".to_string(),
                path_bytes_b64: "c3JjL2xpYi5ycw==".to_string(),
                file_kind: "text".to_string(),
                status: "modified".to_string(),
                added: 2,
                deleted: 1,
            }],
        };

        let contract = plugin_shadow_contract_from_input(&policy, &input)
            .expect("contract")
            .expect("shadow contract");
        let shadow = PluginInputV2Shadow::from_v1(&input, PLUGIN_SHADOW_BRIDGE_MODE);

        assert_eq!(input.api_version, "patchgate.plugin.v1");
        assert_eq!(shadow.api_version, "patchgate.plugin.v2-shadow");
        assert_eq!(shadow.shadow_of, "patchgate.plugin.v1");
        assert_eq!(shadow.metadata.bridge_mode, "shadow");
        assert_eq!(contract.input_api_version, "patchgate.plugin.v1");
        assert_eq!(contract.shadow_api_version, "patchgate.plugin.v2-shadow");
        assert_eq!(contract.shadow_of, "patchgate.plugin.v1");
        assert_eq!(contract.bridge_mode, "shadow");
        assert_eq!(contract.shadow_envelope_sha256.len(), 64);
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

    #[cfg(not(windows))]
    #[test]
    fn plugin_timeout_applies_when_stdin_writer_blocks_on_unread_input() {
        let policy = Config::default();
        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-unread-stdin-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.sh");
        std::fs::write(&plugin_path, "#!/usr/bin/env sh\nexec sleep 5\n")
            .expect("write plugin script");
        let plugin = patchgate_config::PluginEntry {
            id: "unread-stdin".to_string(),
            command: "sh".to_string(),
            args: vec![plugin_path.to_string_lossy().to_string()],
            timeout_ms: 100,
            fail_mode: "fail_closed".to_string(),
            signature_path: String::new(),
        };
        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: (0..20_000)
                .map(|i| ChangedFile {
                    path: format!("src/file_{i}.rs"),
                    status: ChangeStatus::Modified,
                    old_path: None,
                    added: 1,
                    deleted: 0,
                    added_lines: Vec::new(),
                    removed_lines: Vec::new(),
                    metadata: DiffFileMetadata::default(),
                })
                .collect(),
            fingerprint: "large-plugin-input".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };

        let start = Instant::now();
        let invocation =
            execute_plugin(&policy, &ctx, &diff, "warn", &plugin).expect("execute plugin");

        assert_eq!(invocation.status, PluginInvocationStatus::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "plugin timeout should apply while stdin writer is blocked"
        );
        let _ = std::fs::remove_dir_all(temp_root);
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
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };
        let outcome = evaluate_plugins(&policy, &ctx, &diff, "warn").expect("evaluate");
        assert!(outcome.score.is_none());
        assert!(outcome.findings.is_empty());
        assert!(outcome.invocations.is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn plugin_contract_harness_and_signature_verification_pass() {
        use std::os::unix::fs::PermissionsExt;
        let mut policy = Config::default();
        policy.plugins.enabled = true;
        policy.plugins.signature.required = true;
        let public_key_env = format!("PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_{}", std::process::id());
        policy.plugins.signature.public_key_env = public_key_env.clone();

        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-contract-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.sh");
        let input_capture = temp_root.join("plugin-input.json");
        let signature_path = temp_root.join("plugin.sig");

        let script = format!(
            "#!/usr/bin/env sh\nset -eu\ncat > \"{}\"\necho '{{\"findings\":[],\"diagnostics\":[\"ok\"]}}'\n",
            input_capture.display()
        );
        std::fs::write(&plugin_path, script).expect("write plugin script");
        let mut perms = std::fs::metadata(&plugin_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&plugin_path, perms).expect("chmod +x");

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
        std::env::set_var(public_key_env.as_str(), public_key_b64);

        let command_bytes = std::fs::read(&plugin_path).expect("read plugin");
        let signature = signing_key.sign(command_bytes.as_slice());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(&signature_path, signature_b64).expect("write signature");

        policy.plugins.entries.push(patchgate_config::PluginEntry {
            id: "sample".to_string(),
            command: plugin_path.to_string_lossy().to_string(),
            args: Vec::new(),
            timeout_ms: 3_000,
            fail_mode: "fail_closed".to_string(),
            signature_path: signature_path.to_string_lossy().to_string(),
        });

        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/lib.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 1,
                deleted: 0,
                added_lines: vec!["let x = 1;".to_string()],
                removed_lines: vec![],
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "contract-fp".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };
        let runner = Runner::new(policy);
        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(report
            .plugin_invocations
            .iter()
            .any(|i| i.plugin_id == "sample" && i.status == PluginInvocationStatus::Pass));
        let captured = std::fs::read_to_string(&input_capture).expect("captured input");
        assert!(captured.contains("\"api_version\":\"patchgate.plugin.v1\""));
        assert!(captured.contains("\"plugin_id\":\"sample\""));
        std::env::remove_var(public_key_env);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(not(windows))]
    #[test]
    fn plugin_signature_verification_uses_script_arg_for_interpreter_commands() {
        use std::os::unix::fs::PermissionsExt;

        let mut policy = Config::default();
        policy.plugins.enabled = true;
        policy.plugins.signature.required = true;
        let public_key_env = format!(
            "PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_INTERPRETER_{}",
            std::process::id()
        );
        policy.plugins.signature.public_key_env = public_key_env.clone();

        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-signature-interpreter-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.sh");
        let signature_path = temp_root.join("plugin.sig");
        std::fs::write(
            &plugin_path,
            "#!/usr/bin/env sh\ncat >/dev/null\necho '{\"findings\":[],\"diagnostics\":[\"ok\"]}'\n",
        )
        .expect("write plugin script");
        let mut perms = std::fs::metadata(&plugin_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&plugin_path, perms).expect("chmod +x");

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
        std::env::set_var(public_key_env.as_str(), public_key_b64);

        let script_bytes = std::fs::read(&plugin_path).expect("read plugin script");
        let signature = signing_key.sign(script_bytes.as_slice());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(&signature_path, signature_b64).expect("write signature");

        policy.plugins.entries.push(patchgate_config::PluginEntry {
            id: "sample".to_string(),
            command: "sh".to_string(),
            args: vec![plugin_path.to_string_lossy().to_string()],
            timeout_ms: 3_000,
            fail_mode: "fail_closed".to_string(),
            signature_path: signature_path.to_string_lossy().to_string(),
        });

        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/lib.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 1,
                deleted: 0,
                added_lines: vec!["let z = 1;".to_string()],
                removed_lines: vec![],
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "interpreter-signature".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };
        let runner = Runner::new(policy);
        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(report
            .plugin_invocations
            .iter()
            .any(|i| i.plugin_id == "sample" && i.status == PluginInvocationStatus::Pass));

        std::env::remove_var(public_key_env);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(not(windows))]
    #[test]
    fn plugin_signature_verification_accepts_rotated_trusted_key() {
        let mut policy = Config::default();
        policy.plugins.signature.required = true;
        let old_key_env = format!(
            "PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_ROTATION_OLD_{}",
            std::process::id()
        );
        let new_key_env = format!(
            "PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_ROTATION_NEW_{}",
            std::process::id()
        );
        policy.plugins.signature.public_key_env = old_key_env.clone();
        policy.plugins.signature.trusted_key_envs = vec![new_key_env.clone()];

        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-signature-rotation-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.sh");
        let signature_path = temp_root.join("plugin.sig");
        std::fs::write(&plugin_path, "#!/usr/bin/env sh\necho ok\n").expect("write plugin");

        let old_signing_key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let new_signing_key = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        let old_public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(old_signing_key.verifying_key().as_bytes());
        let new_public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(new_signing_key.verifying_key().as_bytes());
        policy
            .plugins
            .signature
            .revoked_key_sha256
            .push(plugin_public_key_fingerprint(
                old_signing_key.verifying_key().as_bytes(),
            ));
        std::env::set_var(old_key_env.as_str(), old_public_key_b64);
        std::env::set_var(new_key_env.as_str(), new_public_key_b64);

        let command_bytes = std::fs::read(&plugin_path).expect("read plugin");
        let signature = new_signing_key.sign(command_bytes.as_slice());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(&signature_path, signature_b64).expect("write signature");

        let plugin = patchgate_config::PluginEntry {
            id: "sample".to_string(),
            command: plugin_path.to_string_lossy().to_string(),
            args: Vec::new(),
            timeout_ms: 3_000,
            fail_mode: "fail_closed".to_string(),
            signature_path: signature_path.to_string_lossy().to_string(),
        };
        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };

        verify_plugin_signature(&policy, &ctx, &plugin).expect("rotated key should verify");

        std::env::remove_var(old_key_env);
        std::env::remove_var(new_key_env);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(not(windows))]
    #[test]
    fn plugin_signature_verification_prefers_executable_over_file_args() {
        use std::os::unix::fs::PermissionsExt;

        let mut policy = Config::default();
        policy.plugins.enabled = true;
        policy.plugins.signature.required = true;
        let public_key_env = format!(
            "PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_EXECUTABLE_{}",
            std::process::id()
        );
        policy.plugins.signature.public_key_env = public_key_env.clone();

        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-signature-executable-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.sh");
        let config_path = temp_root.join("rules.json");
        let signature_path = temp_root.join("plugin.sig");
        std::fs::write(
            &plugin_path,
            "#!/usr/bin/env sh\ncat >/dev/null\necho '{\"findings\":[],\"diagnostics\":[\"ok\"]}'\n",
        )
        .expect("write plugin script");
        std::fs::write(&config_path, "{\"mode\":\"strict\"}\n").expect("write config");
        let mut perms = std::fs::metadata(&plugin_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&plugin_path, perms).expect("chmod +x");

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
        std::env::set_var(public_key_env.as_str(), public_key_b64);

        let command_bytes = std::fs::read(&plugin_path).expect("read plugin");
        let signature = signing_key.sign(command_bytes.as_slice());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(&signature_path, signature_b64).expect("write signature");

        policy.plugins.entries.push(patchgate_config::PluginEntry {
            id: "sample".to_string(),
            command: plugin_path.to_string_lossy().to_string(),
            args: vec![config_path.to_string_lossy().to_string()],
            timeout_ms: 3_000,
            fail_mode: "fail_closed".to_string(),
            signature_path: signature_path.to_string_lossy().to_string(),
        });

        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/lib.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 1,
                deleted: 0,
                added_lines: vec!["let q = 1;".to_string()],
                removed_lines: vec![],
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "absolute-command-signature".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };
        let runner = Runner::new(policy);
        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(report
            .plugin_invocations
            .iter()
            .any(|i| i.plugin_id == "sample" && i.status == PluginInvocationStatus::Pass));

        std::env::remove_var(public_key_env);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(not(windows))]
    #[test]
    fn plugin_signature_verification_uses_script_arg_for_absolute_interpreter_commands() {
        use std::os::unix::fs::PermissionsExt;

        let mut policy = Config::default();
        policy.plugins.enabled = true;
        policy.plugins.signature.required = true;
        let public_key_env = format!(
            "PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_ABSOLUTE_INTERPRETER_{}",
            std::process::id()
        );
        policy.plugins.signature.public_key_env = public_key_env.clone();

        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-signature-absolute-interpreter-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.py");
        let signature_path = temp_root.join("plugin.sig");
        std::fs::write(
            &plugin_path,
            "#!/usr/bin/env python3\nimport json, sys\njson.load(sys.stdin)\nprint('{\"findings\":[],\"diagnostics\":[\"ok\"]}')\n",
        )
        .expect("write plugin script");
        let mut perms = std::fs::metadata(&plugin_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&plugin_path, perms).expect("chmod +x");

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[15u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
        std::env::set_var(public_key_env.as_str(), public_key_b64);

        let command_bytes = std::fs::read(&plugin_path).expect("read plugin");
        let signature = signing_key.sign(command_bytes.as_slice());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(&signature_path, signature_b64).expect("write signature");

        policy.plugins.entries.push(patchgate_config::PluginEntry {
            id: "sample".to_string(),
            command: "/usr/bin/env".to_string(),
            args: vec![
                "python3".to_string(),
                plugin_path.to_string_lossy().to_string(),
            ],
            timeout_ms: 3_000,
            fail_mode: "fail_closed".to_string(),
            signature_path: signature_path.to_string_lossy().to_string(),
        });

        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/lib.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 1,
                deleted: 0,
                added_lines: vec!["let w = 1;".to_string()],
                removed_lines: vec![],
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "absolute-interpreter-signature".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };
        let runner = Runner::new(policy);
        let report = runner.evaluate(&ctx, diff, "warn").expect("evaluate");
        assert!(report
            .plugin_invocations
            .iter()
            .any(|i| i.plugin_id == "sample" && i.status == PluginInvocationStatus::Pass));

        std::env::remove_var(public_key_env);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolated_runtime_mounts_include_common_host_paths() {
        let mut command = Command::new("bwrap");
        append_isolated_runtime_mounts(&mut command, true);
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();

        assert!(args.contains(&"--share-net".to_string()));
        if std::path::Path::new("/usr").exists() {
            assert!(args.windows(3).any(|window| {
                window
                    == [
                        "--ro-bind".to_string(),
                        "/usr".to_string(),
                        "/usr".to_string(),
                    ]
            }));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn plugin_signature_verification_rejects_revoked_key() {
        let mut policy = Config::default();
        policy.plugins.signature.required = true;
        let public_key_env = format!(
            "PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_REVOKED_{}",
            std::process::id()
        );
        policy.plugins.signature.public_key_env = public_key_env.clone();

        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-signature-revoked-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.sh");
        let signature_path = temp_root.join("plugin.sig");
        std::fs::write(&plugin_path, "#!/usr/bin/env sh\necho ok\n").expect("write plugin");

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let public_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
        policy
            .plugins
            .signature
            .revoked_key_sha256
            .push(plugin_public_key_fingerprint(public_key.as_bytes()));
        std::env::set_var(public_key_env.as_str(), public_key_b64);

        let command_bytes = std::fs::read(&plugin_path).expect("read plugin");
        let signature = signing_key.sign(command_bytes.as_slice());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        std::fs::write(&signature_path, signature_b64).expect("write signature");

        let plugin = patchgate_config::PluginEntry {
            id: "sample".to_string(),
            command: plugin_path.to_string_lossy().to_string(),
            args: Vec::new(),
            timeout_ms: 3_000,
            fail_mode: "fail_closed".to_string(),
            signature_path: signature_path.to_string_lossy().to_string(),
        };
        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };

        let err = verify_plugin_signature(&policy, &ctx, &plugin)
            .expect_err("revoked key must not verify");
        assert!(format!("{err:#}").contains("is revoked"));

        std::env::remove_var(public_key_env);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(not(windows))]
    #[test]
    fn plugin_signature_verification_fails_with_tampered_signature() {
        use std::os::unix::fs::PermissionsExt;
        let mut policy = Config::default();
        policy.plugins.enabled = true;
        policy.plugins.signature.required = true;
        let public_key_env = format!(
            "PATCHGATE_PLUGIN_PUBLIC_KEY_TEST_BAD_{}",
            std::process::id()
        );
        policy.plugins.signature.public_key_env = public_key_env.clone();

        let temp_root = std::env::temp_dir().join(format!(
            "patchgate-plugin-signature-bad-{}",
            current_unix_nanos()
        ));
        std::fs::create_dir_all(&temp_root).expect("create temp root");
        let plugin_path = temp_root.join("plugin.sh");
        let signature_path = temp_root.join("plugin.sig");
        std::fs::write(
            &plugin_path,
            "#!/usr/bin/env sh\necho '{\"findings\":[],\"diagnostics\":[]}'\n",
        )
        .expect("write plugin script");
        let mut perms = std::fs::metadata(&plugin_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&plugin_path, perms).expect("chmod +x");

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(verifying_key.as_bytes());
        std::env::set_var(public_key_env.as_str(), public_key_b64);
        std::fs::write(&signature_path, "ZmFrZS1zaWduYXR1cmU=").expect("write fake signature");

        policy.plugins.entries.push(patchgate_config::PluginEntry {
            id: "sample".to_string(),
            command: plugin_path.to_string_lossy().to_string(),
            args: Vec::new(),
            timeout_ms: 3_000,
            fail_mode: "fail_closed".to_string(),
            signature_path: signature_path.to_string_lossy().to_string(),
        });

        let ctx = Context {
            repo_root: temp_root.clone(),
            scope: ScopeMode::Worktree,
        };
        let diff = DiffData {
            files: vec![ChangedFile {
                path: "src/lib.rs".to_string(),
                status: ChangeStatus::Modified,
                old_path: None,
                added: 1,
                deleted: 0,
                added_lines: vec!["let y = 1;".to_string()],
                removed_lines: vec![],
                metadata: DiffFileMetadata::default(),
            }],
            fingerprint: "bad-signature".to_string(),
            base_ref: None,
            head_ref: None,
            merge_base: None,
        };
        let runner = Runner::new(policy);
        let err = runner
            .evaluate(&ctx, diff, "warn")
            .expect_err("must fail when tampered");
        assert!(format!("{err:#}").contains("fail_closed policy"));
        std::env::remove_var(public_key_env);
        let _ = std::fs::remove_dir_all(temp_root);
    }

    #[cfg(not(windows))]
    fn current_unix_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    }
}
