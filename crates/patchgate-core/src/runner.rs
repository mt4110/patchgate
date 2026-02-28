use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use anyhow::{Context as _, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use patchgate_config::Config;
use sha2::{Digest, Sha256};

use crate::model::{CheckId, CheckScore, Finding, Location, Report, ReportMeta, Severity};

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

        let mut findings = Vec::new();
        let mut checks = Vec::new();

        let test_gap = evaluate_test_gap(&self.policy, &diff, &exclude_set)?;
        findings.extend(test_gap.findings);
        checks.push(test_gap.score);

        let dangerous_change = evaluate_dangerous_change(&self.policy, &diff, &exclude_set)?;
        findings.extend(dangerous_change.findings);
        checks.push(dangerous_change.score);

        let dependency_update = evaluate_dependency_update(&self.policy, &diff, &exclude_set)?;
        findings.extend(dependency_update.findings);
        checks.push(dependency_update.score);

        Ok(Report::new(
            findings,
            checks,
            ReportMeta {
                threshold: self.policy.output.fail_threshold,
                mode: mode.to_string(),
                scope: ctx.scope.as_str().to_string(),
                fingerprint: diff.fingerprint,
                duration_ms: start.elapsed().as_millis(),
                skipped_by_cache: false,
            },
        ))
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

fn evaluate_test_gap(
    policy: &Config,
    diff: &DiffData,
    exclude_set: &GlobSet,
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

    let mut test_files = Vec::new();
    let mut production_files = Vec::new();
    let mut production_churn = 0u32;

    for file in &diff.files {
        if exclude_set.is_match(&file.path) {
            continue;
        }
        if file.status == ChangeStatus::Deleted {
            continue;
        }
        // Skip metadata-only changes (e.g. pure rename/mode change) to reduce false positives.
        if file.added == 0 && file.deleted == 0 {
            continue;
        }
        if test_set.is_match(&file.path) {
            test_files.push(file.path.clone());
            continue;
        }
        if ignore_set.is_match(&file.path)
            || manifest_set.is_match(&file.path)
            || lock_set.is_match(&file.path)
        {
            continue;
        }
        production_churn = production_churn.saturating_add(file.added + file.deleted);
        production_files.push(file.path.clone());
    }

    let mut findings = Vec::new();
    let mut penalty = 0u8;

    if !production_files.is_empty() && test_files.is_empty() {
        penalty = penalty.saturating_add(policy.test_gap.missing_tests_penalty);
        findings.push(Finding {
            id: "TG-001".to_string(),
            check: CheckId::TestGap,
            title: "No test changes detected".to_string(),
            message: format!(
                "{} production file(s) changed but no test file changed. Example: {}",
                production_files.len(),
                production_files
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::High,
            penalty: policy.test_gap.missing_tests_penalty,
            location: Some(Location {
                file: production_files[0].clone(),
                line: None,
            }),
            tags: vec!["test-gap".to_string()],
        });
    }

    if !production_files.is_empty()
        && production_churn >= policy.test_gap.large_change_lines
        && test_files.len() <= 1
    {
        penalty = penalty.saturating_add(policy.test_gap.large_change_penalty);
        findings.push(Finding {
            id: "TG-002".to_string(),
            check: CheckId::TestGap,
            title: "Large code change with limited test updates".to_string(),
            message: format!(
                "Changed {} lines across production files with only {} test file(s) updated.",
                production_churn,
                test_files.len()
            ),
            severity: Severity::Medium,
            penalty: policy.test_gap.large_change_penalty,
            location: Some(Location {
                file: production_files[0].clone(),
                line: None,
            }),
            tags: vec!["test-gap".to_string(), "large-change".to_string()],
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

        penalty = penalty.saturating_add(file_penalty);
        findings.push(Finding {
            id: if is_critical {
                "DC-002".to_string()
            } else {
                "DC-001".to_string()
            },
            check: CheckId::DangerousChange,
            title: if is_critical {
                "Critical infrastructure path changed".to_string()
            } else {
                "High-risk path changed".to_string()
            },
            message: format!(
                "{} was changed (status: {:?}, classification: {}).",
                file.path,
                file.status,
                if is_critical {
                    "critical (matched dangerous_change.critical_patterns)"
                } else {
                    "non-critical (matched dangerous_change.patterns only)"
                }
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
            tags: vec![
                "dangerous-change".to_string(),
                if is_critical {
                    "critical".to_string()
                } else {
                    "non-critical".to_string()
                },
            ],
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

    let mut manifests = Vec::new();
    let mut lockfiles = Vec::new();
    let mut total_lockfile_churn = 0u32;

    for file in &diff.files {
        if exclude_set.is_match(&file.path) {
            continue;
        }
        // Ignore metadata-only diffs to avoid manifest/lock false positives.
        if file.added == 0 && file.deleted == 0 {
            continue;
        }
        if manifest_set.is_match(&file.path) {
            manifests.push(file.path.clone());
        }
        if lock_set.is_match(&file.path) {
            total_lockfile_churn = total_lockfile_churn.saturating_add(file.added + file.deleted);
            lockfiles.push(file.path.clone());
        }
    }

    let mut findings = Vec::new();
    let mut penalty = 0u8;

    if !manifests.is_empty() {
        penalty = penalty.saturating_add(policy.dependency_update.manifest_penalty);
        findings.push(Finding {
            id: "DU-001".to_string(),
            check: CheckId::DependencyUpdate,
            title: "Dependency manifest updated".to_string(),
            message: format!(
                "Dependency manifest changed: {}",
                manifests
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::Medium,
            penalty: policy.dependency_update.manifest_penalty,
            location: Some(Location {
                file: manifests[0].clone(),
                line: None,
            }),
            tags: vec!["dependencies".to_string(), "manifest".to_string()],
        });
    }

    if !lockfiles.is_empty() {
        penalty = penalty.saturating_add(policy.dependency_update.lockfile_penalty);
        findings.push(Finding {
            id: "DU-002".to_string(),
            check: CheckId::DependencyUpdate,
            title: "Dependency lockfile updated".to_string(),
            message: format!(
                "Dependency lockfile changed: {}",
                lockfiles
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            severity: Severity::Low,
            penalty: policy.dependency_update.lockfile_penalty,
            location: Some(Location {
                file: lockfiles[0].clone(),
                line: None,
            }),
            tags: vec!["dependencies".to_string(), "lockfile".to_string()],
        });
    }

    if total_lockfile_churn >= policy.dependency_update.large_lockfile_churn
        && !lockfiles.is_empty()
    {
        penalty = penalty.saturating_add(policy.dependency_update.large_lockfile_penalty);
        findings.push(Finding {
            id: "DU-003".to_string(),
            check: CheckId::DependencyUpdate,
            title: "Large lockfile churn".to_string(),
            message: format!(
                "Lockfile churn is high ({} changed lines). Prioritize review.",
                total_lockfile_churn
            ),
            severity: Severity::High,
            penalty: policy.dependency_update.large_lockfile_penalty,
            location: Some(Location {
                file: lockfiles[0].clone(),
                line: None,
            }),
            tags: vec!["dependencies".to_string(), "large-churn".to_string()],
        });
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

fn collect_diff(ctx: &Context) -> Result<DiffData> {
    let name_status_args = diff_args(ctx.scope, "--name-status");
    let name_status = run_git(&ctx.repo_root, &name_status_args)
        .with_context(|| format!("git {:?} failed", name_status_args))?;

    let patch_args = diff_args(ctx.scope, "--unified=0");
    let patch = run_git(&ctx.repo_root, &patch_args)
        .with_context(|| format!("git {:?} failed", patch_args))?;

    let mut files = parse_name_status(&name_status);
    apply_patch_stats(&mut files, &patch);

    let fingerprint = format!("{:x}", Sha256::digest(patch.as_bytes()));

    Ok(DiffData {
        files: files.into_values().collect(),
        fingerprint,
    })
}

fn diff_args(scope: ScopeMode, terminal_flag: &str) -> Vec<String> {
    match scope {
        ScopeMode::Staged => vec![
            "diff".to_string(),
            "--cached".to_string(),
            "--find-renames".to_string(),
            "--no-color".to_string(),
            terminal_flag.to_string(),
        ],
        ScopeMode::Worktree => vec![
            "diff".to_string(),
            "--find-renames".to_string(),
            "--no-color".to_string(),
            terminal_flag.to_string(),
        ],
        ScopeMode::Repo => vec![
            "diff".to_string(),
            "HEAD".to_string(),
            "--find-renames".to_string(),
            "--no-color".to_string(),
            terminal_flag.to_string(),
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
            if file.added_lines.len() < 200 {
                file.added_lines.push(stripped.to_string());
            }
        } else if let Some(stripped) = line.strip_prefix('-') {
            file.deleted = file.deleted.saturating_add(1);
            if file.removed_lines.len() < 200 {
                file.removed_lines.push(stripped.to_string());
            }
        }
    }
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

        let eval = evaluate_test_gap(&policy, &diff, &exclude_set).expect("evaluate");
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

        let eval = evaluate_test_gap(&policy, &diff, &exclude_set).expect("evaluate");
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

        let eval = evaluate_test_gap(&policy, &diff, &exclude_set).expect("evaluate");
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

        let eval = evaluate_test_gap(&policy, &diff, &exclude_set).expect("evaluate");
        assert!(
            eval.findings.iter().any(|f| f.id == "TG-001"),
            "metadata-only test rename must not suppress missing test finding"
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

        let eval = evaluate_dangerous_change(&policy, &diff, &exclude_set).expect("evaluate");
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

        let eval = evaluate_dangerous_change(&policy, &diff, &exclude_set).expect("evaluate");
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

        let eval = evaluate_dependency_update(&policy, &diff, &exclude_set).expect("evaluate");
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

        let eval = evaluate_dependency_update(&policy, &diff, &exclude_set).expect("evaluate");
        assert_eq!(eval.score.penalty, 0);
        assert!(eval.findings.is_empty());
    }
}
