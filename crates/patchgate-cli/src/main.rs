use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context as _, Result};
use clap::{Args, Parser, Subcommand};
use patchgate_github::{publish_report, PublishRequest};
use rusqlite::{params, Connection, OpenFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};

use patchgate_config::{
    Config, ConfigError, LoadedConfig, PolicyMigrationError, PolicyPreset, ValidationCategory,
    POLICY_VERSION_CURRENT,
};
use patchgate_core::{Context, Finding, Report, Runner, ScopeMode, Severity};

#[derive(Parser, Debug)]
#[command(
    name = "patchgate",
    version,
    about = "Diff-aware quality gate for pull requests."
)]
struct Cli {
    /// Repo root (default: current dir)
    #[arg(long)]
    repo: Option<PathBuf>,

    /// Policy file path (default: policy.toml if present)
    #[arg(long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run diff-based quality checks
    Scan(Box<ScanArgs>),

    /// Print environment and config diagnostics
    Doctor,

    /// Validate and migrate policy files
    Policy(PolicyArgs),
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Apply policy preset before loading policy file: strict|balanced|relaxed
    #[arg(long)]
    policy_preset: Option<String>,

    /// Output format: text|json
    #[arg(long)]
    format: Option<String>,

    /// Scope: staged|worktree|repo
    #[arg(long)]
    scope: Option<String>,

    /// Gate mode: warn|enforce
    #[arg(long)]
    mode: Option<String>,

    /// Fail threshold (0..=100), lower score fails in enforce mode
    #[arg(long)]
    threshold: Option<u8>,

    /// Disable SQLite cache
    #[arg(long)]
    no_cache: bool,

    /// Write PR comment markdown to a file
    #[arg(long)]
    github_comment: Option<PathBuf>,

    /// Publish PR comment + check-run to GitHub
    #[arg(long)]
    github_publish: bool,

    /// Override target repository (owner/repo)
    #[arg(long)]
    github_repo: Option<String>,

    /// Override pull request number
    #[arg(long)]
    github_pr: Option<u64>,

    /// Override commit SHA for check-run
    #[arg(long)]
    github_sha: Option<String>,

    /// Environment variable name for GitHub token (default: GITHUB_TOKEN)
    #[arg(long)]
    github_token_env: Option<String>,

    /// Check-run name (default: patchgate)
    #[arg(long)]
    github_check_name: Option<String>,
}

#[derive(Args, Debug)]
struct PolicyArgs {
    #[command(subcommand)]
    cmd: PolicyCommand,
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Lint policy config and report compatibility status
    Lint(PolicyLintArgs),

    /// Migrate policy config across policy versions
    Migrate(PolicyMigrateArgs),
}

#[derive(Args, Debug)]
struct PolicyLintArgs {
    /// Policy file path (default: auto-discover policy.toml)
    #[arg(long)]
    path: Option<PathBuf>,

    /// Apply policy preset before loading policy file: strict|balanced|relaxed
    #[arg(long)]
    policy_preset: Option<String>,

    /// Fail if policy_version is not the current version
    #[arg(long)]
    require_current_version: bool,
}

#[derive(Args, Debug)]
struct PolicyMigrateArgs {
    /// Source policy version
    #[arg(long)]
    from: u32,

    /// Target policy version
    #[arg(long)]
    to: u32,

    /// Policy file path (default: auto-discover policy.toml)
    #[arg(long)]
    path: Option<PathBuf>,

    /// Overwrite input file. Without this flag, output is dry-run to stdout.
    #[arg(long)]
    write: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanErrorKind {
    Input,
    Config,
    Runtime,
    Output,
    Publish,
}

impl ScanErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ScanErrorKind::Input => "input",
            ScanErrorKind::Config => "config",
            ScanErrorKind::Runtime => "runtime",
            ScanErrorKind::Output => "output",
            ScanErrorKind::Publish => "publish",
        }
    }

    fn exit_code(self) -> i32 {
        match self {
            ScanErrorKind::Input => 2,
            ScanErrorKind::Config => 3,
            ScanErrorKind::Runtime => 4,
            ScanErrorKind::Output => 5,
            ScanErrorKind::Publish => 6,
        }
    }
}

#[derive(Debug)]
struct ScanError {
    kind: ScanErrorKind,
    source: anyhow::Error,
}

impl ScanError {
    fn new(kind: ScanErrorKind, source: anyhow::Error) -> Self {
        Self { kind, source }
    }

    fn render(&self) -> String {
        format!(
            "patchgate scan error [{}]: {:#}",
            self.kind.as_str(),
            self.source
        )
    }

    fn print(&self) {
        eprintln!("{}", self.render());
    }

    fn exit_code(&self) -> i32 {
        self.kind.exit_code()
    }

    #[cfg(test)]
    fn kind(&self) -> ScanErrorKind {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyExitCode {
    Ok,
    ReadOrParse,
    ValidationType,
    ValidationRange,
    ValidationDependency,
    MigrationRequired,
    MigrationFailed,
    IoFailed,
}

impl PolicyExitCode {
    fn as_i32(self) -> i32 {
        match self {
            PolicyExitCode::Ok => 0,
            PolicyExitCode::ReadOrParse => 10,
            PolicyExitCode::ValidationType => 11,
            PolicyExitCode::ValidationRange => 12,
            PolicyExitCode::ValidationDependency => 13,
            PolicyExitCode::MigrationRequired => 14,
            PolicyExitCode::MigrationFailed => 15,
            PolicyExitCode::IoFailed => 16,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OptionSource {
    Cli,
    Config,
}

struct ResolvedScanOptions {
    format: String,
    mode: String,
    scope: ScopeMode,
}

type ScanResult<T> = std::result::Result<T, ScanError>;
const CACHE_KEY_SCHEMA_VERSION: &str = "v1";

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = cli.repo.unwrap_or(std::env::current_dir()?);

    match cli.cmd {
        Command::Doctor => run_doctor(&repo_root, cli.config.as_deref()),
        Command::Scan(scan) => {
            let code = match execute_scan(&repo_root, cli.config.as_deref(), *scan) {
                Ok(code) => code,
                Err(err) => {
                    err.print();
                    err.exit_code()
                }
            };
            std::process::exit(code);
        }
        Command::Policy(policy) => {
            let code = execute_policy(&repo_root, cli.config.as_deref(), policy);
            std::process::exit(code);
        }
    }
}

fn run_doctor(repo_root: &Path, config_override: Option<&Path>) -> Result<()> {
    let config_path = resolve_config_path(repo_root, config_override);
    println!("patchgate doctor");
    println!("- repo_root: {}", repo_root.display());
    println!(
        "- config_path: {}",
        config_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<default only>".to_string())
    );
    println!("- rust: {}", env!("CARGO_PKG_RUST_VERSION"));

    match diagnose_git(repo_root) {
        Ok((head, dirty)) => {
            println!("- git: ok (head: {}, dirty_files: {})", head, dirty);
        }
        Err(err) => {
            println!("- git: error ({err})");
        }
    }

    let loaded_cfg = match load_policy_config(config_path.as_deref(), None) {
        Ok(cfg) => {
            println!("- config: ok");
            cfg
        }
        Err(err) => {
            println!("- config: error ({err:#})");
            println!("- cache: unknown (skipping cache diagnostics because config failed to load)");
            return Ok(());
        }
    };
    println!("- policy_version: {}", loaded_cfg.config.policy_version);
    for warning in &loaded_cfg.compatibility_warnings {
        println!("- compatibility: warning ({warning})");
    }

    let effective_cfg = loaded_cfg.config;

    if !effective_cfg.cache.enabled {
        println!("- cache: disabled (cache.enabled=false)");
        return Ok(());
    }

    let db_full_path = repo_root.join(&effective_cfg.cache.db_path);
    match diagnose_cache(repo_root, &effective_cfg.cache.db_path) {
        Ok(CacheDoctorStatus::Ok) => println!("- cache: ok ({})", db_full_path.display()),
        Ok(CacheDoctorStatus::Missing) => {
            println!("- cache: missing ({})", db_full_path.display())
        }
        Err(err) => println!("- cache: error ({:#})", err),
    }

    Ok(())
}

fn execute_policy(repo_root: &Path, config_override: Option<&Path>, policy: PolicyArgs) -> i32 {
    match policy.cmd {
        PolicyCommand::Lint(args) => run_policy_lint(repo_root, config_override, args).as_i32(),
        PolicyCommand::Migrate(args) => {
            run_policy_migrate(repo_root, config_override, args).as_i32()
        }
    }
}

fn run_policy_lint(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyLintArgs,
) -> PolicyExitCode {
    let policy_path = resolve_policy_path(repo_root, config_override, args.path.as_deref());
    let preset = match parse_policy_preset(args.policy_preset.as_deref()) {
        Ok(preset) => preset,
        Err(err) => {
            eprintln!("patchgate policy lint error: {err}");
            return PolicyExitCode::ReadOrParse;
        }
    };

    let loaded = match load_policy_config(policy_path.as_deref(), preset) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("patchgate policy lint error: {err:#}");
            return map_config_error_to_policy_exit(&err);
        }
    };

    println!("patchgate policy lint");
    println!(
        "- config_path: {}",
        policy_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "<default only>".to_string())
    );
    println!(
        "- preset: {}",
        preset
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "<none>".to_string())
    );
    println!("- policy_version: {}", loaded.config.policy_version);
    for warning in &loaded.compatibility_warnings {
        println!("- warning: {warning}");
    }

    if args.require_current_version && loaded.config.policy_version < POLICY_VERSION_CURRENT {
        eprintln!(
            "patchgate policy lint error: policy_version {} is legacy (current: {})",
            loaded.config.policy_version, POLICY_VERSION_CURRENT
        );
        return PolicyExitCode::MigrationRequired;
    }

    PolicyExitCode::Ok
}

fn run_policy_migrate(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyMigrateArgs,
) -> PolicyExitCode {
    let Some(policy_path) = resolve_policy_path(repo_root, config_override, args.path.as_deref())
    else {
        eprintln!(
            "patchgate policy migrate error: policy file was not found (pass --path or --config)"
        );
        return PolicyExitCode::ReadOrParse;
    };

    let input = match fs::read_to_string(&policy_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!(
                "patchgate policy migrate error: failed to read {}: {err}",
                policy_path.display()
            );
            return PolicyExitCode::IoFailed;
        }
    };

    let migrated = match patchgate_config::migrate_policy_text(&input, args.from, args.to) {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("patchgate policy migrate error: {err}");
            return map_migration_error_to_policy_exit(&err);
        }
    };

    if args.write {
        if let Err(err) = fs::write(&policy_path, &migrated.migrated_toml) {
            eprintln!(
                "patchgate policy migrate error: failed to write {}: {err}",
                policy_path.display()
            );
            return PolicyExitCode::IoFailed;
        }
        println!(
            "policy migration applied: {} -> {} ({})",
            migrated.from,
            migrated.to,
            policy_path.display()
        );
    } else {
        println!("{}", migrated.migrated_toml);
    }

    PolicyExitCode::Ok
}

fn map_config_error_to_policy_exit(err: &ConfigError) -> PolicyExitCode {
    match err {
        ConfigError::Read { .. } | ConfigError::Parse { .. } => PolicyExitCode::ReadOrParse,
        ConfigError::Validation { category, .. } => match category {
            ValidationCategory::Type => PolicyExitCode::ValidationType,
            ValidationCategory::Range => PolicyExitCode::ValidationRange,
            ValidationCategory::Dependency => PolicyExitCode::ValidationDependency,
        },
    }
}

fn map_migration_error_to_policy_exit(err: &PolicyMigrationError) -> PolicyExitCode {
    match err {
        PolicyMigrationError::Parse { .. } | PolicyMigrationError::InvalidVersionField => {
            PolicyExitCode::ReadOrParse
        }
        PolicyMigrationError::UnsupportedPath { .. }
        | PolicyMigrationError::VersionMismatch { .. }
        | PolicyMigrationError::Validation { .. } => PolicyExitCode::MigrationFailed,
        PolicyMigrationError::Render { .. } => PolicyExitCode::IoFailed,
    }
}

fn diagnose_git(repo_root: &Path) -> Result<(String, usize)> {
    let rev_parse = ProcessCommand::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(repo_root)
        .output()
        .context("failed to invoke git rev-parse")?;
    if !rev_parse.status.success() {
        return Err(anyhow!(
            "not a git repository: {}",
            String::from_utf8_lossy(&rev_parse.stderr).trim()
        ));
    }

    let head = ProcessCommand::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo_root)
        .output()
        .context("failed to resolve git HEAD")?;
    let head_str = if head.status.success() {
        String::from_utf8_lossy(&head.stdout).trim().to_string()
    } else {
        "unborn".to_string()
    };

    let status = ProcessCommand::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo_root)
        .output()
        .context("failed to read git status")?;
    if !status.status.success() {
        return Err(anyhow!(
            "git status failed: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }
    let dirty = String::from_utf8_lossy(&status.stdout).lines().count();
    Ok((head_str, dirty))
}

enum CacheDoctorStatus {
    Ok,
    Missing,
}

fn diagnose_cache(repo_root: &Path, db_path: &str) -> Result<CacheDoctorStatus> {
    let db_full_path = repo_root.join(db_path);
    if !db_full_path.exists() {
        return Ok(CacheDoctorStatus::Missing);
    }
    let conn = Connection::open_with_flags(&db_full_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {}", db_full_path.display()))?;
    conn.query_row("SELECT 1", [], |_row| Ok(()))
        .context("cache db probe query failed")?;
    Ok(CacheDoctorStatus::Ok)
}

fn execute_scan(
    repo_root: &Path,
    config_override: Option<&Path>,
    scan: ScanArgs,
) -> ScanResult<i32> {
    let run_start = Instant::now();
    let ScanArgs {
        policy_preset,
        format,
        scope,
        mode,
        threshold,
        no_cache,
        github_comment,
        github_publish,
        github_repo,
        github_pr,
        github_sha,
        github_token_env,
        github_check_name,
    } = scan;
    let preset = parse_policy_preset(policy_preset.as_deref()).map_err(|err| {
        ScanError::new(
            ScanErrorKind::Input,
            anyhow!("invalid value for scan.policy_preset from cli: {err}"),
        )
    })?;

    let config_path = resolve_config_path(repo_root, config_override);
    let loaded_cfg = load_policy_config(config_path.as_deref(), preset).map_err(|err| {
        ScanError::new(
            ScanErrorKind::Config,
            anyhow::Error::new(err).context("failed to load policy config"),
        )
    })?;
    for warning in &loaded_cfg.compatibility_warnings {
        eprintln!("warning: {warning}");
    }
    let mut cfg = loaded_cfg.config;

    apply_threshold_override(&mut cfg, threshold)?;

    let opts = resolve_scan_options(&cfg, format.as_deref(), scope.as_deref(), mode.as_deref())?;

    let ctx = Context {
        repo_root: repo_root.to_path_buf(),
        scope: opts.scope,
    };

    let runner = Runner::new(cfg.clone());
    let diff = runner.collect_diff(&ctx).map_err(|err| {
        ScanError::new(
            ScanErrorKind::Runtime,
            err.context("failed to collect git diff"),
        )
    })?;
    let diff_fingerprint = diff.fingerprint.clone();
    let mut diff_for_eval = Some(diff);

    let cache_enabled = cfg.cache.enabled && !no_cache;
    let mut evaluate_report = || -> ScanResult<Report> {
        let eval_diff = diff_for_eval.take().ok_or_else(|| {
            ScanError::new(
                ScanErrorKind::Runtime,
                anyhow!("internal error: diff already consumed before evaluation"),
            )
        })?;
        runner.evaluate(&ctx, eval_diff, &opts.mode).map_err(|err| {
            ScanError::new(
                ScanErrorKind::Runtime,
                err.context("failed to evaluate scan checks"),
            )
        })
    };

    let report = if cache_enabled {
        let policy_hash = config_hash(&cfg).map_err(|err| {
            ScanError::new(
                ScanErrorKind::Runtime,
                err.context("failed to hash effective config"),
            )
        })?;

        match load_cache(
            repo_root,
            &cfg.cache.db_path,
            &diff_fingerprint,
            &policy_hash,
            &opts.mode,
            opts.scope.as_str(),
        ) {
            Ok(Some(mut cached)) => {
                cached.skipped_by_cache = true;
                cached.duration_ms = run_start.elapsed().as_millis();
                cached
            }
            Ok(None) => {
                let evaluated = evaluate_report()?;
                if let Err(err) =
                    store_cache(repo_root, &cfg.cache.db_path, &evaluated, &policy_hash)
                {
                    handle_cache_fault(repo_root, &cfg.cache.db_path, "write", &err);
                }
                evaluated
            }
            Err(err) => {
                handle_cache_fault(repo_root, &cfg.cache.db_path, "read", &err);
                let evaluated = evaluate_report()?;
                if let Err(err) =
                    store_cache(repo_root, &cfg.cache.db_path, &evaluated, &policy_hash)
                {
                    handle_cache_fault(repo_root, &cfg.cache.db_path, "write", &err);
                }
                evaluated
            }
        }
    } else {
        evaluate_report()?
    };

    let markdown = render_github_comment(&report);

    if let Some(path) = github_comment {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                ScanError::new(
                    ScanErrorKind::Output,
                    anyhow!("failed to create report directory: {parent:?}: {err}"),
                )
            })?;
        }
        fs::write(&path, &markdown).map_err(|err| {
            ScanError::new(
                ScanErrorKind::Output,
                anyhow!("failed to write github comment markdown: {path:?}: {err}"),
            )
        })?;
    }

    if let Ok(step_summary) = std::env::var("GITHUB_STEP_SUMMARY") {
        fs::write(&step_summary, &markdown).map_err(|err| {
            ScanError::new(
                ScanErrorKind::Output,
                anyhow!("failed to write GITHUB_STEP_SUMMARY: {step_summary}: {err}"),
            )
        })?;
    }

    if github_publish {
        let req = resolve_publish_request(
            github_repo,
            github_pr,
            github_sha,
            github_token_env,
            github_check_name,
        )
        .map_err(|err| {
            ScanError::new(
                ScanErrorKind::Publish,
                err.context("failed to resolve GitHub publish inputs"),
            )
        })?;
        let published = publish_report(&report, &markdown, &req).map_err(|err| {
            ScanError::new(
                ScanErrorKind::Publish,
                err.context("failed to publish report to GitHub"),
            )
        })?;
        if let Some(err) = published.comment_error.as_ref() {
            eprintln!("warning: failed to publish PR comment: {err}");
        }
        if let Some(err) = published.check_run_error.as_ref() {
            eprintln!("warning: failed to publish check run: {err}");
        }
        if let Some(url) = published.comment_url {
            eprintln!("published PR comment: {url}");
        }
        if let Some(url) = published.check_run_url {
            eprintln!("published check run: {url}");
        }
    }

    match opts.format.as_str() {
        "json" => {
            let pretty = serde_json::to_string_pretty(&report).map_err(|err| {
                ScanError::new(
                    ScanErrorKind::Output,
                    anyhow!("failed to encode json report: {err}"),
                )
            })?;
            println!("{pretty}");
        }
        _ => print_text(&report),
    }

    Ok(gate_exit_code(&opts.mode, report.should_fail))
}

fn resolve_publish_request(
    github_repo: Option<String>,
    github_pr: Option<u64>,
    github_sha: Option<String>,
    github_token_env: Option<String>,
    github_check_name: Option<String>,
) -> Result<PublishRequest> {
    let repo = github_repo
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .context("github repository was not provided (use --github-repo or GITHUB_REPOSITORY)")?;

    let pr_number = match github_pr {
        Some(n) => n,
        None => detect_pr_number_from_env()?.context(
            "pull request number was not provided (use --github-pr or pull_request event)",
        )?,
    };

    let head_sha = match github_sha {
        Some(sha) => sha,
        None => detect_head_sha_from_env()?
            .or_else(|| std::env::var("GITHUB_SHA").ok())
            .context(
                "head SHA was not provided (use --github-sha, pull_request.head.sha, or GITHUB_SHA)",
            )?,
    };

    let token_env = github_token_env.unwrap_or_else(|| "GITHUB_TOKEN".to_string());
    let token = std::env::var(&token_env)
        .with_context(|| format!("missing GitHub token env var: {token_env}"))?;

    let check_name = github_check_name.unwrap_or_else(|| "patchgate".to_string());

    Ok(PublishRequest {
        repo,
        pr_number,
        head_sha,
        token,
        check_name,
    })
}

fn detect_pr_number_from_env() -> Result<Option<u64>> {
    if let Some(json) = load_github_event_payload() {
        if let Some(number) = pr_number_from_event_payload(&json) {
            return Ok(Some(number));
        }
    }

    if let Ok(reference) = std::env::var("GITHUB_REF") {
        if let Some(number) = pr_number_from_ref(&reference) {
            return Ok(Some(number));
        }
    }

    Ok(None)
}

fn detect_head_sha_from_env() -> Result<Option<String>> {
    if let Some(json) = load_github_event_payload() {
        if let Some(head_sha) = pr_head_sha_from_event_payload(&json) {
            return Ok(Some(head_sha));
        }
    }
    Ok(None)
}

fn load_github_event_payload() -> Option<Value> {
    let event_path = std::env::var("GITHUB_EVENT_PATH").ok()?;
    let payload = match fs::read_to_string(&event_path) {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("warning: failed to read GITHUB_EVENT_PATH ({event_path}): {err}");
            return None;
        }
    };
    match serde_json::from_str::<Value>(&payload) {
        Ok(json) => Some(json),
        Err(err) => {
            eprintln!("warning: failed to parse github event json ({event_path}): {err}");
            None
        }
    }
}

fn pr_number_from_event_payload(payload: &Value) -> Option<u64> {
    payload.get("number").and_then(Value::as_u64).or_else(|| {
        payload
            .get("pull_request")
            .and_then(|pr| pr.get("number"))
            .and_then(Value::as_u64)
    })
}

fn pr_head_sha_from_event_payload(payload: &Value) -> Option<String> {
    payload
        .get("pull_request")
        .and_then(|pr| pr.get("head"))
        .and_then(|head| head.get("sha"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn pr_number_from_ref(reference: &str) -> Option<u64> {
    let parts: Vec<&str> = reference.split('/').collect();
    if parts.len() >= 4 && parts[0] == "refs" && parts[1] == "pull" {
        return parts[2].parse::<u64>().ok();
    }
    None
}

fn resolve_config_path(repo_root: &Path, override_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = override_path {
        if path.is_absolute() {
            return Some(path.to_path_buf());
        }
        return Some(repo_root.join(path));
    }

    for candidate in ["policy.toml", "patchgate.toml", "veto.toml", "veri.toml"] {
        let path = repo_root.join(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

fn resolve_policy_path(
    repo_root: &Path,
    config_override: Option<&Path>,
    policy_path_arg: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = policy_path_arg {
        return resolve_config_path(repo_root, Some(path));
    }
    resolve_config_path(repo_root, config_override)
}

fn apply_threshold_override(cfg: &mut Config, threshold: Option<u8>) -> ScanResult<()> {
    if let Some(t) = threshold {
        if t > 100 {
            return Err(ScanError::new(
                ScanErrorKind::Input,
                anyhow!("invalid value for scan.threshold from cli: `{t}` (expected: 0..=100)"),
            ));
        }
        cfg.output.fail_threshold = t;
    }
    Ok(())
}

fn parse_policy_preset(raw: Option<&str>) -> std::result::Result<Option<PolicyPreset>, String> {
    let Some(value) = raw else {
        return Ok(None);
    };
    match PolicyPreset::parse(value) {
        Some(preset) => Ok(Some(preset)),
        None => Err(format!(
            "`{value}` (expected: {})",
            PolicyPreset::allowed_values()
        )),
    }
}

fn load_policy_config(
    path: Option<&Path>,
    preset: Option<PolicyPreset>,
) -> std::result::Result<LoadedConfig, ConfigError> {
    patchgate_config::load_effective_from_typed(path, preset)
}

fn resolve_scan_options(
    cfg: &Config,
    format: Option<&str>,
    scope: Option<&str>,
    mode: Option<&str>,
) -> ScanResult<ResolvedScanOptions> {
    let (format_raw, format_source) = if let Some(value) = format {
        (value, OptionSource::Cli)
    } else {
        (cfg.output.format.as_str(), OptionSource::Config)
    };
    let (scope_raw, scope_source) = if let Some(value) = scope {
        (value, OptionSource::Cli)
    } else {
        (cfg.scope.mode.as_str(), OptionSource::Config)
    };
    let (mode_raw, mode_source) = if let Some(value) = mode {
        (value, OptionSource::Cli)
    } else {
        (cfg.output.mode.as_str(), OptionSource::Config)
    };

    Ok(ResolvedScanOptions {
        format: parse_format(format_raw, format_source)?,
        mode: parse_mode(mode_raw, mode_source)?,
        scope: parse_scope(scope_raw, scope_source)?,
    })
}

fn parse_scope(raw: &str, source: OptionSource) -> ScanResult<ScopeMode> {
    match raw {
        "staged" => Ok(ScopeMode::Staged),
        "worktree" => Ok(ScopeMode::Worktree),
        "repo" => Ok(ScopeMode::Repo),
        _ => Err(invalid_scan_option(
            "scope",
            raw,
            "staged|worktree|repo",
            source,
        )),
    }
}

fn parse_format(raw: &str, source: OptionSource) -> ScanResult<String> {
    match raw {
        "text" | "json" => Ok(raw.to_string()),
        _ => Err(invalid_scan_option("format", raw, "text|json", source)),
    }
}

fn parse_mode(raw: &str, source: OptionSource) -> ScanResult<String> {
    match raw {
        "warn" | "enforce" => Ok(raw.to_string()),
        _ => Err(invalid_scan_option("mode", raw, "warn|enforce", source)),
    }
}

fn invalid_scan_option(field: &str, raw: &str, expected: &str, source: OptionSource) -> ScanError {
    let (kind, from) = match source {
        OptionSource::Cli => (ScanErrorKind::Input, "cli"),
        OptionSource::Config => (ScanErrorKind::Config, "config"),
    };
    ScanError::new(
        kind,
        anyhow!("invalid value for scan.{field} from {from}: `{raw}` (expected: {expected})"),
    )
}

fn gate_exit_code(mode: &str, should_fail: bool) -> i32 {
    if mode == "enforce" && should_fail {
        1
    } else {
        0
    }
}

fn config_hash(cfg: &Config) -> Result<String> {
    let serialized = serde_json::to_vec(cfg)?;
    Ok(format!("{:x}", Sha256::digest(serialized)))
}

fn build_cache_key(diff_fingerprint: &str, policy_hash: &str, mode: &str, scope: &str) -> String {
    let material = format!(
        "schema={}|cli={}|diff={}|policy={}|mode={}|scope={}",
        CACHE_KEY_SCHEMA_VERSION,
        env!("CARGO_PKG_VERSION"),
        diff_fingerprint,
        policy_hash,
        mode,
        scope
    );
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

fn load_cache(
    repo_root: &Path,
    db_path: &str,
    diff_fingerprint: &str,
    policy_hash: &str,
    mode: &str,
    scope: &str,
) -> Result<Option<Report>> {
    let cache_key = build_cache_key(diff_fingerprint, policy_hash, mode, scope);
    let db_full_path = repo_root.join(db_path);
    if !db_full_path.exists() {
        return Ok(None);
    }

    let conn = Connection::open(db_full_path)?;
    init_cache_table(&conn)?;

    let mut stmt = conn.prepare(
        "SELECT report_json FROM runs
         WHERE fingerprint = ?1
         ORDER BY created_at DESC LIMIT 1",
    )?;

    let mut rows = stmt.query(params![cache_key])?;
    if let Some(row) = rows.next()? {
        let json: String = row.get(0)?;
        let report = serde_json::from_str::<Report>(&json)?;
        Ok(Some(report))
    } else {
        Ok(None)
    }
}

fn store_cache(repo_root: &Path, db_path: &str, report: &Report, policy_hash: &str) -> Result<()> {
    let cache_key = build_cache_key(
        &report.fingerprint,
        policy_hash,
        &report.mode,
        &report.scope,
    );
    let db_full_path = repo_root.join(db_path);
    if let Some(parent) = db_full_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(db_full_path)?;
    init_cache_table(&conn)?;

    let report_json = serde_json::to_string(report)?;
    conn.execute(
        "INSERT INTO runs (fingerprint, policy_hash, mode, scope, report_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))
         ON CONFLICT(fingerprint, policy_hash, mode, scope) DO UPDATE SET
           report_json = excluded.report_json,
           created_at = excluded.created_at",
        params![
            cache_key,
            policy_hash,
            report.mode,
            report.scope,
            report_json
        ],
    )?;

    Ok(())
}

fn init_cache_table(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            policy_hash TEXT NOT NULL,
            mode TEXT NOT NULL,
            scope TEXT NOT NULL,
            report_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(fingerprint, policy_hash, mode, scope)
        );",
    )?;
    Ok(())
}

fn handle_cache_fault(repo_root: &Path, db_path: &str, stage: &str, err: &anyhow::Error) {
    eprintln!("warning: cache {stage} failed: {err:#}");
    if !is_likely_cache_corruption(err) {
        return;
    }
    match recover_cache_db(repo_root, db_path) {
        Ok(Some(backup)) => {
            eprintln!(
                "warning: cache DB was rotated due to corruption; backup: {}",
                backup.display()
            );
        }
        Ok(None) => {
            eprintln!("warning: cache DB recovery skipped (cache file did not exist)");
        }
        Err(recover_err) => {
            eprintln!("warning: cache DB recovery failed: {recover_err:#}");
        }
    }
}

fn is_likely_cache_corruption(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}").to_lowercase();
    msg.contains("malformed")
        || msg.contains("not a database")
        || msg.contains("database disk image is malformed")
        || msg.contains("file is not a database")
}

fn recover_cache_db(repo_root: &Path, db_path: &str) -> Result<Option<PathBuf>> {
    let db_full_path = repo_root.join(db_path);
    if !db_full_path.exists() {
        return Ok(None);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_millis();
    let file_name = db_full_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("cache.db");
    let backup_path =
        db_full_path.with_file_name(format!("{file_name}.corrupt-{now}-{}", std::process::id()));
    fs::rename(&db_full_path, &backup_path).with_context(|| {
        format!(
            "failed to rotate broken cache db {} -> {}",
            db_full_path.display(),
            backup_path.display()
        )
    })?;

    if let Some(parent) = db_full_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(&db_full_path)
        .with_context(|| format!("failed to recreate cache db: {}", db_full_path.display()))?;
    init_cache_table(&conn)?;
    Ok(Some(backup_path))
}

fn print_text(report: &Report) {
    let cache_note = if report.skipped_by_cache {
        " (cache hit)"
    } else {
        ""
    };
    println!(
        "Score: {}/100 | threshold: {} | priority: {:?}{}",
        report.score, report.threshold, report.review_priority, cache_note
    );
    println!("Mode: {} | Scope: {}", report.mode, report.scope);
    println!("Fingerprint: {}", report.fingerprint);
    println!("Duration: {}ms", report.duration_ms);

    println!("\nCheck penalties:");
    for check in &report.checks {
        println!(
            "- {} ({}) {}/{}",
            check.label,
            if check.triggered { "triggered" } else { "ok" },
            check.penalty,
            check.max_penalty
        );
    }

    if report.findings.is_empty() {
        println!("\nNo findings.");
        return;
    }

    println!("\nFindings ({}):", report.findings.len());
    for finding in &report.findings {
        let loc = finding
            .location
            .as_ref()
            .map(|l| l.file.clone())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "- [{}] {} (+{}) @ {}",
            format!("{:?}", finding.severity).to_uppercase(),
            finding.title,
            finding.penalty,
            loc
        );
        println!("  {}", finding.message);
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 3,
        Severity::High => 2,
        Severity::Medium => 1,
        Severity::Low => 0,
    }
}

fn sorted_findings_for_comment(findings: &[Finding]) -> Vec<&Finding> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| {
        severity_rank(b.severity)
            .cmp(&severity_rank(a.severity))
            .then_with(|| b.penalty.cmp(&a.penalty))
            .then_with(|| a.title.cmp(&b.title))
    });
    sorted
}

fn render_github_comment(report: &Report) -> String {
    let mut lines = Vec::new();
    let sorted_findings = sorted_findings_for_comment(&report.findings);
    let critical_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    lines.push("<!-- patchgate:report -->".to_string());
    lines.push(String::new());
    lines.push("## patchgate report".to_string());
    lines.push(String::new());
    lines.push(format!(
        "- Score: **{}/100** (threshold: **{}**)",
        report.score, report.threshold
    ));
    lines.push(format!(
        "- Review priority: **{:?}**",
        report.review_priority
    ));
    lines.push(format!("- Mode: `{}`", report.mode));
    lines.push(format!("- Scope: `{}`", report.scope));
    lines.push(format!(
        "- Cache: {}",
        if report.skipped_by_cache {
            "hit"
        } else {
            "miss"
        }
    ));
    lines.push(format!(
        "- Findings: {} (critical: {}, high: {}, medium: {}, low: {})",
        report.findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count
    ));
    lines.push(String::new());

    lines.push("### Priority findings".to_string());
    if sorted_findings.is_empty() {
        lines.push("- No findings".to_string());
    } else {
        let mut priority: Vec<&Finding> = sorted_findings
            .iter()
            .copied()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .take(5)
            .collect();
        if priority.is_empty() {
            priority = sorted_findings.iter().copied().take(3).collect();
        }
        for finding in priority {
            let loc = finding
                .location
                .as_ref()
                .map(|l| l.file.clone())
                .unwrap_or_else(|| "-".to_string());
            lines.push(format!(
                "- **{}** [{} +{}] `{}`",
                finding.title,
                format!("{:?}", finding.severity).to_uppercase(),
                finding.penalty,
                loc
            ));
        }
    }

    lines.push(String::new());
    lines.push("### Check penalties".to_string());
    for check in &report.checks {
        lines.push(format!(
            "- `{}`: {}/{} {}",
            check.check.as_str(),
            check.penalty,
            check.max_penalty,
            if check.triggered {
                "(triggered)"
            } else {
                "(ok)"
            }
        ));
    }

    lines.push(String::new());
    lines.push("### All findings".to_string());

    if sorted_findings.is_empty() {
        lines.push("- No findings".to_string());
    } else {
        for finding in sorted_findings {
            let loc = finding
                .location
                .as_ref()
                .map(|l| l.file.clone())
                .unwrap_or_else(|| "-".to_string());
            lines.push(format!(
                "- **{}** [{} +{}] `{}`",
                finding.title,
                format!("{:?}", finding.severity).to_uppercase(),
                finding.penalty,
                loc
            ));
            lines.push(format!("  - {}", finding.message));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use patchgate_config::Config;
    use patchgate_core::{CheckId, CheckScore, Finding, Report, ReportMeta, Severity};

    use super::{
        apply_threshold_override, build_cache_key, detect_head_sha_from_env,
        detect_pr_number_from_env, gate_exit_code, is_likely_cache_corruption, parse_mode,
        parse_policy_preset, parse_scope, pr_head_sha_from_event_payload,
        pr_number_from_event_payload, pr_number_from_ref, recover_cache_db, render_github_comment,
        resolve_config_path, resolve_policy_path, resolve_publish_request, resolve_scan_options,
        sorted_findings_for_comment, OptionSource, PolicyExitCode, ScanErrorKind, ScopeMode,
    };

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    struct EnvSnapshot(Vec<(&'static str, Option<OsString>)>);

    impl EnvSnapshot {
        fn capture(keys: &[&'static str]) -> Self {
            Self(keys.iter().map(|k| (*k, env::var_os(k))).collect())
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                if let Some(v) = value {
                    env::set_var(key, v);
                } else {
                    env::remove_var(key);
                }
            }
        }
    }

    fn write_temp_event(payload: &serde_json::Value) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "patchgate-cli-event-{}-{ts}-{seq}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            serde_json::to_vec(payload).expect("serialize event payload"),
        )
        .expect("write temp event");
        path
    }

    #[test]
    fn pr_number_parsed_from_ref() {
        assert_eq!(pr_number_from_ref("refs/pull/42/merge"), Some(42));
        assert_eq!(pr_number_from_ref("refs/heads/main"), None);
    }

    #[test]
    fn pr_number_parsed_from_event() {
        let payload = serde_json::json!({
            "number": 777,
            "pull_request": {
                "number": 123
            }
        });
        assert_eq!(pr_number_from_event_payload(&payload), Some(777));
    }

    #[test]
    fn pr_head_sha_parsed_from_event() {
        let payload = serde_json::json!({
            "pull_request": {
                "head": {
                    "sha": "abc123"
                }
            }
        });
        assert_eq!(
            pr_head_sha_from_event_payload(&payload).as_deref(),
            Some("abc123")
        );
    }

    #[test]
    fn env_pr_number_prefers_event_payload_over_github_ref() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_EVENT_PATH", "GITHUB_REF"]);
        let event_path = write_temp_event(&serde_json::json!({
            "number": 321,
            "pull_request": { "head": { "sha": "eventsha" } }
        }));
        env::set_var("GITHUB_EVENT_PATH", &event_path);
        env::set_var("GITHUB_REF", "refs/pull/999/merge");

        let pr = detect_pr_number_from_env().expect("detect PR number");
        assert_eq!(pr, Some(321));

        env::remove_var("GITHUB_EVENT_PATH");
        env::remove_var("GITHUB_REF");
        let _ = fs::remove_file(event_path);
    }

    #[test]
    fn env_pr_number_falls_back_to_github_ref() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_EVENT_PATH", "GITHUB_REF"]);
        env::remove_var("GITHUB_EVENT_PATH");
        env::set_var("GITHUB_REF", "refs/pull/456/merge");

        let pr = detect_pr_number_from_env().expect("detect fallback PR number");
        assert_eq!(pr, Some(456));

        env::remove_var("GITHUB_REF");
    }

    #[test]
    fn env_pr_number_falls_back_to_ref_when_event_payload_is_invalid() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_EVENT_PATH", "GITHUB_REF"]);
        let mut bad_event = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        bad_event.push(format!("patchgate-cli-bad-event-{ts}.json"));
        fs::write(&bad_event, "{invalid json").expect("write broken event");
        env::set_var("GITHUB_EVENT_PATH", &bad_event);
        env::set_var("GITHUB_REF", "refs/pull/654/merge");

        let pr = detect_pr_number_from_env().expect("detect PR from ref fallback");
        assert_eq!(pr, Some(654));

        env::remove_var("GITHUB_EVENT_PATH");
        env::remove_var("GITHUB_REF");
        let _ = fs::remove_file(bad_event);
    }

    #[test]
    fn env_head_sha_detected_from_event() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_EVENT_PATH"]);
        let event_path = write_temp_event(&serde_json::json!({
            "number": 5,
            "pull_request": { "head": { "sha": "event-sha-001" } }
        }));
        env::set_var("GITHUB_EVENT_PATH", &event_path);

        let sha = detect_head_sha_from_env().expect("detect SHA from event");
        assert_eq!(sha.as_deref(), Some("event-sha-001"));

        env::remove_var("GITHUB_EVENT_PATH");
        let _ = fs::remove_file(event_path);
    }

    #[test]
    fn env_head_sha_falls_back_when_event_payload_is_invalid() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_EVENT_PATH"]);
        let mut bad_event = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        bad_event.push(format!("patchgate-cli-bad-sha-event-{ts}.json"));
        fs::write(&bad_event, "{invalid json").expect("write broken event");
        env::set_var("GITHUB_EVENT_PATH", &bad_event);

        let sha = detect_head_sha_from_env().expect("detect SHA with invalid event");
        assert!(sha.is_none());

        env::remove_var("GITHUB_EVENT_PATH");
        let _ = fs::remove_file(bad_event);
    }

    #[test]
    fn resolve_publish_request_prefers_cli_over_env() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&[
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_SHA",
            "GITHUB_TOKEN",
        ]);
        env::set_var("GITHUB_REPOSITORY", "env/repo");
        env::set_var("GITHUB_REF", "refs/pull/999/merge");
        env::set_var("GITHUB_SHA", "env-sha");
        env::set_var("GITHUB_TOKEN", "env-token");

        let req = resolve_publish_request(
            Some("cli/repo".to_string()),
            Some(12),
            Some("cli-sha".to_string()),
            None,
            Some("cli-check".to_string()),
        )
        .expect("resolve publish request");

        assert_eq!(req.repo, "cli/repo");
        assert_eq!(req.pr_number, 12);
        assert_eq!(req.head_sha, "cli-sha");
        assert_eq!(req.token, "env-token");
        assert_eq!(req.check_name, "cli-check");

        env::remove_var("GITHUB_REPOSITORY");
        env::remove_var("GITHUB_REF");
        env::remove_var("GITHUB_SHA");
        env::remove_var("GITHUB_TOKEN");
    }

    #[test]
    fn resolve_publish_request_uses_event_then_fallback_sha() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&[
            "GITHUB_EVENT_PATH",
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_SHA",
            "GITHUB_TOKEN",
        ]);
        let event_path = write_temp_event(&serde_json::json!({
            "number": 88,
            "pull_request": { "head": { "sha": "event-sha-88" } }
        }));
        env::set_var("GITHUB_EVENT_PATH", &event_path);
        env::set_var("GITHUB_REPOSITORY", "env/repo");
        env::set_var("GITHUB_REF", "refs/pull/999/merge");
        env::set_var("GITHUB_SHA", "fallback-sha");
        env::set_var("GITHUB_TOKEN", "env-token");

        let req = resolve_publish_request(None, None, None, None, None).expect("resolve from env");
        assert_eq!(req.repo, "env/repo");
        assert_eq!(req.pr_number, 88);
        assert_eq!(req.head_sha, "event-sha-88");
        assert_eq!(req.check_name, "patchgate");

        env::remove_var("GITHUB_EVENT_PATH");
        env::remove_var("GITHUB_REPOSITORY");
        env::remove_var("GITHUB_REF");
        env::remove_var("GITHUB_SHA");
        env::remove_var("GITHUB_TOKEN");
        let _ = fs::remove_file(event_path);
    }

    #[test]
    fn resolve_publish_request_uses_github_sha_when_event_has_no_head_sha() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&[
            "GITHUB_EVENT_PATH",
            "GITHUB_REPOSITORY",
            "GITHUB_SHA",
            "GITHUB_TOKEN",
        ]);
        let event_path = write_temp_event(&serde_json::json!({
            "number": 42,
            "pull_request": { "head": {} }
        }));
        env::set_var("GITHUB_EVENT_PATH", &event_path);
        env::set_var("GITHUB_REPOSITORY", "env/repo");
        env::set_var("GITHUB_SHA", "fallback-sha-42");
        env::set_var("GITHUB_TOKEN", "env-token");

        let req = resolve_publish_request(None, None, None, None, None).expect("resolve from env");
        assert_eq!(req.pr_number, 42);
        assert_eq!(req.head_sha, "fallback-sha-42");

        env::remove_var("GITHUB_EVENT_PATH");
        env::remove_var("GITHUB_REPOSITORY");
        env::remove_var("GITHUB_SHA");
        env::remove_var("GITHUB_TOKEN");
        let _ = fs::remove_file(event_path);
    }

    #[test]
    fn gate_exit_code_matches_mode_and_result() {
        assert_eq!(gate_exit_code("warn", false), 0);
        assert_eq!(gate_exit_code("warn", true), 0);
        assert_eq!(gate_exit_code("enforce", false), 0);
        assert_eq!(gate_exit_code("enforce", true), 1);
    }

    #[test]
    fn invalid_cli_scope_is_input_error() {
        let err = parse_scope("all", OptionSource::Cli).expect_err("scope should be rejected");
        assert_eq!(err.kind(), ScanErrorKind::Input);
        assert_eq!(err.exit_code(), 2);
        assert_eq!(
            err.render(),
            "patchgate scan error [input]: invalid value for scan.scope from cli: `all` (expected: staged|worktree|repo)"
        );
    }

    #[test]
    fn invalid_config_mode_is_config_error() {
        let err = parse_mode("strict", OptionSource::Config).expect_err("mode should be rejected");
        assert_eq!(err.kind(), ScanErrorKind::Config);
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.render(),
            "patchgate scan error [config]: invalid value for scan.mode from config: `strict` (expected: warn|enforce)"
        );
    }

    #[test]
    fn cli_options_override_config_options() {
        let mut cfg = Config::default();
        cfg.output.format = "text".to_string();
        cfg.output.mode = "warn".to_string();
        cfg.scope.mode = "staged".to_string();

        let opts = resolve_scan_options(&cfg, Some("json"), Some("repo"), Some("enforce"))
            .expect("valid cli options should parse");
        assert_eq!(opts.format, "json");
        assert_eq!(opts.mode, "enforce");
        assert_eq!(opts.scope.as_str(), ScopeMode::Repo.as_str());
    }

    fn finding(id: &str, severity: Severity, penalty: u8) -> Finding {
        Finding {
            id: id.to_string(),
            rule_id: id.to_string(),
            category: "test".to_string(),
            docs_url: "https://example.com/docs".to_string(),
            check: CheckId::TestGap,
            title: id.to_string(),
            message: format!("message-{id}"),
            severity,
            penalty,
            location: None,
            tags: vec!["test".to_string()],
        }
    }

    #[test]
    fn sorted_findings_prioritize_severity_then_penalty() {
        let input = vec![
            finding("medium-high-penalty", Severity::Medium, 20),
            finding("critical-low-penalty", Severity::Critical, 5),
            finding("high-high-penalty", Severity::High, 30),
            finding("critical-high-penalty", Severity::Critical, 15),
        ];

        let sorted = sorted_findings_for_comment(&input);
        let ids: Vec<String> = sorted.iter().map(|f| f.id.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "critical-high-penalty".to_string(),
                "critical-low-penalty".to_string(),
                "high-high-penalty".to_string(),
                "medium-high-penalty".to_string()
            ]
        );
    }

    #[test]
    fn github_comment_places_priority_findings_section_first() {
        let report = Report::new(
            vec![
                finding("medium-find", Severity::Medium, 8),
                finding("critical-find", Severity::Critical, 4),
                finding("high-find", Severity::High, 10),
            ],
            vec![CheckScore {
                check: CheckId::TestGap,
                label: "Test coverage gap".to_string(),
                penalty: 12,
                max_penalty: 35,
                triggered: true,
            }],
            ReportMeta {
                threshold: 70,
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );

        let comment = render_github_comment(&report);
        let priority_idx = comment
            .find("### Priority findings")
            .expect("priority section");
        let all_idx = comment.find("### All findings").expect("all section");
        assert!(priority_idx < all_idx);

        let critical_line_idx = comment
            .find("**critical-find** [CRITICAL")
            .expect("critical finding line");
        assert!(critical_line_idx > priority_idx);
        assert!(critical_line_idx < all_idx);
    }

    #[test]
    fn cache_key_is_deterministic_for_same_inputs() {
        let key1 = build_cache_key("diff-a", "policy-a", "warn", "staged");
        let key2 = build_cache_key("diff-a", "policy-a", "warn", "staged");
        assert_eq!(key1, key2);
    }

    #[test]
    fn cache_key_changes_when_any_dimension_changes() {
        let base = build_cache_key("diff-a", "policy-a", "warn", "staged");
        assert_ne!(
            base,
            build_cache_key("diff-b", "policy-a", "warn", "staged")
        );
        assert_ne!(
            base,
            build_cache_key("diff-a", "policy-b", "warn", "staged")
        );
        assert_ne!(
            base,
            build_cache_key("diff-a", "policy-a", "enforce", "staged")
        );
        assert_ne!(base, build_cache_key("diff-a", "policy-a", "warn", "repo"));
    }

    #[test]
    fn cache_corruption_detector_matches_known_messages() {
        let err = anyhow::anyhow!("SQLite error: file is not a database");
        assert!(is_likely_cache_corruption(&err));
        let err = anyhow::anyhow!("permission denied");
        assert!(!is_likely_cache_corruption(&err));
    }

    #[test]
    fn recover_cache_db_rotates_broken_file_and_reinitializes() {
        let mut repo_root = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        repo_root.push(format!("patchgate-cli-cache-recover-{ts}"));
        fs::create_dir_all(repo_root.join(".patchgate")).expect("create cache dir");

        let db_relative = ".patchgate/cache.db";
        let db_full = repo_root.join(db_relative);
        fs::write(&db_full, "not a sqlite database").expect("write broken db");

        let backup = recover_cache_db(&repo_root, db_relative)
            .expect("recover cache db")
            .expect("backup path should exist");
        assert!(backup.exists(), "broken db should be moved to backup");
        assert!(db_full.exists(), "new cache db should be recreated");

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn threshold_over_100_returns_input_error() {
        let mut cfg = Config::default();
        let err = apply_threshold_override(&mut cfg, Some(101)).expect_err("must reject >100");
        assert_eq!(err.kind(), ScanErrorKind::Input);
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn resolve_config_path_uses_repo_root_candidates() {
        let mut repo_root = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        repo_root.push(format!("patchgate-cli-config-test-{ts}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(&policy_path, "mode = \"warn\"\n").expect("write policy");

        let resolved = resolve_config_path(&repo_root, None).expect("should resolve policy");
        assert_eq!(resolved, policy_path);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn parse_policy_preset_accepts_known_values() {
        assert_eq!(
            parse_policy_preset(Some("strict"))
                .expect("strict")
                .map(|p| p.as_str()),
            Some("strict")
        );
        assert_eq!(
            parse_policy_preset(Some("balanced"))
                .expect("balanced")
                .map(|p| p.as_str()),
            Some("balanced")
        );
        assert_eq!(
            parse_policy_preset(Some("relaxed"))
                .expect("relaxed")
                .map(|p| p.as_str()),
            Some("relaxed")
        );
    }

    #[test]
    fn parse_policy_preset_rejects_unknown_value() {
        let err = parse_policy_preset(Some("custom")).expect_err("must reject unknown preset");
        assert!(err.contains("expected: strict|balanced|relaxed"));
    }

    #[test]
    fn resolve_policy_path_prefers_subcommand_path_over_global_override() {
        let repo_root = PathBuf::from("/tmp/patchgate");
        let global = PathBuf::from("global.toml");
        let subcmd = PathBuf::from("subcmd.toml");
        let resolved =
            resolve_policy_path(&repo_root, Some(&global), Some(&subcmd)).expect("resolved path");
        assert_eq!(resolved, repo_root.join("subcmd.toml"));
    }

    #[test]
    fn policy_exit_codes_are_stable() {
        assert_eq!(PolicyExitCode::ReadOrParse.as_i32(), 10);
        assert_eq!(PolicyExitCode::ValidationType.as_i32(), 11);
        assert_eq!(PolicyExitCode::ValidationRange.as_i32(), 12);
        assert_eq!(PolicyExitCode::ValidationDependency.as_i32(), 13);
        assert_eq!(PolicyExitCode::MigrationRequired.as_i32(), 14);
        assert_eq!(PolicyExitCode::MigrationFailed.as_i32(), 15);
        assert_eq!(PolicyExitCode::IoFailed.as_i32(), 16);
    }

    #[test]
    fn github_comment_includes_upsert_marker() {
        let report = Report::new(
            vec![],
            vec![CheckScore {
                check: CheckId::TestGap,
                label: "Test coverage gap".to_string(),
                penalty: 0,
                max_penalty: 35,
                triggered: false,
            }],
            ReportMeta {
                threshold: 70,
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );
        let comment = render_github_comment(&report);
        assert!(comment.starts_with("<!-- patchgate:report -->"));
    }
}
