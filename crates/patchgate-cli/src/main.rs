use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context as _, Result};
use clap::{Args, Parser, Subcommand};
use hmac::{Hmac, Mac};
use patchgate_github::{
    mask_secrets as mask_sensitive, publish_report, PublishAuth, PublishRequest, RetryPolicy,
};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::Url;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use toml_edit::{value, DocumentMut, Item, Table};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

use patchgate_config::{
    Config, ConfigError, LoadedConfig, PolicyMigrationError, PolicyPreset, ValidationCategory,
    POLICY_VERSION_CURRENT,
};
use patchgate_core::{
    CheckId, CheckScore, Context, Finding, Report, ReportMeta, ReviewPriority, Runner, ScopeMode,
    Severity,
};

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

    /// Aggregate scan history from JSONL records
    History(HistoryArgs),

    /// Validate and migrate policy files
    Policy(PolicyArgs),

    /// Manage external plugin templates
    Plugin(PluginArgs),

    /// Replay delivery dead-letter records
    Delivery(DeliveryArgs),
}

#[derive(Args, Debug, Clone)]
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

    /// Maximum number of changed files to process
    #[arg(long)]
    max_changed_files: Option<u32>,

    /// Behavior when max changed files exceeded: fail_open|fail_closed
    #[arg(long)]
    on_exceed: Option<String>,

    /// Disable SQLite cache
    #[arg(long)]
    no_cache: bool,

    /// Write machine-readable scan profile JSON
    #[arg(long)]
    profile_output: Option<PathBuf>,

    /// Append scan metrics JSONL record
    #[arg(long)]
    metrics_output: Option<PathBuf>,

    /// Append audit log JSONL record
    #[arg(long)]
    audit_log_output: Option<PathBuf>,

    /// Override actor for audit logs (default: GITHUB_ACTOR or $USER)
    #[arg(long)]
    audit_actor: Option<String>,

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

    /// GitHub auth mode: token|app
    #[arg(long)]
    github_auth: Option<String>,

    /// Environment variable name for GitHub App installation token
    #[arg(long)]
    github_app_token_env: Option<String>,

    /// Max retry attempts for GitHub publish operations
    #[arg(long, default_value_t = 3)]
    github_retry_max_attempts: u8,

    /// Initial retry backoff in milliseconds
    #[arg(long, default_value_t = 300)]
    github_retry_backoff_ms: u64,

    /// Max retry backoff in milliseconds
    #[arg(long, default_value_t = 3000)]
    github_retry_max_backoff_ms: u64,

    /// Build GitHub payloads but do not call GitHub API
    #[arg(long)]
    github_dry_run: bool,

    /// Write dry-run payload JSON to a file
    #[arg(long)]
    github_dry_run_output: Option<PathBuf>,

    /// Skip PR comment publishing
    #[arg(long)]
    github_no_comment: bool,

    /// Skip check-run publishing
    #[arg(long)]
    github_no_check_run: bool,

    /// Apply review-priority label to PR (opt-in)
    #[arg(long)]
    github_apply_labels: bool,

    /// Suppress comment when result is unchanged/cache-hit or has no findings
    #[arg(long)]
    github_suppress_comment_no_change: bool,

    /// Suppress comment when review priority is low (P3)
    #[arg(long)]
    github_suppress_comment_low_priority: bool,

    /// Suppress comment on rerun attempts (GITHUB_RUN_ATTEMPT > 1)
    #[arg(long)]
    github_suppress_comment_rerun: bool,

    /// Publish scan results through provider abstraction
    #[arg(long)]
    publish: bool,

    /// CI provider: github|generic
    #[arg(long)]
    ci_provider: Option<String>,

    /// Generic provider payload output path
    #[arg(long)]
    ci_generic_output: Option<PathBuf>,

    /// Signed webhook endpoint URL (repeatable)
    #[arg(long = "webhook-url")]
    webhook_urls: Vec<String>,

    /// Env var name for webhook signing secret
    #[arg(long)]
    webhook_secret_env: Option<String>,

    /// Webhook request timeout (ms)
    #[arg(long)]
    webhook_timeout_ms: Option<u64>,

    /// Webhook retry max attempts
    #[arg(long)]
    webhook_retry_max_attempts: Option<u8>,

    /// Notification target in `kind=url` format (kind: slack|teams|generic)
    #[arg(long = "notify-target")]
    notify_targets: Vec<String>,

    /// Notification retry max attempts
    #[arg(long)]
    notify_retry_max_attempts: Option<u8>,

    /// Notification retry backoff (ms)
    #[arg(long)]
    notify_retry_backoff_ms: Option<u64>,

    /// Notification request timeout (ms)
    #[arg(long)]
    notify_timeout_ms: Option<u64>,

    /// JSONL output path for failed delivery payloads
    #[arg(long)]
    dead_letter_output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct HistoryArgs {
    #[command(subcommand)]
    cmd: HistoryCommand,
}

#[derive(Subcommand, Debug)]
enum HistoryCommand {
    /// Summarize scan history metrics JSONL
    Summary(HistorySummaryArgs),

    /// Build per-repo/scope/check trend aggregates
    Trend(HistoryTrendArgs),
}

#[derive(Args, Debug)]
struct HistorySummaryArgs {
    /// Input metrics JSONL path
    #[arg(long)]
    input: PathBuf,

    /// Optional baseline metrics JSONL path for alert threshold comparison
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Output format: text|json
    #[arg(long, default_value = "text")]
    format: String,
}

#[derive(Args, Debug)]
struct HistoryTrendArgs {
    /// Input metrics JSONL path
    #[arg(long)]
    input: PathBuf,

    /// Output format: text|json
    #[arg(long, default_value = "json")]
    format: String,
}

#[derive(Args, Debug)]
struct PolicyArgs {
    #[command(subcommand)]
    cmd: PolicyCommand,
}

#[derive(Args, Debug)]
struct PluginArgs {
    #[command(subcommand)]
    cmd: PluginCommand,
}

#[derive(Args, Debug)]
struct DeliveryArgs {
    #[command(subcommand)]
    cmd: DeliveryCommand,
}

#[derive(Subcommand, Debug)]
enum DeliveryCommand {
    /// Replay dead-letter records to their original endpoints
    Replay(DeliveryReplayArgs),
}

#[derive(Args, Debug, Clone)]
struct DeliveryReplayArgs {
    /// Dead-letter JSONL input path
    #[arg(long)]
    input: PathBuf,

    /// Filter by transport kind: webhook|notification
    #[arg(long)]
    transport: Option<String>,

    /// Max records to replay
    #[arg(long)]
    max_records: Option<usize>,

    /// Retry max attempts per record
    #[arg(long, default_value_t = 2)]
    retry_max_attempts: u8,

    /// Retry backoff milliseconds
    #[arg(long, default_value_t = 500)]
    retry_backoff_ms: u64,

    /// Rewrite the input JSONL so only unreplayed records remain
    #[arg(long)]
    rewrite_input: bool,

    /// Write a machine-readable replay summary JSON file
    #[arg(long)]
    summary_output: Option<PathBuf>,

    /// Print target records but do not send requests
    #[arg(long)]
    dry_run: bool,
}

#[derive(Subcommand, Debug)]
enum PluginCommand {
    /// Generate a plugin template project
    Init(PluginInitArgs),
}

#[derive(Args, Debug, Clone)]
struct PluginInitArgs {
    /// Template language: python|node|rust
    #[arg(long, default_value = "python")]
    lang: String,

    /// Plugin id used by template defaults
    #[arg(long)]
    plugin_id: String,

    /// Output directory for generated plugin
    #[arg(long)]
    output: PathBuf,

    /// Overwrite output directory if it already exists
    #[arg(long)]
    force: bool,
}

static DEAD_LETTER_ENDPOINT_WARNING_EMITTED: AtomicBool = AtomicBool::new(false);

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Lint policy config and report compatibility status
    Lint(PolicyLintArgs),

    /// Migrate policy config across policy versions
    Migrate(PolicyMigrateArgs),

    /// Verify v1.0 readiness for migration
    VerifyV1(PolicyVerifyV1Args),
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

#[derive(Args, Debug)]
struct PolicyVerifyV1Args {
    /// Policy file path (default: auto-discover policy.toml)
    #[arg(long)]
    path: Option<PathBuf>,

    /// Apply policy preset before loading policy file: strict|balanced|relaxed
    #[arg(long)]
    policy_preset: Option<String>,

    /// Output format: text|json
    #[arg(long, default_value = "text")]
    format: String,

    /// Readiness profile: standard|strict|lts
    #[arg(long, default_value = "standard")]
    readiness_profile: String,

    /// Write a policy file with safe autofixes applied
    #[arg(long)]
    autofix_output: Option<PathBuf>,

    /// Overwrite the input policy file with safe autofixes
    #[arg(long)]
    autofix_write: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureCode {
    InputInvalidOption,
    ConfigLoadFailed,
    GitDiffFailed,
    RuntimeEvaluationFailed,
    OutputWriteFailed,
    PublishInputFailed,
    PublishApiFailed,
    PublishSsoRequired,
    PublishOrgPolicyBlocked,
    PublishWebhookFailed,
    NotificationFailed,
    WaiverExpired,
}

impl FailureCode {
    fn as_str(self) -> &'static str {
        match self {
            FailureCode::InputInvalidOption => "PG-IN-001",
            FailureCode::ConfigLoadFailed => "PG-CFG-001",
            FailureCode::GitDiffFailed => "PG-GIT-001",
            FailureCode::RuntimeEvaluationFailed => "PG-RT-001",
            FailureCode::OutputWriteFailed => "PG-OUT-001",
            FailureCode::PublishInputFailed => "PG-PUB-001",
            FailureCode::PublishApiFailed => "PG-PUB-002",
            FailureCode::PublishSsoRequired => "PG-PUB-SSO-001",
            FailureCode::PublishOrgPolicyBlocked => "PG-PUB-ORG-001",
            FailureCode::PublishWebhookFailed => "PG-PUB-WEB-001",
            FailureCode::NotificationFailed => "PG-NOT-001",
            FailureCode::WaiverExpired => "PG-GOV-001",
        }
    }

    fn category(self) -> &'static str {
        match self {
            FailureCode::InputInvalidOption => "input",
            FailureCode::ConfigLoadFailed | FailureCode::WaiverExpired => "config",
            FailureCode::GitDiffFailed => "git",
            FailureCode::RuntimeEvaluationFailed => "runtime",
            FailureCode::OutputWriteFailed => "output",
            FailureCode::PublishInputFailed
            | FailureCode::PublishApiFailed
            | FailureCode::PublishSsoRequired
            | FailureCode::PublishOrgPolicyBlocked
            | FailureCode::PublishWebhookFailed
            | FailureCode::NotificationFailed => "publish",
        }
    }
}

#[derive(Debug)]
struct ScanError {
    kind: ScanErrorKind,
    code: FailureCode,
    hint: Option<String>,
    source: anyhow::Error,
}

impl ScanError {
    fn new(kind: ScanErrorKind, source: anyhow::Error) -> Self {
        Self {
            kind,
            code: default_failure_code(kind),
            hint: None,
            source,
        }
    }

    fn with_code(kind: ScanErrorKind, code: FailureCode, source: anyhow::Error) -> Self {
        Self {
            kind,
            code,
            hint: None,
            source,
        }
    }

    fn with_hint(
        kind: ScanErrorKind,
        code: FailureCode,
        hint: impl Into<String>,
        source: anyhow::Error,
    ) -> Self {
        Self {
            kind,
            code,
            hint: Some(hint.into()),
            source,
        }
    }

    fn render(&self) -> String {
        format!(
            "patchgate scan error [{}:{}]: {:#}",
            self.kind.as_str(),
            self.code.as_str(),
            self.source
        )
    }

    fn print(&self) {
        eprintln!("{}", mask_sensitive(self.render().as_str()));
        if let Some(hint) = self.hint.as_ref() {
            eprintln!("hint: {}", hint);
        }
    }

    fn exit_code(&self) -> i32 {
        self.kind.exit_code()
    }

    #[cfg(test)]
    fn kind(&self) -> ScanErrorKind {
        self.kind
    }

    fn code(&self) -> FailureCode {
        self.code
    }

    fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }
}

fn default_failure_code(kind: ScanErrorKind) -> FailureCode {
    match kind {
        ScanErrorKind::Input => FailureCode::InputInvalidOption,
        ScanErrorKind::Config => FailureCode::ConfigLoadFailed,
        ScanErrorKind::Runtime => FailureCode::RuntimeEvaluationFailed,
        ScanErrorKind::Output => FailureCode::OutputWriteFailed,
        ScanErrorKind::Publish => FailureCode::PublishApiFailed,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitHubAuthMode {
    Token,
    App,
}

impl GitHubAuthMode {
    fn parse(raw: Option<&str>) -> std::result::Result<Self, String> {
        match raw.unwrap_or("token") {
            "token" => Ok(GitHubAuthMode::Token),
            "app" => Ok(GitHubAuthMode::App),
            other => Err(format!("`{other}` (expected: token|app)")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CiProvider {
    GitHub,
    Generic,
}

impl CiProvider {
    fn parse(raw: Option<&str>) -> std::result::Result<Self, String> {
        match raw.unwrap_or("github") {
            "github" => Ok(CiProvider::GitHub),
            "generic" => Ok(CiProvider::Generic),
            other => Err(format!("`{other}` (expected: github|generic)")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationKind {
    Slack,
    Teams,
    Generic,
}

impl NotificationKind {
    fn parse(raw: &str) -> std::result::Result<Self, String> {
        match raw {
            "slack" => Ok(NotificationKind::Slack),
            "teams" => Ok(NotificationKind::Teams),
            "generic" => Ok(NotificationKind::Generic),
            other => Err(format!("`{other}` (expected: slack|teams|generic)")),
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedNotificationTarget {
    name: String,
    kind: NotificationKind,
    url: String,
}

#[derive(Debug, Serialize)]
struct GenericCiPublishPayload {
    schema_version: u8,
    provider: String,
    repo: String,
    unix_ts: u64,
    summary: GenericPublishSummary,
    report: Report,
    markdown: String,
}

#[derive(Debug, Serialize)]
struct GenericPublishSummary {
    score: u8,
    threshold: u8,
    should_fail: bool,
    mode: String,
    scope: String,
    findings: usize,
}

#[derive(Debug, Serialize)]
struct WebhookEnvelope<'a> {
    event: &'a str,
    unix_ts: u64,
    repo: &'a str,
    report: &'a Report,
}

struct ResolvedScanOptions {
    format: String,
    mode: String,
    scope: ScopeMode,
}

#[derive(Debug, Default, Serialize)]
struct ScanProfile {
    schema_version: u8,
    mode: String,
    scope: String,
    changed_files: usize,
    skipped_by_cache: bool,
    total_ms: u128,
    diff_ms: u128,
    evaluate_ms: u128,
    cache_read_ms: u128,
    cache_write_ms: u128,
    publish_ms: u128,
    output_ms: u128,
    check_durations_ms: BTreeMap<String, u128>,
    delivery: DeliveryStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DeliveryStats {
    webhook_attempted: usize,
    webhook_succeeded: usize,
    webhook_failed: usize,
    notification_attempted: usize,
    notification_succeeded: usize,
    notification_failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanMetricRecord {
    schema_version: u8,
    unix_ts: u64,
    repo: String,
    mode: String,
    scope: String,
    duration_ms: u128,
    changed_files: usize,
    skipped_by_cache: bool,
    score: Option<u8>,
    threshold: Option<u8>,
    should_fail: Option<bool>,
    check_penalties: BTreeMap<String, u8>,
    failure_code: Option<String>,
    failure_category: Option<String>,
    diagnostic_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditLogRecord {
    schema_version: u8,
    audit_format: String,
    unix_ts: u64,
    actor: String,
    repo: String,
    target: String,
    mode: String,
    scope: String,
    result: String,
    failure_code: Option<String>,
    failure_category: Option<String>,
    score: Option<u8>,
    threshold: Option<u8>,
    changed_files: Option<usize>,
    diagnostic_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeadLetterRecord {
    schema_version: u8,
    unix_ts: u64,
    transport: String,
    endpoint: String,
    idempotency_key: String,
    error: String,
    payload: Value,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    payload_raw: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DeadLetterReplayFailure {
    transport: String,
    endpoint: String,
    idempotency_key: String,
    error: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeadLetterReplaySummary {
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
    failures: Vec<DeadLetterReplayFailure>,
}

#[derive(Debug, Clone, Serialize)]
struct HistorySummary {
    runs: usize,
    gate_failures: usize,
    execution_errors: usize,
    failure_rate: f64,
    average_duration_ms: f64,
    avg_score: f64,
    failure_code_counts: BTreeMap<String, usize>,
    alerts: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HistoryTrendRow {
    key: String,
    runs: usize,
    gate_failures: usize,
    failure_rate: f64,
    average_duration_ms: f64,
    average_score: f64,
}

type ScanResult<T> = std::result::Result<T, ScanError>;
const CACHE_KEY_SCHEMA_VERSION: &str = "v1";

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = cli.repo.unwrap_or(std::env::current_dir()?);

    match cli.cmd {
        Command::Doctor => run_doctor(&repo_root, cli.config.as_deref()),
        Command::History(history) => run_history(&repo_root, cli.config.as_deref(), history),
        Command::Scan(scan) => {
            let scan_args = *scan;
            let failure_log_args = scan_args.clone();
            let code = match execute_scan(&repo_root, cli.config.as_deref(), scan_args) {
                Ok(code) => code,
                Err(err) => {
                    err.print();
                    if let Err(write_err) = append_scan_failure_records(
                        &repo_root,
                        cli.config.as_deref(),
                        &failure_log_args,
                        &err,
                    ) {
                        eprintln!("warning: failed to append failure telemetry: {write_err:#}");
                    }
                    err.exit_code()
                }
            };
            std::process::exit(code);
        }
        Command::Policy(policy) => {
            let code = execute_policy(&repo_root, cli.config.as_deref(), policy);
            std::process::exit(code);
        }
        Command::Plugin(plugin) => {
            let code = execute_plugin(&repo_root, plugin);
            std::process::exit(code);
        }
        Command::Delivery(delivery) => {
            let code = execute_delivery(delivery);
            std::process::exit(code);
        }
    }
}

fn execute_plugin(repo_root: &Path, plugin: PluginArgs) -> i32 {
    match plugin.cmd {
        PluginCommand::Init(args) => match run_plugin_init(repo_root, args) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("patchgate plugin init error: {err:#}");
                2
            }
        },
    }
}

fn execute_delivery(delivery: DeliveryArgs) -> i32 {
    match delivery.cmd {
        DeliveryCommand::Replay(args) => match run_dead_letter_replay(args) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("patchgate delivery replay error: {err:#}");
                6
            }
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginTemplateLang {
    Python,
    Node,
    Rust,
}

impl PluginTemplateLang {
    fn parse(raw: &str) -> std::result::Result<Self, String> {
        match raw {
            "python" => Ok(Self::Python),
            "node" => Ok(Self::Node),
            "rust" => Ok(Self::Rust),
            other => Err(format!("`{other}` (expected: python|node|rust)")),
        }
    }
}

fn run_plugin_init(repo_root: &Path, args: PluginInitArgs) -> Result<()> {
    let lang = PluginTemplateLang::parse(args.lang.as_str())
        .map_err(|err| anyhow!("invalid --lang value: {err}"))?;
    let plugin_id = args.plugin_id.trim();
    if plugin_id.is_empty() {
        anyhow::bail!("--plugin-id must be non-empty");
    }
    validate_plugin_id(plugin_id)?;

    let repo_root = repo_root
        .canonicalize()
        .with_context(|| format!("canonicalize repo root {}", repo_root.display()))?;
    let output_dir = if args.output.is_absolute() {
        args.output.clone()
    } else {
        repo_root.join(args.output.as_path())
    };
    let output_dir = normalize_absolute_path(output_dir.as_path());
    if !output_dir.starts_with(repo_root.as_path()) {
        anyhow::bail!(
            "--output must be inside repository root: {}",
            repo_root.display()
        );
    }
    ensure_output_dir_has_no_symlink_components(repo_root.as_path(), output_dir.as_path())?;
    if output_dir == repo_root {
        anyhow::bail!("--output must not point to repository root");
    }
    let relative_output_dir = output_dir
        .strip_prefix(repo_root.as_path())
        .with_context(|| {
            format!(
                "strip repo root prefix from output directory {}",
                output_dir.display()
            )
        })?;
    if has_git_component(relative_output_dir) || output_dir.join(".git").exists() {
        anyhow::bail!("--output must not target a git repository path");
    }

    if output_dir.exists() {
        if !args.force {
            anyhow::bail!(
                "output directory already exists: {} (use --force to overwrite)",
                output_dir.display()
            );
        }
        fs::remove_dir_all(&output_dir)
            .with_context(|| format!("remove existing output {}", output_dir.display()))?;
    }
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;
    let canonical_output_dir = output_dir
        .canonicalize()
        .with_context(|| format!("canonicalize output directory {}", output_dir.display()))?;
    if !canonical_output_dir.starts_with(repo_root.as_path()) {
        anyhow::bail!(
            "--output must not resolve outside repository root: {}",
            repo_root.display()
        );
    }

    for (relative, content) in render_plugin_template(lang, plugin_id) {
        let path = canonical_output_dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent directory {}", parent.display()))?;
        }
        fs::write(&path, content).with_context(|| format!("write {}", path.display()))?;
    }

    println!(
        "plugin template generated: lang={} plugin_id={} output={}",
        args.lang,
        plugin_id,
        canonical_output_dir.display()
    );
    Ok(())
}

fn has_git_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::Normal(name) if name == ".git"))
}

fn validate_plugin_id(plugin_id: &str) -> Result<()> {
    if plugin_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Ok(());
    }
    anyhow::bail!("--plugin-id must contain only ASCII letters, digits, '.', '_' or '-'");
}

fn derive_project_name(plugin_id: &str) -> String {
    let mut name = String::new();
    let mut last_was_separator = false;
    for ch in plugin_id.chars() {
        if ch.is_ascii_alphanumeric() {
            name.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            name.push('-');
            last_was_separator = true;
        }
    }
    let name = name.trim_matches('-');
    let mut name = if name.is_empty() {
        "plugin-template".to_string()
    } else {
        name.to_string()
    };
    if name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
    {
        name = format!("plugin-{name}");
    }
    name
}

fn ensure_output_dir_has_no_symlink_components(repo_root: &Path, output_dir: &Path) -> Result<()> {
    let relative = output_dir
        .strip_prefix(repo_root)
        .with_context(|| format!("strip repo root prefix from {}", output_dir.display()))?;
    let mut current = repo_root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!(
                    "--output must not traverse symlinked paths: {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("inspect output path component {}", current.display())
                });
            }
        }
    }
    Ok(())
}

fn normalize_absolute_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

const NODE_TEMPLATE_README: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/node-plugin/README.md"
));
const NODE_TEMPLATE_SAMPLE_INPUT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/node-plugin/sample-input.json"
));
const NODE_TEMPLATE_PACKAGE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/node-plugin/package.json"
));
const NODE_TEMPLATE_INDEX_JS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/node-plugin/index.js"
));
const RUST_TEMPLATE_README: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/rust-plugin/README.md"
));
const RUST_TEMPLATE_SAMPLE_INPUT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/rust-plugin/sample-input.json"
));
const RUST_TEMPLATE_CARGO_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/rust-plugin/Cargo.toml"
));
const RUST_TEMPLATE_MAIN_RS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/rust-plugin/src/main.rs"
));

fn render_embedded_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = template.to_string();
    for (from, to) in replacements {
        rendered = rendered.replace(from, to);
    }
    rendered
}

fn render_plugin_template(
    lang: PluginTemplateLang,
    plugin_id: &str,
) -> Vec<(&'static str, String)> {
    let project_name = derive_project_name(plugin_id);
    match lang {
        PluginTemplateLang::Python => vec![
            (
                "README.md",
                format!(
                    "# {plugin_id} (Python plugin)\n\nGenerated by `patchgate plugin init`.\n\nRun:\n\n```bash\npython3 main.py < sample-input.json\n```\n"
                ),
            ),
            (
                "sample-input.json",
                format!(
                    "{{\"schema_version\":1,\"api_version\":\"patchgate.plugin.v1\",\"plugin_id\":\"{plugin_id}\",\"repo_root\":\".\",\"mode\":\"warn\",\"scope\":\"worktree\",\"changed_files\":[]}}\n"
                ),
            ),
            (
                "main.py",
                format!(
                    "#!/usr/bin/env python3\nimport json\nimport sys\n\n\ndef main() -> int:\n    raw = sys.stdin.read()\n    if not raw.strip():\n        print(json.dumps({{\"findings\": [], \"diagnostics\": [\"empty input\"]}}))\n        return 0\n\n    payload = json.loads(raw)\n    diagnostics = [\n        \"plugin_id={plugin_id}\",\n        f\"changed_files={{len(payload.get('changed_files', []))}}\",\n    ]\n    print(json.dumps({{\"findings\": [], \"diagnostics\": diagnostics}}))\n    return 0\n\n\nif __name__ == \"__main__\":\n    raise SystemExit(main())\n"
                ),
            ),
        ],
        PluginTemplateLang::Node => vec![
            ("README.md", NODE_TEMPLATE_README.to_string()),
            (
                "sample-input.json",
                render_embedded_template(
                    NODE_TEMPLATE_SAMPLE_INPUT,
                    &[("\"plugin_id\":\"sample\"", &format!("\"plugin_id\":\"{plugin_id}\""))],
                ),
            ),
            (
                "package.json",
                render_embedded_template(
                    NODE_TEMPLATE_PACKAGE_JSON,
                    &[("patchgate-node-plugin-template", project_name.as_str())],
                ),
            ),
            (
                "index.js",
                render_embedded_template(
                    NODE_TEMPLATE_INDEX_JS,
                    &[("\"sample\"", &format!("\"{plugin_id}\""))],
                ),
            ),
        ],
        PluginTemplateLang::Rust => vec![
            ("README.md", RUST_TEMPLATE_README.to_string()),
            (
                "sample-input.json",
                render_embedded_template(
                    RUST_TEMPLATE_SAMPLE_INPUT,
                    &[("\"plugin_id\":\"sample\"", &format!("\"plugin_id\":\"{plugin_id}\""))],
                ),
            ),
            (
                "Cargo.toml",
                render_embedded_template(
                    RUST_TEMPLATE_CARGO_TOML,
                    &[("patchgate-rust-plugin-template", project_name.as_str())],
                ),
            ),
            (
                "src/main.rs",
                render_embedded_template(
                    RUST_TEMPLATE_MAIN_RS,
                    &[("\"sample\"", &format!("\"{plugin_id}\""))],
                ),
            ),
        ],
    }
}

fn run_doctor(repo_root: &Path, config_override: Option<&Path>) -> Result<()> {
    let config_path = resolve_config_path(repo_root, config_override);
    let mut lines = vec![
        "patchgate doctor".to_string(),
        format!("- repo_root: {}", repo_root.display()),
        format!(
            "- config_path: {}",
            config_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<default only>".to_string())
        ),
        format!("- rust: {}", env!("CARGO_PKG_RUST_VERSION")),
        format!("- host_os: {}", current_host_os_label()),
        "- sandbox_capabilities:".to_string(),
    ];
    for capability in detect_sandbox_capabilities() {
        lines.push(format!(
            "  - {}: {} ({})",
            capability.profile,
            if capability.supported {
                "supported"
            } else {
                "unavailable"
            },
            capability.enforcement
        ));
        if let Some(requirement) = capability.requirement.as_ref() {
            lines.push(format!("    - requirement: {}", requirement));
        }
        for note in capability.notes {
            lines.push(format!("    - note: {}", note));
        }
    }
    lines.push("- ci_templates:".to_string());
    for (provider, path) in ci_template_catalog() {
        lines.push(format!("  - {}: {}", provider, path));
    }

    match diagnose_git(repo_root) {
        Ok((head, dirty)) => {
            lines.push(format!(
                "- git: ok (head: {}, dirty_files: {})",
                head, dirty
            ));
        }
        Err(err) => {
            lines.push(format!("- git: error ({err})"));
        }
    }

    let loaded_cfg = match load_policy_config(config_path.as_deref(), None) {
        Ok(cfg) => {
            lines.push("- config: ok".to_string());
            cfg
        }
        Err(err) => {
            lines.push(format!("- config: error ({err:#})"));
            lines.push(
                "- cache: unknown (skipping cache diagnostics because config failed to load)"
                    .to_string(),
            );
            for line in lines {
                println!("{line}");
            }
            return Ok(());
        }
    };
    lines.push(format!(
        "- policy_version: {}",
        loaded_cfg.config.policy_version
    ));
    for warning in &loaded_cfg.compatibility_warnings {
        lines.push(format!("- compatibility: warning ({warning})"));
    }

    let effective_cfg = loaded_cfg.config;
    lines.push(format!(
        "- plugin_sandbox_profile: {}",
        effective_cfg.plugins.sandbox.profile
    ));

    if !effective_cfg.cache.enabled {
        lines.push("- cache: disabled (cache.enabled=false)".to_string());
        for line in lines {
            println!("{line}");
        }
        return Ok(());
    }

    let db_full_path = repo_root.join(&effective_cfg.cache.db_path);
    match diagnose_cache(repo_root, &effective_cfg.cache.db_path) {
        Ok(CacheDoctorStatus::Ok) => {
            lines.push(format!("- cache: ok ({})", db_full_path.display()))
        }
        Ok(CacheDoctorStatus::Missing) => {
            lines.push(format!("- cache: missing ({})", db_full_path.display()))
        }
        Err(err) => lines.push(format!("- cache: error ({:#})", err)),
    }

    for line in lines {
        println!("{line}");
    }

    Ok(())
}

fn execute_policy(repo_root: &Path, config_override: Option<&Path>, policy: PolicyArgs) -> i32 {
    match policy.cmd {
        PolicyCommand::Lint(args) => run_policy_lint(repo_root, config_override, args).as_i32(),
        PolicyCommand::Migrate(args) => {
            run_policy_migrate(repo_root, config_override, args).as_i32()
        }
        PolicyCommand::VerifyV1(args) => {
            run_policy_verify_v1(repo_root, config_override, args).as_i32()
        }
    }
}

fn run_history(
    repo_root: &Path,
    config_override: Option<&Path>,
    history: HistoryArgs,
) -> Result<()> {
    match history.cmd {
        HistoryCommand::Summary(args) => {
            let records = load_metrics_jsonl(&args.input)?;
            let baseline_records = match args.baseline.as_ref() {
                Some(path) => Some(load_metrics_jsonl(path)?),
                None => None,
            };
            let config_path = resolve_config_path(repo_root, config_override);
            let alerts = load_policy_config(config_path.as_deref(), None)
                .map(|loaded| loaded.config.alerts)
                .unwrap_or_default();
            let summary = build_history_summary(&records, baseline_records.as_deref(), &alerts);
            match args.format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&summary)?),
                "text" => print_history_summary_text(&summary),
                other => anyhow::bail!("unsupported --format `{other}` (expected: text|json)"),
            }
        }
        HistoryCommand::Trend(args) => {
            let records = load_metrics_jsonl(&args.input)?;
            let trend = build_history_trend(&records);
            match args.format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&trend)?),
                "text" => print_history_trend_text(&trend),
                other => anyhow::bail!("unsupported --format `{other}` (expected: text|json)"),
            }
        }
    }
    Ok(())
}

fn load_metrics_jsonl(path: &Path) -> Result<Vec<ScanMetricRecord>> {
    let file =
        fs::File::open(path).with_context(|| format!("open metrics jsonl: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("read line {} from {}", idx + 1, path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str::<ScanMetricRecord>(&line).with_context(|| {
            format!(
                "decode metrics jsonl line {} from {}",
                idx + 1,
                path.display()
            )
        })?;
        records.push(row);
    }
    Ok(records)
}

fn build_history_summary(
    records: &[ScanMetricRecord],
    baseline: Option<&[ScanMetricRecord]>,
    alerts_cfg: &patchgate_config::AlertConfig,
) -> HistorySummary {
    let runs = records.len();
    let gate_failures = records
        .iter()
        .filter(|r| r.should_fail.unwrap_or(false))
        .count();
    let execution_errors = records.iter().filter(|r| r.failure_code.is_some()).count();
    let failed_runs = records
        .iter()
        .filter(|r| r.should_fail.unwrap_or(false) || r.failure_code.is_some())
        .count();
    let failure_rate = if runs == 0 {
        0.0
    } else {
        (failed_runs as f64 / runs as f64) * 100.0
    };
    let duration_samples: Vec<&ScanMetricRecord> = records
        .iter()
        .filter(|r| r.failure_code.is_none())
        .collect();
    let average_duration_ms = if duration_samples.is_empty() {
        0.0
    } else {
        duration_samples
            .iter()
            .map(|r| r.duration_ms as f64)
            .sum::<f64>()
            / duration_samples.len() as f64
    };
    let scored: Vec<u8> = records.iter().filter_map(|r| r.score).collect();
    let avg_score = if scored.is_empty() {
        0.0
    } else {
        scored.iter().map(|v| *v as f64).sum::<f64>() / scored.len() as f64
    };

    let mut failure_code_counts = BTreeMap::new();
    for code in records.iter().filter_map(|r| r.failure_code.as_ref()) {
        *failure_code_counts.entry(code.clone()).or_insert(0) += 1;
    }

    let mut alerts = Vec::new();
    if let Some(base) = baseline {
        let base_summary = build_history_summary(base, None, alerts_cfg);
        let score_drop = base_summary.avg_score - avg_score;
        if score_drop >= alerts_cfg.score_drop_threshold as f64 {
            alerts.push(format!(
                "score drop alert: {:.2} (threshold {})",
                score_drop, alerts_cfg.score_drop_threshold
            ));
        }
        let failure_rate_increase = failure_rate - base_summary.failure_rate;
        if failure_rate_increase >= alerts_cfg.failure_rate_increase_pct as f64 {
            alerts.push(format!(
                "failure rate alert: +{:.2}% (threshold {}%)",
                failure_rate_increase, alerts_cfg.failure_rate_increase_pct
            ));
        }
        let duration_increase_pct =
            signed_delta(base_summary.average_duration_ms, average_duration_ms);
        if duration_increase_pct >= alerts_cfg.duration_increase_pct as f64 {
            alerts.push(format!(
                "duration alert: +{:.2}% (threshold {}%)",
                duration_increase_pct, alerts_cfg.duration_increase_pct
            ));
        }
    }

    HistorySummary {
        runs,
        gate_failures,
        execution_errors,
        failure_rate,
        average_duration_ms,
        avg_score,
        failure_code_counts,
        alerts,
    }
}

fn print_history_summary_text(summary: &HistorySummary) {
    println!("history summary");
    println!("- runs: {}", summary.runs);
    println!("- gate_failures: {}", summary.gate_failures);
    println!("- execution_errors: {}", summary.execution_errors);
    println!("- failure_rate: {:.2}%", summary.failure_rate);
    println!("- avg_duration_ms: {:.2}", summary.average_duration_ms);
    println!("- avg_score: {:.2}", summary.avg_score);
    if summary.failure_code_counts.is_empty() {
        println!("- failure_codes: none");
    } else {
        println!("- failure_codes:");
        for (code, count) in &summary.failure_code_counts {
            println!("  - {code}: {count}");
        }
    }
    if summary.alerts.is_empty() {
        println!("- alerts: none");
    } else {
        println!("- alerts:");
        for alert in &summary.alerts {
            println!("  - {alert}");
        }
    }
}

fn build_history_trend(records: &[ScanMetricRecord]) -> Vec<HistoryTrendRow> {
    #[derive(Default)]
    struct TrendAgg {
        runs: usize,
        gate_failures: usize,
        failures: usize,
        duration_sum: f64,
        duration_runs: usize,
        score_sum: f64,
        scored_runs: usize,
    }

    let mut grouped: BTreeMap<String, TrendAgg> = BTreeMap::new();
    for row in records {
        let day = row.unix_ts / 86_400;
        let triggered_checks: Vec<&str> = row
            .check_penalties
            .iter()
            .filter_map(|(check, penalty)| (*penalty > 0).then_some(check.as_str()))
            .collect();

        if triggered_checks.is_empty() {
            let key = format!("day:{day}|repo:{}|scope:{}|check:none", row.repo, row.scope);
            let agg = grouped.entry(key).or_default();
            agg.runs += 1;
            if row.should_fail.unwrap_or(false) || row.failure_code.is_some() {
                agg.failures += 1;
            }
            if row.should_fail.unwrap_or(false) {
                agg.gate_failures += 1;
            }
            if row.failure_code.is_none() {
                agg.duration_sum += row.duration_ms as f64;
                agg.duration_runs += 1;
            }
            if let Some(score) = row.score {
                agg.score_sum += score as f64;
                agg.scored_runs += 1;
            }
            continue;
        }

        for check in triggered_checks {
            let key = format!(
                "day:{day}|repo:{}|scope:{}|check:{}",
                row.repo, row.scope, check
            );
            let agg = grouped.entry(key).or_default();
            agg.runs += 1;
            if row.should_fail.unwrap_or(false) || row.failure_code.is_some() {
                agg.failures += 1;
            }
            if row.should_fail.unwrap_or(false) {
                agg.gate_failures += 1;
            }
            if row.failure_code.is_none() {
                agg.duration_sum += row.duration_ms as f64;
                agg.duration_runs += 1;
            }
            if let Some(score) = row.score {
                agg.score_sum += score as f64;
                agg.scored_runs += 1;
            }
        }
    }

    grouped
        .into_iter()
        .map(|(key, agg)| HistoryTrendRow {
            key,
            runs: agg.runs,
            gate_failures: agg.gate_failures,
            failure_rate: if agg.runs == 0 {
                0.0
            } else {
                (agg.failures as f64 / agg.runs as f64) * 100.0
            },
            average_duration_ms: if agg.duration_runs == 0 {
                0.0
            } else {
                agg.duration_sum / agg.duration_runs as f64
            },
            average_score: if agg.scored_runs == 0 {
                0.0
            } else {
                agg.score_sum / agg.scored_runs as f64
            },
        })
        .collect()
}

fn print_history_trend_text(rows: &[HistoryTrendRow]) {
    println!("history trend");
    for row in rows {
        println!(
            "- {} runs={} failure_rate={:.2}% avg_duration_ms={:.2} avg_score={:.2}",
            row.key, row.runs, row.failure_rate, row.average_duration_ms, row.average_score
        );
    }
}

fn signed_delta(previous: f64, current: f64) -> f64 {
    if previous <= 0.0 {
        // Treat zero/invalid baseline as non-comparable to avoid false-positive alerts.
        0.0
    } else {
        ((current - previous) / previous) * 100.0
    }
}

fn run_policy_lint(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyLintArgs,
) -> PolicyExitCode {
    let Some(policy_path) = resolve_policy_path(repo_root, config_override, args.path.as_deref())
    else {
        eprintln!(
            "patchgate policy lint error: policy file not found. tried: `policy.toml`, `.patchgate/policy.toml`"
        );
        return PolicyExitCode::ReadOrParse;
    };
    let preset = match parse_policy_preset(args.policy_preset.as_deref()) {
        Ok(preset) => preset,
        Err(err) => {
            eprintln!("patchgate policy lint error: {err}");
            return PolicyExitCode::ReadOrParse;
        }
    };

    let loaded = match load_policy_config(Some(policy_path.as_path()), preset) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("patchgate policy lint error: {err:#}");
            return map_config_error_to_policy_exit(&err);
        }
    };

    println!("patchgate policy lint");
    println!("- config_path: {}", policy_path.display());
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

#[derive(Debug, Serialize)]
struct V1AutofixResult {
    mode: String,
    path: String,
    applied_changes: Vec<String>,
    ready: bool,
    warnings: Vec<String>,
    next_actions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct V1ReadinessReport {
    ready: bool,
    policy_path: String,
    policy_version: u32,
    readiness_profile: String,
    rc_frozen: bool,
    strict_compatibility: bool,
    plugins_enabled: bool,
    plugin_entries: usize,
    plugin_sandbox_profile: String,
    sandbox_capabilities: Vec<SandboxCapability>,
    lts_active: bool,
    lts_security_sla_hours: u16,
    warnings: Vec<String>,
    next_actions: Vec<String>,
    autofix_suggestions: Vec<String>,
    autofix_result: Option<V1AutofixResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessProfile {
    Standard,
    Strict,
    Lts,
}

impl ReadinessProfile {
    fn parse(raw: &str) -> std::result::Result<Self, String> {
        match raw {
            "standard" => Ok(Self::Standard),
            "strict" => Ok(Self::Strict),
            "lts" => Ok(Self::Lts),
            other => Err(format!("`{other}` (expected: standard|strict|lts)")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Strict => "strict",
            Self::Lts => "lts",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SandboxCapability {
    profile: String,
    supported: bool,
    enforcement: String,
    host_os: String,
    requirement: Option<String>,
    notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct ReadinessAssessment {
    warnings: Vec<String>,
    next_actions: Vec<String>,
    autofix_suggestions: Vec<String>,
    autofixes: Vec<PolicyAutofix>,
    ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyAutofix {
    SetRcFrozen,
    DisableLegacyConfigNames,
    SetPluginSandboxProfile(&'static str),
    SetLtsActive,
    SetLtsSecuritySlaHours(u16),
}

impl PolicyAutofix {
    fn suggestion(&self) -> String {
        match self {
            Self::SetRcFrozen => "compatibility.v1.rc_frozen = true".to_string(),
            Self::DisableLegacyConfigNames => {
                "compatibility.v1.allow_legacy_config_names = false".to_string()
            }
            Self::SetPluginSandboxProfile(profile) => {
                format!("plugins.sandbox.profile = \"{profile}\"")
            }
            Self::SetLtsActive => "release.lts.active = true".to_string(),
            Self::SetLtsSecuritySlaHours(hours) => {
                format!("release.lts.security_sla_hours = {hours}")
            }
        }
    }
}

fn run_policy_verify_v1(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyVerifyV1Args,
) -> PolicyExitCode {
    let Some(policy_path) = resolve_policy_path(repo_root, config_override, args.path.as_deref())
    else {
        eprintln!(
            "patchgate policy verify-v1 error: policy file not found. tried: `policy.toml`, `.patchgate/policy.toml`"
        );
        return PolicyExitCode::ReadOrParse;
    };

    let preset = match parse_policy_preset(args.policy_preset.as_deref()) {
        Ok(preset) => preset,
        Err(err) => {
            eprintln!("patchgate policy verify-v1 error: {err}");
            return PolicyExitCode::ReadOrParse;
        }
    };
    if args.autofix_write && args.autofix_output.is_some() {
        eprintln!(
            "patchgate policy verify-v1 error: --autofix-write and --autofix-output are mutually exclusive"
        );
        return PolicyExitCode::ReadOrParse;
    }
    let readiness_profile = match ReadinessProfile::parse(args.readiness_profile.as_str()) {
        Ok(profile) => profile,
        Err(err) => {
            eprintln!("patchgate policy verify-v1 error: invalid --readiness-profile: {err}");
            return PolicyExitCode::ReadOrParse;
        }
    };

    let loaded = match load_policy_config(Some(policy_path.as_path()), preset) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("patchgate policy verify-v1 error: {err:#}");
            return map_config_error_to_policy_exit(&err);
        }
    };

    let isolated_runtime_supported = isolated_sandbox_runtime_supported();
    let active_policy_path = policy_path.clone();
    let mut active_loaded = loaded;
    let mut active_assessment = assess_v1_readiness(
        active_policy_path.as_path(),
        &active_loaded.config,
        active_loaded.compatibility_warnings.clone(),
        readiness_profile,
        isolated_runtime_supported,
    );
    let mut autofix_result = None;

    if args.autofix_write {
        let applied_changes = active_assessment.autofix_suggestions.clone();
        if let Err(err) = apply_policy_autofixes(
            policy_path.as_path(),
            policy_path.as_path(),
            &active_assessment.autofixes,
        ) {
            eprintln!("patchgate policy verify-v1 error: {err:#}");
            return PolicyExitCode::IoFailed;
        }
        active_loaded = match load_policy_config(Some(policy_path.as_path()), preset) {
            Ok(loaded) => loaded,
            Err(err) => {
                eprintln!("patchgate policy verify-v1 error: {err:#}");
                return map_config_error_to_policy_exit(&err);
            }
        };
        active_assessment = assess_v1_readiness(
            policy_path.as_path(),
            &active_loaded.config,
            active_loaded.compatibility_warnings.clone(),
            readiness_profile,
            isolated_runtime_supported,
        );
        autofix_result = Some(V1AutofixResult {
            mode: "write".to_string(),
            path: policy_path.display().to_string(),
            applied_changes,
            ready: active_assessment.ready,
            warnings: active_assessment.warnings.clone(),
            next_actions: active_assessment.next_actions.clone(),
        });
    } else if let Some(output_path) = args.autofix_output.as_ref() {
        let output_path = resolve_repo_relative_path(repo_root, output_path.clone());
        let applied_changes = active_assessment.autofix_suggestions.clone();
        if let Err(err) = apply_policy_autofixes(
            policy_path.as_path(),
            output_path.as_path(),
            &active_assessment.autofixes,
        ) {
            eprintln!("patchgate policy verify-v1 error: {err:#}");
            return PolicyExitCode::IoFailed;
        }
        let preview_loaded = match load_policy_config(Some(output_path.as_path()), preset) {
            Ok(loaded) => loaded,
            Err(err) => {
                eprintln!("patchgate policy verify-v1 error: {err:#}");
                return map_config_error_to_policy_exit(&err);
            }
        };
        let preview_assessment = assess_v1_readiness(
            policy_path.as_path(),
            &preview_loaded.config,
            preview_loaded.compatibility_warnings.clone(),
            readiness_profile,
            isolated_runtime_supported,
        );
        autofix_result = Some(V1AutofixResult {
            mode: "output".to_string(),
            path: output_path.display().to_string(),
            applied_changes,
            ready: preview_assessment.ready,
            warnings: preview_assessment.warnings,
            next_actions: preview_assessment.next_actions,
        });
    }

    let report = build_v1_readiness_report(
        active_policy_path.as_path(),
        &active_loaded.config,
        readiness_profile,
        active_assessment,
        autofix_result,
    );

    if let Err(err) = print_v1_readiness_report(&report, args.format.as_str()) {
        eprintln!("patchgate policy verify-v1 error: {err}");
        return if err.contains("unsupported --format") {
            PolicyExitCode::ReadOrParse
        } else {
            PolicyExitCode::IoFailed
        };
    }

    if report.ready {
        PolicyExitCode::Ok
    } else {
        PolicyExitCode::MigrationRequired
    }
}

fn assess_v1_readiness(
    policy_path: &Path,
    cfg: &Config,
    mut warnings: Vec<String>,
    readiness_profile: ReadinessProfile,
    isolated_runtime_supported: bool,
) -> ReadinessAssessment {
    let mut next_actions = Vec::new();
    let mut autofixes = Vec::new();

    if policy_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n != "policy.toml")
        .unwrap_or(false)
    {
        warnings.push("legacy policy filename detected; migrate to `policy.toml`".to_string());
        next_actions.push("Rename policy file to `policy.toml` for v1 default path.".to_string());
    }

    if !cfg.compatibility.v1.rc_frozen {
        warnings.push("compatibility.v1.rc_frozen=false".to_string());
        next_actions
            .push("Set `compatibility.v1.rc_frozen = true` after RC review freeze.".to_string());
        autofixes.push(PolicyAutofix::SetRcFrozen);
    }
    if cfg.compatibility.v1.allow_legacy_config_names {
        warnings.push("compatibility.v1.allow_legacy_config_names=true".to_string());
        next_actions.push(
            "Set `compatibility.v1.allow_legacy_config_names = false` before GA.".to_string(),
        );
        autofixes.push(PolicyAutofix::DisableLegacyConfigNames);
    }

    if cfg.plugins.enabled {
        if matches!(
            readiness_profile,
            ReadinessProfile::Strict | ReadinessProfile::Lts
        ) {
            if cfg.plugins.sandbox.profile != "isolated" {
                warnings.push(
                    "strict readiness requires plugins.sandbox.profile=isolated when plugins are enabled"
                        .to_string(),
                );
                next_actions.push(
                    "Set `plugins.sandbox.profile = \"isolated\"` and verify `bwrap` is available."
                        .to_string(),
                );
                autofixes.push(PolicyAutofix::SetPluginSandboxProfile("isolated"));
            } else if !cfg!(target_os = "linux") {
                warnings.push(
                    "strict/lts readiness with plugins.sandbox.profile=isolated requires Linux runtime"
                        .to_string(),
                );
                next_actions.push(
                    "Run strict/lts readiness verification on Linux where isolated plugin sandbox is supported."
                        .to_string(),
                );
            } else if !isolated_runtime_supported {
                warnings.push(
                    "strict/lts readiness with plugins.sandbox.profile=isolated requires bwrap on Linux"
                        .to_string(),
                );
                next_actions.push(
                    "Install `bwrap` (bubblewrap) before relying on isolated plugin sandbox readiness."
                        .to_string(),
                );
            }
        } else if cfg.plugins.sandbox.profile == "none" {
            warnings.push("plugins enabled with sandbox.profile=none".to_string());
            next_actions.push(
                "Use `plugins.sandbox.profile = \"restricted\"` for v1 secure baseline."
                    .to_string(),
            );
            autofixes.push(PolicyAutofix::SetPluginSandboxProfile("restricted"));
        }
    }

    if matches!(readiness_profile, ReadinessProfile::Lts) && !cfg.release.lts.active {
        warnings.push("lts readiness requires release.lts.active=true".to_string());
        next_actions
            .push("Enable `[release.lts] active = true` before LTS readiness gate.".to_string());
        autofixes.push(PolicyAutofix::SetLtsActive);
    }
    if matches!(readiness_profile, ReadinessProfile::Lts) && cfg.release.lts.security_sla_hours > 72
    {
        warnings.push("lts readiness expects release.lts.security_sla_hours <= 72".to_string());
        next_actions.push(
            "Set `release.lts.security_sla_hours` to 72 or lower for default LTS policy."
                .to_string(),
        );
        autofixes.push(PolicyAutofix::SetLtsSecuritySlaHours(72));
    }

    let ready = cfg.policy_version == POLICY_VERSION_CURRENT
        && cfg.compatibility.v1.rc_frozen
        && !cfg.compatibility.v1.allow_legacy_config_names
        && !(cfg.plugins.enabled && cfg.plugins.sandbox.profile == "none")
        && (!cfg.plugins.enabled
            || !matches!(
                readiness_profile,
                ReadinessProfile::Strict | ReadinessProfile::Lts
            )
            || cfg.plugins.sandbox.profile == "isolated")
        && (!cfg.plugins.enabled
            || !matches!(
                readiness_profile,
                ReadinessProfile::Strict | ReadinessProfile::Lts
            )
            || cfg.plugins.sandbox.profile != "isolated"
            || isolated_runtime_supported)
        && (!matches!(readiness_profile, ReadinessProfile::Lts)
            || (cfg.release.lts.active && cfg.release.lts.security_sla_hours <= 72));
    if ready {
        next_actions.push("v1 readiness checks passed.".to_string());
    }

    let autofix_suggestions = autofixes
        .iter()
        .map(PolicyAutofix::suggestion)
        .collect::<Vec<_>>();

    ReadinessAssessment {
        warnings,
        next_actions,
        autofix_suggestions,
        autofixes,
        ready,
    }
}

fn build_v1_readiness_report(
    policy_path: &Path,
    cfg: &Config,
    readiness_profile: ReadinessProfile,
    assessment: ReadinessAssessment,
    autofix_result: Option<V1AutofixResult>,
) -> V1ReadinessReport {
    V1ReadinessReport {
        ready: assessment.ready,
        policy_path: policy_path.display().to_string(),
        policy_version: cfg.policy_version,
        readiness_profile: readiness_profile.as_str().to_string(),
        rc_frozen: cfg.compatibility.v1.rc_frozen,
        strict_compatibility: !cfg.compatibility.v1.allow_legacy_config_names,
        plugins_enabled: cfg.plugins.enabled,
        plugin_entries: cfg.plugins.entries.len(),
        plugin_sandbox_profile: cfg.plugins.sandbox.profile.clone(),
        sandbox_capabilities: detect_sandbox_capabilities(),
        lts_active: cfg.release.lts.active,
        lts_security_sla_hours: cfg.release.lts.security_sla_hours,
        warnings: assessment.warnings,
        next_actions: assessment.next_actions,
        autofix_suggestions: assessment.autofix_suggestions,
        autofix_result,
    }
}

fn print_v1_readiness_report(
    report: &V1ReadinessReport,
    format: &str,
) -> std::result::Result<(), String> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(report)
                .map_err(|err| format!("failed to encode json: {err}"))?;
            println!("{json}");
        }
        "text" => {
            println!("patchgate policy verify-v1");
            println!("- ready: {}", report.ready);
            println!("- policy_path: {}", report.policy_path);
            println!("- policy_version: {}", report.policy_version);
            println!("- readiness_profile: {}", report.readiness_profile);
            println!("- rc_frozen: {}", report.rc_frozen);
            println!("- strict_compatibility: {}", report.strict_compatibility);
            println!("- plugins_enabled: {}", report.plugins_enabled);
            println!("- plugin_entries: {}", report.plugin_entries);
            println!(
                "- plugin_sandbox_profile: {}",
                report.plugin_sandbox_profile
            );
            println!("- sandbox_capabilities:");
            for capability in &report.sandbox_capabilities {
                println!(
                    "  - {}: {} ({})",
                    capability.profile,
                    if capability.supported {
                        "supported"
                    } else {
                        "unavailable"
                    },
                    capability.enforcement
                );
                println!("    - host_os: {}", capability.host_os);
                if let Some(requirement) = capability.requirement.as_ref() {
                    println!("    - requirement: {}", requirement);
                }
                for note in &capability.notes {
                    println!("    - note: {}", note);
                }
            }
            println!("- lts_active: {}", report.lts_active);
            println!(
                "- lts_security_sla_hours: {}",
                report.lts_security_sla_hours
            );
            if report.warnings.is_empty() {
                println!("- warnings: none");
            } else {
                println!("- warnings:");
                for warning in &report.warnings {
                    println!("  - {warning}");
                }
            }
            println!("- next_actions:");
            for action in &report.next_actions {
                println!("  - {action}");
            }
            if report.autofix_suggestions.is_empty() {
                println!("- autofix_suggestions: none");
            } else {
                println!("- autofix_suggestions:");
                for suggestion in &report.autofix_suggestions {
                    println!("  - {suggestion}");
                }
            }
            if let Some(result) = report.autofix_result.as_ref() {
                println!("- autofix_result:");
                println!("  - mode: {}", result.mode);
                println!("  - path: {}", result.path);
                println!("  - ready: {}", result.ready);
                if result.applied_changes.is_empty() {
                    println!("  - applied_changes: none");
                } else {
                    println!("  - applied_changes:");
                    for change in &result.applied_changes {
                        println!("    - {change}");
                    }
                }
                if result.warnings.is_empty() {
                    println!("  - warnings: none");
                } else {
                    println!("  - warnings:");
                    for warning in &result.warnings {
                        println!("    - {warning}");
                    }
                }
                println!("  - next_actions:");
                for action in &result.next_actions {
                    println!("    - {action}");
                }
            }
        }
        other => {
            return Err(format!(
                "unsupported --format `{other}` (expected: text|json)"
            ));
        }
    }
    Ok(())
}

fn apply_policy_autofixes(
    input_path: &Path,
    output_path: &Path,
    autofixes: &[PolicyAutofix],
) -> Result<()> {
    let raw = fs::read_to_string(input_path)
        .with_context(|| format!("read policy for autofix: {}", input_path.display()))?;
    let mut doc = raw
        .parse::<DocumentMut>()
        .with_context(|| format!("parse policy for autofix: {}", input_path.display()))?;
    for autofix in autofixes {
        apply_policy_autofix(&mut doc, autofix);
    }
    write_text_atomic(output_path, doc.to_string().as_str())
        .with_context(|| format!("write autofixed policy: {}", output_path.display()))
}

fn apply_policy_autofix(doc: &mut DocumentMut, autofix: &PolicyAutofix) {
    match autofix {
        PolicyAutofix::SetRcFrozen => {
            let compatibility = ensure_table(doc.as_table_mut(), "compatibility");
            let v1 = ensure_table(compatibility, "v1");
            v1["rc_frozen"] = value(true);
        }
        PolicyAutofix::DisableLegacyConfigNames => {
            let compatibility = ensure_table(doc.as_table_mut(), "compatibility");
            let v1 = ensure_table(compatibility, "v1");
            v1["allow_legacy_config_names"] = value(false);
        }
        PolicyAutofix::SetPluginSandboxProfile(profile) => {
            let plugins = ensure_table(doc.as_table_mut(), "plugins");
            let sandbox = ensure_table(plugins, "sandbox");
            sandbox["profile"] = value(*profile);
        }
        PolicyAutofix::SetLtsActive => {
            let release = ensure_table(doc.as_table_mut(), "release");
            let lts = ensure_table(release, "lts");
            lts["active"] = value(true);
        }
        PolicyAutofix::SetLtsSecuritySlaHours(hours) => {
            let release = ensure_table(doc.as_table_mut(), "release");
            let lts = ensure_table(release, "lts");
            lts["security_sla_hours"] = value(i64::from(*hours));
        }
    }
}

fn ensure_table<'a>(table: &'a mut Table, key: &str) -> &'a mut Table {
    if !table.contains_key(key) || !table[key].is_table() {
        table[key] = Item::Table(Table::new());
    }
    table[key]
        .as_table_mut()
        .expect("table must exist after insertion")
}

fn write_text_atomic(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let temp_path = temp_path_for(path);
    fs::write(&temp_path, content)
        .with_context(|| format!("write temp file {}", temp_path.display()))?;
    if let Err(err) = replace_file(temp_path.as_path(), path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("patchgate-policy");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    path.with_file_name(format!(".{file_name}.tmp-{nonce}"))
}

#[cfg(not(windows))]
fn replace_file(temp_path: &Path, path: &Path) -> Result<()> {
    fs::rename(temp_path, path).with_context(|| {
        format!(
            "rename temp file {} -> {}",
            temp_path.display(),
            path.display()
        )
    })
}

#[cfg(windows)]
fn replace_file(temp_path: &Path, path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    fn encode_wide_null(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let temp = encode_wide_null(temp_path);
    let dest = encode_wide_null(path);
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    let result = unsafe { MoveFileExW(temp.as_ptr(), dest.as_ptr(), flags) };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "replace temp file {} -> {}",
                temp_path.display(),
                path.display()
            )
        });
    }
    Ok(())
}

fn isolated_sandbox_runtime_supported() -> bool {
    #[cfg(test)]
    match BWRAP_AVAILABLE_OVERRIDE.load(Ordering::Relaxed) {
        0 => return false,
        1 => return true,
        _ => {}
    }

    #[cfg(target_os = "linux")]
    {
        ProcessCommand::new("bwrap")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn detect_sandbox_capabilities() -> Vec<SandboxCapability> {
    let host_os = current_host_os_label().to_string();
    let mut capabilities = Vec::with_capacity(3);
    capabilities.push(SandboxCapability {
        profile: "none".to_string(),
        supported: true,
        enforcement: "no isolation".to_string(),
        host_os: host_os.clone(),
        requirement: None,
        notes: vec!["available on every supported host".to_string()],
    });
    capabilities.push(SandboxCapability {
        profile: "restricted".to_string(),
        supported: true,
        enforcement: "env allowlist + process limits".to_string(),
        host_os: host_os.clone(),
        requirement: None,
        notes: vec!["portable baseline profile for plugin execution".to_string()],
    });

    let isolated_supported = isolated_sandbox_runtime_supported();
    let (requirement, notes) = if cfg!(target_os = "linux") {
        if isolated_supported {
            (
                Some("Linux host with `bwrap` available".to_string()),
                vec!["OS-level process/fs isolation is active".to_string()],
            )
        } else {
            (
                Some("Install `bwrap` (bubblewrap) on Linux".to_string()),
                vec!["strict/lts readiness stays blocked until bubblewrap is present".to_string()],
            )
        }
    } else {
        (
            Some("Run on Linux with `bwrap` for isolated sandbox".to_string()),
            vec![
                "macOS/Windows currently support `restricted` but not `isolated` enforcement"
                    .to_string(),
            ],
        )
    };
    capabilities.push(SandboxCapability {
        profile: "isolated".to_string(),
        supported: isolated_supported,
        enforcement: "bubblewrap OS isolation".to_string(),
        host_os,
        requirement,
        notes,
    });
    capabilities
}

fn current_host_os_label() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        std::env::consts::OS
    }
}

fn ci_template_catalog() -> [(&'static str, &'static str); 3] {
    [
        ("github", "docs/patchgate-action.yml"),
        ("gitlab", "docs/patchgate-gitlab-ci.yml"),
        ("jenkins", "docs/Jenkinsfile.patchgate"),
    ]
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
        max_changed_files,
        on_exceed,
        no_cache,
        profile_output,
        metrics_output,
        audit_log_output,
        audit_actor,
        github_comment,
        github_publish,
        github_repo,
        github_pr,
        github_sha,
        github_token_env,
        github_check_name,
        github_auth,
        github_app_token_env,
        github_retry_max_attempts,
        github_retry_backoff_ms,
        github_retry_max_backoff_ms,
        github_dry_run,
        github_dry_run_output,
        github_no_comment,
        github_no_check_run,
        github_apply_labels,
        github_suppress_comment_no_change,
        github_suppress_comment_low_priority,
        github_suppress_comment_rerun,
        publish,
        ci_provider,
        ci_generic_output,
        webhook_urls,
        webhook_secret_env,
        webhook_timeout_ms,
        webhook_retry_max_attempts,
        notify_targets,
        notify_retry_max_attempts,
        notify_retry_backoff_ms,
        notify_timeout_ms,
        dead_letter_output,
    } = scan;
    let telemetry_repo = resolve_telemetry_repo(repo_root, github_repo.as_deref());
    let preset = parse_policy_preset(policy_preset.as_deref()).map_err(|err| {
        ScanError::with_code(
            ScanErrorKind::Input,
            FailureCode::InputInvalidOption,
            anyhow!("invalid value for scan.policy_preset from cli: {err}"),
        )
    })?;

    let config_path = resolve_config_path(repo_root, config_override);
    let loaded_cfg = load_policy_config(config_path.as_deref(), preset).map_err(|err| {
        if matches!(
            &err,
            ConfigError::Validation { field, message, .. }
                if *field == "waiver.entries" && message.contains("expired")
        ) {
            ScanError::with_hint(
                ScanErrorKind::Config,
                FailureCode::WaiverExpired,
                "Update waiver.expires_at or remove expired waiver entries.",
                anyhow::Error::new(err).context("failed to load policy config"),
            )
        } else {
            ScanError::with_code(
                ScanErrorKind::Config,
                FailureCode::ConfigLoadFailed,
                anyhow::Error::new(err).context("failed to load policy config"),
            )
        }
    })?;
    for warning in &loaded_cfg.compatibility_warnings {
        eprintln!("warning: {warning}");
    }
    let mut cfg = loaded_cfg.config;

    apply_threshold_override(&mut cfg, threshold)?;
    apply_changed_file_overrides(&mut cfg, max_changed_files, on_exceed.as_deref())?;

    let opts = resolve_scan_options(&cfg, format.as_deref(), scope.as_deref(), mode.as_deref())?;

    let mut profile = ScanProfile {
        schema_version: 1,
        mode: opts.mode.clone(),
        scope: opts.scope.as_str().to_string(),
        ..ScanProfile::default()
    };

    let ctx = Context {
        repo_root: repo_root.to_path_buf(),
        scope: opts.scope,
    };

    let runner = Runner::new(cfg.clone());
    let diff_collect_start = Instant::now();
    let diff = runner.collect_diff(&ctx).map_err(|err| {
        ScanError::with_hint(
            ScanErrorKind::Runtime,
            FailureCode::GitDiffFailed,
            "Verify the repository is a valid git worktree and retry with --scope worktree.",
            err.context("failed to collect git diff"),
        )
    })?;
    profile.diff_ms = diff_collect_start.elapsed().as_millis();
    profile.changed_files = diff.files.len();
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
            ScanError::with_hint(
                ScanErrorKind::Runtime,
                FailureCode::RuntimeEvaluationFailed,
                "Run `patchgate doctor` and retry with --no-cache to isolate runtime issues.",
                err.context("failed to evaluate scan checks"),
            )
        })
    };

    let mut report = if profile.changed_files > cfg.scope.max_changed_files as usize {
        match cfg.scope.on_exceed.as_str() {
            "fail_open" => {
                eprintln!(
                    "warning: changed file count ({}) exceeded limit ({}). proceeding with fail-open behavior.",
                    profile.changed_files, cfg.scope.max_changed_files
                );
                changed_file_limit_fail_open_report(
                    &cfg,
                    &opts,
                    &diff_fingerprint,
                    profile.changed_files,
                    run_start.elapsed().as_millis(),
                )
            }
            "fail_closed" => {
                return Err(ScanError::new(
                    ScanErrorKind::Runtime,
                    anyhow!(
                        "changed file count ({}) exceeded configured max_changed_files ({}) with on_exceed=fail_closed",
                        profile.changed_files,
                        cfg.scope.max_changed_files
                    ),
                ));
            }
            other => {
                return Err(ScanError::new(
                    ScanErrorKind::Config,
                    anyhow!("invalid value for scope.on_exceed from config: `{other}` (expected: fail_open|fail_closed)"),
                ));
            }
        }
    } else if cache_enabled {
        let policy_hash = config_hash(&cfg).map_err(|err| {
            ScanError::new(
                ScanErrorKind::Runtime,
                err.context("failed to hash effective config"),
            )
        })?;
        let mut cache_conn = match open_cache_connection(repo_root, &cfg.cache.db_path) {
            Ok(conn) => Some(conn),
            Err(err) => {
                handle_cache_fault(repo_root, &cfg.cache.db_path, "open", &err);
                None
            }
        };
        if let Some(conn) = cache_conn.as_ref() {
            let cache_read_start = Instant::now();
            let cached = load_cache_from_conn(
                conn,
                &diff_fingerprint,
                &policy_hash,
                &opts.mode,
                opts.scope.as_str(),
            );
            profile.cache_read_ms = cache_read_start.elapsed().as_millis();
            match cached {
                Ok(Some(mut cached)) => {
                    cached.skipped_by_cache = true;
                    cached.duration_ms = run_start.elapsed().as_millis();
                    cached.check_durations_ms.clear();
                    profile.evaluate_ms = 0;
                    cached
                }
                Ok(None) => {
                    let evaluated = evaluate_report()?;
                    profile.evaluate_ms = evaluated.duration_ms;
                    if let Some(conn) = cache_conn.as_ref() {
                        let cache_write_start = Instant::now();
                        if let Err(err) = store_cache_to_conn(conn, &evaluated, &policy_hash) {
                            handle_cache_fault(repo_root, &cfg.cache.db_path, "write", &err);
                        }
                        profile.cache_write_ms = cache_write_start.elapsed().as_millis();
                    }
                    evaluated
                }
                Err(err) => {
                    handle_cache_fault(repo_root, &cfg.cache.db_path, "read", &err);
                    cache_conn = open_cache_connection(repo_root, &cfg.cache.db_path).ok();
                    let evaluated = evaluate_report()?;
                    profile.evaluate_ms = evaluated.duration_ms;
                    if let Some(conn) = cache_conn.as_ref() {
                        let cache_write_start = Instant::now();
                        if let Err(err) = store_cache_to_conn(conn, &evaluated, &policy_hash) {
                            handle_cache_fault(repo_root, &cfg.cache.db_path, "write", &err);
                        }
                        profile.cache_write_ms = cache_write_start.elapsed().as_millis();
                    }
                    evaluated
                }
            }
        } else {
            let evaluated = evaluate_report()?;
            profile.evaluate_ms = evaluated.duration_ms;
            evaluated
        }
    } else {
        let evaluated = evaluate_report()?;
        profile.evaluate_ms = evaluated.duration_ms;
        evaluated
    };
    profile.skipped_by_cache = report.skipped_by_cache;
    if report.skipped_by_cache {
        profile.check_durations_ms.clear();
    } else {
        profile.check_durations_ms = report.check_durations_ms.clone();
    }

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

    let publish_requested = github_publish || publish;
    if publish_requested {
        let publish_start = Instant::now();
        let ci_provider = resolve_ci_provider_for_publish(
            github_publish,
            ci_provider.as_deref(),
            Some(cfg.integrations.ci.provider.as_str()),
        )
        .map_err(|err| {
            ScanError::with_code(
                ScanErrorKind::Input,
                FailureCode::InputInvalidOption,
                anyhow!("invalid value for scan.ci_provider: {err}"),
            )
        })?;

        match ci_provider {
            CiProvider::GitHub => {
                let suppressed_comment_reason = resolve_comment_suppression_reason(
                    &report,
                    github_suppress_comment_no_change,
                    github_suppress_comment_low_priority,
                    github_suppress_comment_rerun,
                );
                let req = resolve_publish_request(PublishRequestInput {
                    github_repo: github_repo.clone(),
                    github_pr,
                    github_sha,
                    github_token_env,
                    github_check_name,
                    github_auth,
                    github_app_token_env,
                    retry_policy: RetryPolicy {
                        max_attempts: github_retry_max_attempts,
                        backoff_base_ms: github_retry_backoff_ms,
                        backoff_max_ms: github_retry_max_backoff_ms,
                    },
                    github_dry_run,
                    publish_comment: !github_no_comment,
                    publish_check_run: !github_no_check_run,
                    apply_priority_label: github_apply_labels,
                    suppressed_comment_reason,
                })
                .map_err(|err| {
                    ScanError::with_hint(
                        ScanErrorKind::Publish,
                        FailureCode::PublishInputFailed,
                        "Set --github-repo/--github-pr/--github-sha or provide matching GitHub Actions env vars.",
                        err.context("failed to resolve GitHub publish inputs"),
                    )
                })?;
                let published = publish_report(&report, &markdown, &req).map_err(|err| {
                    classify_publish_scan_error(err.context("failed to publish report to GitHub"))
                })?;
                if let Some(payload) = published.dry_run_payload.as_ref() {
                    let pretty = serde_json::to_string_pretty(payload).map_err(|err| {
                        ScanError::new(
                            ScanErrorKind::Output,
                            anyhow!("failed to encode github dry-run payload: {err}"),
                        )
                    })?;
                    eprintln!(
                        "github dry-run payload:\n{}",
                        mask_sensitive(pretty.as_str())
                    );
                    if let Some(path) = github_dry_run_output.as_ref() {
                        if let Some(parent) = path.parent() {
                            fs::create_dir_all(parent).map_err(|err| {
                                ScanError::new(
                                    ScanErrorKind::Output,
                                    anyhow!(
                                        "failed to create dry-run output directory: {parent:?}: {err}"
                                    ),
                                )
                            })?;
                        }
                        fs::write(path, pretty).map_err(|err| {
                            ScanError::new(
                                ScanErrorKind::Output,
                                anyhow!("failed to write github dry-run payload: {path:?}: {err}"),
                            )
                        })?;
                    }
                }
                if let Some(reason) = published.skipped_comment_reason.as_ref() {
                    eprintln!(
                        "github comment skipped: {}",
                        mask_sensitive(reason.as_str())
                    );
                }
                if let Some(err) = published.comment_error.as_ref() {
                    eprintln!(
                        "warning: failed to publish PR comment: {}",
                        mask_sensitive(err.as_str())
                    );
                }
                if let Some(err) = published.check_run_error.as_ref() {
                    eprintln!(
                        "warning: failed to publish check run: {}",
                        mask_sensitive(err.as_str())
                    );
                }
                if let Some(err) = published.label_error.as_ref() {
                    eprintln!(
                        "warning: failed to apply labels: {}",
                        mask_sensitive(err.as_str())
                    );
                }
                if let Some(mode) = published.degraded_mode.as_ref() {
                    eprintln!("warning: publish degraded mode activated: {mode}");
                }
                if !published.applied_labels.is_empty() {
                    eprintln!("applied PR labels: {}", published.applied_labels.join(", "));
                }
                if let Some(url) = published.comment_url {
                    eprintln!("published PR comment: {url}");
                }
                if let Some(url) = published.check_run_url {
                    eprintln!("published check run: {url}");
                }
            }
            CiProvider::Generic => {
                let config_generic_output =
                    non_empty_path(cfg.integrations.ci.generic_output_path.as_str())
                        .map(|p| resolve_repo_relative_path(repo_root, p));
                let generic_output = ci_generic_output.clone().or(config_generic_output);
                publish_generic_ci_payload(
                    telemetry_repo.as_str(),
                    &report,
                    &markdown,
                    generic_output.as_deref(),
                )
                .map_err(|err| {
                    ScanError::with_code(
                        ScanErrorKind::Publish,
                        FailureCode::PublishApiFailed,
                        err.context("failed to publish generic CI payload"),
                    )
                })?;
            }
        }
        profile.publish_ms = publish_start.elapsed().as_millis();
    }

    let dead_letter_path = dead_letter_output
        .as_ref()
        .map(|p| resolve_repo_relative_path(repo_root, p.clone()));
    let idempotency_key = build_delivery_idempotency_key(telemetry_repo.as_str(), &report);

    let webhook_targets = resolve_webhook_targets(&cfg, &webhook_urls);
    if !webhook_targets.is_empty() {
        let timeout_ms = webhook_timeout_ms.unwrap_or(cfg.integrations.webhook.timeout_ms);
        let secret_env = webhook_secret_env
            .as_deref()
            .unwrap_or(cfg.integrations.webhook.secret_env.as_str());
        let retry_max_attempts = webhook_retry_max_attempts.unwrap_or(3);
        dispatch_signed_webhooks(
            telemetry_repo.as_str(),
            &report,
            &webhook_targets,
            WebhookDispatchOptions {
                timeout_ms,
                retry_max_attempts,
                secret_env,
                idempotency_key: idempotency_key.as_str(),
                dead_letter_path: dead_letter_path.as_deref(),
            },
            &mut profile.delivery,
        )
        .map_err(|err| {
            ScanError::with_hint(
                ScanErrorKind::Publish,
                FailureCode::PublishWebhookFailed,
                "Verify webhook URL reachability and webhook secret configuration.",
                err.context("failed to dispatch webhook"),
            )
        })?;
    }

    let notification_targets =
        resolve_notification_targets(&cfg, &notify_targets).map_err(|err| {
            ScanError::with_code(
                ScanErrorKind::Input,
                FailureCode::InputInvalidOption,
                err.context("failed to resolve notify targets"),
            )
        })?;
    if !notification_targets.is_empty() {
        dispatch_notifications(
            telemetry_repo.as_str(),
            &report,
            notification_targets.as_slice(),
            NotificationDispatchOptions {
                retry_max_attempts: notify_retry_max_attempts
                    .unwrap_or(cfg.integrations.notifications.retry_max_attempts),
                retry_backoff_ms: notify_retry_backoff_ms
                    .unwrap_or(cfg.integrations.notifications.retry_backoff_ms),
                timeout_ms: notify_timeout_ms.unwrap_or(cfg.integrations.notifications.timeout_ms),
                idempotency_key: idempotency_key.as_str(),
                dead_letter_path: dead_letter_path.as_deref(),
            },
            &mut profile.delivery,
        )
        .map_err(|err| {
            ScanError::with_hint(
                ScanErrorKind::Publish,
                FailureCode::NotificationFailed,
                "Check notification endpoint URL, payload contract, and retry settings.",
                err.context("failed to send notifications"),
            )
        })?;
    }

    if profile.delivery.webhook_failed > 0 || profile.delivery.notification_failed > 0 {
        report.diagnostic_hints.push(format!(
            "delivery failures: webhook_failed={}, notification_failed={}",
            profile.delivery.webhook_failed, profile.delivery.notification_failed
        ));
    }
    report.diagnostic_hints.push(format!(
        "delivery stats: webhook {}/{}, notification {}/{}",
        profile.delivery.webhook_succeeded,
        profile.delivery.webhook_attempted,
        profile.delivery.notification_succeeded,
        profile.delivery.notification_attempted
    ));

    let output_start = Instant::now();
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
    profile.output_ms = output_start.elapsed().as_millis();
    profile.total_ms = run_start.elapsed().as_millis();

    if let Some(path) = profile_output.as_ref() {
        write_scan_profile(path, &profile)?;
    }

    let metrics_path = metrics_output
        .as_deref()
        .map(Path::to_path_buf)
        .or_else(|| {
            non_empty_path(cfg.observability.metrics_jsonl_path.as_str())
                .map(|p| resolve_repo_relative_path(repo_root, p))
        });
    let audit_path = audit_log_output
        .as_deref()
        .map(Path::to_path_buf)
        .or_else(|| {
            non_empty_path(cfg.observability.audit_jsonl_path.as_str())
                .map(|p| resolve_repo_relative_path(repo_root, p))
        });
    append_scan_success_records(
        telemetry_repo.as_str(),
        &report,
        metrics_path.as_deref(),
        audit_path.as_deref(),
        resolve_audit_actor(audit_actor.as_deref()),
        cfg.observability.audit_schema_version,
    )?;

    Ok(gate_exit_code(&opts.mode, report.should_fail))
}

fn append_scan_success_records(
    telemetry_repo: &str,
    report: &Report,
    metrics_path: Option<&Path>,
    audit_path: Option<&Path>,
    actor: String,
    audit_schema_version: u8,
) -> ScanResult<()> {
    let unix_ts = current_unix_ts();
    if let Some(path) = metrics_path {
        let metrics = ScanMetricRecord {
            schema_version: 1,
            unix_ts,
            repo: telemetry_repo.to_string(),
            mode: report.mode.clone(),
            scope: report.scope.clone(),
            duration_ms: report.duration_ms,
            changed_files: report.changed_files,
            skipped_by_cache: report.skipped_by_cache,
            score: Some(report.score),
            threshold: Some(report.threshold),
            should_fail: Some(report.should_fail),
            check_penalties: report
                .checks
                .iter()
                .filter(|c| c.triggered && c.penalty > 0)
                .map(|c| (c.check.as_str().to_string(), c.penalty))
                .collect(),
            failure_code: None,
            failure_category: None,
            diagnostic_hints: report.diagnostic_hints.clone(),
        };
        append_jsonl(path, &metrics).map_err(|err| {
            ScanError::with_code(
                ScanErrorKind::Output,
                FailureCode::OutputWriteFailed,
                err.context("failed to append metrics jsonl"),
            )
        })?;
    }

    if let Some(path) = audit_path {
        let result = if report.should_fail {
            "gate_fail"
        } else {
            "pass"
        };
        let audit = AuditLogRecord {
            schema_version: audit_schema_version,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts,
            actor,
            repo: telemetry_repo.to_string(),
            target: "scan".to_string(),
            mode: report.mode.clone(),
            scope: report.scope.clone(),
            result: result.to_string(),
            failure_code: None,
            failure_category: None,
            score: Some(report.score),
            threshold: Some(report.threshold),
            changed_files: Some(report.changed_files),
            diagnostic_hints: report.diagnostic_hints.clone(),
        };
        append_jsonl(path, &audit).map_err(|err| {
            ScanError::with_code(
                ScanErrorKind::Output,
                FailureCode::OutputWriteFailed,
                err.context("failed to append audit jsonl"),
            )
        })?;
    }

    Ok(())
}

fn append_scan_failure_records(
    repo_root: &Path,
    config_override: Option<&Path>,
    scan: &ScanArgs,
    err: &ScanError,
) -> Result<()> {
    let mut metrics_path = scan.metrics_output.clone();
    let mut audit_path = scan.audit_log_output.clone();
    let mut audit_schema_version = 1u8;
    let mut telemetry_mode = scan.mode.clone().unwrap_or_else(|| "unknown".to_string());
    let mut telemetry_scope = scan.scope.clone().unwrap_or_else(|| "unknown".to_string());

    let preset = parse_policy_preset(scan.policy_preset.as_deref())
        .ok()
        .flatten();
    let config_path = resolve_config_path(repo_root, config_override);
    if let Ok(loaded) = load_policy_config(config_path.as_deref(), preset) {
        if metrics_path.is_none() {
            metrics_path = non_empty_path(loaded.config.observability.metrics_jsonl_path.as_str())
                .map(|p| resolve_repo_relative_path(repo_root, p));
        }
        if audit_path.is_none() {
            audit_path = non_empty_path(loaded.config.observability.audit_jsonl_path.as_str())
                .map(|p| resolve_repo_relative_path(repo_root, p));
        }
        audit_schema_version = loaded.config.observability.audit_schema_version;
        if let Ok(opts) = resolve_scan_options(
            &loaded.config,
            None,
            scan.scope.as_deref(),
            scan.mode.as_deref(),
        ) {
            telemetry_mode = opts.mode;
            telemetry_scope = opts.scope.as_str().to_string();
        }
    }

    let unix_ts = current_unix_ts();
    let telemetry_repo = resolve_telemetry_repo(repo_root, scan.github_repo.as_deref());
    if let Some(path) = metrics_path.as_deref() {
        let metrics = ScanMetricRecord {
            schema_version: 1,
            unix_ts,
            repo: telemetry_repo.clone(),
            mode: telemetry_mode.clone(),
            scope: telemetry_scope.clone(),
            duration_ms: 0,
            changed_files: 0,
            skipped_by_cache: false,
            score: None,
            threshold: None,
            should_fail: None,
            check_penalties: BTreeMap::new(),
            failure_code: Some(err.code().as_str().to_string()),
            failure_category: Some(err.code().category().to_string()),
            diagnostic_hints: err.hint().map(|h| vec![h.to_string()]).unwrap_or_default(),
        };
        append_jsonl(path, &metrics)?;
    }

    if let Some(path) = audit_path.as_deref() {
        let audit = AuditLogRecord {
            schema_version: audit_schema_version,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts,
            actor: resolve_audit_actor(scan.audit_actor.as_deref()),
            repo: telemetry_repo,
            target: "scan".to_string(),
            mode: telemetry_mode,
            scope: telemetry_scope,
            result: "error".to_string(),
            failure_code: Some(err.code().as_str().to_string()),
            failure_category: Some(err.code().category().to_string()),
            score: None,
            threshold: None,
            changed_files: None,
            diagnostic_hints: err.hint().map(|h| vec![h.to_string()]).unwrap_or_default(),
        };
        append_jsonl(path, &audit)?;
    }

    Ok(())
}

fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(value)?)
        .with_context(|| format!("append jsonl {}", path.display()))?;
    Ok(())
}

fn non_empty_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn resolve_repo_relative_path(repo_root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    }
}

fn resolve_audit_actor(override_actor: Option<&str>) -> String {
    if let Some(actor) = override_actor {
        if !actor.trim().is_empty() {
            return actor.to_string();
        }
    }
    if let Ok(actor) = std::env::var("GITHUB_ACTOR") {
        if !actor.trim().is_empty() {
            return actor;
        }
    }
    if let Ok(actor) = std::env::var("USER") {
        if !actor.trim().is_empty() {
            return actor;
        }
    }
    if let Ok(actor) = std::env::var("USERNAME") {
        if !actor.trim().is_empty() {
            return actor;
        }
    }
    "unknown".to_string()
}

fn resolve_telemetry_repo(repo_root: &Path, github_repo_override: Option<&str>) -> String {
    if let Some(repo) = github_repo_override {
        if !repo.trim().is_empty() {
            return repo.to_string();
        }
    }
    if let Ok(repo) = std::env::var("GITHUB_REPOSITORY") {
        if !repo.trim().is_empty() {
            return repo;
        }
    }
    if let Some(name) = repo_root.file_name() {
        let name = name.to_string_lossy();
        if !name.trim().is_empty() {
            return format!("local/{name}");
        }
    }
    "local".to_string()
}

fn current_unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn classify_publish_scan_error(err: anyhow::Error) -> ScanError {
    let lower = err.to_string().to_ascii_lowercase();
    if lower.contains("saml") || lower.contains("sso") {
        return ScanError::with_hint(
            ScanErrorKind::Publish,
            FailureCode::PublishSsoRequired,
            "Authorize SSO for the token or use a GitHub App installation token approved for the organization.",
            err,
        );
    }
    if lower.contains("resource not accessible by integration")
        || lower.contains("organization")
        || lower.contains("org policy")
    {
        return ScanError::with_hint(
            ScanErrorKind::Publish,
            FailureCode::PublishOrgPolicyBlocked,
            "Check organization policy restrictions and required repository permissions for comments/check-runs/labels.",
            err,
        );
    }
    ScanError::with_hint(
        ScanErrorKind::Publish,
        FailureCode::PublishApiFailed,
        "Retry with --github-dry-run to inspect payload and verify token scopes.",
        err,
    )
}

fn resolve_publish_request(input: PublishRequestInput) -> Result<PublishRequest> {
    let PublishRequestInput {
        github_repo,
        github_pr,
        github_sha,
        github_token_env,
        github_check_name,
        github_auth,
        github_app_token_env,
        retry_policy,
        github_dry_run,
        publish_comment,
        publish_check_run,
        apply_priority_label,
        suppressed_comment_reason,
    } = input;

    let repo = github_repo
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .context("github repository was not provided (use --github-repo or GITHUB_REPOSITORY)")?;

    let pr_number = match github_pr {
        Some(n) => n,
        None => detect_pr_number_from_env()?.context(
            "pull request number was not provided (use --github-pr or pull_request event)",
        )?,
    };

    let detected_head_sha = match github_sha {
        Some(sha) => Some(sha),
        None => detect_head_sha_from_env()?.or_else(|| std::env::var("GITHUB_SHA").ok()),
    };
    let head_sha = if publish_check_run {
        detected_head_sha.context(
            "head SHA was not provided (use --github-sha, pull_request.head.sha, or GITHUB_SHA)",
        )?
    } else {
        detected_head_sha.unwrap_or_default()
    };

    let auth_mode = GitHubAuthMode::parse(github_auth.as_deref())
        .map_err(|err| anyhow!("invalid value for github_auth: {err}"))?;
    let check_name = github_check_name.unwrap_or_else(|| "patchgate".to_string());
    let auth = match auth_mode {
        GitHubAuthMode::Token => {
            let token_env = github_token_env.unwrap_or_else(|| "GITHUB_TOKEN".to_string());
            let token = if github_dry_run {
                std::env::var(&token_env).unwrap_or_else(|_| "<dry-run-token>".to_string())
            } else {
                std::env::var(&token_env)
                    .with_context(|| format!("missing GitHub token env var: {token_env}"))?
            };
            PublishAuth::Token { token }
        }
        GitHubAuthMode::App => {
            let app_token_env =
                github_app_token_env.unwrap_or_else(|| "GITHUB_APP_INSTALLATION_TOKEN".to_string());
            let installation_token = if github_dry_run {
                std::env::var(&app_token_env)
                    .unwrap_or_else(|_| "<dry-run-app-installation-token>".to_string())
            } else {
                std::env::var(&app_token_env).with_context(|| {
                    format!("missing GitHub App installation token env var: {app_token_env}")
                })?
            };
            let app_id = std::env::var("GITHUB_APP_ID").ok();
            PublishAuth::App {
                installation_token,
                app_id,
            }
        }
    };

    let mut req = PublishRequest::new(repo, pr_number, head_sha, auth, check_name);
    req.retry_policy = retry_policy;
    req.publish_comment = publish_comment;
    req.publish_check_run = publish_check_run;
    req.apply_priority_label = apply_priority_label;
    req.dry_run = github_dry_run;
    req.suppressed_comment_reason = suppressed_comment_reason;
    Ok(req)
}

struct PublishRequestInput {
    github_repo: Option<String>,
    github_pr: Option<u64>,
    github_sha: Option<String>,
    github_token_env: Option<String>,
    github_check_name: Option<String>,
    github_auth: Option<String>,
    github_app_token_env: Option<String>,
    retry_policy: RetryPolicy,
    github_dry_run: bool,
    publish_comment: bool,
    publish_check_run: bool,
    apply_priority_label: bool,
    suppressed_comment_reason: Option<String>,
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

fn resolve_comment_suppression_reason(
    report: &Report,
    suppress_no_change: bool,
    suppress_low_priority: bool,
    suppress_rerun: bool,
) -> Option<String> {
    if suppress_no_change && (report.skipped_by_cache || report.findings.is_empty()) {
        return Some("suppressed by --github-suppress-comment-no-change".to_string());
    }

    if suppress_low_priority && report.review_priority == ReviewPriority::P3 {
        return Some("suppressed by --github-suppress-comment-low-priority".to_string());
    }

    if suppress_rerun {
        let attempt = std::env::var("GITHUB_RUN_ATTEMPT")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);
        if attempt > 1 {
            return Some(format!(
                "suppressed by --github-suppress-comment-rerun (GITHUB_RUN_ATTEMPT={attempt})"
            ));
        }
    }

    None
}

fn resolve_ci_provider(
    cli_value: Option<&str>,
    config_value: Option<&str>,
) -> std::result::Result<CiProvider, String> {
    CiProvider::parse(cli_value.or(config_value))
}

fn resolve_ci_provider_for_publish(
    github_publish: bool,
    cli_value: Option<&str>,
    config_value: Option<&str>,
) -> std::result::Result<CiProvider, String> {
    let effective_cli_value = if github_publish && cli_value.is_none() {
        Some("github")
    } else {
        cli_value
    };
    resolve_ci_provider(effective_cli_value, config_value)
}

fn publish_generic_ci_payload(
    telemetry_repo: &str,
    report: &Report,
    markdown: &str,
    output_path: Option<&Path>,
) -> Result<()> {
    let sanitized_report = sanitize_report_for_external(report)?;
    let payload = GenericCiPublishPayload {
        schema_version: 1,
        provider: "generic".to_string(),
        repo: telemetry_repo.to_string(),
        unix_ts: current_unix_ts(),
        summary: GenericPublishSummary {
            score: report.score,
            threshold: report.threshold,
            should_fail: report.should_fail,
            mode: report.mode.clone(),
            scope: report.scope.clone(),
            findings: report.findings.len(),
        },
        report: sanitized_report,
        markdown: markdown.to_string(),
    };
    let pretty = serde_json::to_string_pretty(&payload)?;
    let pretty = mask_sensitive(pretty.as_str());
    let path = output_path.ok_or_else(|| {
        anyhow!(
            "generic CI publish requires output path; set --ci-generic-output or integrations.ci.generic_output_path"
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(path, pretty).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn resolve_webhook_targets(cfg: &Config, cli_urls: &[String]) -> Vec<String> {
    if !cli_urls.is_empty() {
        return cli_urls.to_vec();
    }
    if cfg.integrations.webhook.enabled {
        return cfg.integrations.webhook.urls.clone();
    }
    Vec::new()
}

fn resolve_notification_targets(
    cfg: &Config,
    cli_targets: &[String],
) -> std::result::Result<Vec<ResolvedNotificationTarget>, anyhow::Error> {
    if !cli_targets.is_empty() {
        let mut targets = Vec::new();
        for (idx, raw) in cli_targets.iter().enumerate() {
            let (kind_raw, url) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("invalid notify target `{raw}` (expected: kind=url)"))?;
            let kind = NotificationKind::parse(kind_raw)
                .map_err(|err| anyhow!("invalid notify target kind: {err}"))?;
            targets.push(ResolvedNotificationTarget {
                name: format!("cli-{kind_raw}-{idx}"),
                kind,
                url: url.to_string(),
            });
        }
        return Ok(targets);
    }

    if !cfg.integrations.notifications.enabled {
        return Ok(Vec::new());
    }

    cfg.integrations
        .notifications
        .targets
        .iter()
        .map(|target| {
            let kind = NotificationKind::parse(target.kind.as_str())
                .map_err(|err| anyhow!("invalid notification target kind in config: {err}"))?;
            Ok(ResolvedNotificationTarget {
                name: target.name.clone(),
                kind,
                url: target.url.clone(),
            })
        })
        .collect()
}

type HmacSha256 = Hmac<Sha256>;

struct WebhookDispatchOptions<'a> {
    timeout_ms: u64,
    retry_max_attempts: u8,
    secret_env: &'a str,
    idempotency_key: &'a str,
    dead_letter_path: Option<&'a Path>,
}

struct NotificationDispatchOptions<'a> {
    retry_max_attempts: u8,
    retry_backoff_ms: u64,
    timeout_ms: u64,
    idempotency_key: &'a str,
    dead_letter_path: Option<&'a Path>,
}

struct DeadLetterWriteOptions<'a> {
    transport: &'a str,
    endpoint: &'a str,
    idempotency_key: &'a str,
    error: &'a str,
    payload: &'a Value,
    headers: Option<&'a BTreeMap<String, String>>,
    payload_raw: Option<&'a str>,
}

#[cfg(test)]
static BWRAP_AVAILABLE_OVERRIDE: std::sync::atomic::AtomicI8 = std::sync::atomic::AtomicI8::new(-1);

fn build_delivery_idempotency_key(telemetry_repo: &str, report: &Report) -> String {
    let mut hasher = Sha256::new();
    hasher.update(telemetry_repo.as_bytes());
    hasher.update(b":");
    hasher.update(report.fingerprint.as_bytes());
    hasher.update(b":");
    hasher.update(report.mode.as_bytes());
    hasher.update(b":");
    hasher.update(report.scope.as_bytes());
    let digest = hasher.finalize();
    format!("pgv1-{}", encode_hex(digest.as_slice()))
}

fn append_dead_letter(path: Option<&Path>, options: DeadLetterWriteOptions<'_>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let safe_endpoint = redacted_endpoint(options.endpoint);
    if safe_endpoint != options.endpoint
        && !DEAD_LETTER_ENDPOINT_WARNING_EMITTED.swap(true, Ordering::Relaxed)
    {
        eprintln!(
            "warning: dead-letter records persist raw endpoint URLs; treat {} as secret material",
            path.display()
        );
    }
    let record = DeadLetterRecord {
        schema_version: 1,
        unix_ts: current_unix_ts(),
        transport: options.transport.to_string(),
        endpoint: options.endpoint.to_string(),
        idempotency_key: options.idempotency_key.to_string(),
        error: options.error.to_string(),
        payload: options.payload.clone(),
        headers: options.headers.cloned().unwrap_or_default(),
        payload_raw: options.payload_raw.map(ToOwned::to_owned),
    };
    append_jsonl(path, &record).context("failed to append dead-letter record")
}

#[cfg(test)]
fn load_dead_letter_jsonl(
    path: &Path,
    transport_filter: Option<&str>,
    max_records: Option<usize>,
) -> Result<Vec<DeadLetterRecord>> {
    let rows = load_all_dead_letter_jsonl(path)?;
    let mut filtered = Vec::new();
    for row in rows {
        if let Some(filter) = transport_filter {
            if row.transport != filter {
                continue;
            }
        }
        filtered.push(row);
        if let Some(limit) = max_records {
            if filtered.len() >= limit {
                break;
            }
        }
    }
    Ok(filtered)
}

#[cfg(test)]
fn load_all_dead_letter_jsonl(path: &Path) -> Result<Vec<DeadLetterRecord>> {
    let file =
        fs::File::open(path).with_context(|| format!("open dead-letter: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("read line {} from {}", idx + 1, path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let row = serde_json::from_str::<DeadLetterRecord>(&line).with_context(|| {
            format!(
                "decode dead-letter line {} from {}",
                idx + 1,
                path.display()
            )
        })?;
        validate_dead_letter_record(&row, path, idx + 1)?;
        rows.push(row);
    }
    Ok(rows)
}

fn validate_dead_letter_record(
    record: &DeadLetterRecord,
    path: &Path,
    line_number: usize,
) -> Result<()> {
    if record.schema_version != 1 {
        anyhow::bail!(
            "unsupported dead-letter schema_version {} in line {} from {}",
            record.schema_version,
            line_number,
            path.display()
        );
    }
    if record.transport != "webhook" && record.transport != "notification" {
        anyhow::bail!(
            "unsupported dead-letter transport `{}` in line {} from {}",
            record.transport,
            line_number,
            path.display()
        );
    }
    Ok(())
}

fn run_dead_letter_replay(args: DeliveryReplayArgs) -> Result<()> {
    let transport_filter = args.transport.as_deref();
    if let Some(transport) = transport_filter {
        if transport != "webhook" && transport != "notification" {
            anyhow::bail!(
                "invalid --transport value `{transport}` (expected: webhook|notification)"
            );
        }
    }
    let attempts = args.retry_max_attempts.max(1);
    let client = Client::builder()
        .timeout(Duration::from_millis(5_000))
        .build()
        .context("failed to build replay client")?;
    let mut summary = DeadLetterReplaySummary {
        input_path: args.input.display().to_string(),
        transport_filter: transport_filter.map(ToOwned::to_owned),
        selected_records: 0,
        successful_records: 0,
        dry_run_records: 0,
        failed_records: 0,
        skipped_records: 0,
        retained_records: 0,
        dry_run: args.dry_run,
        rewrite_input: args.rewrite_input,
        failures: Vec::new(),
    };
    let mut rewrite_state = if args.rewrite_input && !args.dry_run {
        Some(create_dead_letter_rewrite_state(args.input.as_path())?)
    } else {
        None
    };
    let replay_result = (|| -> Result<()> {
        let file = fs::File::open(&args.input)
            .with_context(|| format!("open dead-letter: {}", args.input.display()))?;
        let reader = BufReader::new(file);
        let mut matched_records = 0usize;
        let mut saw_record = false;

        for (idx, line) in reader.lines().enumerate() {
            let line = line
                .with_context(|| format!("read line {} from {}", idx + 1, args.input.display()))?;
            if line.trim().is_empty() {
                continue;
            }
            saw_record = true;
            let record = serde_json::from_str::<DeadLetterRecord>(&line).with_context(|| {
                format!(
                    "decode dead-letter line {} from {}",
                    idx + 1,
                    args.input.display()
                )
            })?;
            validate_dead_letter_record(&record, args.input.as_path(), idx + 1)?;

            let matches_transport = transport_filter
                .map(|transport| record.transport == transport)
                .unwrap_or(true);
            let within_limit = args
                .max_records
                .map(|limit| matched_records < limit)
                .unwrap_or(true);
            if !matches_transport || !within_limit {
                retain_dead_letter_line(rewrite_state.as_mut(), &line, &mut summary)?;
                continue;
            }

            matched_records += 1;
            summary.selected_records += 1;

            if record.endpoint.contains("***") {
                let error = "redacted endpoint cannot be replayed".to_string();
                eprintln!(
                    "skip replay (redacted endpoint): transport={} endpoint={}",
                    record.transport, record.endpoint
                );
                summary.skipped_records += 1;
                summary.failed_records += 1;
                summary.failures.push(DeadLetterReplayFailure {
                    transport: record.transport.clone(),
                    endpoint: record.endpoint.clone(),
                    idempotency_key: record.idempotency_key.clone(),
                    error: error.clone(),
                });
                let mut retained = record;
                retained.error = error;
                retained.unix_ts = current_unix_ts();
                retain_dead_letter_record(rewrite_state.as_mut(), &retained, &mut summary)?;
                continue;
            }
            if args.dry_run {
                println!(
                    "dry-run replay: transport={} endpoint={} idempotency_key={}",
                    record.transport,
                    redacted_endpoint(record.endpoint.as_str()),
                    record.idempotency_key
                );
                summary.dry_run_records += 1;
                summary.retained_records += 1;
                continue;
            }

            match replay_dead_letter_record(&client, &record, attempts, args.retry_backoff_ms) {
                Ok(()) => {
                    summary.successful_records += 1;
                    if !args.rewrite_input {
                        summary.retained_records += 1;
                    }
                }
                Err(error) => {
                    summary.failed_records += 1;
                    summary.failures.push(DeadLetterReplayFailure {
                        transport: record.transport.clone(),
                        endpoint: redacted_endpoint(record.endpoint.as_str()),
                        idempotency_key: record.idempotency_key.clone(),
                        error: error.clone(),
                    });
                    let mut retained = record;
                    retained.error = error;
                    retained.unix_ts = current_unix_ts();
                    retain_dead_letter_record(rewrite_state.as_mut(), &retained, &mut summary)?;
                }
            }
        }

        if !saw_record || summary.selected_records == 0 {
            println!("no dead-letter records to replay");
        }

        Ok(())
    })();

    if let Some(state) = rewrite_state.take() {
        if replay_result.is_ok() {
            finalize_dead_letter_rewrite(state, args.input.as_path())?;
        } else {
            cleanup_dead_letter_rewrite(state);
        }
    }
    replay_result?;

    write_dead_letter_replay_summary(args.summary_output.as_deref(), &summary)?;
    if summary.selected_records > 0 {
        println!(
            "dead-letter replay completed: selected_records={} successful_records={} dry_run_records={} failed_records={} skipped_records={} retained_records={}",
            summary.selected_records,
            summary.successful_records,
            summary.dry_run_records,
            summary.failed_records,
            summary.skipped_records,
            summary.retained_records
        );
    }
    if summary.failed_records > 0 {
        anyhow::bail!(
            "dead-letter replay completed with {} failed record(s)",
            summary.failed_records
        );
    }
    Ok(())
}

fn replay_dead_letter_record(
    client: &Client,
    record: &DeadLetterRecord,
    attempts: u8,
    retry_backoff_ms: u64,
) -> std::result::Result<(), String> {
    let body = match record.payload_raw.as_ref() {
        Some(raw) => raw.as_bytes().to_vec(),
        None => serde_json::to_vec(&record.payload)
            .map_err(|err| format!("encode dead-letter payload: {err}"))?,
    };
    let mut last_error = None;
    for attempt in 1..=attempts {
        let mut request = client
            .post(record.endpoint.as_str())
            .header(CONTENT_TYPE, "application/json")
            .header(
                "X-Patchgate-Idempotency-Key",
                record.idempotency_key.as_str(),
            );
        for (header_name, header_value) in &record.headers {
            let name = HeaderName::from_bytes(header_name.as_bytes()).map_err(|_| {
                format!("invalid dead-letter header name for replay: {header_name}")
            })?;
            let value = HeaderValue::from_str(header_value).map_err(|_| {
                format!("invalid dead-letter header value for replay: {header_name}")
            })?;
            request = request.header(name, value);
        }
        let response = request.body(body.clone()).send();
        match response {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                last_error = Some(format!(
                    "replay target returned status {} for {}",
                    resp.status(),
                    redacted_endpoint(record.endpoint.as_str())
                ));
            }
            Err(err) => {
                last_error = Some(format!(
                    "replay request failed for {}: {err}",
                    redacted_endpoint(record.endpoint.as_str())
                ));
            }
        }
        if attempt < attempts {
            let delay = retry_backoff_ms.saturating_mul(2u64.saturating_pow((attempt - 1) as u32));
            thread::sleep(Duration::from_millis(delay.min(10_000)));
        }
    }
    Err(last_error.unwrap_or_else(|| "dead-letter replay failed".to_string()))
}

struct DeadLetterRewriteState {
    temp_path: PathBuf,
    file: fs::File,
}

fn create_dead_letter_rewrite_state(path: &Path) -> Result<DeadLetterRewriteState> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let temp_path = temp_path_for(path);
    let file = fs::File::create(&temp_path)
        .with_context(|| format!("create dead-letter rewrite file {}", temp_path.display()))?;
    Ok(DeadLetterRewriteState { temp_path, file })
}

fn finalize_dead_letter_rewrite(mut state: DeadLetterRewriteState, path: &Path) -> Result<()> {
    state.file.flush().with_context(|| {
        format!(
            "flush dead-letter rewrite file {}",
            state.temp_path.display()
        )
    })?;
    drop(state.file);
    replace_file(state.temp_path.as_path(), path).with_context(|| {
        format!(
            "replace dead-letter file {} -> {}",
            state.temp_path.display(),
            path.display()
        )
    })
}

fn cleanup_dead_letter_rewrite(state: DeadLetterRewriteState) {
    drop(state.file);
    let _ = fs::remove_file(state.temp_path);
}

fn retain_dead_letter_line(
    state: Option<&mut DeadLetterRewriteState>,
    line: &str,
    summary: &mut DeadLetterReplaySummary,
) -> Result<()> {
    summary.retained_records += 1;
    if let Some(state) = state {
        writeln!(state.file, "{line}").with_context(|| {
            format!(
                "append retained dead-letter line {}",
                state.temp_path.display()
            )
        })?;
    }
    Ok(())
}

fn retain_dead_letter_record(
    state: Option<&mut DeadLetterRewriteState>,
    record: &DeadLetterRecord,
    summary: &mut DeadLetterReplaySummary,
) -> Result<()> {
    summary.retained_records += 1;
    if let Some(state) = state {
        writeln!(state.file, "{}", serde_json::to_string(record)?).with_context(|| {
            format!(
                "append retained dead-letter record {}",
                state.temp_path.display()
            )
        })?;
    }
    Ok(())
}

fn write_dead_letter_replay_summary(
    output_path: Option<&Path>,
    summary: &DeadLetterReplaySummary,
) -> Result<()> {
    let Some(path) = output_path else {
        return Ok(());
    };
    let encoded = serde_json::to_string_pretty(summary)?;
    write_text_atomic(path, encoded.as_str())
}

fn dispatch_signed_webhooks(
    telemetry_repo: &str,
    report: &Report,
    urls: &[String],
    options: WebhookDispatchOptions<'_>,
    delivery: &mut DeliveryStats,
) -> Result<()> {
    if urls.is_empty() {
        return Ok(());
    }
    let attempts = options.retry_max_attempts.max(1);
    let sanitized_report = sanitize_report_for_external(report)?;
    let unix_ts = current_unix_ts();
    let envelope = WebhookEnvelope {
        event: "scan.completed",
        unix_ts,
        repo: telemetry_repo,
        report: &sanitized_report,
    };
    let payload_value = serde_json::to_value(&envelope)?;
    let payload_raw = mask_sensitive(serde_json::to_string(&envelope)?.as_str());
    let body = payload_raw.as_bytes().to_vec();
    let timestamp = unix_ts.to_string();
    let signature =
        resolve_webhook_signature(options.secret_env, timestamp.as_bytes(), body.as_slice())?;
    let client = Client::builder()
        .timeout(Duration::from_millis(options.timeout_ms))
        .build()
        .context("failed to build webhook client")?;
    for url in urls {
        delivery.webhook_attempted += 1;
        let safe_url = redacted_endpoint(url.as_str());
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            HeaderName::from_static("x-patchgate-event"),
            HeaderValue::from_static("scan.completed"),
        );
        headers.insert(
            HeaderName::from_static("x-patchgate-timestamp"),
            HeaderValue::from_str(timestamp.as_str())?,
        );
        headers.insert(
            HeaderName::from_static("x-patchgate-signature"),
            HeaderValue::from_str(signature.as_str())?,
        );
        headers.insert(
            HeaderName::from_static("x-patchgate-idempotency-key"),
            HeaderValue::from_str(options.idempotency_key)?,
        );
        let mut replay_headers = BTreeMap::new();
        replay_headers.insert(
            "X-Patchgate-Event".to_string(),
            "scan.completed".to_string(),
        );
        replay_headers.insert("X-Patchgate-Timestamp".to_string(), timestamp.clone());
        replay_headers.insert("X-Patchgate-Signature".to_string(), signature.clone());

        let mut last_error: Option<anyhow::Error> = None;
        for attempt in 1..=attempts {
            let response = client
                .post(url)
                .headers(headers.clone())
                .body(body.clone())
                .send();
            match response {
                Ok(resp) if resp.status().is_success() => {
                    delivery.webhook_succeeded += 1;
                    last_error = None;
                    break;
                }
                Ok(resp) => {
                    last_error = Some(anyhow!(
                        "webhook endpoint returned {} for {}",
                        resp.status(),
                        safe_url
                    ));
                }
                Err(err) => {
                    last_error =
                        Some(anyhow!(err).context(format!("webhook request failed: {safe_url}")));
                }
            }
            if attempt < attempts {
                let delay = 250u64.saturating_mul(2u64.saturating_pow((attempt - 1) as u32));
                thread::sleep(Duration::from_millis(delay.min(10_000)));
            }
        }
        if let Some(err) = last_error {
            delivery.webhook_failed += 1;
            let error_message = format!("{err:#}");
            if let Err(dead_err) = append_dead_letter(
                options.dead_letter_path,
                DeadLetterWriteOptions {
                    transport: "webhook",
                    endpoint: url,
                    idempotency_key: options.idempotency_key,
                    error: error_message.as_str(),
                    payload: &payload_value,
                    headers: Some(&replay_headers),
                    payload_raw: Some(payload_raw.as_str()),
                },
            ) {
                eprintln!("warning: failed to write dead-letter record: {dead_err:#}");
            }
            return Err(err);
        }
    }
    Ok(())
}

fn resolve_webhook_signature(secret_env: &str, timestamp: &[u8], body: &[u8]) -> Result<String> {
    if secret_env.trim().is_empty() {
        return Err(anyhow!(
            "webhook secret env var name is empty; set --webhook-secret-env or integrations.webhook.secret_env"
        ));
    }
    let secret = std::env::var(secret_env)
        .with_context(|| format!("missing webhook secret env var: {secret_env}"))?;
    sign_webhook_payload(secret.as_bytes(), timestamp, body)
}

fn dispatch_notifications(
    telemetry_repo: &str,
    report: &Report,
    targets: &[ResolvedNotificationTarget],
    options: NotificationDispatchOptions<'_>,
    delivery: &mut DeliveryStats,
) -> Result<()> {
    let attempts = options.retry_max_attempts.max(1);
    let client = Client::builder()
        .timeout(Duration::from_millis(options.timeout_ms))
        .build()
        .context("failed to build notifications client")?;

    for target in targets {
        delivery.notification_attempted += 1;
        let safe_url = redacted_endpoint(target.url.as_str());
        let mut payload = notification_payload(target.kind, telemetry_repo, report)?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "idempotency_key".to_string(),
                Value::String(options.idempotency_key.to_string()),
            );
        }
        let payload_raw = mask_sensitive(serde_json::to_string(&payload)?.as_str());
        let body = payload_raw.as_bytes().to_vec();
        let mut last_error: Option<anyhow::Error> = None;
        for attempt in 1..=attempts {
            let response = client
                .post(target.url.as_str())
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send();
            match response {
                Ok(resp) if resp.status().is_success() => {
                    last_error = None;
                    break;
                }
                Ok(resp) => {
                    last_error = Some(anyhow!(
                        "target `{}` ({}) returned status {}",
                        target.name,
                        safe_url,
                        resp.status()
                    ));
                }
                Err(err) => {
                    last_error = Some(anyhow!(err).context(format!(
                        "target `{}` ({}) request failed",
                        target.name, safe_url
                    )));
                }
            }
            if attempt < attempts {
                let delay = options
                    .retry_backoff_ms
                    .saturating_mul(2u64.saturating_pow((attempt - 1) as u32));
                thread::sleep(Duration::from_millis(delay.min(10_000)));
            }
        }
        if let Some(err) = last_error {
            delivery.notification_failed += 1;
            let error_message = format!("{err:#}");
            if let Err(dead_err) = append_dead_letter(
                options.dead_letter_path,
                DeadLetterWriteOptions {
                    transport: "notification",
                    endpoint: target.url.as_str(),
                    idempotency_key: options.idempotency_key,
                    error: error_message.as_str(),
                    payload: &payload,
                    headers: None,
                    payload_raw: Some(payload_raw.as_str()),
                },
            ) {
                eprintln!("warning: failed to write dead-letter record: {dead_err:#}");
            }
            return Err(err);
        }
        delivery.notification_succeeded += 1;
    }
    Ok(())
}

fn notification_payload(
    kind: NotificationKind,
    telemetry_repo: &str,
    report: &Report,
) -> Result<Value> {
    let summary = format!(
        "patchgate {}: score {}/{} (mode={}, scope={})",
        telemetry_repo, report.score, report.threshold, report.mode, report.scope
    );
    let payload = match kind {
        NotificationKind::Slack => serde_json::json!({
            "text": summary,
            "attachments": [
                {
                    "color": if report.should_fail { "danger" } else { "good" },
                    "fields": [
                        {"title": "findings", "value": report.findings.len().to_string(), "short": true},
                        {"title": "priority", "value": format!("{:?}", report.review_priority), "short": true}
                    ]
                }
            ],
        }),
        NotificationKind::Teams => serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "patchgate scan notification",
            "text": summary,
            "sections": [
                {
                    "facts": [
                        {"name": "findings", "value": report.findings.len().to_string()},
                        {"name": "priority", "value": format!("{:?}", report.review_priority)}
                    ]
                }
            ],
        }),
        NotificationKind::Generic => serde_json::json!({
            "event": "scan.completed.notification",
            "repo": telemetry_repo,
            "summary": {
                "score": report.score,
                "threshold": report.threshold,
                "should_fail": report.should_fail,
                "mode": report.mode,
                "scope": report.scope,
                "review_priority": format!("{:?}", report.review_priority),
                "findings": report.findings.len(),
            },
        }),
    };
    Ok(payload)
}

fn sanitize_report_for_external(report: &Report) -> Result<Report> {
    let mut value = serde_json::to_value(report).context("failed to encode report")?;
    mask_json_string_values(&mut value);
    serde_json::from_value(value).context("failed to decode sanitized report")
}

fn mask_json_string_values(value: &mut Value) {
    match value {
        Value::String(s) => {
            *s = mask_sensitive(s.as_str());
        }
        Value::Array(values) => {
            for item in values {
                mask_json_string_values(item);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                mask_json_string_values(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn sign_webhook_payload(secret: &[u8], timestamp: &[u8], body: &[u8]) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(secret).context("failed to initialize webhook signer")?;
    mac.update(timestamp);
    mac.update(b".");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    Ok(format!("sha256={}", encode_hex(digest.as_slice())))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn redacted_endpoint(raw_url: &str) -> String {
    match Url::parse(raw_url) {
        Ok(url) => {
            let mut output = format!("{}://", url.scheme());
            if let Some(host) = url.host_str() {
                output.push_str(host);
            } else {
                output.push_str("<host>");
            }
            if let Some(port) = url.port() {
                output.push_str(format!(":{port}").as_str());
            }
            output.push_str("/***");
            output
        }
        Err(_) => "<redacted-url>".to_string(),
    }
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

fn apply_changed_file_overrides(
    cfg: &mut Config,
    max_changed_files: Option<u32>,
    on_exceed: Option<&str>,
) -> ScanResult<()> {
    if let Some(limit) = max_changed_files {
        if limit == 0 {
            return Err(ScanError::new(
                ScanErrorKind::Input,
                anyhow!("invalid value for scan.max_changed_files from cli: `0` (expected: > 0)"),
            ));
        }
        cfg.scope.max_changed_files = limit;
    }
    if let Some(mode) = on_exceed {
        match mode {
            "fail_open" | "fail_closed" => {
                cfg.scope.on_exceed = mode.to_string();
            }
            _ => {
                return Err(ScanError::new(
                    ScanErrorKind::Input,
                    anyhow!(
                        "invalid value for scan.on_exceed from cli: `{mode}` (expected: fail_open|fail_closed)"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn changed_file_limit_fail_open_report(
    cfg: &Config,
    opts: &ResolvedScanOptions,
    fingerprint: &str,
    changed_files: usize,
    duration_ms: u128,
) -> Report {
    let checks = vec![
        CheckScore {
            check: CheckId::TestGap,
            label: CheckId::TestGap.label().to_string(),
            penalty: 0,
            max_penalty: cfg.weights.test_gap_max_penalty,
            triggered: false,
        },
        CheckScore {
            check: CheckId::DangerousChange,
            label: CheckId::DangerousChange.label().to_string(),
            penalty: 0,
            max_penalty: cfg.weights.dangerous_change_max_penalty,
            triggered: true,
        },
        CheckScore {
            check: CheckId::DependencyUpdate,
            label: CheckId::DependencyUpdate.label().to_string(),
            penalty: 0,
            max_penalty: cfg.weights.dependency_update_max_penalty,
            triggered: false,
        },
    ];
    let findings = vec![Finding {
        id: "SC-001".to_string(),
        rule_id: "SC-001".to_string(),
        category: "scale_guard".to_string(),
        docs_url:
            "https://github.com/mt4110/patchgate/blob/main/docs/03_cli_reference.md#patchgate-scan"
                .to_string(),
        check: CheckId::DangerousChange,
        title: "Changed file limit exceeded (fail-open)".to_string(),
        message: format!(
            "changed files ({changed_files}) exceeded max_changed_files ({}). check evaluation skipped due to fail-open.",
            cfg.scope.max_changed_files
        ),
        severity: Severity::Low,
        penalty: 0,
        location: None,
        tags: vec!["scale".to_string(), "file-limit".to_string(), "fail-open".to_string()],
    }];
    let mut report = Report::new(
        findings,
        checks,
        ReportMeta {
            threshold: cfg.output.fail_threshold,
            mode: opts.mode.clone(),
            scope: opts.scope.as_str().to_string(),
            fingerprint: fingerprint.to_string(),
            duration_ms,
            skipped_by_cache: false,
        },
    );
    report.changed_files = changed_files;
    report
}

fn write_scan_profile(path: &Path, profile: &ScanProfile) -> ScanResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            ScanError::new(
                ScanErrorKind::Output,
                anyhow!("failed to create profile directory: {parent:?}: {err}"),
            )
        })?;
    }
    let pretty = serde_json::to_string_pretty(profile).map_err(|err| {
        ScanError::new(
            ScanErrorKind::Output,
            anyhow!("failed to encode scan profile json: {err}"),
        )
    })?;
    fs::write(path, pretty).map_err(|err| {
        ScanError::new(
            ScanErrorKind::Output,
            anyhow!("failed to write scan profile: {path:?}: {err}"),
        )
    })?;
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

fn open_cache_connection(repo_root: &Path, db_path: &str) -> Result<Connection> {
    let db_full_path = repo_root.join(db_path);
    if let Some(parent) = db_full_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_full_path)?;
    init_cache_table(&conn)?;
    Ok(conn)
}

fn load_cache_from_conn(
    conn: &Connection,
    diff_fingerprint: &str,
    policy_hash: &str,
    mode: &str,
    scope: &str,
) -> Result<Option<Report>> {
    let cache_key = build_cache_key(diff_fingerprint, policy_hash, mode, scope);
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

fn store_cache_to_conn(conn: &Connection, report: &Report, policy_hash: &str) -> Result<()> {
    let cache_key = build_cache_key(
        &report.fingerprint,
        policy_hash,
        &report.mode,
        &report.scope,
    );
    let report_json = serde_json::to_string(report)?;
    let tx = conn.unchecked_transaction()?;
    tx.execute(
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
    tx.commit()?;
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
    println!("Changed files: {}", report.changed_files);
    if !report.diagnostic_hints.is_empty() {
        println!("Diagnostics:");
        for hint in &report.diagnostic_hints {
            println!("- {hint}");
        }
    }
    if !report.supply_chain_signals.is_empty() {
        println!("Supply-chain signals:");
        for signal in &report.supply_chain_signals {
            println!(
                "- {} [{}] {}",
                signal.id,
                format!("{:?}", signal.severity).to_uppercase(),
                signal.title
            );
        }
    }
    if !report.plugin_invocations.is_empty() {
        println!("Plugin invocations:");
        for invocation in &report.plugin_invocations {
            println!(
                "- {} status={:?} duration={}ms findings={}",
                invocation.plugin_id,
                invocation.status,
                invocation.duration_ms,
                invocation.findings.len()
            );
            if let Some(err) = invocation.error.as_ref() {
                println!("  error: {err}");
            }
        }
    }
    if !report.check_durations_ms.is_empty() {
        let mut entries: Vec<String> = report
            .check_durations_ms
            .iter()
            .map(|(k, v)| format!("{k}={v}ms"))
            .collect();
        entries.sort();
        println!("Check timings: {}", entries.join(", "));
    }

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
    lines.push(format!("- Changed files: `{}`", report.changed_files));
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
    if !report.supply_chain_signals.is_empty() {
        lines.push(format!(
            "- Supply-chain signals: {}",
            report.supply_chain_signals.len()
        ));
    }
    if !report.plugin_invocations.is_empty() {
        lines.push(format!(
            "- Plugin invocations: {}",
            report.plugin_invocations.len()
        ));
    }
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
    lines.push("### PR template hints".to_string());
    if sorted_findings.is_empty() {
        lines.push("- No action items".to_string());
    } else {
        for finding in sorted_findings.iter().take(5) {
            lines.push(finding.pr_template_hint());
        }
    }

    lines.push(String::new());
    lines.push("### Diagnostic hints".to_string());
    if report.diagnostic_hints.is_empty() {
        lines.push("- No hints".to_string());
    } else {
        for hint in &report.diagnostic_hints {
            lines.push(format!("- {hint}"));
        }
    }

    lines.push(String::new());
    lines.push("### Supply-chain signals".to_string());
    if report.supply_chain_signals.is_empty() {
        lines.push("- No signals".to_string());
    } else {
        for signal in &report.supply_chain_signals {
            lines.push(format!(
                "- **{}** [{}] {}",
                signal.title,
                format!("{:?}", signal.severity).to_uppercase(),
                signal.message
            ));
            if !signal.related_files.is_empty() {
                lines.push(format!(
                    "  - related files: {}",
                    signal.related_files.join(", ")
                ));
            }
        }
    }

    lines.push(String::new());
    lines.push("### Plugin invocations".to_string());
    if report.plugin_invocations.is_empty() {
        lines.push("- No plugin invocations".to_string());
    } else {
        for invocation in &report.plugin_invocations {
            lines.push(format!(
                "- **{}** status=`{:?}` duration=`{}ms` findings=`{}` sandbox=`{}`",
                invocation.plugin_id,
                invocation.status,
                invocation.duration_ms,
                invocation.findings.len(),
                invocation.sandbox_profile
            ));
            if let Some(err) = invocation.error.as_ref() {
                lines.push(format!("  - error: {}", mask_sensitive(err.as_str())));
            }
        }
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
    use std::collections::BTreeMap;
    use std::env;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    use patchgate_config::Config;
    use patchgate_core::{CheckId, CheckScore, Finding, Report, ReportMeta, Severity};
    use patchgate_github::PublishAuth;

    use super::{
        append_dead_letter, append_scan_failure_records, apply_changed_file_overrides,
        apply_policy_autofixes, apply_threshold_override, assess_v1_readiness, build_cache_key,
        build_delivery_idempotency_key, build_history_summary, build_history_trend,
        changed_file_limit_fail_open_report, ci_template_catalog, detect_head_sha_from_env,
        detect_pr_number_from_env, detect_sandbox_capabilities, gate_exit_code,
        is_likely_cache_corruption, load_dead_letter_jsonl, load_policy_config,
        notification_payload, parse_mode, parse_policy_preset, parse_scope,
        pr_head_sha_from_event_payload, pr_number_from_event_payload, pr_number_from_ref,
        publish_generic_ci_payload, recover_cache_db, redacted_endpoint, render_github_comment,
        resolve_audit_actor, resolve_ci_provider, resolve_ci_provider_for_publish,
        resolve_comment_suppression_reason, resolve_config_path, resolve_policy_path,
        resolve_publish_request, resolve_scan_options, resolve_telemetry_repo,
        resolve_webhook_signature, run_dead_letter_replay, run_plugin_init, run_policy_lint,
        run_policy_verify_v1, sign_webhook_payload, sorted_findings_for_comment, write_text_atomic,
        CiProvider, DeadLetterWriteOptions, DeliveryReplayArgs, FailureCode, NotificationKind,
        OptionSource, PluginInitArgs, PolicyAutofix, PolicyExitCode, PolicyLintArgs,
        PolicyVerifyV1Args, PublishRequestInput, ReadinessProfile, ResolvedScanOptions,
        RetryPolicy, ScanArgs, ScanError, ScanErrorKind, ScanMetricRecord, ScopeMode,
    };

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock poisoned")
    }

    fn spawn_http_ok_server(expected_requests: usize) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let handle = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().expect("accept test connection");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set read timeout");
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer);
                let body = "ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write test response");
            }
        });
        (format!("http://{}", addr), handle)
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

    fn default_scan_args() -> ScanArgs {
        ScanArgs {
            policy_preset: None,
            format: None,
            scope: None,
            mode: None,
            threshold: None,
            max_changed_files: None,
            on_exceed: None,
            no_cache: false,
            profile_output: None,
            metrics_output: None,
            audit_log_output: None,
            audit_actor: None,
            github_comment: None,
            github_publish: false,
            github_repo: None,
            github_pr: None,
            github_sha: None,
            github_token_env: None,
            github_check_name: None,
            github_auth: None,
            github_app_token_env: None,
            github_retry_max_attempts: 3,
            github_retry_backoff_ms: 300,
            github_retry_max_backoff_ms: 3000,
            github_dry_run: false,
            github_dry_run_output: None,
            github_no_comment: false,
            github_no_check_run: false,
            github_apply_labels: false,
            github_suppress_comment_no_change: false,
            github_suppress_comment_low_priority: false,
            github_suppress_comment_rerun: false,
            publish: false,
            ci_provider: None,
            ci_generic_output: None,
            webhook_urls: Vec::new(),
            webhook_secret_env: None,
            webhook_timeout_ms: None,
            webhook_retry_max_attempts: None,
            notify_targets: Vec::new(),
            notify_retry_max_attempts: None,
            notify_retry_backoff_ms: None,
            notify_timeout_ms: None,
            dead_letter_output: None,
        }
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

        let req = resolve_publish_request(PublishRequestInput {
            github_repo: Some("cli/repo".to_string()),
            github_pr: Some(12),
            github_sha: Some("cli-sha".to_string()),
            github_token_env: None,
            github_check_name: Some("cli-check".to_string()),
            github_auth: Some("token".to_string()),
            github_app_token_env: None,
            retry_policy: RetryPolicy::default(),
            github_dry_run: false,
            publish_comment: true,
            publish_check_run: true,
            apply_priority_label: false,
            suppressed_comment_reason: None,
        })
        .expect("resolve publish request");

        assert_eq!(req.repo, "cli/repo");
        assert_eq!(req.pr_number, 12);
        assert_eq!(req.head_sha, "cli-sha");
        assert_eq!(req.check_name, "cli-check");
        match req.auth {
            PublishAuth::Token { token } => assert_eq!(token, "env-token"),
            _ => panic!("expected token auth"),
        }

        env::remove_var("GITHUB_REPOSITORY");
        env::remove_var("GITHUB_REF");
        env::remove_var("GITHUB_SHA");
        env::remove_var("GITHUB_TOKEN");
    }

    #[test]
    fn resolve_telemetry_repo_prefers_cli_override() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_REPOSITORY"]);
        env::set_var("GITHUB_REPOSITORY", "env/repo");

        let repo =
            resolve_telemetry_repo(PathBuf::from("/tmp/local-repo").as_path(), Some("cli/repo"));
        assert_eq!(repo, "cli/repo");

        env::remove_var("GITHUB_REPOSITORY");
    }

    #[test]
    fn resolve_telemetry_repo_falls_back_to_env_then_path() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_REPOSITORY"]);

        env::set_var("GITHUB_REPOSITORY", "env/repo");
        let from_env = resolve_telemetry_repo(PathBuf::from("/tmp/local-repo").as_path(), None);
        assert_eq!(from_env, "env/repo");

        env::remove_var("GITHUB_REPOSITORY");
        let from_path = resolve_telemetry_repo(PathBuf::from("/tmp/local-repo").as_path(), None);
        assert_eq!(from_path, "local/local-repo");
    }

    #[test]
    fn resolve_telemetry_repo_uses_local_when_repo_name_unavailable() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_REPOSITORY"]);
        env::remove_var("GITHUB_REPOSITORY");

        let from_root = resolve_telemetry_repo(PathBuf::from("/").as_path(), None);
        assert_eq!(from_root, "local");
    }

    #[test]
    fn resolve_audit_actor_uses_username_when_user_missing() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_ACTOR", "USER", "USERNAME"]);
        env::remove_var("GITHUB_ACTOR");
        env::remove_var("USER");
        env::set_var("USERNAME", "windows-user");

        assert_eq!(resolve_audit_actor(None), "windows-user");
    }

    #[test]
    fn failure_telemetry_uses_resolved_mode_and_scope_from_config_defaults() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&["GITHUB_REPOSITORY"]);
        env::remove_var("GITHUB_REPOSITORY");

        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-failure-telemetry-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");

        let mut config_path = repo_root.clone();
        config_path.push("policy.toml");
        fs::write(
            &config_path,
            "policy_version = 2\n[output]\nmode = \"enforce\"\n[scope]\nmode = \"repo\"\n",
        )
        .expect("write policy");

        let mut metrics_path = repo_root.clone();
        metrics_path.push("metrics.jsonl");
        let mut audit_path = repo_root.clone();
        audit_path.push("audit.jsonl");

        let mut scan = default_scan_args();
        scan.metrics_output = Some(metrics_path.clone());
        scan.audit_log_output = Some(audit_path.clone());
        scan.mode = None;
        scan.scope = None;

        let err = ScanError::with_code(
            ScanErrorKind::Runtime,
            FailureCode::RuntimeEvaluationFailed,
            anyhow::anyhow!("boom"),
        );
        append_scan_failure_records(&repo_root, Some(&config_path), &scan, &err)
            .expect("append failure telemetry");

        let metric_line = fs::read_to_string(&metrics_path)
            .expect("read metrics")
            .lines()
            .next()
            .expect("metrics line")
            .to_string();
        let metric: serde_json::Value =
            serde_json::from_str(&metric_line).expect("decode metrics json");
        assert_eq!(metric.get("mode").and_then(|v| v.as_str()), Some("enforce"));
        assert_eq!(metric.get("scope").and_then(|v| v.as_str()), Some("repo"));

        let audit_line = fs::read_to_string(&audit_path)
            .expect("read audit")
            .lines()
            .next()
            .expect("audit line")
            .to_string();
        let audit: serde_json::Value = serde_json::from_str(&audit_line).expect("decode audit");
        assert_eq!(audit.get("mode").and_then(|v| v.as_str()), Some("enforce"));
        assert_eq!(audit.get("scope").and_then(|v| v.as_str()), Some("repo"));

        let _ = fs::remove_file(metrics_path);
        let _ = fs::remove_file(audit_path);
        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir_all(repo_root);
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

        let req = resolve_publish_request(PublishRequestInput {
            github_repo: None,
            github_pr: None,
            github_sha: None,
            github_token_env: None,
            github_check_name: None,
            github_auth: None,
            github_app_token_env: None,
            retry_policy: RetryPolicy::default(),
            github_dry_run: false,
            publish_comment: true,
            publish_check_run: true,
            apply_priority_label: false,
            suppressed_comment_reason: None,
        })
        .expect("resolve from env");
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

        let req = resolve_publish_request(PublishRequestInput {
            github_repo: None,
            github_pr: None,
            github_sha: None,
            github_token_env: None,
            github_check_name: None,
            github_auth: None,
            github_app_token_env: None,
            retry_policy: RetryPolicy::default(),
            github_dry_run: false,
            publish_comment: true,
            publish_check_run: true,
            apply_priority_label: false,
            suppressed_comment_reason: None,
        })
        .expect("resolve from env");
        assert_eq!(req.pr_number, 42);
        assert_eq!(req.head_sha, "fallback-sha-42");

        env::remove_var("GITHUB_EVENT_PATH");
        env::remove_var("GITHUB_REPOSITORY");
        env::remove_var("GITHUB_SHA");
        env::remove_var("GITHUB_TOKEN");
        let _ = fs::remove_file(event_path);
    }

    #[test]
    fn resolve_publish_request_supports_app_auth() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&[
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_SHA",
            "GITHUB_APP_INSTALLATION_TOKEN",
            "GITHUB_APP_ID",
        ]);
        env::set_var("GITHUB_REPOSITORY", "env/repo");
        env::set_var("GITHUB_REF", "refs/pull/42/merge");
        env::set_var("GITHUB_SHA", "sha42");
        env::set_var("GITHUB_APP_INSTALLATION_TOKEN", "app-token");
        env::set_var("GITHUB_APP_ID", "12345");

        let req = resolve_publish_request(PublishRequestInput {
            github_repo: None,
            github_pr: None,
            github_sha: None,
            github_token_env: None,
            github_check_name: None,
            github_auth: Some("app".to_string()),
            github_app_token_env: None,
            retry_policy: RetryPolicy::default(),
            github_dry_run: false,
            publish_comment: true,
            publish_check_run: true,
            apply_priority_label: false,
            suppressed_comment_reason: None,
        })
        .expect("resolve app auth");

        match req.auth {
            PublishAuth::App {
                installation_token,
                app_id,
            } => {
                assert_eq!(installation_token, "app-token");
                assert_eq!(app_id.as_deref(), Some("12345"));
            }
            _ => panic!("expected app auth"),
        }
    }

    #[test]
    fn resolve_publish_request_allows_dry_run_without_token() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&[
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_SHA",
            "GITHUB_TOKEN",
        ]);
        env::set_var("GITHUB_REPOSITORY", "env/repo");
        env::set_var("GITHUB_REF", "refs/pull/7/merge");
        env::set_var("GITHUB_SHA", "sha7");
        env::remove_var("GITHUB_TOKEN");

        let req = resolve_publish_request(PublishRequestInput {
            github_repo: None,
            github_pr: None,
            github_sha: None,
            github_token_env: None,
            github_check_name: None,
            github_auth: None,
            github_app_token_env: None,
            retry_policy: RetryPolicy::default(),
            github_dry_run: true,
            publish_comment: true,
            publish_check_run: true,
            apply_priority_label: false,
            suppressed_comment_reason: None,
        })
        .expect("dry run should not require token");

        match req.auth {
            PublishAuth::Token { token } => assert_eq!(token, "<dry-run-token>"),
            _ => panic!("expected token auth"),
        }
    }

    #[test]
    fn resolve_publish_request_allows_comment_only_without_head_sha() {
        let _guard = env_lock();
        let _env_snapshot = EnvSnapshot::capture(&[
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_EVENT_PATH",
            "GITHUB_SHA",
            "GITHUB_TOKEN",
        ]);
        env::set_var("GITHUB_REPOSITORY", "env/repo");
        env::set_var("GITHUB_REF", "refs/pull/7/merge");
        env::remove_var("GITHUB_EVENT_PATH");
        env::remove_var("GITHUB_SHA");
        env::set_var("GITHUB_TOKEN", "env-token");

        let req = resolve_publish_request(PublishRequestInput {
            github_repo: None,
            github_pr: None,
            github_sha: None,
            github_token_env: None,
            github_check_name: None,
            github_auth: None,
            github_app_token_env: None,
            retry_policy: RetryPolicy::default(),
            github_dry_run: false,
            publish_comment: true,
            publish_check_run: false,
            apply_priority_label: false,
            suppressed_comment_reason: None,
        })
        .expect("comment-only publish should not require head sha");

        assert_eq!(req.head_sha, "");
        assert!(!req.publish_check_run);
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
            "patchgate scan error [input:PG-IN-001]: invalid value for scan.scope from cli: `all` (expected: staged|worktree|repo)"
        );
    }

    #[test]
    fn invalid_config_mode_is_config_error() {
        let err = parse_mode("strict", OptionSource::Config).expect_err("mode should be rejected");
        assert_eq!(err.kind(), ScanErrorKind::Config);
        assert_eq!(err.exit_code(), 3);
        assert_eq!(
            err.render(),
            "patchgate scan error [config:PG-CFG-001]: invalid value for scan.mode from config: `strict` (expected: warn|enforce)"
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
    fn history_trend_excludes_unscored_rows_from_average_score() {
        let mut penalties = BTreeMap::new();
        penalties.insert("test_gap".to_string(), 10);
        let records = vec![
            ScanMetricRecord {
                schema_version: 1,
                unix_ts: 86_400,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 10,
                changed_files: 1,
                skipped_by_cache: false,
                score: Some(80),
                threshold: Some(70),
                should_fail: Some(false),
                check_penalties: penalties.clone(),
                failure_code: None,
                failure_category: None,
                diagnostic_hints: vec![],
            },
            ScanMetricRecord {
                schema_version: 1,
                unix_ts: 86_401,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 15,
                changed_files: 0,
                skipped_by_cache: false,
                score: None,
                threshold: None,
                should_fail: None,
                check_penalties: penalties,
                failure_code: Some("PG-RT-001".to_string()),
                failure_category: Some("runtime".to_string()),
                diagnostic_hints: vec![],
            },
        ];

        let trend = build_history_trend(&records);
        let row = trend
            .iter()
            .find(|r| r.key.contains("check:test_gap"))
            .expect("test_gap row");
        assert_eq!(row.runs, 2);
        assert_eq!(row.failure_rate, 50.0);
        assert_eq!(row.average_duration_ms, 10.0);
        assert_eq!(row.average_score, 80.0);
    }

    #[test]
    fn history_summary_excludes_execution_error_rows_from_duration_average() {
        let records = vec![
            ScanMetricRecord {
                schema_version: 1,
                unix_ts: 86_400,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 12,
                changed_files: 1,
                skipped_by_cache: false,
                score: Some(90),
                threshold: Some(70),
                should_fail: Some(false),
                check_penalties: BTreeMap::new(),
                failure_code: None,
                failure_category: None,
                diagnostic_hints: vec![],
            },
            ScanMetricRecord {
                schema_version: 1,
                unix_ts: 86_401,
                repo: "repo".to_string(),
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                duration_ms: 0,
                changed_files: 0,
                skipped_by_cache: false,
                score: None,
                threshold: None,
                should_fail: None,
                check_penalties: BTreeMap::new(),
                failure_code: Some("PG-RT-001".to_string()),
                failure_category: Some("runtime".to_string()),
                diagnostic_hints: vec![],
            },
        ];

        let summary = build_history_summary(&records, None, &Config::default().alerts);
        assert_eq!(summary.failure_rate, 50.0);
        assert_eq!(summary.average_duration_ms, 12.0);
    }

    #[test]
    fn history_trend_ignores_non_triggered_check_penalty_keys() {
        let mut penalties = BTreeMap::new();
        penalties.insert("test_gap".to_string(), 0);
        penalties.insert("dangerous_change".to_string(), 0);
        let records = vec![ScanMetricRecord {
            schema_version: 1,
            unix_ts: 86_400,
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 7,
            changed_files: 1,
            skipped_by_cache: false,
            score: Some(100),
            threshold: Some(70),
            should_fail: Some(false),
            check_penalties: penalties,
            failure_code: None,
            failure_category: None,
            diagnostic_hints: vec![],
        }];

        let trend = build_history_trend(&records);
        assert_eq!(trend.len(), 1);
        assert!(trend[0].key.contains("check:none"));
    }

    #[test]
    fn history_trend_only_counts_triggered_checks_when_mixed_penalties_exist() {
        let mut penalties = BTreeMap::new();
        penalties.insert("test_gap".to_string(), 12);
        penalties.insert("dangerous_change".to_string(), 0);
        let records = vec![ScanMetricRecord {
            schema_version: 1,
            unix_ts: 86_400,
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 9,
            changed_files: 2,
            skipped_by_cache: false,
            score: Some(88),
            threshold: Some(70),
            should_fail: Some(true),
            check_penalties: penalties,
            failure_code: None,
            failure_category: None,
            diagnostic_hints: vec![],
        }];

        let trend = build_history_trend(&records);
        assert_eq!(trend.len(), 1);
        assert!(trend[0].key.contains("check:test_gap"));
        assert!(!trend[0].key.contains("dangerous_change"));
    }

    #[test]
    fn history_summary_does_not_alert_duration_when_baseline_has_no_successful_runs() {
        let baseline = vec![ScanMetricRecord {
            schema_version: 1,
            unix_ts: 86_400,
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 0,
            changed_files: 0,
            skipped_by_cache: false,
            score: None,
            threshold: None,
            should_fail: None,
            check_penalties: BTreeMap::new(),
            failure_code: Some("PG-RT-001".to_string()),
            failure_category: Some("runtime".to_string()),
            diagnostic_hints: vec![],
        }];
        let current = vec![ScanMetricRecord {
            schema_version: 1,
            unix_ts: 86_500,
            repo: "repo".to_string(),
            mode: "warn".to_string(),
            scope: "staged".to_string(),
            duration_ms: 20,
            changed_files: 2,
            skipped_by_cache: false,
            score: Some(95),
            threshold: Some(70),
            should_fail: Some(false),
            check_penalties: BTreeMap::new(),
            failure_code: None,
            failure_category: None,
            diagnostic_hints: vec![],
        }];
        let alerts_cfg = patchgate_config::AlertConfig {
            score_drop_threshold: 99,
            failure_rate_increase_pct: 99,
            duration_increase_pct: 1,
        };

        let summary = build_history_summary(&current, Some(&baseline), &alerts_cfg);
        assert!(
            summary.alerts.is_empty(),
            "unexpected alerts: {:?}",
            summary.alerts
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
    fn changed_file_override_rejects_invalid_values() {
        let mut cfg = Config::default();
        let err =
            apply_changed_file_overrides(&mut cfg, Some(0), None).expect_err("must reject zero");
        assert_eq!(err.kind(), ScanErrorKind::Input);

        let err = apply_changed_file_overrides(&mut cfg, None, Some("warn"))
            .expect_err("must reject unknown on_exceed");
        assert_eq!(err.kind(), ScanErrorKind::Input);
    }

    #[test]
    fn fail_open_limit_report_is_non_failing_and_has_marker_finding() {
        let cfg = Config::default();
        let opts = ResolvedScanOptions {
            format: "json".to_string(),
            mode: "enforce".to_string(),
            scope: ScopeMode::Worktree,
        };
        let report = changed_file_limit_fail_open_report(&cfg, &opts, "fp", 12345, 7);
        assert_eq!(report.score, 100);
        assert!(!report.should_fail);
        assert_eq!(report.changed_files, 12345);
        assert!(report.findings.iter().any(|f| f.id == "SC-001"));
        let dangerous = report
            .checks
            .iter()
            .find(|c| c.check == CheckId::DangerousChange)
            .expect("dangerous_change check exists");
        assert!(dangerous.triggered);
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
    fn policy_lint_requires_existing_policy_file() {
        let mut repo_root = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        repo_root.push(format!("patchgate-cli-policy-lint-missing-{ts}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let code = run_policy_lint(
            &repo_root,
            None,
            PolicyLintArgs {
                path: None,
                policy_preset: None,
                require_current_version: false,
            },
        );
        assert_eq!(code, PolicyExitCode::ReadOrParse);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_requires_ready_flags() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v1-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = false
allow_legacy_config_names = true
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                autofix_output: None,
                autofix_write: false,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_passes_with_ready_flags() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v1-ready-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                autofix_output: None,
                autofix_write: false,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_strict_requires_isolated_sandbox_when_plugins_enabled() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v1-strict-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[plugins]
enabled = true
[plugins.sandbox]
profile = "restricted"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "strict".to_string(),
                autofix_output: None,
                autofix_write: false,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_lts_requires_lts_active() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v1-lts-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[release.lts]
active = false
security_sla_hours = 72
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "lts".to_string(),
                autofix_output: None,
                autofix_write: false,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn policy_verify_v1_strict_requires_linux_runtime_for_isolated_plugins() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!(
            "patchgate-cli-policy-verify-v1-strict-runtime-{seq}"
        ));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[plugins]
enabled = true
[plugins.sandbox]
profile = "isolated"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "strict".to_string(),
                autofix_output: None,
                autofix_write: false,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn policy_verify_v1_strict_requires_bwrap_for_isolated_plugins() {
        let _guard = env_lock();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v1-strict-bwrap-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[plugins]
enabled = true
[plugins.sandbox]
profile = "isolated"
"#,
        )
        .expect("write policy");

        super::BWRAP_AVAILABLE_OVERRIDE.store(0, Ordering::Relaxed);
        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "strict".to_string(),
                autofix_output: None,
                autofix_write: false,
            },
        );
        super::BWRAP_AVAILABLE_OVERRIDE.store(-1, Ordering::Relaxed);
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_autofix_output_writes_ready_policy_preview() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root =
            std::env::temp_dir().join(format!("patchgate-cli-policy-autofix-out-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        let output_path = repo_root.join("artifacts/policy.autofix.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = false
allow_legacy_config_names = true
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path.clone()),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                autofix_output: Some(output_path.clone()),
                autofix_write: false,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let output = fs::read_to_string(&output_path).expect("read autofix output");
        assert!(output.contains("rc_frozen = true"));
        assert!(output.contains("allow_legacy_config_names = false"));

        let recheck = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(output_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                autofix_output: None,
                autofix_write: false,
            },
        );
        assert_eq!(recheck, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_autofix_output_uses_source_filename_for_preview_warnings() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root =
            std::env::temp_dir().join(format!("patchgate-cli-policy-autofix-preview-name-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        let output_path = repo_root.join("artifacts/policy.autofix.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = false
allow_legacy_config_names = true
"#,
        )
        .expect("write policy");

        apply_policy_autofixes(
            policy_path.as_path(),
            output_path.as_path(),
            &[
                PolicyAutofix::SetRcFrozen,
                PolicyAutofix::DisableLegacyConfigNames,
            ],
        )
        .expect("write preview policy");

        let loaded = load_policy_config(Some(output_path.as_path()), None).expect("load preview");
        let assessment = assess_v1_readiness(
            policy_path.as_path(),
            &loaded.config,
            loaded.compatibility_warnings,
            ReadinessProfile::Standard,
            false,
        );

        assert!(
            !assessment
                .warnings
                .iter()
                .any(|warning| warning.contains("legacy policy filename")),
            "preview warnings should reflect the source policy filename"
        );

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_autofix_write_updates_policy_in_place() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root =
            std::env::temp_dir().join(format!("patchgate-cli-policy-autofix-write-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = false
allow_legacy_config_names = true
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path.clone()),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                autofix_output: None,
                autofix_write: true,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let output = fs::read_to_string(&policy_path).expect("read rewritten policy");
        assert!(output.contains("rc_frozen = true"));
        assert!(output.contains("allow_legacy_config_names = false"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn write_text_atomic_overwrites_existing_file() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-write-text-atomic-{seq}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("policy.toml");
        fs::write(&path, "before").expect("seed file");

        write_text_atomic(&path, "after").expect("overwrite file");

        let content = fs::read_to_string(&path).expect("read overwritten file");
        assert_eq!(content, "after");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn policy_verify_v1_strict_autofix_prefers_isolated_profile() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root =
            std::env::temp_dir().join(format!("patchgate-cli-policy-autofix-strict-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        let output_path = repo_root.join("policy.strict.autofix.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[plugins]
enabled = true
[plugins.sandbox]
profile = "none"
"#,
        )
        .expect("write policy");

        let _ = run_policy_verify_v1(
            &repo_root,
            None,
            PolicyVerifyV1Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "strict".to_string(),
                autofix_output: Some(output_path.clone()),
                autofix_write: false,
            },
        );

        let output = fs::read_to_string(&output_path).expect("read strict autofix output");
        assert!(output.contains("profile = \"isolated\""));
        assert!(!output.contains("profile = \"restricted\""));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn sandbox_capabilities_include_portable_profiles_and_template_catalog() {
        #[cfg(target_os = "linux")]
        let _guard = env_lock();
        #[cfg(target_os = "linux")]
        super::BWRAP_AVAILABLE_OVERRIDE.store(0, Ordering::Relaxed);

        let capabilities = detect_sandbox_capabilities();
        assert_eq!(capabilities.len(), 3);
        assert!(capabilities
            .iter()
            .find(|cap| cap.profile == "none")
            .is_some_and(|cap| cap.supported));
        assert!(capabilities
            .iter()
            .find(|cap| cap.profile == "restricted")
            .is_some_and(|cap| cap.supported));
        let isolated = capabilities
            .iter()
            .find(|cap| cap.profile == "isolated")
            .expect("isolated capability");
        #[cfg(target_os = "linux")]
        assert!(!isolated.supported);
        #[cfg(not(target_os = "linux"))]
        assert!(!isolated.supported);

        #[cfg(target_os = "linux")]
        super::BWRAP_AVAILABLE_OVERRIDE.store(-1, Ordering::Relaxed);

        let templates = ci_template_catalog();
        assert_eq!(templates[0], ("github", "docs/patchgate-action.yml"));
        assert_eq!(templates[1], ("gitlab", "docs/patchgate-gitlab-ci.yml"));
        assert_eq!(templates[2], ("jenkins", "docs/Jenkinsfile.patchgate"));
    }

    #[test]
    fn resolve_ci_provider_prefers_cli_value() {
        let provider = resolve_ci_provider(Some("generic"), Some("github")).expect("provider");
        assert_eq!(provider, CiProvider::Generic);
    }

    #[test]
    fn resolve_ci_provider_for_publish_prefers_github_publish_default() {
        let provider = resolve_ci_provider_for_publish(true, None, Some("generic"))
            .expect("provider for github publish");
        assert_eq!(provider, CiProvider::GitHub);
    }

    #[test]
    fn resolve_ci_provider_for_publish_keeps_explicit_cli_value() {
        let provider = resolve_ci_provider_for_publish(true, Some("generic"), Some("github"))
            .expect("explicit cli provider");
        assert_eq!(provider, CiProvider::Generic);
    }

    #[test]
    fn sign_webhook_payload_is_stable_and_prefixed() {
        let sig =
            sign_webhook_payload(b"secret", b"1700000000", br#"{"ok":true}"#).expect("signature");
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), "sha256=".len() + 64);
    }

    #[test]
    fn delivery_idempotency_key_is_stable_for_same_report() {
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
        let key1 = build_delivery_idempotency_key("example/repo", &report);
        let key2 = build_delivery_idempotency_key("example/repo", &report);
        assert_eq!(key1, key2);
        assert!(key1.starts_with("pgv1-"));
    }

    #[test]
    fn append_dead_letter_writes_jsonl_record() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-dead-letter-{seq}"));
        fs::create_dir_all(&dir).expect("create dead-letter dir");
        let path = dir.join("dead-letter.jsonl");
        let mut headers = BTreeMap::new();
        headers.insert(
            "X-Patchgate-Signature".to_string(),
            "sha256=testsignature".to_string(),
        );
        append_dead_letter(
            Some(path.as_path()),
            DeadLetterWriteOptions {
                transport: "webhook",
                endpoint: "https://hooks.example.com/***",
                idempotency_key: "pgv1-key",
                error: "test error",
                payload: &serde_json::json!({ "event": "scan.completed" }),
                headers: Some(&headers),
                payload_raw: Some("{\"event\":\"scan.completed\"}"),
            },
        )
        .expect("append dead-letter");
        let content = fs::read_to_string(&path).expect("read dead-letter file");
        assert!(content.contains("\"transport\":\"webhook\""));
        assert!(content.contains("\"idempotency_key\":\"pgv1-key\""));
        assert!(
            content.contains("\"headers\":{\"X-Patchgate-Signature\":\"sha256=testsignature\"}")
        );
        assert!(content.contains("\"payload_raw\":\"{\\\"event\\\":\\\"scan.completed\\\"}\""));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dead_letter_replay_dry_run_succeeds() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-dry-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        append_dead_letter(
            Some(input.as_path()),
            DeadLetterWriteOptions {
                transport: "notification",
                endpoint: "https://example.internal/hook",
                idempotency_key: "pgv1-replay-key",
                error: "network timeout",
                payload: &serde_json::json!({ "event": "scan.completed.notification", "summary": { "score": 90 } }),
                headers: None,
                payload_raw: None,
            },
        )
        .expect("seed dead-letter");

        run_dead_letter_replay(DeliveryReplayArgs {
            input: input.clone(),
            transport: Some("notification".to_string()),
            max_records: Some(1),
            retry_max_attempts: 1,
            retry_backoff_ms: 10,
            rewrite_input: false,
            summary_output: None,
            dry_run: true,
        })
        .expect("replay dry-run");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dead_letter_replay_rejects_unknown_transport() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-transport-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        append_dead_letter(
            Some(input.as_path()),
            DeadLetterWriteOptions {
                transport: "notification",
                endpoint: "https://example.internal/hook",
                idempotency_key: "pgv1-replay-key",
                error: "network timeout",
                payload: &serde_json::json!({ "event": "scan.completed.notification" }),
                headers: None,
                payload_raw: None,
            },
        )
        .expect("seed dead-letter");
        let err = run_dead_letter_replay(DeliveryReplayArgs {
            input: input.clone(),
            transport: Some("webhhok".to_string()),
            max_records: Some(1),
            retry_max_attempts: 1,
            retry_backoff_ms: 10,
            rewrite_input: false,
            summary_output: None,
            dry_run: true,
        })
        .expect_err("must reject unknown transport");
        assert!(format!("{err:#}").contains("invalid --transport value"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dead_letter_replay_rewrite_input_removes_successful_records_and_writes_summary() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-rewrite-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        let summary_output = dir.join("replay-summary.json");
        let (endpoint, handle) = spawn_http_ok_server(1);

        append_dead_letter(
            Some(input.as_path()),
            DeadLetterWriteOptions {
                transport: "notification",
                endpoint: endpoint.as_str(),
                idempotency_key: "pgv1-success",
                error: "network timeout",
                payload: &serde_json::json!({ "event": "scan.completed.notification" }),
                headers: None,
                payload_raw: None,
            },
        )
        .expect("seed successful replay record");
        append_dead_letter(
            Some(input.as_path()),
            DeadLetterWriteOptions {
                transport: "webhook",
                endpoint: "https://example.internal/webhook",
                idempotency_key: "pgv1-unmatched",
                error: "network timeout",
                payload: &serde_json::json!({ "event": "scan.completed" }),
                headers: None,
                payload_raw: None,
            },
        )
        .expect("seed unmatched replay record");

        run_dead_letter_replay(DeliveryReplayArgs {
            input: input.clone(),
            transport: Some("notification".to_string()),
            max_records: Some(1),
            retry_max_attempts: 1,
            retry_backoff_ms: 10,
            rewrite_input: true,
            summary_output: Some(summary_output.clone()),
            dry_run: false,
        })
        .expect("successful replay");
        handle.join().expect("join server thread");

        let remaining = fs::read_to_string(&input).expect("read rewritten dead-letter");
        assert!(!remaining.contains("pgv1-success"));
        assert!(remaining.contains("pgv1-unmatched"));

        let summary: serde_json::Value = serde_json::from_str(
            fs::read_to_string(&summary_output)
                .expect("read summary")
                .as_str(),
        )
        .expect("parse summary json");
        assert_eq!(summary["successful_records"], 1);
        assert_eq!(summary["failed_records"], 0);
        assert_eq!(summary["retained_records"], 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dead_letter_replay_keeps_failed_records_and_reports_summary() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-failed-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        let summary_output = dir.join("replay-summary.json");
        append_dead_letter(
            Some(input.as_path()),
            DeadLetterWriteOptions {
                transport: "notification",
                endpoint: "http://127.0.0.1:9/replay",
                idempotency_key: "pgv1-failed",
                error: "network timeout",
                payload: &serde_json::json!({ "event": "scan.completed.notification" }),
                headers: None,
                payload_raw: None,
            },
        )
        .expect("seed failed replay record");

        let err = run_dead_letter_replay(DeliveryReplayArgs {
            input: input.clone(),
            transport: Some("notification".to_string()),
            max_records: Some(1),
            retry_max_attempts: 1,
            retry_backoff_ms: 10,
            rewrite_input: true,
            summary_output: Some(summary_output.clone()),
            dry_run: false,
        })
        .expect_err("replay should fail");
        assert!(format!("{err:#}").contains("failed record"));

        let remaining = fs::read_to_string(&input).expect("read retained dead-letter");
        assert!(remaining.contains("pgv1-failed"));
        assert!(remaining.contains("replay request failed"));

        let summary: serde_json::Value = serde_json::from_str(
            fs::read_to_string(&summary_output)
                .expect("read summary")
                .as_str(),
        )
        .expect("parse summary json");
        assert_eq!(summary["successful_records"], 0);
        assert_eq!(summary["failed_records"], 1);
        assert_eq!(summary["retained_records"], 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_dead_letter_jsonl_applies_filter_and_limit_while_reading() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-filter-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        fs::write(
            &input,
            concat!(
                "{\"schema_version\":1,\"unix_ts\":1,\"transport\":\"notification\",\"endpoint\":\"https://example.invalid/one\",\"idempotency_key\":\"k1\",\"error\":\"timeout\",\"payload\":{\"event\":\"one\"},\"headers\":{},\"payload_raw\":null}\n",
                "{\"schema_version\":1,\"unix_ts\":2,\"transport\":\"webhook\",\"endpoint\":\"https://example.invalid/two\",\"idempotency_key\":\"k2\",\"error\":\"timeout\",\"payload\":{\"event\":\"two\"},\"headers\":{},\"payload_raw\":null}\n",
                "{\"schema_version\":1,\"unix_ts\":3,\"transport\":\"notification\",\"endpoint\":\"https://example.invalid/three\",\"idempotency_key\":\"k3\",\"error\":\"timeout\",\"payload\":{\"event\":\"three\"},\"headers\":{},\"payload_raw\":null}\n"
            ),
        )
        .expect("seed dead-letter");

        let rows = load_dead_letter_jsonl(&input, Some("notification"), Some(1))
            .expect("load filtered dead-letter");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].transport, "notification");
        assert_eq!(rows[0].idempotency_key, "k1");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_dead_letter_jsonl_rejects_unknown_schema_version() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-schema-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        fs::write(
            &input,
            "{\"schema_version\":2,\"unix_ts\":1,\"transport\":\"notification\",\"endpoint\":\"https://example.invalid/one\",\"idempotency_key\":\"k1\",\"error\":\"timeout\",\"payload\":{\"event\":\"one\"},\"headers\":{},\"payload_raw\":null}\n",
        )
        .expect("seed dead-letter");

        let err = load_dead_letter_jsonl(&input, None, None).expect_err("must reject schema");
        assert!(format!("{err:#}").contains("unsupported dead-letter schema_version 2"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_dead_letter_jsonl_rejects_unknown_transport_rows() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-row-transport-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        fs::write(
            &input,
            "{\"schema_version\":1,\"unix_ts\":1,\"transport\":\"email\",\"endpoint\":\"https://example.invalid/one\",\"idempotency_key\":\"k1\",\"error\":\"timeout\",\"payload\":{\"event\":\"one\"},\"headers\":{},\"payload_raw\":null}\n",
        )
        .expect("seed dead-letter");

        let err = load_dead_letter_jsonl(&input, None, None).expect_err("must reject transport");
        assert!(format!("{err:#}").contains("unsupported dead-letter transport `email`"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_webhook_signature_rejects_empty_env_name() {
        let err = resolve_webhook_signature("   ", b"1700000000", br#"{"ok":true}"#)
            .expect_err("must reject empty env name");
        let message = format!("{err:#}");
        assert!(message.contains("webhook secret env var name is empty"));
    }

    #[test]
    fn resolve_webhook_signature_requires_existing_env_var() {
        let err = resolve_webhook_signature(
            "PATCHGATE_WEBHOOK_SECRET_MISSING_FOR_TEST",
            b"1700000000",
            br#"{"ok":true}"#,
        )
        .expect_err("must require env var");
        let message = format!("{err:#}");
        assert!(message.contains("missing webhook secret env var"));
    }

    #[test]
    fn redacted_endpoint_masks_path_and_query() {
        let masked = redacted_endpoint("https://hooks.example.com/services/abc/def?token=secret");
        assert_eq!(masked, "https://hooks.example.com/***");
    }

    #[test]
    fn notification_payload_slack_fields_are_strings() {
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
        let payload = notification_payload(NotificationKind::Slack, "example/repo", &report)
            .expect("payload");
        let findings_value = payload
            .get("attachments")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("fields"))
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("value"))
            .expect("findings value");
        assert!(
            findings_value.is_string(),
            "slack findings value must be encoded as string"
        );
    }

    #[test]
    fn notification_payload_does_not_embed_full_report() {
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
        let slack = notification_payload(NotificationKind::Slack, "example/repo", &report)
            .expect("slack payload");
        assert!(
            slack.get("patchgate").is_none(),
            "slack payload must avoid full report embedding"
        );
        let teams = notification_payload(NotificationKind::Teams, "example/repo", &report)
            .expect("teams payload");
        assert!(
            teams.get("patchgate").is_none(),
            "teams payload must avoid full report embedding"
        );
        let generic = notification_payload(NotificationKind::Generic, "example/repo", &report)
            .expect("generic payload");
        assert!(
            generic.get("report").is_none(),
            "generic payload must avoid full report embedding"
        );
        assert!(
            generic.get("summary").is_some(),
            "generic payload must include bounded summary"
        );
    }

    #[test]
    fn publish_generic_ci_payload_requires_output_path() {
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

        let err = publish_generic_ci_payload("example/repo", &report, "md", None)
            .expect_err("missing output path must fail");
        let message = format!("{err:#}");
        assert!(message.contains("generic CI publish requires output path"));
    }

    #[test]
    fn publish_generic_ci_payload_masks_sensitive_report_strings() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-generic-mask-{seq}"));
        fs::create_dir_all(&dir).expect("create output dir");
        let output = dir.join("payload.json");

        let mut report = Report::new(
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
        report
            .diagnostic_hints
            .push("bearer super-secret-token".to_string());

        publish_generic_ci_payload("example/repo", &report, "md", Some(output.as_path()))
            .expect("publish generic payload");
        let written = fs::read_to_string(output).expect("read payload");
        assert!(
            !written.contains("super-secret-token"),
            "payload must not contain raw bearer token"
        );
        assert!(written.contains("bearer ***"), "payload should be masked");

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn plugin_init_generates_python_template_files() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-python-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");
        let output = repo_root.join("generated-plugin");

        run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "python".to_string(),
                plugin_id: "sample-plugin".to_string(),
                output: PathBuf::from("generated-plugin"),
                force: false,
            },
        )
        .expect("generate template");

        let main_py = fs::read_to_string(output.join("main.py")).expect("main.py");
        assert!(main_py.contains("plugin_id=sample-plugin"));
        assert!(output.join("README.md").exists());
        assert!(output.join("sample-input.json").exists());

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_generates_node_template_from_sdk_assets() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-node-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");
        let output = repo_root.join("generated-node-plugin");

        run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "sample-node-plugin".to_string(),
                output: PathBuf::from("generated-node-plugin"),
                force: false,
            },
        )
        .expect("generate node template");

        let package_json = fs::read_to_string(output.join("package.json")).expect("package.json");
        let index_js = fs::read_to_string(output.join("index.js")).expect("index.js");
        let sample_input =
            fs::read_to_string(output.join("sample-input.json")).expect("sample-input.json");
        assert!(package_json.contains("\"name\": \"sample-node-plugin\""));
        assert!(index_js.contains("invalid json input:"));
        assert!(index_js.contains("payload.plugin_id ?? \"sample-node-plugin\""));
        assert!(sample_input.contains("\"plugin_id\":\"sample-node-plugin\""));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_sanitizes_project_names_for_package_manifests() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-project-name-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");

        let node_output = repo_root.join("generated-node-plugin");
        run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "Sample.Plugin_01".to_string(),
                output: PathBuf::from("generated-node-plugin"),
                force: false,
            },
        )
        .expect("generate node template");
        let node_package =
            fs::read_to_string(node_output.join("package.json")).expect("package.json");
        assert!(node_package.contains("\"name\": \"sample-plugin-01\""));

        let rust_output = repo_root.join("generated-rust-plugin");
        run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "rust".to_string(),
                plugin_id: "Sample.Plugin_01".to_string(),
                output: PathBuf::from("generated-rust-plugin"),
                force: false,
            },
        )
        .expect("generate rust template");
        let cargo_toml = fs::read_to_string(rust_output.join("Cargo.toml")).expect("Cargo.toml");
        assert!(cargo_toml.contains("name = \"sample-plugin-01\""));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_generates_rust_template_with_workspace_boundary() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-rust-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");
        let output = repo_root.join("generated-rust-plugin");

        run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "rust".to_string(),
                plugin_id: "sample-rust-plugin".to_string(),
                output: PathBuf::from("generated-rust-plugin"),
                force: false,
            },
        )
        .expect("generate rust template");

        let cargo_toml = fs::read_to_string(output.join("Cargo.toml")).expect("Cargo.toml");
        let main_rs = fs::read_to_string(output.join("src/main.rs")).expect("src/main.rs");
        assert!(cargo_toml.contains("[workspace]"));
        assert!(cargo_toml.contains("name = \"sample-rust-plugin\""));
        assert!(main_rs.contains("invalid json input:"));
        assert!(main_rs.contains("unwrap_or(\"sample-rust-plugin\")"));
        assert!(output.join("src/main.rs").exists());
        assert!(output.join("sample-input.json").exists());

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_rejects_invalid_plugin_id_characters() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-invalid-plugin-id-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");

        let err = run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "bad id".to_string(),
                output: PathBuf::from("generated-node-plugin"),
                force: false,
            },
        )
        .expect_err("must reject invalid plugin id");
        assert!(format!("{err:#}").contains("must contain only ASCII letters"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_refuses_existing_output_without_force() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-force-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");
        let output = repo_root.join("existing");
        fs::create_dir_all(&output).expect("create output dir");

        let err = run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "node-plugin".to_string(),
                output: PathBuf::from("existing"),
                force: false,
            },
        )
        .expect_err("must fail");
        assert!(format!("{err:#}").contains("already exists"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_rejects_repo_root_output_even_with_force() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-root-guard-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");

        let err = run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "python".to_string(),
                plugin_id: "sample-plugin".to_string(),
                output: PathBuf::from("."),
                force: true,
            },
        )
        .expect_err("must reject repo root");
        assert!(format!("{err:#}").contains("must not point to repository root"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_rejects_output_outside_repo_root() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-outside-guard-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");

        let err = run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "sample-node-plugin".to_string(),
                output: PathBuf::from("../outside"),
                force: false,
            },
        )
        .expect_err("must reject outside path");
        assert!(format!("{err:#}").contains("must be inside repository root"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_rejects_git_internal_output_paths() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-git-guard-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");

        let err = run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "sample-node-plugin".to_string(),
                output: PathBuf::from(".git/hooks/my-plugin"),
                force: false,
            },
        )
        .expect_err("must reject .git internal path");
        assert!(format!("{err:#}").contains("must not target a git repository path"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn plugin_init_allows_repo_under_dot_git_parent_directory() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_parent = std::env::temp_dir();
        repo_parent.push(format!("patchgate-plugin-init-parent-dot-git-{seq}"));
        let repo_root = repo_parent.join(".git").join("repo");
        fs::create_dir_all(&repo_root).expect("create repo root");

        run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "sample-node-plugin".to_string(),
                output: PathBuf::from("generated/plugin"),
                force: false,
            },
        )
        .expect("repo under .git parent should be allowed");

        assert!(repo_root.join("generated/plugin/package.json").exists());
        let _ = fs::remove_dir_all(repo_parent);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_init_rejects_symlinked_output_components() {
        use std::os::unix::fs::symlink;

        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-plugin-init-symlink-guard-{seq}"));
        fs::create_dir_all(&repo_root).expect("create repo root");

        let mut outside_root = std::env::temp_dir();
        outside_root.push(format!("patchgate-plugin-init-symlink-target-{seq}"));
        fs::create_dir_all(&outside_root).expect("create outside root");

        let link_path = repo_root.join("linked");
        symlink(&outside_root, &link_path).expect("create symlink");

        let err = run_plugin_init(
            &repo_root,
            PluginInitArgs {
                lang: "node".to_string(),
                plugin_id: "sample-node-plugin".to_string(),
                output: PathBuf::from("linked/generated"),
                force: false,
            },
        )
        .expect_err("must reject symlink traversal");
        assert!(format!("{err:#}").contains("must not traverse symlinked paths"));

        let _ = fs::remove_file(&link_path);
        let _ = fs::remove_dir_all(&outside_root);
        let _ = fs::remove_dir_all(&repo_root);
    }

    #[test]
    fn comment_suppression_uses_priority_rules() {
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
                skipped_by_cache: true,
            },
        );
        let reason = resolve_comment_suppression_reason(&report, true, false, false);
        assert!(
            reason
                .as_deref()
                .is_some_and(|msg| msg.contains("no-change")),
            "must suppress by no-change rule"
        );
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
