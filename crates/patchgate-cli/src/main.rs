use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    Config, ConfigError, LoadedConfig, PolicyAuthority, PolicyAuthorityFailure,
    PolicyAuthorityResolution, PolicyAuthorityResolverInput, PolicyAuthoritySourceInput,
    PolicyBundleSourceInput, PolicyMigrationError, PolicyPreset, ValidationCategory,
    POLICY_VERSION_CURRENT,
};
use patchgate_core::{
    failure_codes, CheckId, CheckScore, Context, Finding, Report, ReportMeta, ReviewPriority,
    Runner, ScopeMode, Severity,
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
    Policy(Box<PolicyArgs>),

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

    /// Trusted base ref for enforce-mode policy authority
    #[arg(long)]
    base_ref: Option<String>,

    /// Optional protected policy ref (for example refs/patchgate/policy/main)
    #[arg(long)]
    protected_policy_ref: Option<String>,

    /// Signed organization policy bundle path
    #[arg(long)]
    org_policy_bundle: Option<PathBuf>,

    /// Signature for --org-policy-bundle
    #[arg(long)]
    org_policy_bundle_signature: Option<PathBuf>,

    /// Env var containing the org policy bundle public key
    #[arg(long)]
    org_policy_public_key_env: Option<String>,

    /// Allow local-only enforce scans to continue as an explicit local escape hatch
    #[arg(long)]
    allow_untrusted_policy_for_local_enforce: bool,

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

    /// Append audit log v2 JSONL record
    #[arg(long)]
    audit_log_v2_output: Option<PathBuf>,

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

    /// Generic provider payload schema: v1|v2|dual
    #[arg(long)]
    ci_generic_schema: Option<String>,

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
static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    /// Lint policy config and report compatibility status
    Lint(PolicyLintArgs),

    /// Resolve trusted policy authority and PR overlay status
    Resolve(PolicyResolveArgs),

    /// Show PR overlay policy diff against trusted authority
    Diff(PolicyDiffArgs),

    /// Verify and emit an org policy bundle authority attestation
    Attest(PolicyAttestArgs),

    /// Verify policy authority readiness for warn/enforce mode
    VerifyAuthority(PolicyVerifyAuthorityArgs),

    /// Migrate policy config across policy versions
    Migrate(PolicyMigrateArgs),

    /// Verify v1.0 readiness for migration
    VerifyV1(PolicyVerifyV1Args),

    /// Verify v2 shadow/bridge readiness
    VerifyV2(PolicyVerifyV2Args),

    /// Show v1/v2 contract migration diff
    DiffContract(PolicyDiffContractArgs),
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

#[derive(Args, Debug, Clone)]
struct PolicyAuthorityCommonArgs {
    /// Policy file path (default: auto-discover policy.toml)
    #[arg(long)]
    path: Option<PathBuf>,

    /// Apply policy preset before loading policy file: strict|balanced|relaxed
    #[arg(long)]
    policy_preset: Option<String>,

    /// Mode to resolve authority for: warn|enforce
    #[arg(long, default_value = "warn")]
    mode: String,

    /// Trusted base ref for base branch policy
    #[arg(long)]
    base_ref: Option<String>,

    /// PR/head ref to read overlay policy from; defaults to the worktree file
    #[arg(long)]
    head_ref: Option<String>,

    /// Optional protected policy ref (for example refs/patchgate/policy/main)
    #[arg(long)]
    protected_policy_ref: Option<String>,

    /// Signed organization policy bundle path
    #[arg(long)]
    org_policy_bundle: Option<PathBuf>,

    /// Signature for --org-policy-bundle
    #[arg(long)]
    org_policy_bundle_signature: Option<PathBuf>,

    /// Env var containing the org policy bundle public key
    #[arg(long)]
    org_policy_public_key_env: Option<String>,

    /// Allow local-only enforce scans to continue as an explicit local escape hatch
    #[arg(long)]
    allow_untrusted_policy_for_local_enforce: bool,

    /// Output format: text|json
    #[arg(long, default_value = "text")]
    format: String,
}

#[derive(Args, Debug)]
struct PolicyResolveArgs {
    #[command(flatten)]
    authority: PolicyAuthorityCommonArgs,
}

#[derive(Args, Debug)]
struct PolicyDiffArgs {
    #[command(flatten)]
    authority: PolicyAuthorityCommonArgs,
}

#[derive(Args, Debug)]
struct PolicyVerifyAuthorityArgs {
    #[command(flatten)]
    authority: PolicyAuthorityCommonArgs,
}

#[derive(Args, Debug)]
struct PolicyAttestArgs {
    /// Signed organization policy bundle path
    #[arg(long)]
    bundle: PathBuf,

    /// Signature path for --bundle
    #[arg(long)]
    signature: PathBuf,

    /// Env var containing the org policy bundle public key
    #[arg(long, default_value = "PATCHGATE_POLICY_BUNDLE_PUBLIC_KEY")]
    public_key_env: String,

    /// Output format: text|json
    #[arg(long, default_value = "text")]
    format: String,
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
    #[arg(long, conflicts_with = "autofix_write")]
    autofix_output: Option<PathBuf>,

    /// Overwrite the input policy file with safe autofixes
    #[arg(long, conflicts_with = "autofix_output")]
    autofix_write: bool,
}

#[derive(Args, Debug)]
struct PolicyVerifyV2Args {
    /// Policy file path (default: auto-discover policy.toml)
    #[arg(long)]
    path: Option<PathBuf>,

    /// Apply policy preset before loading policy file: strict|balanced|relaxed
    #[arg(long)]
    policy_preset: Option<String>,

    /// Output format: text|json
    #[arg(long, default_value = "text")]
    format: String,

    /// Readiness profile: standard|ga|lts
    #[arg(long, default_value = "standard")]
    readiness_profile: String,

    /// Generic provider v2 or dual artifact to validate (repeatable)
    #[arg(long = "provider-input")]
    provider_inputs: Vec<PathBuf>,

    /// Audit v1 JSONL artifact for dual-write validation
    #[arg(long)]
    audit_input: Option<PathBuf>,

    /// Audit v2 JSONL artifact for dual-write validation
    #[arg(long = "audit-v2-input")]
    audit_v2_input: Option<PathBuf>,

    /// Plugin v2 shadow sample input to validate (repeatable)
    #[arg(long = "plugin-shadow-input")]
    plugin_shadow_inputs: Vec<PathBuf>,

    /// Webhook v2 shadow envelope artifact to validate (repeatable)
    #[arg(long = "webhook-envelope-input")]
    webhook_envelope_inputs: Vec<PathBuf>,

    /// Notification v2 shadow envelope artifact to validate (repeatable)
    #[arg(long = "notification-envelope-input")]
    notification_envelope_inputs: Vec<PathBuf>,

    /// Fleet bundle catalog artifact to validate
    #[arg(long = "bundle-catalog-input")]
    bundle_catalog_input: Option<PathBuf>,

    /// Plugin registry provenance artifact to validate
    #[arg(long = "registry-input")]
    registry_input: Option<PathBuf>,

    /// Organization exception governance artifact to validate
    #[arg(long = "exceptions-input")]
    exceptions_input: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct PolicyDiffContractArgs {
    /// Policy file path (default: auto-discover policy.toml)
    #[arg(long)]
    path: Option<PathBuf>,

    /// Apply policy preset before loading policy file: strict|balanced|relaxed
    #[arg(long)]
    policy_preset: Option<String>,

    /// Output format: text|json
    #[arg(long, default_value = "text")]
    format: String,

    /// Fail when the v1/v2 contract boundary is not ready for RC freeze
    #[arg(long)]
    enforce: bool,
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
            FailureCode::InputInvalidOption => failure_codes::INPUT_INVALID_OPTION,
            FailureCode::ConfigLoadFailed => failure_codes::CONFIG_LOAD_FAILED,
            FailureCode::GitDiffFailed => failure_codes::GIT_DIFF_FAILED,
            FailureCode::RuntimeEvaluationFailed => failure_codes::RUNTIME_EVALUATION_FAILED,
            FailureCode::OutputWriteFailed => failure_codes::OUTPUT_WRITE_FAILED,
            FailureCode::PublishInputFailed => failure_codes::PUBLISH_INPUT_FAILED,
            FailureCode::PublishApiFailed => failure_codes::PUBLISH_API_FAILED,
            FailureCode::PublishSsoRequired => failure_codes::PUBLISH_SSO_REQUIRED,
            FailureCode::PublishOrgPolicyBlocked => failure_codes::PUBLISH_ORG_POLICY_BLOCKED,
            FailureCode::PublishWebhookFailed => failure_codes::PUBLISH_WEBHOOK_FAILED,
            FailureCode::NotificationFailed => failure_codes::NOTIFICATION_FAILED,
            FailureCode::WaiverExpired => failure_codes::WAIVER_EXPIRED,
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
enum GenericCiSchemaMode {
    V1,
    V2,
    Dual,
}

impl GenericCiSchemaMode {
    fn parse(raw: Option<&str>) -> std::result::Result<Self, String> {
        match raw.unwrap_or("v1") {
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2),
            "dual" => Ok(Self::Dual),
            other => Err(format!("`{other}` (expected: v1|v2|dual)")),
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
struct GenericCiPublishPayloadV2 {
    schema_version: u8,
    publish_format: String,
    repo: String,
    emitted_at: u64,
    capabilities: Vec<String>,
    gate: GenericPublishGateV2,
    artifacts: GenericPublishArtifactsV2,
}

#[derive(Debug, Serialize)]
struct GenericPublishGateV2 {
    score: u8,
    threshold: u8,
    should_fail: bool,
    mode: String,
    scope: String,
    findings_count: usize,
}

#[derive(Debug, Serialize)]
struct GenericPublishArtifactsV2 {
    report: Report,
    markdown: String,
}

#[derive(Debug, Serialize)]
struct GenericCiPublishBridgePayload {
    schema_version: u8,
    bridge_format: String,
    repo: String,
    emitted_at: u64,
    capabilities: Vec<String>,
    v1: GenericCiPublishPayload,
    v2: GenericCiPublishPayloadV2,
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

fn generic_ci_v2_capabilities() -> Vec<String> {
    vec!["generic.v2".to_string(), "audit.shadow".to_string()]
}

fn generic_ci_dual_capabilities() -> Vec<String> {
    vec!["generic.dual".to_string(), "audit.shadow".to_string()]
}

#[derive(Debug, Serialize)]
struct WebhookEnvelope<'a> {
    event: &'a str,
    unix_ts: u64,
    repo: &'a str,
    report: &'a Report,
    #[serde(skip_serializing_if = "Option::is_none")]
    bridge: Option<DeliveryBridgeMetadata<'a>>,
}

#[derive(Debug, Clone, Copy)]
struct DeliveryBridgeContext<'a> {
    enabled: bool,
    shadow_mode: bool,
    bridge_mode: &'a str,
}

impl<'a> DeliveryBridgeContext<'a> {
    fn from_config(cfg: &'a Config) -> Self {
        let bridge_mode = cfg.compatibility.v2.bridge_mode.as_str();
        Self {
            enabled: cfg.compatibility.v2.shadow_mode && bridge_mode == "full",
            shadow_mode: cfg.compatibility.v2.shadow_mode,
            bridge_mode,
        }
    }
}

#[derive(Debug, Serialize)]
struct DeliveryBridgeMetadata<'a> {
    schema_version: u8,
    bridge_format: &'a str,
    shadow_of: &'a str,
    bridge_mode: &'a str,
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
struct AuditLogV2Record {
    schema_version: u8,
    audit_format: String,
    emitted_at: u64,
    actor: String,
    repo: String,
    operation: AuditOperationV2,
    gate: AuditGateV2,
    failure: AuditFailureV2,
    diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditOperationV2 {
    target: String,
    mode: String,
    scope: String,
    result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditGateV2 {
    score: Option<u8>,
    threshold: Option<u8>,
    changed_files: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditFailureV2 {
    code: Option<String>,
    category: Option<String>,
}

struct ScanSuccessOutputs<'a> {
    metrics_path: Option<&'a Path>,
    audit_path: Option<&'a Path>,
    audit_v2_path: Option<&'a Path>,
    actor: String,
    audit_schema_version: u8,
    audit_v2_schema_version: u8,
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
const DEFAULT_GITHUB_CHECK_NAME: &str = "patchgate";
const TRUST_BOUNDARY_DOCS_PATH: &str = "docs/trust-boundary.md";

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
            let code = execute_policy(&repo_root, cli.config.as_deref(), *policy);
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
const NODE_TEMPLATE_SAMPLE_INPUT_V2: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/node-plugin/sample-input.v2.json"
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
const RUST_TEMPLATE_SAMPLE_INPUT_V2: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/rust-plugin/sample-input.v2.json"
));
const RUST_TEMPLATE_CARGO_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/rust-plugin/Cargo.toml"
));
const RUST_TEMPLATE_MAIN_RS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/rust-plugin/src/main.rs"
));
const PYTHON_TEMPLATE_README: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/python-plugin/README.md"
));
const PYTHON_TEMPLATE_SAMPLE_INPUT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/python-plugin/sample-input.json"
));
const PYTHON_TEMPLATE_SAMPLE_INPUT_V2: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/python-plugin/sample-input.v2.json"
));
const PYTHON_TEMPLATE_MAIN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk/templates/python-plugin/main.py"
));

fn render_embedded_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = template.to_string();
    for (from, to) in replacements {
        rendered = rendered.replace(from, to);
    }
    rendered
}

fn render_plugin_sample_input(template: &str, plugin_id: &str) -> String {
    render_embedded_template(
        template,
        &[(
            "\"plugin_id\":\"sample\"",
            &format!("\"plugin_id\":\"{plugin_id}\""),
        )],
    )
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
                render_embedded_template(
                    PYTHON_TEMPLATE_README,
                    &[("plugin_id=sample", &format!("plugin_id={plugin_id}"))],
                ),
            ),
            (
                "sample-input.json",
                render_plugin_sample_input(PYTHON_TEMPLATE_SAMPLE_INPUT, plugin_id),
            ),
            (
                "sample-input.v2.json",
                render_plugin_sample_input(PYTHON_TEMPLATE_SAMPLE_INPUT_V2, plugin_id),
            ),
            ("main.py", PYTHON_TEMPLATE_MAIN.to_string()),
        ],
        PluginTemplateLang::Node => vec![
            ("README.md", NODE_TEMPLATE_README.to_string()),
            (
                "sample-input.json",
                render_plugin_sample_input(NODE_TEMPLATE_SAMPLE_INPUT, plugin_id),
            ),
            (
                "sample-input.v2.json",
                render_plugin_sample_input(NODE_TEMPLATE_SAMPLE_INPUT_V2, plugin_id),
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
                render_plugin_sample_input(RUST_TEMPLATE_SAMPLE_INPUT, plugin_id),
            ),
            (
                "sample-input.v2.json",
                render_plugin_sample_input(RUST_TEMPLATE_SAMPLE_INPUT_V2, plugin_id),
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
        PolicyCommand::Resolve(args) => {
            run_policy_resolve(repo_root, config_override, args).as_i32()
        }
        PolicyCommand::Diff(args) => run_policy_diff(repo_root, config_override, args).as_i32(),
        PolicyCommand::Attest(args) => run_policy_attest(repo_root, args).as_i32(),
        PolicyCommand::VerifyAuthority(args) => {
            run_policy_verify_authority(repo_root, config_override, args).as_i32()
        }
        PolicyCommand::Migrate(args) => {
            run_policy_migrate(repo_root, config_override, args).as_i32()
        }
        PolicyCommand::VerifyV1(args) => {
            run_policy_verify_v1(repo_root, config_override, args).as_i32()
        }
        PolicyCommand::VerifyV2(args) => {
            run_policy_verify_v2(repo_root, config_override, args).as_i32()
        }
        PolicyCommand::DiffContract(args) => {
            run_policy_diff_contract(repo_root, config_override, args).as_i32()
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

fn run_policy_resolve(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyResolveArgs,
) -> PolicyExitCode {
    let resolved =
        match resolve_policy_authority_from_common(repo_root, config_override, &args.authority) {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("patchgate policy resolve error: {err:#}");
                return PolicyExitCode::ReadOrParse;
            }
        };
    if let Err(err) = print_policy_authority_resolution(
        &resolved,
        args.authority.format.as_str(),
        PolicyAuthorityPrintMode::Resolve,
    ) {
        eprintln!("patchgate policy resolve error: {err}");
        return PolicyExitCode::IoFailed;
    }
    PolicyExitCode::Ok
}

fn run_policy_diff(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyDiffArgs,
) -> PolicyExitCode {
    let resolved =
        match resolve_policy_authority_from_common(repo_root, config_override, &args.authority) {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("patchgate policy diff error: {err:#}");
                return PolicyExitCode::ReadOrParse;
            }
        };
    if let Err(err) = print_policy_authority_resolution(
        &resolved,
        args.authority.format.as_str(),
        PolicyAuthorityPrintMode::Diff,
    ) {
        eprintln!("patchgate policy diff error: {err}");
        return PolicyExitCode::IoFailed;
    }
    if args.authority.mode == "enforce" && !resolved.resolution.enforce_failures.is_empty() {
        PolicyExitCode::MigrationRequired
    } else {
        PolicyExitCode::Ok
    }
}

fn run_policy_attest(repo_root: &Path, args: PolicyAttestArgs) -> PolicyExitCode {
    let bundle_path = resolve_repo_relative_path(repo_root, args.bundle);
    let signature_path = resolve_repo_relative_path(repo_root, args.signature);
    let bundle_text = match fs::read_to_string(&bundle_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!(
                "patchgate policy attest error: failed to read bundle {}: {err}",
                bundle_path.display()
            );
            return PolicyExitCode::IoFailed;
        }
    };
    let signature_text = match fs::read_to_string(&signature_path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!(
                "patchgate policy attest error: failed to read signature {}: {err}",
                signature_path.display()
            );
            return PolicyExitCode::IoFailed;
        }
    };
    let public_key_base64 = match std::env::var(args.public_key_env.as_str()) {
        Ok(value) => Some(value),
        Err(_) => {
            eprintln!(
                "patchgate policy attest error: missing public key env var {}",
                args.public_key_env
            );
            return PolicyExitCode::ReadOrParse;
        }
    };
    let resolver_input = PolicyAuthorityResolverInput {
        mode: "enforce".to_string(),
        preset: None,
        base_branch: None,
        protected_ref: None,
        local_file: None,
        org_bundle: Some(PolicyBundleSourceInput {
            path: Some(bundle_path.display().to_string()),
            text: bundle_text,
            signature_path: Some(signature_path.display().to_string()),
            signature_text: Some(signature_text),
            public_key_base64,
        }),
        enforce_trusted_policy_required: true,
        allow_untrusted_local_enforce: false,
    };
    let resolution = match patchgate_config::resolve_policy_authority(resolver_input) {
        Ok(resolution) => resolution,
        Err(err) => {
            eprintln!("patchgate policy attest error: {err:#}");
            return PolicyExitCode::ReadOrParse;
        }
    };
    let resolved = PolicyAuthorityCliResolution {
        policy_path: "<org-bundle>".to_string(),
        mode: "enforce".to_string(),
        resolution,
    };
    if let Err(err) = print_policy_authority_resolution(
        &resolved,
        args.format.as_str(),
        PolicyAuthorityPrintMode::Attest,
    ) {
        eprintln!("patchgate policy attest error: {err}");
        return PolicyExitCode::IoFailed;
    }
    if resolved.resolution.enforce_failures.is_empty() {
        PolicyExitCode::Ok
    } else {
        PolicyExitCode::MigrationRequired
    }
}

fn run_policy_verify_authority(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyVerifyAuthorityArgs,
) -> PolicyExitCode {
    let resolved =
        match resolve_policy_authority_from_common(repo_root, config_override, &args.authority) {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("patchgate policy verify-authority error: {err:#}");
                return PolicyExitCode::ReadOrParse;
            }
        };
    if let Err(err) = print_policy_authority_resolution(
        &resolved,
        args.authority.format.as_str(),
        PolicyAuthorityPrintMode::Verify,
    ) {
        eprintln!("patchgate policy verify-authority error: {err}");
        return PolicyExitCode::IoFailed;
    }
    if resolved.mode == "enforce"
        && (!resolved.resolution.enforce_failures.is_empty()
            || !resolved.resolution.authority.trusted)
    {
        PolicyExitCode::MigrationRequired
    } else {
        PolicyExitCode::Ok
    }
}

#[derive(Debug)]
struct PolicyAuthorityCliResolution {
    policy_path: String,
    mode: String,
    resolution: PolicyAuthorityResolution,
}

#[derive(Debug, Clone, Copy)]
enum PolicyAuthorityPrintMode {
    Resolve,
    Diff,
    Attest,
    Verify,
}

fn resolve_policy_authority_from_common(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: &PolicyAuthorityCommonArgs,
) -> Result<PolicyAuthorityCliResolution> {
    let preset = parse_policy_preset(args.policy_preset.as_deref())
        .map_err(|err| anyhow!("invalid --policy-preset value: {err}"))?;
    resolve_policy_authority_from_common_with_preset(repo_root, config_override, args, preset)
}

fn resolve_policy_authority_from_common_with_preset(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: &PolicyAuthorityCommonArgs,
    preset: Option<PolicyPreset>,
) -> Result<PolicyAuthorityCliResolution> {
    parse_mode(args.mode.as_str(), OptionSource::Cli).map_err(|err| anyhow!("{}", err.render()))?;

    let policy_path = resolve_policy_path(repo_root, config_override, args.path.as_deref());
    let policy_rel = policy_authority_relative_path(repo_root, policy_path.as_deref())?;
    let local_text = if let Some(head_ref) = args.head_ref.as_deref() {
        read_git_file_at_ref(repo_root, head_ref, policy_rel.as_str(), false)?
    } else {
        read_optional_policy_file(policy_path.as_deref())?
    };
    let local_source = local_text.map(|text| {
        PolicyAuthoritySourceInput::new("local_file", text)
            .with_ref(args.head_ref.clone())
            .with_path(Some(policy_rel.clone()))
    });

    let base_branch = match args.base_ref.as_deref() {
        Some(base_ref) => read_git_file_at_ref(repo_root, base_ref, policy_rel.as_str(), true)?
            .map(|text| {
                PolicyAuthoritySourceInput::new("base_branch", text)
                    .with_ref(Some(base_ref.to_string()))
                    .with_path(Some(policy_rel.clone()))
            }),
        None => None,
    };
    let trusted_authority_config = base_branch
        .as_ref()
        .and_then(|source| {
            patchgate_config::load_effective_from_text_typed(source.text.as_str(), preset).ok()
        })
        .map(|loaded| loaded.config.policy_authority)
        .unwrap_or_default();
    let authority_config_from_trusted_policy = base_branch.is_some();
    let authority_config = if authority_config_from_trusted_policy || args.mode == "enforce" {
        trusted_authority_config
    } else {
        local_source
            .as_ref()
            .and_then(|source| {
                patchgate_config::load_effective_from_text_typed(source.text.as_str(), preset).ok()
            })
            .map(|loaded| loaded.config.policy_authority)
            .unwrap_or_default()
    };

    let protected_ref = args
        .protected_policy_ref
        .clone()
        .or_else(|| non_empty_string(authority_config.protected_policy_ref.as_str()));
    let protected_ref_source = match protected_ref.as_deref() {
        Some(ref_name) => read_git_file_at_ref(repo_root, ref_name, policy_rel.as_str(), true)?
            .map(|text| {
                PolicyAuthoritySourceInput::new("protected_ref", text)
                    .with_ref(Some(ref_name.to_string()))
                    .with_path(Some(policy_rel.clone()))
            }),
        None => None,
    };

    let bundle_path = args
        .org_policy_bundle
        .clone()
        .or_else(|| non_empty_path(authority_config.org_bundle_path.as_str()));
    let signature_path = args
        .org_policy_bundle_signature
        .clone()
        .or_else(|| non_empty_path(authority_config.org_bundle_signature_path.as_str()));
    let public_key_env = args
        .org_policy_public_key_env
        .as_deref()
        .or_else(|| non_empty_str(authority_config.org_bundle_public_key_env.as_str()))
        .unwrap_or("PATCHGATE_POLICY_BUNDLE_PUBLIC_KEY");
    let org_bundle = match bundle_path {
        Some(bundle_path) => {
            let bundle_path = resolve_repo_relative_path(repo_root, bundle_path);
            let bundle_text = fs::read_to_string(&bundle_path)
                .with_context(|| format!("read org policy bundle {}", bundle_path.display()))?;
            let signature_path =
                signature_path.map(|path| resolve_repo_relative_path(repo_root, path));
            let signature_text = match signature_path.as_ref() {
                Some(path) => Some(fs::read_to_string(path).with_context(|| {
                    format!("read org policy bundle signature {}", path.display())
                })?),
                None => None,
            };
            let public_key_base64 = std::env::var(public_key_env).ok();
            Some(PolicyBundleSourceInput {
                path: Some(bundle_path.display().to_string()),
                text: bundle_text,
                signature_path: signature_path.map(|path| path.display().to_string()),
                signature_text,
                public_key_base64,
            })
        }
        None => None,
    };

    let resolution = patchgate_config::resolve_policy_authority(PolicyAuthorityResolverInput {
        mode: args.mode.clone(),
        preset,
        base_branch,
        protected_ref: protected_ref_source,
        local_file: local_source,
        org_bundle,
        enforce_trusted_policy_required: authority_config.enforce_trusted_policy_required,
        allow_untrusted_local_enforce: args.allow_untrusted_policy_for_local_enforce
            || (authority_config_from_trusted_policy
                && authority_config.allow_untrusted_local_enforce),
    })
    .map_err(|err| anyhow!(err))?;

    Ok(PolicyAuthorityCliResolution {
        policy_path: policy_rel,
        mode: args.mode.clone(),
        resolution,
    })
}

fn policy_authority_resolution_scan_error(err: anyhow::Error) -> ScanError {
    if error_chain_contains_expired_waiver(&err) {
        ScanError::with_hint(
            ScanErrorKind::Config,
            FailureCode::WaiverExpired,
            "Update waiver.expires_at or remove expired waiver entries.",
            err.context("failed to resolve policy authority"),
        )
    } else {
        ScanError::with_code(
            ScanErrorKind::Config,
            FailureCode::ConfigLoadFailed,
            err.context("failed to resolve policy authority"),
        )
    }
}

fn error_chain_contains_expired_waiver(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<ConfigError>(),
            Some(ConfigError::Validation { field, message, .. })
                if *field == "waiver.entries" && message.contains("expired")
        )
    })
}

fn print_policy_authority_resolution(
    resolved: &PolicyAuthorityCliResolution,
    format: &str,
    mode: PolicyAuthorityPrintMode,
) -> std::result::Result<(), String> {
    match format {
        "json" => {
            let value = match mode {
                PolicyAuthorityPrintMode::Resolve
                | PolicyAuthorityPrintMode::Attest
                | PolicyAuthorityPrintMode::Verify => {
                    serde_json::to_value(&resolved.resolution.artifact)
                        .map_err(|err| format!("failed to encode authority artifact: {err}"))?
                }
                PolicyAuthorityPrintMode::Diff => {
                    serde_json::to_value(&resolved.resolution.authority.pr_overlay)
                        .map_err(|err| format!("failed to encode policy diff: {err}"))?
                }
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&value)
                    .map_err(|err| format!("failed to encode json: {err}"))?
            );
        }
        "text" => match mode {
            PolicyAuthorityPrintMode::Diff => {
                println!("patchgate policy diff");
                println!("- policy_path: {}", resolved.policy_path);
                println!(
                    "- overlay_present: {}",
                    resolved.resolution.authority.pr_overlay.present
                );
                print_string_list(
                    "- accepted_keys",
                    &resolved.resolution.authority.pr_overlay.accepted_keys,
                );
                print_string_list(
                    "- rejected_keys",
                    &resolved.resolution.authority.pr_overlay.rejected_keys,
                );
            }
            PolicyAuthorityPrintMode::Attest => {
                print_policy_authority_text("patchgate policy attest", resolved);
            }
            PolicyAuthorityPrintMode::Verify => {
                print_policy_authority_text("patchgate policy verify-authority", resolved);
            }
            PolicyAuthorityPrintMode::Resolve => {
                print_policy_authority_text("patchgate policy resolve", resolved);
            }
        },
        other => {
            return Err(format!(
                "unsupported --format `{other}` (expected: text|json)"
            ))
        }
    }
    Ok(())
}

fn print_policy_authority_text(title: &str, resolved: &PolicyAuthorityCliResolution) {
    println!("{title}");
    println!("- policy_path: {}", resolved.policy_path);
    println!("- mode: {}", resolved.mode);
    println!("- trusted: {}", resolved.resolution.authority.trusted);
    println!("- digest: {}", resolved.resolution.authority.digest);
    println!("- sources:");
    for source in &resolved.resolution.authority.sources {
        println!(
            "  - kind={} ref={} path={} trusted={} signature_verified={} digest={}",
            source.kind,
            source.ref_name.as_deref().unwrap_or("-"),
            source.path.as_deref().unwrap_or("-"),
            source.trusted,
            source.signature_verified,
            source.digest
        );
    }
    println!(
        "- pr_overlay_present: {}",
        resolved.resolution.authority.pr_overlay.present
    );
    print_string_list(
        "- pr_overlay_accepted_keys",
        &resolved.resolution.authority.pr_overlay.accepted_keys,
    );
    print_string_list(
        "- pr_overlay_rejected_keys",
        &resolved.resolution.authority.pr_overlay.rejected_keys,
    );
    if resolved.resolution.enforce_failures.is_empty() {
        println!("- enforce_failures: none");
    } else {
        println!("- enforce_failures:");
        for failure in &resolved.resolution.enforce_failures {
            println!("  - {}: {}", failure.code, failure.message);
        }
    }
}

fn print_string_list(label: &str, values: &[String]) {
    if values.is_empty() {
        println!("{label}: none");
        return;
    }
    println!("{label}:");
    for value in values {
        println!("  - {value}");
    }
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

#[derive(Debug, Serialize)]
struct V2ReadinessReport {
    ready: bool,
    policy_path: String,
    policy_version: u32,
    readiness_profile: String,
    v1_rc_frozen: bool,
    v1_strict_compatibility: bool,
    v2_shadow_mode: bool,
    v2_bridge_mode: String,
    migration_guide_path: String,
    migration_guide_exists: bool,
    ci_provider: String,
    ci_generic_schema: String,
    audit_schema_version: u8,
    audit_v2_schema_version: u8,
    audit_v2_output_enabled: bool,
    lts_active: bool,
    lts_branch: String,
    lts_security_sla_hours: u16,
    provider_artifact_ready: Option<bool>,
    audit_dual_write_artifact_ready: Option<bool>,
    plugin_shadow_sample_ready: Option<bool>,
    webhook_bridge_artifact_ready: Option<bool>,
    notification_bridge_artifact_ready: Option<bool>,
    fleet_governance_artifact_ready: Option<bool>,
    artifact_checks: Vec<V2ArtifactCheck>,
    warnings: Vec<String>,
    next_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct V2ArtifactCheck {
    kind: String,
    path: String,
    present: bool,
    valid: bool,
    summary: String,
}

#[derive(Debug, Default)]
struct V2ArtifactContext {
    provider_artifact_ready: Option<bool>,
    audit_dual_write_artifact_ready: Option<bool>,
    plugin_shadow_sample_ready: Option<bool>,
    webhook_bridge_artifact_ready: Option<bool>,
    notification_bridge_artifact_ready: Option<bool>,
    fleet_governance_artifact_ready: Option<bool>,
    checks: Vec<V2ArtifactCheck>,
}

impl V2ArtifactContext {
    fn ready(&self) -> bool {
        self.provider_artifact_ready.unwrap_or(true)
            && self.audit_dual_write_artifact_ready.unwrap_or(true)
            && self.plugin_shadow_sample_ready.unwrap_or(true)
            && self.webhook_bridge_artifact_ready.unwrap_or(true)
            && self.notification_bridge_artifact_ready.unwrap_or(true)
            && self.fleet_governance_artifact_ready.unwrap_or(true)
            && self.checks.iter().all(|check| check.valid)
    }

    fn has_checks(&self) -> bool {
        self.provider_artifact_ready.is_some()
            || self.audit_dual_write_artifact_ready.is_some()
            || self.plugin_shadow_sample_ready.is_some()
            || self.webhook_bridge_artifact_ready.is_some()
            || self.notification_bridge_artifact_ready.is_some()
            || self.fleet_governance_artifact_ready.is_some()
    }
}

#[derive(Debug, Serialize)]
struct ContractDiffReport {
    policy_path: String,
    breaking_change_gate_ready: bool,
    v1_contract: ContractSurfaceSummary,
    v2_contract: ContractSurfaceSummary,
    migration_delta: Vec<String>,
    next_actions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ContractSurfaceSummary {
    enabled: bool,
    details: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V2ReadinessProfile {
    Standard,
    Ga,
    Lts,
}

impl V2ReadinessProfile {
    fn parse(raw: &str) -> std::result::Result<Self, String> {
        match raw {
            "standard" => Ok(Self::Standard),
            "ga" => Ok(Self::Ga),
            "lts" => Ok(Self::Lts),
            other => Err(format!("`{other}` (expected: standard|ga|lts)")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Ga => "ga",
            Self::Lts => "lts",
        }
    }

    fn requires_v2_lts(self) -> bool {
        matches!(self, Self::Ga | Self::Lts)
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
        if paths_conflict(policy_path.as_path(), output_path.as_path()) {
            eprintln!(
                "patchgate policy verify-v1 error: --autofix-output must differ from the input policy path"
            );
            return PolicyExitCode::ReadOrParse;
        }
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

fn run_policy_verify_v2(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyVerifyV2Args,
) -> PolicyExitCode {
    let Some(policy_path) = resolve_policy_path(repo_root, config_override, args.path.as_deref())
    else {
        eprintln!(
            "patchgate policy verify-v2 error: policy file not found. tried: `policy.toml`, `.patchgate/policy.toml`"
        );
        return PolicyExitCode::ReadOrParse;
    };

    let preset = match parse_policy_preset(args.policy_preset.as_deref()) {
        Ok(preset) => preset,
        Err(err) => {
            eprintln!("patchgate policy verify-v2 error: {err}");
            return PolicyExitCode::ReadOrParse;
        }
    };
    let loaded = match load_policy_config(Some(policy_path.as_path()), preset) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("patchgate policy verify-v2 error: {err:#}");
            return map_config_error_to_policy_exit(&err);
        }
    };
    let readiness_profile = match V2ReadinessProfile::parse(args.readiness_profile.as_str()) {
        Ok(profile) => profile,
        Err(err) => {
            eprintln!("patchgate policy verify-v2 error: invalid --readiness-profile: {err}");
            return PolicyExitCode::ReadOrParse;
        }
    };

    let artifact_context = build_v2_artifact_context(repo_root, &args);
    let report = build_v2_readiness_report(
        repo_root,
        policy_path.as_path(),
        &loaded.config,
        readiness_profile,
        artifact_context,
    );
    if let Err(err) = print_v2_readiness_report(&report, args.format.as_str()) {
        eprintln!("patchgate policy verify-v2 error: {err}");
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

fn run_policy_diff_contract(
    repo_root: &Path,
    config_override: Option<&Path>,
    args: PolicyDiffContractArgs,
) -> PolicyExitCode {
    let Some(policy_path) = resolve_policy_path(repo_root, config_override, args.path.as_deref())
    else {
        eprintln!(
            "patchgate policy diff-contract error: policy file not found. tried: `policy.toml`, `.patchgate/policy.toml`"
        );
        return PolicyExitCode::ReadOrParse;
    };

    let preset = match parse_policy_preset(args.policy_preset.as_deref()) {
        Ok(preset) => preset,
        Err(err) => {
            eprintln!("patchgate policy diff-contract error: {err}");
            return PolicyExitCode::ReadOrParse;
        }
    };
    let loaded = match load_policy_config(Some(policy_path.as_path()), preset) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!("patchgate policy diff-contract error: {err:#}");
            return map_config_error_to_policy_exit(&err);
        }
    };

    let report = build_contract_diff_report(repo_root, policy_path.as_path(), &loaded.config);
    if let Err(err) = print_contract_diff_report(&report, args.format.as_str()) {
        eprintln!("patchgate policy diff-contract error: {err}");
        return if err.contains("unsupported --format") {
            PolicyExitCode::ReadOrParse
        } else {
            PolicyExitCode::IoFailed
        };
    }
    if args.enforce && !report.breaking_change_gate_ready {
        return PolicyExitCode::MigrationRequired;
    }
    PolicyExitCode::Ok
}

fn build_v2_artifact_context(repo_root: &Path, args: &PolicyVerifyV2Args) -> V2ArtifactContext {
    let mut context = V2ArtifactContext::default();

    if !args.provider_inputs.is_empty() {
        let mut provider_ready = true;
        for raw_path in &args.provider_inputs {
            let path = resolve_repo_relative_path(repo_root, raw_path.clone());
            let check = check_provider_artifact(path.as_path());
            provider_ready &= check.valid;
            context.checks.push(check);
        }
        context.provider_artifact_ready = Some(provider_ready);
    }

    match (args.audit_input.as_ref(), args.audit_v2_input.as_ref()) {
        (Some(audit_input), Some(audit_v2_input)) => {
            let audit_path = resolve_repo_relative_path(repo_root, audit_input.clone());
            let audit_v2_path = resolve_repo_relative_path(repo_root, audit_v2_input.clone());
            let audit = check_audit_jsonl_artifact(
                "audit-v1",
                audit_path.as_path(),
                audit_v1_artifact_row_is_valid,
            );
            let audit_v2 = check_audit_jsonl_artifact(
                "audit-v2",
                audit_v2_path.as_path(),
                audit_v2_artifact_row_is_valid,
            );
            let event_delta = audit.rows as isize - audit_v2.rows as isize;
            context.audit_dual_write_artifact_ready =
                Some(audit.check.valid && audit_v2.check.valid && event_delta.abs() <= 1);
            context.checks.push(audit.check);
            context.checks.push(audit_v2.check);
        }
        (Some(audit_input), None) => {
            let audit_path = resolve_repo_relative_path(repo_root, audit_input.clone());
            context.checks.push(
                check_audit_jsonl_artifact(
                    "audit-v1",
                    audit_path.as_path(),
                    audit_v1_artifact_row_is_valid,
                )
                .check,
            );
            context.audit_dual_write_artifact_ready = Some(false);
        }
        (None, Some(audit_v2_input)) => {
            let audit_v2_path = resolve_repo_relative_path(repo_root, audit_v2_input.clone());
            context.checks.push(
                check_audit_jsonl_artifact(
                    "audit-v2",
                    audit_v2_path.as_path(),
                    audit_v2_artifact_row_is_valid,
                )
                .check,
            );
            context.audit_dual_write_artifact_ready = Some(false);
        }
        (None, None) => {}
    }

    if !args.plugin_shadow_inputs.is_empty() {
        let mut plugin_ready = true;
        for raw_path in &args.plugin_shadow_inputs {
            let path = resolve_repo_relative_path(repo_root, raw_path.clone());
            let check = check_plugin_shadow_sample(path.as_path());
            plugin_ready &= check.valid;
            context.checks.push(check);
        }
        context.plugin_shadow_sample_ready = Some(plugin_ready);
    }

    if !args.webhook_envelope_inputs.is_empty() {
        let mut webhook_ready = true;
        for raw_path in &args.webhook_envelope_inputs {
            let path = resolve_repo_relative_path(repo_root, raw_path.clone());
            let check = check_delivery_bridge_artifact(
                "webhook-bridge",
                path.as_path(),
                "patchgate.webhook.v2-shadow",
                "scan.completed",
            );
            webhook_ready &= check.valid;
            context.checks.push(check);
        }
        context.webhook_bridge_artifact_ready = Some(webhook_ready);
    }

    if !args.notification_envelope_inputs.is_empty() {
        let mut notification_ready = true;
        for raw_path in &args.notification_envelope_inputs {
            let path = resolve_repo_relative_path(repo_root, raw_path.clone());
            let check = check_delivery_bridge_artifact(
                "notification-bridge",
                path.as_path(),
                "patchgate.notification.v2-shadow",
                "scan.completed.notification",
            );
            notification_ready &= check.valid;
            context.checks.push(check);
        }
        context.notification_bridge_artifact_ready = Some(notification_ready);
    }

    let mut fleet_checks = Vec::new();
    if let Some(raw_path) = args.bundle_catalog_input.as_ref() {
        let path = resolve_repo_relative_path(repo_root, raw_path.clone());
        fleet_checks.push(check_bundle_catalog_artifact(path.as_path()));
    }
    if let Some(raw_path) = args.registry_input.as_ref() {
        let path = resolve_repo_relative_path(repo_root, raw_path.clone());
        fleet_checks.push(check_registry_provenance_artifact(path.as_path()));
    }
    if let Some(raw_path) = args.exceptions_input.as_ref() {
        let path = resolve_repo_relative_path(repo_root, raw_path.clone());
        fleet_checks.push(check_exception_governance_artifact(path.as_path()));
    }
    if !fleet_checks.is_empty() {
        let fleet_ready = fleet_checks.iter().all(|check| check.valid);
        context.checks.extend(fleet_checks);
        context.fleet_governance_artifact_ready = Some(fleet_ready);
    }

    context
}

fn check_provider_artifact(path: &Path) -> V2ArtifactCheck {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(raw.as_str()) {
            Ok(value) => {
                let schema_mode = classify_provider_artifact(&value);
                let repo = value
                    .get("repo")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let valid = matches!(schema_mode, "dual" | "v2");
                V2ArtifactCheck {
                    kind: "provider".to_string(),
                    path: path.display().to_string(),
                    present: true,
                    valid,
                    summary: format!("schema_mode={schema_mode} repo={repo}"),
                }
            }
            Err(err) => V2ArtifactCheck {
                kind: "provider".to_string(),
                path: path.display().to_string(),
                present: true,
                valid: false,
                summary: format!("invalid json: {err}"),
            },
        },
        Err(err) => V2ArtifactCheck {
            kind: "provider".to_string(),
            path: path.display().to_string(),
            present: false,
            valid: false,
            summary: format!("read failed: {err}"),
        },
    }
}

fn classify_provider_artifact(value: &Value) -> &'static str {
    if value.get("bridge_format").and_then(Value::as_str)
        == Some("patchgate.provider.generic.bridge.v1")
        && value.get("v1").is_some()
        && value.get("v2").is_some()
    {
        "dual"
    } else if value.get("publish_format").and_then(Value::as_str)
        == Some("patchgate.provider.generic.v2")
        && value.get("gate").is_some()
        && value.get("artifacts").is_some()
    {
        "v2"
    } else if value.get("provider").and_then(Value::as_str) == Some("generic")
        && value.get("summary").is_some()
        && value.get("report").is_some()
    {
        "v1"
    } else {
        "unknown"
    }
}

struct JsonlArtifactCheck {
    check: V2ArtifactCheck,
    rows: usize,
}

fn check_audit_jsonl_artifact(
    kind: &str,
    path: &Path,
    row_is_valid: fn(&Value) -> bool,
) -> JsonlArtifactCheck {
    match load_jsonl_values_for_artifact(path) {
        Ok(rows) => {
            let invalid_rows = rows.iter().filter(|row| !row_is_valid(row)).count();
            let row_count = rows.len();
            JsonlArtifactCheck {
                check: V2ArtifactCheck {
                    kind: kind.to_string(),
                    path: path.display().to_string(),
                    present: true,
                    valid: row_count > 0 && invalid_rows == 0,
                    summary: format!("rows={row_count} invalid_rows={invalid_rows}"),
                },
                rows: row_count,
            }
        }
        Err(err) => JsonlArtifactCheck {
            check: V2ArtifactCheck {
                kind: kind.to_string(),
                path: path.display().to_string(),
                present: path.exists(),
                valid: false,
                summary: err,
            },
            rows: 0,
        },
    }
}

fn load_jsonl_values_for_artifact(path: &Path) -> std::result::Result<Vec<Value>, String> {
    let file = fs::File::open(path).map_err(|err| format!("open failed: {err}"))?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|err| format!("read line {} failed: {err}", idx + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(line.as_str())
            .map_err(|err| format!("decode line {} failed: {err}", idx + 1))?;
        rows.push(value);
    }
    Ok(rows)
}

fn audit_v1_artifact_row_is_valid(row: &Value) -> bool {
    schema_version_in_range(row, 1, 10)
        && row.get("audit_format").and_then(Value::as_str) == Some("patchgate.audit.v1")
        && required_string(row, "actor")
        && required_string(row, "repo")
        && required_string(row, "target")
        && required_string(row, "mode")
        && required_string(row, "scope")
        && required_string(row, "result")
}

fn audit_v2_artifact_row_is_valid(row: &Value) -> bool {
    let Some(operation) = row.get("operation") else {
        return false;
    };
    schema_version_in_range(row, 2, 10)
        && row.get("audit_format").and_then(Value::as_str) == Some("patchgate.audit.v2")
        && required_string(row, "actor")
        && required_string(row, "repo")
        && required_string(operation, "target")
        && required_string(operation, "mode")
        && required_string(operation, "scope")
        && required_string(operation, "result")
        && row.get("gate").is_some()
        && row.get("failure").is_some()
}

fn schema_version_in_range(row: &Value, min: u64, max: u64) -> bool {
    row.get("schema_version")
        .and_then(Value::as_u64)
        .is_some_and(|version| (min..=max).contains(&version))
}

fn required_string(row: &Value, key: &str) -> bool {
    row.get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn check_plugin_shadow_sample(path: &Path) -> V2ArtifactCheck {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(raw.as_str()) {
            Ok(value) => {
                let valid = plugin_shadow_sample_is_valid(&value);
                let plugin_id = value
                    .get("plugin_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let bridge_mode = value
                    .get("metadata")
                    .and_then(|metadata| metadata.get("bridge_mode"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                V2ArtifactCheck {
                    kind: "plugin-shadow".to_string(),
                    path: path.display().to_string(),
                    present: true,
                    valid,
                    summary: format!("plugin_id={plugin_id} bridge_mode={bridge_mode}"),
                }
            }
            Err(err) => V2ArtifactCheck {
                kind: "plugin-shadow".to_string(),
                path: path.display().to_string(),
                present: true,
                valid: false,
                summary: format!("invalid json: {err}"),
            },
        },
        Err(err) => V2ArtifactCheck {
            kind: "plugin-shadow".to_string(),
            path: path.display().to_string(),
            present: false,
            valid: false,
            summary: format!("read failed: {err}"),
        },
    }
}

fn plugin_shadow_sample_is_valid(value: &Value) -> bool {
    value.get("schema_version").and_then(Value::as_u64) == Some(2)
        && value.get("api_version").and_then(Value::as_str) == Some("patchgate.plugin.v2-shadow")
        && value.get("shadow_of").and_then(Value::as_str) == Some("patchgate.plugin.v1")
        && required_string(value, "plugin_id")
        && value
            .get("changed_files")
            .and_then(Value::as_array)
            .is_some()
        && value
            .get("metadata")
            .and_then(|metadata| metadata.get("bridge_mode"))
            .and_then(Value::as_str)
            == Some("shadow")
}

fn check_delivery_bridge_artifact(
    kind: &str,
    path: &Path,
    expected_bridge_format: &str,
    expected_shadow_of: &str,
) -> V2ArtifactCheck {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(raw.as_str()) {
            Ok(value) => {
                let valid = delivery_bridge_artifact_is_valid(
                    &value,
                    expected_bridge_format,
                    expected_shadow_of,
                );
                let bridge_format = value
                    .get("bridge")
                    .and_then(|bridge| bridge.get("bridge_format"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let bridge_mode = value
                    .get("bridge")
                    .and_then(|bridge| bridge.get("bridge_mode"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                V2ArtifactCheck {
                    kind: kind.to_string(),
                    path: path.display().to_string(),
                    present: true,
                    valid,
                    summary: format!("bridge_format={bridge_format} bridge_mode={bridge_mode}"),
                }
            }
            Err(err) => V2ArtifactCheck {
                kind: kind.to_string(),
                path: path.display().to_string(),
                present: true,
                valid: false,
                summary: format!("invalid json: {err}"),
            },
        },
        Err(err) => V2ArtifactCheck {
            kind: kind.to_string(),
            path: path.display().to_string(),
            present: false,
            valid: false,
            summary: format!("read failed: {err}"),
        },
    }
}

fn delivery_bridge_artifact_is_valid(
    value: &Value,
    expected_bridge_format: &str,
    expected_shadow_of: &str,
) -> bool {
    required_string(value, "repo")
        && value.get("event").and_then(Value::as_str) == Some(expected_shadow_of)
        && value.get("bridge").is_some_and(|bridge| {
            delivery_bridge_metadata_is_valid(bridge, expected_bridge_format, expected_shadow_of)
        })
        && if expected_shadow_of == "scan.completed" {
            value.get("report").is_some()
        } else {
            value.get("summary").is_some()
        }
}

fn delivery_bridge_metadata_is_valid(
    bridge: &Value,
    expected_bridge_format: &str,
    expected_shadow_of: &str,
) -> bool {
    bridge.get("schema_version").and_then(Value::as_u64) == Some(1)
        && bridge.get("bridge_format").and_then(Value::as_str) == Some(expected_bridge_format)
        && bridge.get("shadow_of").and_then(Value::as_str) == Some(expected_shadow_of)
        && bridge.get("bridge_mode").and_then(Value::as_str) == Some("full")
}

fn check_bundle_catalog_artifact(path: &Path) -> V2ArtifactCheck {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(raw.as_str()) {
            Ok(value) => {
                let (valid, summary) = bundle_catalog_artifact_summary(&value);
                V2ArtifactCheck {
                    kind: "bundle-catalog".to_string(),
                    path: path.display().to_string(),
                    present: true,
                    valid,
                    summary,
                }
            }
            Err(err) => V2ArtifactCheck {
                kind: "bundle-catalog".to_string(),
                path: path.display().to_string(),
                present: true,
                valid: false,
                summary: format!("invalid json: {err}"),
            },
        },
        Err(err) => V2ArtifactCheck {
            kind: "bundle-catalog".to_string(),
            path: path.display().to_string(),
            present: false,
            valid: false,
            summary: format!("read failed: {err}"),
        },
    }
}

fn check_registry_provenance_artifact(path: &Path) -> V2ArtifactCheck {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(raw.as_str()) {
            Ok(value) => {
                let (valid, summary) = registry_provenance_artifact_summary(&value);
                V2ArtifactCheck {
                    kind: "registry-provenance".to_string(),
                    path: path.display().to_string(),
                    present: true,
                    valid,
                    summary,
                }
            }
            Err(err) => V2ArtifactCheck {
                kind: "registry-provenance".to_string(),
                path: path.display().to_string(),
                present: true,
                valid: false,
                summary: format!("invalid json: {err}"),
            },
        },
        Err(err) => V2ArtifactCheck {
            kind: "registry-provenance".to_string(),
            path: path.display().to_string(),
            present: false,
            valid: false,
            summary: format!("read failed: {err}"),
        },
    }
}

fn check_exception_governance_artifact(path: &Path) -> V2ArtifactCheck {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<Value>(raw.as_str()) {
            Ok(value) => {
                let (valid, summary) = exception_governance_artifact_summary(&value);
                V2ArtifactCheck {
                    kind: "exception-governance".to_string(),
                    path: path.display().to_string(),
                    present: true,
                    valid,
                    summary,
                }
            }
            Err(err) => V2ArtifactCheck {
                kind: "exception-governance".to_string(),
                path: path.display().to_string(),
                present: true,
                valid: false,
                summary: format!("invalid json: {err}"),
            },
        },
        Err(err) => V2ArtifactCheck {
            kind: "exception-governance".to_string(),
            path: path.display().to_string(),
            present: false,
            valid: false,
            summary: format!("read failed: {err}"),
        },
    }
}

fn value_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn string_values(value: &Value, key: &str) -> Vec<String> {
    value_array(value, key)
        .iter()
        .filter_map(Value::as_str)
        .filter(|item| !item.trim().is_empty())
        .map(ToString::to_string)
        .collect()
}

fn bundle_catalog_artifact_summary(value: &Value) -> (bool, String) {
    let bundles = value_array(value, "bundles");
    let segments = value_array(value, "segments");
    let retention_tiers = value_array(value, "retention_tiers");
    let rollout_waves = value_array(value, "rollout_waves");
    let segment_names = segments
        .iter()
        .filter_map(|segment| segment.get("segment").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let retention_names = retention_tiers
        .iter()
        .filter_map(|tier| tier.get("tier").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let wave_names = rollout_waves
        .iter()
        .filter_map(|wave| wave.get("wave").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let bundle_repo_names = bundles
        .iter()
        .filter_map(|bundle| bundle.get("repo").and_then(Value::as_str))
        .map(str::trim)
        .collect::<std::collections::BTreeSet<_>>();

    let valid_segments = segments.iter().all(|segment| {
        required_string(segment, "segment")
            && required_string(segment, "owner")
            && required_string(segment, "review_cadence")
            && segment
                .get("cost_ceiling_minutes")
                .and_then(Value::as_u64)
                .is_some_and(|ceiling| ceiling > 0)
    });
    let valid_retention = retention_tiers.iter().all(|tier| {
        let hot = tier.get("hot_days").and_then(Value::as_u64).unwrap_or(0);
        let warm = tier.get("warm_days").and_then(Value::as_u64).unwrap_or(0);
        let cold = tier.get("cold_days").and_then(Value::as_u64).unwrap_or(0);
        required_string(tier, "tier") && hot > 0 && hot <= warm && warm <= cold
    });
    let valid_waves = rollout_waves.iter().all(|wave| {
        required_string(wave, "wave")
            && required_string(wave, "entry_gate")
            && required_string(wave, "rollback_trigger")
            && wave
                .get("order")
                .and_then(Value::as_u64)
                .is_some_and(|order| order > 0)
            && wave
                .get("max_parallel")
                .and_then(Value::as_u64)
                .is_some_and(|max_parallel| max_parallel > 0)
    });
    let valid_bundles = !bundles.is_empty()
        && bundle_repo_names.len() == bundles.len()
        && bundles.iter().all(|bundle| {
            let required_modes = string_values(bundle, "required_provider_modes");
            let providers = string_values(bundle, "providers");
            let required_capabilities = string_values(bundle, "required_provider_capabilities");
            required_string(bundle, "repo")
                && required_string(bundle, "policy_bundle")
                && required_string(bundle, "wave")
                && required_string(bundle, "segment")
                && required_string(bundle, "retention_tier")
                && !providers.is_empty()
                && !required_modes.is_empty()
                && !required_capabilities.is_empty()
                && (wave_names.is_empty()
                    || bundle
                        .get("wave")
                        .and_then(Value::as_str)
                        .is_some_and(|wave| wave_names.contains(wave)))
                && (segment_names.is_empty()
                    || bundle
                        .get("segment")
                        .and_then(Value::as_str)
                        .is_some_and(|segment| segment_names.contains(segment)))
                && (retention_names.is_empty()
                    || bundle
                        .get("retention_tier")
                        .and_then(Value::as_str)
                        .is_some_and(|tier| retention_names.contains(tier)))
                && required_modes
                    .iter()
                    .all(|mode| matches!(mode.as_str(), "v1" | "v2" | "dual"))
                && bundle
                    .get("cost_ceiling_minutes")
                    .and_then(Value::as_u64)
                    .map_or(true, |ceiling| ceiling > 0)
        });
    let valid = schema_version_in_range(value, 1, 10)
        && value
            .get("generated_at")
            .and_then(Value::as_str)
            .and_then(ymd_key_for_artifact)
            .is_some()
        && !segments.is_empty()
        && !retention_tiers.is_empty()
        && !rollout_waves.is_empty()
        && segment_names.len() == segments.len()
        && retention_names.len() == retention_tiers.len()
        && wave_names.len() == rollout_waves.len()
        && valid_segments
        && valid_retention
        && valid_waves
        && valid_bundles;
    (
        valid,
        format!(
            "bundles={} segments={} retention_tiers={} rollout_waves={}",
            bundles.len(),
            segments.len(),
            retention_tiers.len(),
            rollout_waves.len()
        ),
    )
}

fn registry_provenance_artifact_summary(value: &Value) -> (bool, String) {
    let plugins = value_array(value, "plugins");
    let trusted = string_values(value, "trusted_provenance");
    let valid_plugins = !plugins.is_empty()
        && !trusted.is_empty()
        && trusted
            .iter()
            .all(|provenance| !provenance.trim().is_empty())
        && plugins.iter().all(|plugin| {
            let provenance = plugin
                .get("provenance")
                .and_then(Value::as_str)
                .unwrap_or("");
            required_string(plugin, "plugin_id")
                && required_string(plugin, "version")
                && required_string(plugin, "owner")
                && required_string(plugin, "source_repo")
                && required_string(plugin, "provenance")
                && required_string(plugin, "digest")
                && required_string(plugin, "attestation")
                && required_string(plugin, "sandbox_profile")
                && !string_values(plugin, "allowed_segments").is_empty()
                && plugin.get("verified").and_then(Value::as_bool) == Some(true)
                && plugin.get("revoked").and_then(Value::as_bool) != Some(true)
                && trusted.iter().any(|item| item == provenance)
        });
    let valid = schema_version_in_range(value, 1, 10) && valid_plugins;
    (
        valid,
        format!(
            "plugins={} trusted_provenance={}",
            plugins.len(),
            if trusted.is_empty() {
                "none".to_string()
            } else {
                trusted.join(",")
            }
        ),
    )
}

fn exception_governance_artifact_summary(value: &Value) -> (bool, String) {
    let exceptions = value_array(value, "exceptions");
    let exceptions_is_array = value.get("exceptions").is_some_and(Value::is_array);
    let reviewed_at = value
        .get("reviewed_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let valid_exceptions = exceptions.iter().all(|exception| {
        let status = exception
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("");
        required_string(exception, "repo")
            && required_string(exception, "kind")
            && required_string(exception, "scope")
            && required_string(exception, "ticket")
            && required_string(exception, "owner")
            && required_string(exception, "segment")
            && required_string(exception, "approved_by")
            && required_string(exception, "expires_at")
            && required_string(exception, "review_cadence")
            && matches!(status, "approved" | "active" | "temporary")
            && exception_expired(
                exception
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                reviewed_at,
            ) == Some(false)
    });
    let valid = schema_version_in_range(value, 1, 10)
        && ymd_key_for_artifact(reviewed_at).is_some()
        && exceptions_is_array
        && valid_exceptions;
    (
        valid,
        format!("exceptions={} reviewed_at={reviewed_at}", exceptions.len()),
    )
}

fn ymd_key_for_artifact(raw: &str) -> Option<(u16, u8, u8)> {
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
    let year = artifact_parse_ascii_u16(&bytes[0..4])?;
    let month = artifact_parse_ascii_u8(&bytes[5..7])?;
    let day = artifact_parse_ascii_u8(&bytes[8..10])?;
    if month == 0 || month > 12 {
        return None;
    }
    let max_day = artifact_days_in_month(year, month)?;
    if day == 0 || day > max_day {
        return None;
    }
    Some((year, month, day))
}

fn artifact_parse_ascii_u16(bytes: &[u8]) -> Option<u16> {
    bytes.iter().try_fold(0u16, |acc, byte| {
        byte.is_ascii_digit()
            .then_some(acc * 10 + u16::from(*byte - b'0'))
    })
}

fn artifact_parse_ascii_u8(bytes: &[u8]) -> Option<u8> {
    bytes.iter().try_fold(0u8, |acc, byte| {
        byte.is_ascii_digit().then_some(acc * 10 + (*byte - b'0'))
    })
}

fn artifact_days_in_month(year: u16, month: u8) -> Option<u8> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if artifact_is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    })
}

fn artifact_is_leap_year(year: u16) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn exception_expired(expires_at: &str, reviewed_at: &str) -> Option<bool> {
    let expires = ymd_key_for_artifact(expires_at)?;
    let reviewed = ymd_key_for_artifact(reviewed_at)?;
    Some(expires < reviewed)
}

fn build_v2_readiness_report(
    repo_root: &Path,
    policy_path: &Path,
    cfg: &Config,
    readiness_profile: V2ReadinessProfile,
    artifact_context: V2ArtifactContext,
) -> V2ReadinessReport {
    let mut warnings = Vec::new();
    let mut next_actions = Vec::new();
    let migration_guide_path = cfg.compatibility.v2.migration_guide_path.clone();
    let migration_guide_exists =
        resolve_optional_repo_path(repo_root, migration_guide_path.as_str())
            .is_some_and(|path| path.exists());
    let bridge_mode = cfg.compatibility.v2.bridge_mode.as_str();
    let uses_generic_provider = cfg.integrations.ci.provider == "generic";
    let audit_v2_output_enabled = !cfg.observability.audit_v2_jsonl_path.trim().is_empty();
    let lts_branch_ready = cfg.release.lts.branch == "lts/v2";
    let lts_sla_ready = cfg.release.lts.security_sla_hours <= 72;

    if !cfg.compatibility.v1.rc_frozen {
        warnings.push("verify-v2 requires compatibility.v1.rc_frozen=true".to_string());
        next_actions.push("Freeze v1 compatibility before enabling v2 shadow work.".to_string());
    }
    if cfg.compatibility.v1.allow_legacy_config_names {
        warnings.push(
            "verify-v2 requires compatibility.v1.allow_legacy_config_names=false".to_string(),
        );
        next_actions
            .push("Disable legacy config names before widening the contract surface.".to_string());
    }
    if !cfg.compatibility.v2.shadow_mode {
        warnings.push("compatibility.v2.shadow_mode=false".to_string());
        next_actions
            .push("Enable compatibility.v2.shadow_mode to start bridge validation.".to_string());
    }
    if bridge_mode == "off" {
        warnings.push("compatibility.v2.bridge_mode=off".to_string());
        next_actions
            .push("Use bridge_mode=provider|audit|full before claiming v2 readiness.".to_string());
    }
    if uses_generic_provider
        && matches!(bridge_mode, "provider" | "full")
        && cfg.integrations.ci.generic_schema == "v1"
    {
        warnings
            .push("provider bridge requires integrations.ci.generic_schema=v2|dual".to_string());
        next_actions.push("Switch integrations.ci.generic_schema to `v2` or `dual`.".to_string());
    }
    if matches!(bridge_mode, "audit" | "full") && !audit_v2_output_enabled {
        warnings.push("audit bridge requires observability.audit_v2_jsonl_path".to_string());
        next_actions
            .push("Configure observability.audit_v2_jsonl_path for audit dual-write.".to_string());
    }
    if cfg.compatibility.v2.shadow_mode && !migration_guide_exists {
        warnings.push("compatibility.v2.migration_guide_path is missing or unresolved".to_string());
        next_actions.push("Add a migration guide artifact for the v2 shadow rollout.".to_string());
    }
    if artifact_context.provider_artifact_ready == Some(false) {
        warnings.push("provider bridge artifact check failed".to_string());
        next_actions.push(
            "Generate a generic provider artifact with `--ci-generic-schema dual` or `v2`."
                .to_string(),
        );
    }
    if artifact_context.audit_dual_write_artifact_ready == Some(false) {
        warnings.push("audit dual-write artifact check failed".to_string());
        next_actions.push(
            "Regenerate audit v1/v2 JSONL with matching scan scope, then run shadow-review."
                .to_string(),
        );
    }
    if artifact_context.plugin_shadow_sample_ready == Some(false) {
        warnings.push("plugin v2 shadow sample check failed".to_string());
        next_actions.push(
            "Regenerate SDK template samples or provide a valid `sample-input.v2.json`."
                .to_string(),
        );
    }
    if artifact_context.webhook_bridge_artifact_ready == Some(false) {
        warnings.push("webhook bridge artifact check failed".to_string());
        next_actions.push(
            "Capture or provide a webhook envelope with `patchgate.webhook.v2-shadow` metadata."
                .to_string(),
        );
    }
    if artifact_context.notification_bridge_artifact_ready == Some(false) {
        warnings.push("notification bridge artifact check failed".to_string());
        next_actions.push(
            "Capture or provide a notification envelope with `patchgate.notification.v2-shadow` metadata."
                .to_string(),
        );
    }
    if artifact_context.fleet_governance_artifact_ready == Some(false) {
        warnings.push("fleet governance artifact check failed".to_string());
        next_actions.push(
            "Fix bundle catalog, registry provenance, or exception governance fixtures before fleet review."
                .to_string(),
        );
    }
    if readiness_profile.requires_v2_lts() {
        if !cfg.release.lts.active {
            warnings.push("v2 GA/LTS readiness requires release.lts.active=true".to_string());
            next_actions.push("Enable release.lts before promoting the v2 GA packet.".to_string());
        }
        if !lts_branch_ready {
            warnings.push("v2 GA/LTS readiness requires release.lts.branch=lts/v2".to_string());
            next_actions
                .push("Set release.lts.branch to `lts/v2` for the v2 LTS line.".to_string());
        }
        if !lts_sla_ready {
            warnings.push(
                "v2 GA/LTS readiness expects release.lts.security_sla_hours <= 72".to_string(),
            );
            next_actions
                .push("Set release.lts.security_sla_hours to 72 or lower for v2 LTS.".to_string());
        }
    }

    let ready = cfg.policy_version == POLICY_VERSION_CURRENT
        && cfg.compatibility.v1.rc_frozen
        && !cfg.compatibility.v1.allow_legacy_config_names
        && cfg.compatibility.v2.shadow_mode
        && bridge_mode != "off"
        && (!uses_generic_provider
            || !matches!(bridge_mode, "provider" | "full")
            || cfg.integrations.ci.generic_schema != "v1")
        && (!matches!(bridge_mode, "audit" | "full") || audit_v2_output_enabled)
        && migration_guide_exists
        && artifact_context.ready()
        && (!readiness_profile.requires_v2_lts()
            || (cfg.release.lts.active && lts_branch_ready && lts_sla_ready));

    if ready {
        if artifact_context.has_checks() {
            next_actions
                .push("v2 shadow/bridge policy and artifact checks are satisfied.".to_string());
        } else {
            next_actions.push("v2 shadow/bridge prerequisites are satisfied.".to_string());
        }
    }

    V2ReadinessReport {
        ready,
        policy_path: policy_path.display().to_string(),
        policy_version: cfg.policy_version,
        readiness_profile: readiness_profile.as_str().to_string(),
        v1_rc_frozen: cfg.compatibility.v1.rc_frozen,
        v1_strict_compatibility: !cfg.compatibility.v1.allow_legacy_config_names,
        v2_shadow_mode: cfg.compatibility.v2.shadow_mode,
        v2_bridge_mode: cfg.compatibility.v2.bridge_mode.clone(),
        migration_guide_path,
        migration_guide_exists,
        ci_provider: cfg.integrations.ci.provider.clone(),
        ci_generic_schema: cfg.integrations.ci.generic_schema.clone(),
        audit_schema_version: cfg.observability.audit_schema_version,
        audit_v2_schema_version: cfg.observability.audit_v2_schema_version,
        audit_v2_output_enabled,
        lts_active: cfg.release.lts.active,
        lts_branch: cfg.release.lts.branch.clone(),
        lts_security_sla_hours: cfg.release.lts.security_sla_hours,
        provider_artifact_ready: artifact_context.provider_artifact_ready,
        audit_dual_write_artifact_ready: artifact_context.audit_dual_write_artifact_ready,
        plugin_shadow_sample_ready: artifact_context.plugin_shadow_sample_ready,
        webhook_bridge_artifact_ready: artifact_context.webhook_bridge_artifact_ready,
        notification_bridge_artifact_ready: artifact_context.notification_bridge_artifact_ready,
        fleet_governance_artifact_ready: artifact_context.fleet_governance_artifact_ready,
        artifact_checks: artifact_context.checks,
        warnings,
        next_actions,
    }
}

fn print_v2_readiness_report(
    report: &V2ReadinessReport,
    format: &str,
) -> std::result::Result<(), String> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(report)
                .map_err(|err| format!("failed to encode json: {err}"))?;
            println!("{json}");
        }
        "text" => {
            println!("patchgate policy verify-v2");
            println!("- ready: {}", report.ready);
            println!("- policy_path: {}", report.policy_path);
            println!("- policy_version: {}", report.policy_version);
            println!("- readiness_profile: {}", report.readiness_profile);
            println!("- v1_rc_frozen: {}", report.v1_rc_frozen);
            println!(
                "- v1_strict_compatibility: {}",
                report.v1_strict_compatibility
            );
            println!("- v2_shadow_mode: {}", report.v2_shadow_mode);
            println!("- v2_bridge_mode: {}", report.v2_bridge_mode);
            println!("- migration_guide_path: {}", report.migration_guide_path);
            println!(
                "- migration_guide_exists: {}",
                report.migration_guide_exists
            );
            println!("- ci_provider: {}", report.ci_provider);
            println!("- ci_generic_schema: {}", report.ci_generic_schema);
            println!("- audit_schema_version: {}", report.audit_schema_version);
            println!(
                "- audit_v2_schema_version: {}",
                report.audit_v2_schema_version
            );
            println!(
                "- audit_v2_output_enabled: {}",
                report.audit_v2_output_enabled
            );
            println!("- lts_active: {}", report.lts_active);
            println!("- lts_branch: {}", report.lts_branch);
            println!(
                "- lts_security_sla_hours: {}",
                report.lts_security_sla_hours
            );
            print_optional_bool("- provider_artifact_ready", report.provider_artifact_ready);
            print_optional_bool(
                "- audit_dual_write_artifact_ready",
                report.audit_dual_write_artifact_ready,
            );
            print_optional_bool(
                "- plugin_shadow_sample_ready",
                report.plugin_shadow_sample_ready,
            );
            print_optional_bool(
                "- webhook_bridge_artifact_ready",
                report.webhook_bridge_artifact_ready,
            );
            print_optional_bool(
                "- notification_bridge_artifact_ready",
                report.notification_bridge_artifact_ready,
            );
            print_optional_bool(
                "- fleet_governance_artifact_ready",
                report.fleet_governance_artifact_ready,
            );
            if report.artifact_checks.is_empty() {
                println!("- artifact_checks: none");
            } else {
                println!("- artifact_checks:");
                for check in &report.artifact_checks {
                    println!(
                        "  - {}: present={} valid={} path={}",
                        check.kind, check.present, check.valid, check.path
                    );
                    println!("    - {}", check.summary);
                }
            }
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
        }
        other => {
            return Err(format!(
                "unsupported --format `{other}` (expected: text|json)"
            ))
        }
    }
    Ok(())
}

fn print_optional_bool(label: &str, value: Option<bool>) {
    match value {
        Some(value) => println!("{label}: {value}"),
        None => println!("{label}: not_checked"),
    }
}

fn build_contract_diff_report(
    repo_root: &Path,
    policy_path: &Path,
    cfg: &Config,
) -> ContractDiffReport {
    let migration_guide_exists = resolve_optional_repo_path(
        repo_root,
        cfg.compatibility.v2.migration_guide_path.as_str(),
    )
    .is_some_and(|path| path.exists());
    let v1_contract = ContractSurfaceSummary {
        enabled: true,
        details: vec![
            format!("policy_version={}", cfg.policy_version),
            format!(
                "compatibility.v1.rc_frozen={}",
                cfg.compatibility.v1.rc_frozen
            ),
            format!(
                "compatibility.v1.allow_legacy_config_names={}",
                cfg.compatibility.v1.allow_legacy_config_names
            ),
            format!("integrations.ci.provider={}", cfg.integrations.ci.provider),
            format!(
                "observability.audit_schema_version={}",
                cfg.observability.audit_schema_version
            ),
        ],
    };
    let v2_contract = ContractSurfaceSummary {
        enabled: cfg.compatibility.v2.shadow_mode || cfg.compatibility.v2.bridge_mode != "off",
        details: vec![
            format!(
                "compatibility.v2.shadow_mode={}",
                cfg.compatibility.v2.shadow_mode
            ),
            format!(
                "compatibility.v2.bridge_mode={}",
                cfg.compatibility.v2.bridge_mode
            ),
            format!(
                "integrations.ci.generic_schema={}",
                cfg.integrations.ci.generic_schema
            ),
            format!(
                "observability.audit_v2_schema_version={}",
                cfg.observability.audit_v2_schema_version
            ),
            format!(
                "observability.audit_v2_jsonl_path={}",
                if cfg.observability.audit_v2_jsonl_path.is_empty() {
                    "<disabled>".to_string()
                } else {
                    cfg.observability.audit_v2_jsonl_path.clone()
                }
            ),
            format!("migration_guide_exists={migration_guide_exists}"),
        ],
    };
    let mut migration_delta = Vec::new();
    migration_delta.push(format!(
        "provider payload schema: {} -> {}",
        "v1", cfg.integrations.ci.generic_schema
    ));
    migration_delta.push(format!(
        "audit export: v{} -> v{}",
        cfg.observability.audit_schema_version, cfg.observability.audit_v2_schema_version
    ));
    migration_delta.push(format!(
        "bridge mode: off -> {}",
        cfg.compatibility.v2.bridge_mode
    ));

    let mut next_actions = Vec::new();
    if cfg.policy_version != POLICY_VERSION_CURRENT {
        next_actions.push(format!(
            "Migrate policy_version to {POLICY_VERSION_CURRENT} before freezing the v2 contract."
        ));
    }
    if !cfg.compatibility.v1.rc_frozen {
        next_actions
            .push("Set compatibility.v1.rc_frozen=true before RC contract freeze.".to_string());
    }
    if cfg.compatibility.v1.allow_legacy_config_names {
        next_actions.push(
            "Set compatibility.v1.allow_legacy_config_names=false to enforce the freeze boundary."
                .to_string(),
        );
    }
    if !cfg.compatibility.v2.shadow_mode {
        next_actions
            .push("Enable compatibility.v2.shadow_mode before attempting dual-run.".to_string());
    }
    if cfg.compatibility.v2.bridge_mode == "off" {
        next_actions.push(
            "Set compatibility.v2.bridge_mode to provider, audit, or full for RC evidence."
                .to_string(),
        );
    }
    if cfg.integrations.ci.generic_schema == "v1" {
        next_actions.push("Switch integrations.ci.generic_schema to `v2` or `dual` for provider bridge validation.".to_string());
    }
    if cfg.observability.audit_v2_schema_version != 2 {
        next_actions.push(
            "Set observability.audit_v2_schema_version=2 for the v2 audit export gate.".to_string(),
        );
    }
    if cfg.observability.audit_v2_jsonl_path.trim().is_empty() {
        next_actions
            .push("Configure observability.audit_v2_jsonl_path for audit dual-write.".to_string());
    }
    if !migration_guide_exists {
        next_actions.push(
            "Add the migration guide referenced by compatibility.v2.migration_guide_path."
                .to_string(),
        );
    }
    let breaking_change_gate_ready = cfg.policy_version == POLICY_VERSION_CURRENT
        && cfg.compatibility.v1.rc_frozen
        && !cfg.compatibility.v1.allow_legacy_config_names
        && cfg.compatibility.v2.shadow_mode
        && v2_contract.enabled
        && migration_guide_exists
        && cfg.compatibility.v2.bridge_mode != "off"
        && cfg.observability.audit_v2_schema_version == 2
        && !cfg.observability.audit_v2_jsonl_path.trim().is_empty()
        && (cfg.integrations.ci.provider != "generic"
            || cfg.integrations.ci.generic_schema != "v1");

    if next_actions.is_empty() {
        next_actions.push(if breaking_change_gate_ready {
            "Breaking-change boundary is ready for RC freeze.".to_string()
        } else {
            "Contract bridge inputs are present; continue with shadow traffic review.".to_string()
        });
    }

    ContractDiffReport {
        policy_path: policy_path.display().to_string(),
        breaking_change_gate_ready,
        v1_contract,
        v2_contract,
        migration_delta,
        next_actions,
    }
}

fn print_contract_diff_report(
    report: &ContractDiffReport,
    format: &str,
) -> std::result::Result<(), String> {
    match format {
        "json" => {
            let json = render_contract_diff_report_json(report)?;
            println!("{json}");
        }
        "text" => {
            print!("{}", render_contract_diff_report_text(report));
        }
        other => {
            return Err(format!(
                "unsupported --format `{other}` (expected: text|json)"
            ))
        }
    }
    Ok(())
}

fn render_contract_diff_report_json(
    report: &ContractDiffReport,
) -> std::result::Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|err| format!("failed to encode json: {err}"))
}

fn render_contract_diff_report_text(report: &ContractDiffReport) -> String {
    let mut out = String::new();
    out.push_str("patchgate policy diff-contract\n");
    out.push_str(&format!("- policy_path: {}\n", report.policy_path));
    out.push_str(&format!(
        "- breaking_change_gate_ready: {}\n",
        report.breaking_change_gate_ready
    ));
    out.push_str(&format!(
        "- v1_contract_enabled: {}\n",
        report.v1_contract.enabled
    ));
    for detail in &report.v1_contract.details {
        out.push_str(&format!("  - v1: {detail}\n"));
    }
    out.push_str(&format!(
        "- v2_contract_enabled: {}\n",
        report.v2_contract.enabled
    ));
    for detail in &report.v2_contract.details {
        out.push_str(&format!("  - v2: {detail}\n"));
    }
    out.push_str("- migration_delta:\n");
    for item in &report.migration_delta {
        out.push_str(&format!("  - {item}\n"));
    }
    out.push_str("- next_actions:\n");
    for action in &report.next_actions {
        out.push_str(&format!("  - {action}\n"));
    }
    out
}

fn resolve_optional_repo_path(repo_root: &Path, raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(resolve_repo_relative_path(
            repo_root,
            PathBuf::from(trimmed),
        ))
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
                if cfg!(target_os = "linux") && isolated_runtime_supported {
                    next_actions.push(
                        "Set `plugins.sandbox.profile = \"isolated\"` for strict/lts readiness."
                            .to_string(),
                    );
                    autofixes.push(PolicyAutofix::SetPluginSandboxProfile("isolated"));
                } else if !cfg!(target_os = "linux") {
                    warnings.push(
                        "strict/lts readiness with plugins.sandbox.profile=isolated requires Linux runtime"
                            .to_string(),
                    );
                    next_actions.push(
                        "Run strict/lts readiness verification on Linux before switching plugins to the isolated sandbox profile."
                            .to_string(),
                    );
                } else {
                    warnings.push(
                        "strict/lts readiness with plugins.sandbox.profile=isolated requires bwrap on Linux"
                            .to_string(),
                    );
                    next_actions.push(
                        "Install `bwrap` (bubblewrap) before switching plugins to the isolated sandbox profile."
                            .to_string(),
                    );
                }
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
        apply_policy_autofix(&mut doc, autofix)?;
    }
    write_text_atomic(output_path, doc.to_string().as_str())
        .with_context(|| format!("write autofixed policy: {}", output_path.display()))
}

fn apply_policy_autofix(doc: &mut DocumentMut, autofix: &PolicyAutofix) -> Result<()> {
    match autofix {
        PolicyAutofix::SetRcFrozen => {
            let compatibility = ensure_table(doc.as_table_mut(), "compatibility")?;
            let v1 = ensure_table(compatibility, "v1")?;
            v1["rc_frozen"] = value(true);
        }
        PolicyAutofix::DisableLegacyConfigNames => {
            let compatibility = ensure_table(doc.as_table_mut(), "compatibility")?;
            let v1 = ensure_table(compatibility, "v1")?;
            v1["allow_legacy_config_names"] = value(false);
        }
        PolicyAutofix::SetPluginSandboxProfile(profile) => {
            let plugins = ensure_table(doc.as_table_mut(), "plugins")?;
            let sandbox = ensure_table(plugins, "sandbox")?;
            sandbox["profile"] = value(*profile);
        }
        PolicyAutofix::SetLtsActive => {
            let release = ensure_table(doc.as_table_mut(), "release")?;
            let lts = ensure_table(release, "lts")?;
            lts["active"] = value(true);
        }
        PolicyAutofix::SetLtsSecuritySlaHours(hours) => {
            let release = ensure_table(doc.as_table_mut(), "release")?;
            let lts = ensure_table(release, "lts")?;
            lts["security_sla_hours"] = value(i64::from(*hours));
        }
    }
    Ok(())
}

fn ensure_table<'a>(table: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    if !table.contains_key(key) {
        table[key] = Item::Table(Table::new());
    } else if !table[key].is_table() {
        let item = table
            .remove(key)
            .expect("key must exist when converting autofix path");
        match item.into_table() {
            Ok(converted) => {
                table[key] = Item::Table(converted);
            }
            Err(original) => {
                table[key] = original;
                anyhow::bail!(
                    "autofix expected `{key}` to be a table or inline table; refusing to overwrite existing non-table value"
                );
            }
        }
    }
    table[key]
        .as_table_mut()
        .ok_or_else(|| anyhow!("autofix expected `{key}` to resolve to a table"))
}

fn write_text_atomic(path: &Path, content: &str) -> Result<()> {
    let (temp_path, mut temp_file) = create_sibling_temp_file(path)?;
    temp_file
        .write_all(content.as_bytes())
        .with_context(|| format!("write temp file {}", temp_path.display()))?;
    temp_file
        .sync_all()
        .with_context(|| format!("sync temp file {}", temp_path.display()))?;
    drop(temp_file);
    if let Err(err) = replace_file(temp_path.as_path(), path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    Ok(())
}

fn create_sibling_temp_file(path: &Path) -> Result<(PathBuf, fs::File)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    // `create_new(true)` avoids overwriting attacker-controlled symlinks or files.
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("patchgate-policy");
    let pid = std::process::id();
    #[cfg(unix)]
    let existing_mode = existing_file_mode(path)?;
    for _ in 0..64 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let temp_path = path.with_file_name(format!(".{file_name}.tmp-{pid}-{nonce}-{seq}"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            if let Some(mode) = existing_mode {
                options.mode(mode);
            }
        }
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("create temp file {}", temp_path.display()));
            }
        }
    }

    anyhow::bail!(
        "failed to allocate unique temp file alongside {}",
        path.display()
    );
}

#[cfg(unix)]
fn existing_file_mode(path: &Path) -> Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;

    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.permissions().mode() & 0o777)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("stat existing file {}", path.display())),
    }
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
        base_ref,
        protected_policy_ref,
        org_policy_bundle,
        org_policy_bundle_signature,
        org_policy_public_key_env,
        allow_untrusted_policy_for_local_enforce,
        threshold,
        max_changed_files,
        on_exceed,
        no_cache,
        profile_output,
        metrics_output,
        audit_log_output,
        audit_log_v2_output,
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
        ci_generic_schema,
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
    let provisional_mode = mode.clone().unwrap_or_else(|| "warn".to_string());
    let mut authority_common = PolicyAuthorityCommonArgs {
        path: config_path.clone(),
        policy_preset: policy_preset.clone(),
        mode: provisional_mode,
        base_ref,
        head_ref: None,
        protected_policy_ref,
        org_policy_bundle,
        org_policy_bundle_signature,
        org_policy_public_key_env,
        allow_untrusted_policy_for_local_enforce,
        format: "json".to_string(),
    };
    let mut authority_resolution = resolve_policy_authority_from_common_with_preset(
        repo_root,
        config_override,
        &authority_common,
        preset,
    )
    .map_err(policy_authority_resolution_scan_error)?;
    let requested_mode = mode
        .clone()
        .unwrap_or_else(|| authority_resolution.resolution.config.output.mode.clone());
    if requested_mode != authority_common.mode {
        authority_common.mode = requested_mode.clone();
        authority_resolution = resolve_policy_authority_from_common_with_preset(
            repo_root,
            config_override,
            &authority_common,
            preset,
        )
        .map_err(policy_authority_resolution_scan_error)?;
    }
    for warning in &authority_resolution
        .resolution
        .loaded
        .compatibility_warnings
    {
        eprintln!("warning: {warning}");
    }
    if requested_mode == "enforce"
        && (threshold.is_some() || max_changed_files.is_some() || on_exceed.is_some())
    {
        return Err(ScanError::with_hint(
            ScanErrorKind::Input,
            FailureCode::InputInvalidOption,
            "Move enforce-mode policy changes into the trusted base policy or use a stricter PR overlay.",
            anyhow!(
                "enforce mode does not accept policy-changing CLI overrides: --threshold, --max-changed-files, --on-exceed"
            ),
        ));
    }
    let authority = authority_resolution.resolution.authority.clone();
    let authority_failures = authority_resolution.resolution.enforce_failures.clone();
    let mut cfg = authority_resolution.resolution.config.clone();

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
        let policy_hash =
            effective_policy_hash(&cfg, &authority, &authority_failures).map_err(|err| {
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
    attach_policy_authority(
        &mut report,
        authority,
        &authority_failures,
        opts.mode.as_str(),
    );
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
                let generic_schema_mode = resolve_generic_ci_schema_mode(
                    ci_generic_schema.as_deref(),
                    Some(cfg.integrations.ci.generic_schema.as_str()),
                )
                .map_err(|err| {
                    ScanError::with_code(
                        ScanErrorKind::Input,
                        FailureCode::InputInvalidOption,
                        anyhow!(
                            "invalid value for --ci-generic-schema / integrations.ci.generic_schema: {err}"
                        ),
                    )
                })?;
                let generic_output = ci_generic_output.clone().or(config_generic_output);
                publish_generic_ci_payload(
                    telemetry_repo.as_str(),
                    &report,
                    &markdown,
                    generic_schema_mode,
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
    let delivery_bridge = DeliveryBridgeContext::from_config(&cfg);

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
                bridge: delivery_bridge,
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
                bridge: delivery_bridge,
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
    let audit_v2_path = audit_log_v2_output
        .as_deref()
        .map(Path::to_path_buf)
        .or_else(|| {
            non_empty_path(cfg.observability.audit_v2_jsonl_path.as_str())
                .map(|p| resolve_repo_relative_path(repo_root, p))
        });
    append_scan_success_records(
        telemetry_repo.as_str(),
        &report,
        ScanSuccessOutputs {
            metrics_path: metrics_path.as_deref(),
            audit_path: audit_path.as_deref(),
            audit_v2_path: audit_v2_path.as_deref(),
            actor: resolve_audit_actor(audit_actor.as_deref()),
            audit_schema_version: cfg.observability.audit_schema_version,
            audit_v2_schema_version: cfg.observability.audit_v2_schema_version,
        },
    )?;

    Ok(gate_exit_code(&opts.mode, report.should_fail))
}

fn append_scan_success_records(
    telemetry_repo: &str,
    report: &Report,
    outputs: ScanSuccessOutputs<'_>,
) -> ScanResult<()> {
    let unix_ts = current_unix_ts();
    if let Some(path) = outputs.metrics_path {
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

    if let Some(path) = outputs.audit_path {
        let result = if report.should_fail {
            "gate_fail"
        } else {
            "pass"
        };
        let audit = AuditLogRecord {
            schema_version: outputs.audit_schema_version,
            audit_format: "patchgate.audit.v1".to_string(),
            unix_ts,
            actor: outputs.actor.clone(),
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

    if let Some(path) = outputs.audit_v2_path {
        let result = if report.should_fail {
            "gate_fail"
        } else {
            "pass"
        };
        let audit = AuditLogV2Record {
            schema_version: outputs.audit_v2_schema_version,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: unix_ts,
            actor: outputs.actor,
            repo: telemetry_repo.to_string(),
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: report.mode.clone(),
                scope: report.scope.clone(),
                result: result.to_string(),
            },
            gate: AuditGateV2 {
                score: Some(report.score),
                threshold: Some(report.threshold),
                changed_files: Some(report.changed_files),
            },
            failure: AuditFailureV2 {
                code: None,
                category: None,
            },
            diagnostics: report.diagnostic_hints.clone(),
        };
        append_jsonl(path, &audit).map_err(|err| {
            ScanError::with_code(
                ScanErrorKind::Output,
                FailureCode::OutputWriteFailed,
                err.context("failed to append audit v2 jsonl"),
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
    let mut audit_v2_path = scan.audit_log_v2_output.clone();
    let mut audit_schema_version = 1u8;
    let mut audit_v2_schema_version = 2u8;
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
        if audit_v2_path.is_none() {
            audit_v2_path =
                non_empty_path(loaded.config.observability.audit_v2_jsonl_path.as_str())
                    .map(|p| resolve_repo_relative_path(repo_root, p));
        }
        audit_schema_version = loaded.config.observability.audit_schema_version;
        audit_v2_schema_version = loaded.config.observability.audit_v2_schema_version;
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
            repo: telemetry_repo.clone(),
            target: "scan".to_string(),
            mode: telemetry_mode.clone(),
            scope: telemetry_scope.clone(),
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

    if let Some(path) = audit_v2_path.as_deref() {
        let audit = AuditLogV2Record {
            schema_version: audit_v2_schema_version,
            audit_format: "patchgate.audit.v2".to_string(),
            emitted_at: unix_ts,
            actor: resolve_audit_actor(scan.audit_actor.as_deref()),
            repo: telemetry_repo,
            operation: AuditOperationV2 {
                target: "scan".to_string(),
                mode: telemetry_mode,
                scope: telemetry_scope,
                result: "error".to_string(),
            },
            gate: AuditGateV2 {
                score: None,
                threshold: None,
                changed_files: None,
            },
            failure: AuditFailureV2 {
                code: Some(err.code().as_str().to_string()),
                category: Some(err.code().category().to_string()),
            },
            diagnostics: err.hint().map(|h| vec![h.to_string()]).unwrap_or_default(),
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

fn resolve_cwd_relative_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("resolve current directory")?
            .join(path))
    }
}

fn paths_conflict(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
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
    let check_name = github_check_name.unwrap_or_else(|| DEFAULT_GITHUB_CHECK_NAME.to_string());
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

fn policy_authority_relative_path(repo_root: &Path, policy_path: Option<&Path>) -> Result<String> {
    match policy_path {
        Some(path) if path.is_absolute() => {
            let relative = path.strip_prefix(repo_root).with_context(|| {
                format!(
                    "policy path {} must be inside repository root {} for trusted ref resolution",
                    path.display(),
                    repo_root.display()
                )
            })?;
            let relative = relative
                .to_str()
                .ok_or_else(|| anyhow!("policy path {} is not valid UTF-8", path.display()))?;
            Ok(relative.replace('\\', "/"))
        }
        Some(path) => Ok(path.to_string_lossy().replace('\\', "/")),
        None => Ok("policy.toml".to_string()),
    }
}

fn read_optional_policy_file(path: Option<&Path>) -> Result<Option<String>> {
    match path {
        Some(path) if path.exists() => fs::read_to_string(path)
            .map(Some)
            .with_context(|| format!("read policy file {}", path.display())),
        _ => Ok(None),
    }
}

fn read_git_file_at_ref(
    repo_root: &Path,
    ref_name: &str,
    rel_path: &str,
    missing_policy_is_error: bool,
) -> Result<Option<String>> {
    if ref_name.trim().is_empty() || rel_path.trim().is_empty() {
        return Ok(None);
    }
    let object = format!("{ref_name}:{rel_path}");
    let output = ProcessCommand::new("git")
        .arg("show")
        .arg(object)
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("run git show for {ref_name}:{rel_path}"))?;
    if output.status.success() {
        return String::from_utf8(output.stdout)
            .map(Some)
            .with_context(|| format!("decode git show output for {ref_name}:{rel_path}"));
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if git_ref_exists(repo_root, ref_name)? {
        if missing_policy_is_error {
            return Err(anyhow!(
                "trusted policy ref `{ref_name}` exists but `{rel_path}` is missing: {stderr}"
            ));
        }
        return Ok(None);
    }
    Err(anyhow!(
        "trusted policy ref `{ref_name}` is not available for `{rel_path}`: {stderr}"
    ))
}

fn git_ref_exists(repo_root: &Path, ref_name: &str) -> Result<bool> {
    let output = ProcessCommand::new("git")
        .arg("rev-parse")
        .arg("--verify")
        .arg("--quiet")
        .arg(format!("{ref_name}^{{tree}}"))
        .current_dir(repo_root)
        .output()
        .with_context(|| format!("run git rev-parse for {ref_name}"))?;
    Ok(output.status.success())
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn non_empty_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
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

fn resolve_generic_ci_schema_mode(
    cli_value: Option<&str>,
    config_value: Option<&str>,
) -> std::result::Result<GenericCiSchemaMode, String> {
    GenericCiSchemaMode::parse(cli_value.or(config_value))
}

fn publish_generic_ci_payload(
    telemetry_repo: &str,
    report: &Report,
    markdown: &str,
    schema_mode: GenericCiSchemaMode,
    output_path: Option<&Path>,
) -> Result<()> {
    let sanitized_report = sanitize_report_for_external(report)?;
    let unix_ts = current_unix_ts();
    let pretty = match schema_mode {
        GenericCiSchemaMode::V1 => serde_json::to_string_pretty(&GenericCiPublishPayload {
            schema_version: 1,
            provider: "generic".to_string(),
            repo: telemetry_repo.to_string(),
            unix_ts,
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
        })?,
        GenericCiSchemaMode::V2 => serde_json::to_string_pretty(&GenericCiPublishPayloadV2 {
            schema_version: 2,
            publish_format: "patchgate.provider.generic.v2".to_string(),
            repo: telemetry_repo.to_string(),
            emitted_at: unix_ts,
            capabilities: generic_ci_v2_capabilities(),
            gate: GenericPublishGateV2 {
                score: report.score,
                threshold: report.threshold,
                should_fail: report.should_fail,
                mode: report.mode.clone(),
                scope: report.scope.clone(),
                findings_count: report.findings.len(),
            },
            artifacts: GenericPublishArtifactsV2 {
                report: sanitized_report,
                markdown: markdown.to_string(),
            },
        })?,
        GenericCiSchemaMode::Dual => {
            let payload_v1 = GenericCiPublishPayload {
                schema_version: 1,
                provider: "generic".to_string(),
                repo: telemetry_repo.to_string(),
                unix_ts,
                summary: GenericPublishSummary {
                    score: report.score,
                    threshold: report.threshold,
                    should_fail: report.should_fail,
                    mode: report.mode.clone(),
                    scope: report.scope.clone(),
                    findings: report.findings.len(),
                },
                report: sanitized_report.clone(),
                markdown: markdown.to_string(),
            };
            let payload_v2 = GenericCiPublishPayloadV2 {
                schema_version: 2,
                publish_format: "patchgate.provider.generic.v2".to_string(),
                repo: telemetry_repo.to_string(),
                emitted_at: unix_ts,
                capabilities: generic_ci_v2_capabilities(),
                gate: GenericPublishGateV2 {
                    score: report.score,
                    threshold: report.threshold,
                    should_fail: report.should_fail,
                    mode: report.mode.clone(),
                    scope: report.scope.clone(),
                    findings_count: report.findings.len(),
                },
                artifacts: GenericPublishArtifactsV2 {
                    report: sanitized_report,
                    markdown: markdown.to_string(),
                },
            };
            serde_json::to_string_pretty(&GenericCiPublishBridgePayload {
                schema_version: 1,
                bridge_format: "patchgate.provider.generic.bridge.v1".to_string(),
                repo: telemetry_repo.to_string(),
                emitted_at: unix_ts,
                capabilities: generic_ci_dual_capabilities(),
                v1: payload_v1,
                v2: payload_v2,
            })?
        }
    };
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
    bridge: DeliveryBridgeContext<'a>,
}

struct NotificationDispatchOptions<'a> {
    retry_max_attempts: u8,
    retry_backoff_ms: u64,
    timeout_ms: u64,
    idempotency_key: &'a str,
    dead_letter_path: Option<&'a Path>,
    bridge: DeliveryBridgeContext<'a>,
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

fn delivery_bridge_headers(bridge: DeliveryBridgeContext<'_>) -> Vec<(&'static str, String)> {
    if !bridge.enabled {
        return Vec::new();
    }
    vec![
        (
            "x-patchgate-bridge-format",
            "patchgate.delivery.v2-shadow".to_string(),
        ),
        ("x-patchgate-bridge-mode", bridge.bridge_mode.to_string()),
        ("x-patchgate-shadow-mode", bridge.shadow_mode.to_string()),
    ]
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
    let input_path = resolve_cwd_relative_path(args.input.as_path())?;
    let summary_output_path = args
        .summary_output
        .as_ref()
        .map(|path| resolve_cwd_relative_path(path))
        .transpose()?;
    if let Some(summary_output_path) = summary_output_path.as_ref() {
        if paths_conflict(input_path.as_path(), summary_output_path.as_path()) {
            anyhow::bail!("--summary-output must differ from --input");
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

    write_dead_letter_replay_summary(summary_output_path.as_deref(), &summary)?;
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
    let (temp_path, file) = create_sibling_temp_file(path)?;
    Ok(DeadLetterRewriteState { temp_path, file })
}

fn finalize_dead_letter_rewrite(mut state: DeadLetterRewriteState, path: &Path) -> Result<()> {
    state.file.flush().with_context(|| {
        format!(
            "flush dead-letter rewrite file {}",
            state.temp_path.display()
        )
    })?;
    state.file.sync_all().with_context(|| {
        format!(
            "sync dead-letter rewrite file {}",
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
        bridge: delivery_bridge_metadata(
            options.bridge,
            "patchgate.webhook.v2-shadow",
            "scan.completed",
        ),
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
        for (name, value) in delivery_bridge_headers(options.bridge) {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value.as_str())?,
            );
            replay_headers.insert(header_name_to_title_case(name), value);
        }

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
        let mut payload =
            notification_payload(target.kind, telemetry_repo, report, options.bridge)?;
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
    bridge: DeliveryBridgeContext<'_>,
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
    let payload = if bridge.enabled && matches!(kind, NotificationKind::Generic) {
        let mut payload = payload;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "bridge".to_string(),
                serde_json::to_value(
                    delivery_bridge_metadata(
                        bridge,
                        "patchgate.notification.v2-shadow",
                        "scan.completed.notification",
                    )
                    .expect("bridge metadata must exist when bridge is enabled"),
                )?,
            );
        }
        payload
    } else {
        payload
    };
    Ok(payload)
}

fn delivery_bridge_metadata<'a>(
    bridge: DeliveryBridgeContext<'a>,
    bridge_format: &'a str,
    shadow_of: &'a str,
) -> Option<DeliveryBridgeMetadata<'a>> {
    if bridge.enabled {
        Some(DeliveryBridgeMetadata {
            schema_version: 1,
            bridge_format,
            shadow_of,
            bridge_mode: bridge.bridge_mode,
        })
    } else {
        None
    }
}

fn header_name_to_title_case(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut title = String::new();
                    title.extend(first.to_uppercase());
                    title.push_str(chars.as_str());
                    title
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
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

fn effective_policy_hash(
    cfg: &Config,
    authority: &PolicyAuthority,
    failures: &[PolicyAuthorityFailure],
) -> Result<String> {
    #[derive(Serialize)]
    struct PolicyHashMaterial<'a> {
        config_hash: String,
        authority: &'a PolicyAuthority,
        enforce_failure_codes: Vec<&'a str>,
    }

    let material = PolicyHashMaterial {
        config_hash: config_hash(cfg)?,
        authority,
        enforce_failure_codes: failures
            .iter()
            .map(|failure| failure.code.as_str())
            .collect(),
    };
    let serialized = serde_json::to_vec(&material)?;
    Ok(format!("{:x}", Sha256::digest(serialized)))
}

fn attach_policy_authority(
    report: &mut Report,
    authority: PolicyAuthority,
    failures: &[PolicyAuthorityFailure],
    mode: &str,
) {
    report.policy_authority = authority;
    if mode != "enforce" || failures.is_empty() {
        return;
    }
    if !report
        .checks
        .iter()
        .any(|check| check.check == CheckId::PolicyAuthority)
    {
        report.checks.push(CheckScore {
            check: CheckId::PolicyAuthority,
            label: CheckId::PolicyAuthority.label().to_string(),
            penalty: 100,
            max_penalty: 100,
            triggered: true,
        });
    }
    for failure in failures {
        let finding_id = format!("POLICY-AUTHORITY-{}", failure.code.to_ascii_uppercase());
        if report
            .findings
            .iter()
            .any(|finding| finding.id == finding_id)
        {
            continue;
        }
        report.findings.push(Finding {
            id: finding_id.clone(),
            rule_id: finding_id,
            category: "policy_authority".to_string(),
            docs_url: TRUST_BOUNDARY_DOCS_PATH.to_string(),
            check: CheckId::PolicyAuthority,
            title: "Policy authority failed".to_string(),
            message: failure.message.clone(),
            severity: Severity::Critical,
            penalty: 100,
            location: None,
            tags: vec!["policy-authority".to_string(), failure.code.clone()],
        });
    }
    report
        .diagnostic_hints
        .push("Policy authority failure blocks enforce mode.".to_string());
    report.recompute_score();
    report.should_fail = true;
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
    println!(
        "Policy authority: trusted={} digest={}",
        report.policy_authority.trusted, report.policy_authority.digest
    );
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
    lines.push(format!(
        "- Policy authority: trusted=`{}` digest=`{}`",
        report.policy_authority.trusted, report.policy_authority.digest
    ));
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
    lines.push("### Policy authority".to_string());
    lines.push(format!("- Trusted: `{}`", report.policy_authority.trusted));
    lines.push(format!("- Digest: `{}`", report.policy_authority.digest));
    if report.policy_authority.sources.is_empty() {
        lines.push("- Sources: none".to_string());
    } else {
        lines.push("- Sources:".to_string());
        for source in &report.policy_authority.sources {
            lines.push(format!(
                "  - `{}` ref=`{}` path=`{}` trusted=`{}` signature_verified=`{}`",
                source.kind,
                source.ref_name.as_deref().unwrap_or("-"),
                source.path.as_deref().unwrap_or("-"),
                source.trusted,
                source.signature_verified
            ));
        }
    }
    if report.policy_authority.pr_overlay.present {
        lines.push(format!(
            "- PR overlay accepted: `{}`",
            report.policy_authority.pr_overlay.accepted_keys.join(", ")
        ));
        lines.push(format!(
            "- PR overlay rejected: `{}`",
            report.policy_authority.pr_overlay.rejected_keys.join(", ")
        ));
    } else {
        lines.push("- PR overlay: none".to_string());
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

    use clap::Parser as _;
    use patchgate_config::{Config, PolicyAuthority, PolicyAuthorityFailure};
    use patchgate_core::{CheckId, CheckScore, Finding, Report, ReportMeta, Severity};
    use patchgate_github::PublishAuth;
    use serde_json::Value;

    use super::{
        append_dead_letter, append_scan_failure_records, apply_changed_file_overrides,
        apply_policy_autofixes, apply_threshold_override, assess_v1_readiness, build_cache_key,
        build_contract_diff_report, build_delivery_idempotency_key, build_history_summary,
        build_history_trend, bundle_catalog_artifact_summary, changed_file_limit_fail_open_report,
        ci_template_catalog, delivery_bridge_headers, delivery_bridge_metadata,
        detect_head_sha_from_env, detect_pr_number_from_env, detect_sandbox_capabilities,
        effective_policy_hash, exception_expired, exception_governance_artifact_summary,
        gate_exit_code, is_likely_cache_corruption, load_dead_letter_jsonl, load_policy_config,
        notification_payload, parse_mode, parse_policy_preset, parse_scope,
        policy_authority_relative_path, pr_head_sha_from_event_payload,
        pr_number_from_event_payload, pr_number_from_ref, publish_generic_ci_payload,
        recover_cache_db, redacted_endpoint, registry_provenance_artifact_summary,
        render_contract_diff_report_json, render_contract_diff_report_text, render_github_comment,
        resolve_audit_actor, resolve_ci_provider, resolve_ci_provider_for_publish,
        resolve_comment_suppression_reason, resolve_config_path, resolve_policy_path,
        resolve_publish_request, resolve_scan_options, resolve_telemetry_repo,
        resolve_webhook_signature, run_dead_letter_replay, run_plugin_init,
        run_policy_diff_contract, run_policy_lint, run_policy_verify_v1, run_policy_verify_v2,
        sign_webhook_payload, sorted_findings_for_comment, write_text_atomic, CiProvider, Cli,
        DeadLetterWriteOptions, DeliveryBridgeContext, DeliveryReplayArgs, FailureCode,
        GenericCiSchemaMode, NotificationKind, OptionSource, PluginInitArgs, PolicyAutofix,
        PolicyDiffContractArgs, PolicyExitCode, PolicyLintArgs, PolicyVerifyV1Args,
        PolicyVerifyV2Args, PublishRequestInput, ReadinessProfile, ResolvedScanOptions,
        RetryPolicy, ScanArgs, ScanError, ScanErrorKind, ScanMetricRecord, ScopeMode,
        WebhookEnvelope, DEFAULT_GITHUB_CHECK_NAME,
    };

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
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
            base_ref: None,
            protected_policy_ref: None,
            org_policy_bundle: None,
            org_policy_bundle_signature: None,
            org_policy_public_key_env: None,
            allow_untrusted_policy_for_local_enforce: false,
            threshold: None,
            max_changed_files: None,
            on_exceed: None,
            no_cache: false,
            profile_output: None,
            metrics_output: None,
            audit_log_output: None,
            audit_log_v2_output: None,
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
            ci_generic_schema: None,
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
        assert_eq!(req.check_name, DEFAULT_GITHUB_CHECK_NAME);

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
    fn effective_policy_hash_includes_authority_state() {
        let cfg = Config::default();
        let mut trusted_authority = PolicyAuthority {
            trusted: true,
            digest: "sha256:same-policy".to_string(),
            ..PolicyAuthority::default()
        };
        trusted_authority.diagnostics.clear();
        let mut untrusted_authority = trusted_authority.clone();
        untrusted_authority.trusted = false;

        let trusted_hash =
            effective_policy_hash(&cfg, &trusted_authority, &[]).expect("trusted hash");
        let untrusted_hash =
            effective_policy_hash(&cfg, &untrusted_authority, &[]).expect("untrusted hash");
        assert_ne!(trusted_hash, untrusted_hash);

        let failure_hash = effective_policy_hash(
            &cfg,
            &trusted_authority,
            &[PolicyAuthorityFailure {
                code: "untrusted_policy_in_enforce".to_string(),
                message: "blocked".to_string(),
            }],
        )
        .expect("failure hash");
        assert_ne!(trusted_hash, failure_hash);
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
    fn policy_authority_relative_path_rejects_external_absolute_policy_path() {
        let repo_root = PathBuf::from("/tmp/patchgate-repo");
        let external = PathBuf::from("/tmp/external-policy.toml");
        let err = policy_authority_relative_path(&repo_root, Some(&external))
            .expect_err("external absolute policy path must be rejected");
        assert!(err.to_string().contains("must be inside repository root"));
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

    #[test]
    fn policy_verify_v2_requires_shadow_bridge_inputs() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v2-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = false
bridge_mode = "off"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                provider_inputs: Vec::new(),
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: Vec::new(),
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v2_passes_with_full_bridge_inputs() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v2-ready-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let guide_path = repo_root.join("docs/v2-migration-alpha.md");
        fs::create_dir_all(guide_path.parent().expect("guide parent")).expect("create guide dir");
        fs::write(&guide_path, "# v2 migration\n").expect("write guide");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                provider_inputs: Vec::new(),
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: Vec::new(),
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v2_accepts_dual_contract_artifact_inputs() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v2-artifacts-{seq}"));
        fs::create_dir_all(repo_root.join("docs")).expect("create docs");
        fs::create_dir_all(repo_root.join("artifacts")).expect("create artifacts");
        fs::write(
            repo_root.join("docs/v2-migration-alpha.md"),
            "# v2 migration\n",
        )
        .expect("write guide");
        fs::write(
            repo_root.join("artifacts/provider-dual.json"),
            r#"{"schema_version":1,"bridge_format":"patchgate.provider.generic.bridge.v1","repo":"example/repo","v1":{"provider":"generic","summary":{},"report":{}},"v2":{"schema_version":2,"publish_format":"patchgate.provider.generic.v2","repo":"example/repo","gate":{},"artifacts":{}}}"#,
        )
        .expect("write provider");
        fs::write(
            repo_root.join("artifacts/scan-audit.jsonl"),
            r#"{"schema_version":1,"audit_format":"patchgate.audit.v1","unix_ts":1,"actor":"user","repo":"example/repo","target":"scan","mode":"warn","scope":"staged","result":"pass"}"#,
        )
        .expect("write audit");
        fs::write(
            repo_root.join("artifacts/scan-audit-v2.jsonl"),
            r#"{"schema_version":2,"audit_format":"patchgate.audit.v2","emitted_at":1,"actor":"user","repo":"example/repo","operation":{"target":"scan","mode":"warn","scope":"staged","result":"pass"},"gate":{},"failure":{},"diagnostics":[]}"#,
        )
        .expect("write audit v2");
        fs::write(
            repo_root.join("artifacts/plugin-shadow.v2.json"),
            r#"{"schema_version":2,"api_version":"patchgate.plugin.v2-shadow","shadow_of":"patchgate.plugin.v1","plugin_id":"sample","repo_root":".","mode":"warn","scope":"staged","changed_files":[],"metadata":{"bridge_mode":"shadow"}}"#,
        )
        .expect("write plugin shadow sample");
        fs::write(
            repo_root.join("artifacts/webhook-shadow.json"),
            r#"{"event":"scan.completed","unix_ts":1,"repo":"example/repo","report":{},"bridge":{"schema_version":1,"bridge_format":"patchgate.webhook.v2-shadow","shadow_of":"scan.completed","bridge_mode":"full"}}"#,
        )
        .expect("write webhook bridge envelope");
        fs::write(
            repo_root.join("artifacts/notification-shadow.json"),
            r#"{"event":"scan.completed.notification","repo":"example/repo","summary":{},"bridge":{"schema_version":1,"bridge_format":"patchgate.notification.v2-shadow","shadow_of":"scan.completed.notification","bridge_mode":"full"}}"#,
        )
        .expect("write notification bridge envelope");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "json".to_string(),
                readiness_profile: "standard".to_string(),
                provider_inputs: vec![PathBuf::from("artifacts/provider-dual.json")],
                audit_input: Some(PathBuf::from("artifacts/scan-audit.jsonl")),
                audit_v2_input: Some(PathBuf::from("artifacts/scan-audit-v2.jsonl")),
                plugin_shadow_inputs: vec![PathBuf::from("artifacts/plugin-shadow.v2.json")],
                webhook_envelope_inputs: vec![PathBuf::from("artifacts/webhook-shadow.json")],
                notification_envelope_inputs: vec![PathBuf::from(
                    "artifacts/notification-shadow.json",
                )],
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v2_accepts_fleet_governance_artifact_inputs() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!(
            "patchgate-cli-policy-verify-v2-fleet-governance-{seq}"
        ));
        fs::create_dir_all(repo_root.join("docs")).expect("create docs");
        fs::create_dir_all(repo_root.join("artifacts")).expect("create artifacts");
        fs::write(
            repo_root.join("docs/v2-migration-alpha.md"),
            "# v2 migration\n",
        )
        .expect("write guide");
        fs::write(
            repo_root.join("artifacts/bundle-catalog.json"),
            r#"{"schema_version":1,"generated_at":"2026-05-13T00:00:00Z","segments":[{"segment":"prod","owner":"platform","cost_ceiling_minutes":30,"review_cadence":"weekly"}],"retention_tiers":[{"tier":"regulated","hot_days":14,"warm_days":90,"cold_days":365}],"rollout_waves":[{"wave":"canary","order":1,"max_parallel":1,"entry_gate":"shadow clean","rollback_trigger":"provider drift"}],"bundles":[{"repo":"example/repo","policy_bundle":"core-strict","wave":"canary","segment":"prod","providers":["generic"],"required_provider_modes":["dual"],"required_provider_capabilities":["audit.shadow"],"retention_tier":"regulated","cost_ceiling_minutes":20,"phase181_rc_candidate":true}]}"#,
        )
        .expect("write bundle catalog");
        fs::write(
            repo_root.join("artifacts/plugin-registry.json"),
            r#"{"schema_version":1,"trusted_provenance":["sigstore"],"plugins":[{"plugin_id":"example/security-rules","version":"0.3.0","owner":"security","source_repo":"example/security-rules","provenance":"sigstore","digest":"sha256:abc","attestation":"https://attestations.example/security-rules","verified":true,"revoked":false,"sandbox_profile":"isolated","allowed_segments":["prod"]}]}"#,
        )
        .expect("write registry");
        fs::write(
            repo_root.join("artifacts/exceptions.json"),
            r#"{"schema_version":1,"reviewed_at":"2026-05-13T00:00:00Z","exceptions":[{"repo":"example/repo","kind":"waiver","scope":"provider-bridge","ticket":"SEC-1","owner":"platform","segment":"prod","approved_by":"ops-lead","status":"approved","review_cadence":"weekly","expires_at":"2026-05-30T00:00:00Z"}]}"#,
        )
        .expect("write exceptions");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                provider_inputs: Vec::new(),
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: Vec::new(),
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: Some(PathBuf::from("artifacts/bundle-catalog.json")),
                registry_input: Some(PathBuf::from("artifacts/plugin-registry.json")),
                exceptions_input: Some(PathBuf::from("artifacts/exceptions.json")),
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn fleet_governance_artifact_checks_reject_thin_or_stale_evidence() {
        let thin_catalog = serde_json::json!({
            "schema_version": 1,
            "bundles": [{
                "repo": "example/repo",
                "policy_bundle": "core-strict",
                "wave": "canary",
                "segment": "prod"
            }]
        });
        assert!(!bundle_catalog_artifact_summary(&thin_catalog).0);

        let weak_provider_contract = serde_json::json!({
            "schema_version": 1,
            "segments": [{"segment": "prod", "owner": "platform", "cost_ceiling_minutes": 30, "review_cadence": "weekly"}],
            "retention_tiers": [{"tier": "regulated", "hot_days": 14, "warm_days": 90, "cold_days": 365}],
            "rollout_waves": [{"wave": "canary", "order": 1, "max_parallel": 1, "entry_gate": "shadow clean", "rollback_trigger": "provider drift"}],
            "bundles": [{
                "repo": "example/repo",
                "policy_bundle": "core-strict",
                "wave": "canary",
                "segment": "prod",
                "providers": ["generic"],
                "required_provider_modes": ["dual"],
                "retention_tier": "regulated"
            }]
        });
        assert!(!bundle_catalog_artifact_summary(&weak_provider_contract).0);

        let mut duplicate_repo_catalog = serde_json::json!({
            "schema_version": 1,
            "generated_at": "2026-05-13T00:00:00Z",
            "segments": [{"segment": "prod", "owner": "platform", "cost_ceiling_minutes": 30, "review_cadence": "weekly"}],
            "retention_tiers": [{"tier": "regulated", "hot_days": 14, "warm_days": 90, "cold_days": 365}],
            "rollout_waves": [{"wave": "canary", "order": 1, "max_parallel": 1, "entry_gate": "shadow clean", "rollback_trigger": "provider drift"}],
            "bundles": [{
                "repo": "example/repo",
                "policy_bundle": "core-strict",
                "wave": "canary",
                "segment": "prod",
                "providers": ["generic"],
                "required_provider_modes": ["dual"],
                "required_provider_capabilities": ["audit.shadow"],
                "retention_tier": "regulated"
            }]
        });
        let duplicate_bundle = duplicate_repo_catalog["bundles"][0].clone();
        duplicate_repo_catalog["bundles"]
            .as_array_mut()
            .expect("bundles array")
            .push(duplicate_bundle);
        assert!(!bundle_catalog_artifact_summary(&duplicate_repo_catalog).0);

        let incomplete_registry = serde_json::json!({
            "schema_version": 1,
            "trusted_provenance": ["sigstore"],
            "plugins": [{
                "plugin_id": "example/security-rules",
                "version": "0.3.0",
                "owner": "security",
                "source_repo": "example/security-rules",
                "provenance": "sigstore",
                "digest": "sha256:abc",
                "attestation": "https://attestations.example/security-rules",
                "verified": true,
                "revoked": false
            }]
        });
        assert!(!registry_provenance_artifact_summary(&incomplete_registry).0);
        let untrusted_registry = serde_json::json!({
            "schema_version": 1,
            "plugins": [{
                "plugin_id": "example/security-rules",
                "version": "0.3.0",
                "owner": "security",
                "source_repo": "example/security-rules",
                "provenance": "sigstore",
                "digest": "sha256:abc",
                "attestation": "https://attestations.example/security-rules",
                "verified": true,
                "revoked": false,
                "sandbox_profile": "isolated",
                "allowed_segments": ["prod"]
            }]
        });
        assert!(!registry_provenance_artifact_summary(&untrusted_registry).0);
        assert_eq!(
            exception_expired("2026-99-99T00:00:00Z", "2026-05-13T00:00:00Z"),
            None
        );
        assert_eq!(
            exception_expired("2026-05-1é", "2026-05-13T00:00:00Z"),
            None
        );

        let stale_exception = serde_json::json!({
            "schema_version": 1,
            "reviewed_at": "2026-05-13T00:00:00Z",
            "exceptions": [{
                "repo": "example/repo",
                "kind": "waiver",
                "scope": "provider-bridge",
                "ticket": "SEC-1",
                "owner": "platform",
                "approved_by": "ops-lead",
                "status": "approved",
                "expires_at": "2026-04-30T00:00:00Z"
            }]
        });
        assert!(!exception_governance_artifact_summary(&stale_exception).0);

        let malformed_exception_packet = serde_json::json!({
            "schema_version": 1,
            "reviewed_at": "2026-05-13T00:00:00Z",
            "exceptions": {"repo": "example/repo"}
        });
        assert!(!exception_governance_artifact_summary(&malformed_exception_packet).0);
    }

    #[test]
    fn policy_verify_v2_rejects_v1_only_provider_artifact_input() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v2-v1-provider-{seq}"));
        fs::create_dir_all(repo_root.join("docs")).expect("create docs");
        fs::create_dir_all(repo_root.join("artifacts")).expect("create artifacts");
        fs::write(
            repo_root.join("docs/v2-migration-alpha.md"),
            "# v2 migration\n",
        )
        .expect("write guide");
        fs::write(
            repo_root.join("artifacts/provider-v1.json"),
            r#"{"schema_version":1,"provider":"generic","repo":"example/repo","summary":{},"report":{},"markdown":""}"#,
        )
        .expect("write provider v1");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                provider_inputs: vec![PathBuf::from("artifacts/provider-v1.json")],
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: Vec::new(),
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v2_rejects_invalid_delivery_bridge_artifact_input() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v2-delivery-{seq}"));
        fs::create_dir_all(repo_root.join("docs")).expect("create docs");
        fs::create_dir_all(repo_root.join("artifacts")).expect("create artifacts");
        fs::write(
            repo_root.join("docs/v2-migration-alpha.md"),
            "# v2 migration\n",
        )
        .expect("write guide");
        fs::write(
            repo_root.join("artifacts/webhook-shadow.json"),
            r#"{"event":"scan.completed","repo":"example/repo","report":{},"bridge":{"schema_version":1,"bridge_format":"patchgate.webhook.v2-shadow","shadow_of":"scan.completed","bridge_mode":"provider"}}"#,
        )
        .expect("write invalid webhook bridge envelope");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                provider_inputs: Vec::new(),
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: vec![PathBuf::from("artifacts/webhook-shadow.json")],
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v2_does_not_require_generic_schema_for_github_provider() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v2-github-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let guide_path = repo_root.join("docs/v2-migration-alpha.md");
        fs::create_dir_all(guide_path.parent().expect("guide parent")).expect("create guide dir");
        fs::write(&guide_path, "# v2 migration\n").expect("write guide");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "github"
generic_schema = "v1"
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "standard".to_string(),
                provider_inputs: Vec::new(),
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: Vec::new(),
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v2_ga_profile_requires_lts_v2_branch() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-verify-v2-ga-lts-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let guide_path = repo_root.join("docs/v2-migration-alpha.md");
        fs::create_dir_all(guide_path.parent().expect("guide parent")).expect("create guide dir");
        fs::write(&guide_path, "# v2 migration\n").expect("write guide");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[release.lts]
active = true
branch = "lts/v1"
security_sla_hours = 72
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path.clone()),
                policy_preset: None,
                format: "text".to_string(),
                readiness_profile: "ga".to_string(),
                provider_inputs: Vec::new(),
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: Vec::new(),
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[release.lts]
active = true
branch = "lts/v2"
security_sla_hours = 72
[compatibility.v1]
rc_frozen = true
allow_legacy_config_names = false
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write v2 lts policy");

        let code = run_policy_verify_v2(
            &repo_root,
            None,
            PolicyVerifyV2Args {
                path: Some(policy_path),
                policy_preset: None,
                format: "json".to_string(),
                readiness_profile: "ga".to_string(),
                provider_inputs: Vec::new(),
                audit_input: None,
                audit_v2_input: None,
                plugin_shadow_inputs: Vec::new(),
                webhook_envelope_inputs: Vec::new(),
                notification_envelope_inputs: Vec::new(),
                bundle_catalog_input: None,
                registry_input: None,
                exceptions_input: None,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_diff_contract_reports_missing_bridge_inputs() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-diff-contract-missing-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[compatibility.v2]
shadow_mode = false
bridge_mode = "off"
"#,
        )
        .expect("write policy");

        let loaded =
            load_policy_config(Some(policy_path.as_path()), None).expect("load policy config");
        let report = build_contract_diff_report(&repo_root, policy_path.as_path(), &loaded.config);
        let text = render_contract_diff_report_text(&report);
        let json = render_contract_diff_report_json(&report).expect("render json");

        assert!(!report.v2_contract.enabled);
        assert!(!report.breaking_change_gate_ready);
        assert!(text.contains("patchgate policy diff-contract"));
        assert!(text.contains("- breaking_change_gate_ready: false"));
        assert!(text.contains("- v2_contract_enabled: false"));
        assert!(text.contains("Enable compatibility.v2.shadow_mode before attempting dual-run."));
        assert!(json.contains("\"policy_path\""));
        assert!(json.contains("\"breaking_change_gate_ready\""));
        assert!(json.contains("\"v2_contract\""));
        assert!(json.contains("\"next_actions\""));

        let code = run_policy_diff_contract(
            &repo_root,
            None,
            PolicyDiffContractArgs {
                path: Some(policy_path),
                policy_preset: None,
                format: "text".to_string(),
                enforce: false,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_diff_contract_enforce_requires_shadow_mode() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-diff-contract-shadow-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let guide_path = repo_root.join("docs/v2-migration-alpha.md");
        fs::create_dir_all(guide_path.parent().expect("guide parent")).expect("create guide dir");
        fs::write(&guide_path, "# v2 migration\n").expect("write guide");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[compatibility.v2]
shadow_mode = false
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let loaded =
            load_policy_config(Some(policy_path.as_path()), None).expect("load policy config");
        let report = build_contract_diff_report(&repo_root, policy_path.as_path(), &loaded.config);
        assert!(report.v2_contract.enabled);
        assert!(!report.breaking_change_gate_ready);
        assert!(report
            .next_actions
            .iter()
            .any(|action| action.contains("shadow_mode")));

        let code = run_policy_diff_contract(
            &repo_root,
            None,
            PolicyDiffContractArgs {
                path: Some(policy_path),
                policy_preset: None,
                format: "json".to_string(),
                enforce: true,
            },
        );
        assert_eq!(code, PolicyExitCode::MigrationRequired);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_diff_contract_succeeds_for_ready_bridge_configs() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut repo_root = std::env::temp_dir();
        repo_root.push(format!("patchgate-cli-policy-diff-contract-ready-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let guide_path = repo_root.join("docs/v2-migration-alpha.md");
        fs::create_dir_all(guide_path.parent().expect("guide parent")).expect("create guide dir");
        fs::write(&guide_path, "# v2 migration\n").expect("write guide");

        let policy_path = repo_root.join("policy.toml");
        fs::write(
            &policy_path,
            r#"
policy_version = 2
[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
[integrations.ci]
provider = "generic"
generic_schema = "dual"
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"
"#,
        )
        .expect("write policy");

        let loaded =
            load_policy_config(Some(policy_path.as_path()), None).expect("load policy config");
        let report = build_contract_diff_report(&repo_root, policy_path.as_path(), &loaded.config);
        let text = render_contract_diff_report_text(&report);

        assert!(report.v2_contract.enabled);
        assert!(report.breaking_change_gate_ready);
        assert!(text.contains("- breaking_change_gate_ready: true"));
        assert!(text.contains("- v2_contract_enabled: true"));
        assert!(text.contains("Breaking-change boundary is ready for RC freeze."));

        let code = run_policy_diff_contract(
            &repo_root,
            None,
            PolicyDiffContractArgs {
                path: Some(policy_path),
                policy_preset: None,
                format: "json".to_string(),
                enforce: true,
            },
        );
        assert_eq!(code, PolicyExitCode::Ok);

        let _ = fs::remove_dir_all(repo_root);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn policy_verify_v1_strict_requires_linux_runtime_for_isolated_plugins() {
        let _guard = env_lock();
        super::BWRAP_AVAILABLE_OVERRIDE.store(-1, Ordering::Relaxed);
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
    fn policy_verify_v1_rejects_autofix_output_equal_to_input_path() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root =
            std::env::temp_dir().join(format!("patchgate-cli-policy-autofix-same-path-{seq}"));
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
                autofix_output: Some(policy_path.clone()),
                autofix_write: false,
            },
        );
        assert_eq!(code, PolicyExitCode::ReadOrParse);

        let output = fs::read_to_string(&policy_path).expect("read unchanged policy");
        assert!(output.contains("rc_frozen = false"));
        assert!(output.contains("allow_legacy_config_names = true"));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_autofix_preserves_inline_table_fields() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root = std::env::temp_dir().join(format!("patchgate-cli-policy-inline-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let input_path = repo_root.join("policy.toml");
        let output_path = repo_root.join("policy.autofix.toml");
        fs::write(
            &input_path,
            r#"
policy_version = 2
compatibility = { v1 = { rc_frozen = false, allow_legacy_config_names = true }, extra = true }
plugins = { enabled = true, sandbox = { profile = "none", allow_network = true } }
"#,
        )
        .expect("write policy");

        apply_policy_autofixes(
            input_path.as_path(),
            output_path.as_path(),
            &[
                PolicyAutofix::SetRcFrozen,
                PolicyAutofix::DisableLegacyConfigNames,
                PolicyAutofix::SetPluginSandboxProfile("restricted"),
            ],
        )
        .expect("apply autofixes");

        let output = fs::read_to_string(&output_path).expect("read autofixed policy");
        assert!(output.contains("extra = true"));
        assert!(output.contains("allow_network = true"));
        assert!(output.contains("rc_frozen = true"));
        assert!(output.contains("allow_legacy_config_names = false"));
        assert!(output.contains("profile = \"restricted\""));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_autofix_refuses_to_overwrite_non_table_values() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root = std::env::temp_dir().join(format!("patchgate-cli-policy-non-table-{seq}"));
        fs::create_dir_all(&repo_root).expect("create temp root");

        let input_path = repo_root.join("policy.toml");
        let output_path = repo_root.join("policy.autofix.toml");
        fs::write(
            &input_path,
            r#"
policy_version = 2
compatibility = "legacy"
"#,
        )
        .expect("write policy");

        let err = apply_policy_autofixes(
            input_path.as_path(),
            output_path.as_path(),
            &[PolicyAutofix::SetRcFrozen],
        )
        .expect_err("non-table path should block autofix");
        assert!(format!("{err:#}").contains("compatibility"));
        assert!(!output_path.exists());

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
    fn policy_verify_v1_cli_rejects_conflicting_autofix_flags() {
        let err = Cli::try_parse_from([
            "patchgate",
            "policy",
            "verify-v1",
            "--autofix-write",
            "--autofix-output",
            "artifacts/policy.autofix.toml",
        ])
        .expect_err("conflicting autofix flags should be rejected");

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
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

    #[cfg(unix)]
    #[test]
    fn write_text_atomic_preserves_existing_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-write-text-atomic-mode-{seq}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("policy.toml");
        fs::write(&path, "before").expect("seed file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set strict permissions");

        write_text_atomic(&path, "after").expect("overwrite file");

        let mode = fs::metadata(&path)
            .expect("stat rewritten file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn policy_verify_v1_strict_autofix_prefers_isolated_profile() {
        let _guard = env_lock();
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

        super::BWRAP_AVAILABLE_OVERRIDE.store(1, Ordering::Relaxed);
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
        super::BWRAP_AVAILABLE_OVERRIDE.store(-1, Ordering::Relaxed);

        let output = fs::read_to_string(&output_path).expect("read strict autofix output");
        assert!(output.contains("profile = \"isolated\""));
        assert!(!output.contains("profile = \"restricted\""));

        let _ = fs::remove_dir_all(repo_root);
    }

    #[test]
    fn policy_verify_v1_strict_autofix_skips_isolated_without_runtime_support() {
        let _guard = env_lock();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let repo_root =
            std::env::temp_dir().join(format!("patchgate-cli-policy-autofix-strict-guard-{seq}"));
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

        super::BWRAP_AVAILABLE_OVERRIDE.store(0, Ordering::Relaxed);
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
        super::BWRAP_AVAILABLE_OVERRIDE.store(-1, Ordering::Relaxed);

        let output = fs::read_to_string(&output_path).expect("read strict autofix output");
        assert!(output.contains("profile = \"none\""));
        assert!(!output.contains("profile = \"isolated\""));
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
    fn dead_letter_replay_skips_redacted_endpoints_without_failing() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-redacted-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        let summary_output = dir.join("replay-summary.json");
        fs::write(
            &input,
            "{\"schema_version\":1,\"unix_ts\":1,\"transport\":\"notification\",\"endpoint\":\"https://***/hook\",\"idempotency_key\":\"pgv1-redacted\",\"error\":\"timeout\",\"payload\":{\"event\":\"scan.completed.notification\"},\"headers\":{},\"payload_raw\":null}\n",
        )
        .expect("seed dead-letter");

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
        .expect("redacted endpoints should be skipped without failing");

        let remaining = fs::read_to_string(&input).expect("read retained dead-letter");
        assert!(remaining.contains("pgv1-redacted"));
        assert!(remaining.contains("redacted endpoint cannot be replayed"));

        let summary: serde_json::Value = serde_json::from_str(
            fs::read_to_string(&summary_output)
                .expect("read summary")
                .as_str(),
        )
        .expect("parse summary json");
        assert_eq!(summary["successful_records"], 0);
        assert_eq!(summary["failed_records"], 0);
        assert_eq!(summary["skipped_records"], 1);
        assert_eq!(summary["retained_records"], 1);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn dead_letter_replay_rejects_summary_output_equal_to_input() {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("patchgate-replay-summary-conflict-{seq}"));
        fs::create_dir_all(&dir).expect("create replay dir");
        let input = dir.join("dead-letter.jsonl");
        fs::write(
            &input,
            "{\"schema_version\":1,\"unix_ts\":1,\"transport\":\"notification\",\"endpoint\":\"https://example.invalid/hook\",\"idempotency_key\":\"pgv1-conflict\",\"error\":\"timeout\",\"payload\":{\"event\":\"scan.completed.notification\"},\"headers\":{},\"payload_raw\":null}\n",
        )
        .expect("seed dead-letter");

        let err = run_dead_letter_replay(DeliveryReplayArgs {
            input: input.clone(),
            transport: Some("notification".to_string()),
            max_records: Some(1),
            retry_max_attempts: 1,
            retry_backoff_ms: 10,
            rewrite_input: true,
            summary_output: Some(input.clone()),
            dry_run: false,
        })
        .expect_err("summary output path conflict should fail");
        assert!(format!("{err:#}").contains("--summary-output must differ from --input"));

        let retained = fs::read_to_string(&input).expect("read unchanged queue");
        assert!(retained.contains("pgv1-conflict"));

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
        let payload = notification_payload(
            NotificationKind::Slack,
            "example/repo",
            &report,
            DeliveryBridgeContext {
                enabled: false,
                shadow_mode: false,
                bridge_mode: "off",
            },
        )
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
        let disabled_bridge = DeliveryBridgeContext {
            enabled: false,
            shadow_mode: false,
            bridge_mode: "off",
        };
        let slack = notification_payload(
            NotificationKind::Slack,
            "example/repo",
            &report,
            disabled_bridge,
        )
        .expect("slack payload");
        assert!(
            slack.get("patchgate").is_none(),
            "slack payload must avoid full report embedding"
        );
        let teams = notification_payload(
            NotificationKind::Teams,
            "example/repo",
            &report,
            disabled_bridge,
        )
        .expect("teams payload");
        assert!(
            teams.get("patchgate").is_none(),
            "teams payload must avoid full report embedding"
        );
        let generic = notification_payload(
            NotificationKind::Generic,
            "example/repo",
            &report,
            disabled_bridge,
        )
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
    fn notification_payload_generic_includes_bridge_metadata_in_shadow_mode() {
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
        let payload = notification_payload(
            NotificationKind::Generic,
            "example/repo",
            &report,
            DeliveryBridgeContext {
                enabled: true,
                shadow_mode: true,
                bridge_mode: "full",
            },
        )
        .expect("generic payload");
        assert_eq!(
            payload
                .get("bridge")
                .and_then(|value| value.get("bridge_format"))
                .and_then(Value::as_str),
            Some("patchgate.notification.v2-shadow")
        );
        assert_eq!(
            payload
                .get("bridge")
                .and_then(|value| value.get("bridge_mode"))
                .and_then(Value::as_str),
            Some("full")
        );
    }

    #[test]
    fn webhook_envelope_includes_bridge_metadata_in_shadow_mode() {
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
        let envelope = WebhookEnvelope {
            event: "scan.completed",
            unix_ts: 1,
            repo: "example/repo",
            report: &report,
            bridge: delivery_bridge_metadata(
                DeliveryBridgeContext {
                    enabled: true,
                    shadow_mode: true,
                    bridge_mode: "full",
                },
                "patchgate.webhook.v2-shadow",
                "scan.completed",
            ),
        };
        let value = serde_json::to_value(&envelope).expect("encode webhook envelope");

        assert_eq!(
            value
                .get("bridge")
                .and_then(|bridge| bridge.get("bridge_format"))
                .and_then(Value::as_str),
            Some("patchgate.webhook.v2-shadow")
        );
        assert_eq!(
            value
                .get("bridge")
                .and_then(|bridge| bridge.get("shadow_of"))
                .and_then(Value::as_str),
            Some("scan.completed")
        );
    }

    #[test]
    fn delivery_bridge_headers_emit_shadow_metadata_when_enabled() {
        let headers = delivery_bridge_headers(DeliveryBridgeContext {
            enabled: true,
            shadow_mode: true,
            bridge_mode: "full",
        });
        assert_eq!(headers.len(), 3);
        assert!(headers.iter().any(|(name, value)| {
            *name == "x-patchgate-bridge-format" && value == "patchgate.delivery.v2-shadow"
        }));
        assert!(headers
            .iter()
            .any(|(name, value)| *name == "x-patchgate-shadow-mode" && value == "true"));
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

        let err = publish_generic_ci_payload(
            "example/repo",
            &report,
            "md",
            GenericCiSchemaMode::V1,
            None,
        )
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

        publish_generic_ci_payload(
            "example/repo",
            &report,
            "md",
            GenericCiSchemaMode::Dual,
            Some(output.as_path()),
        )
        .expect("publish generic payload");
        let written = fs::read_to_string(output).expect("read payload");
        assert!(
            !written.contains("super-secret-token"),
            "payload must not contain raw bearer token"
        );
        assert!(written.contains("bearer ***"), "payload should be masked");
        assert!(
            written.contains("\"bridge_format\": \"patchgate.provider.generic.bridge.v1\""),
            "dual mode should emit bridge payload"
        );
        let payload: serde_json::Value =
            serde_json::from_str(written.as_str()).expect("provider payload json");
        let bridge_capabilities = payload
            .get("capabilities")
            .and_then(serde_json::Value::as_array)
            .expect("bridge capabilities");
        assert!(bridge_capabilities
            .iter()
            .any(|value| value.as_str() == Some("audit.shadow")));
        let v2_capabilities = payload
            .get("v2")
            .and_then(|v2| v2.get("capabilities"))
            .and_then(serde_json::Value::as_array)
            .expect("v2 capabilities");
        assert!(v2_capabilities
            .iter()
            .any(|value| value.as_str() == Some("audit.shadow")));

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
        let readme = fs::read_to_string(output.join("README.md")).expect("README.md");
        let sample_input =
            fs::read_to_string(output.join("sample-input.json")).expect("sample-input.json");
        let shadow_sample_input =
            fs::read_to_string(output.join("sample-input.v2.json")).expect("sample-input.v2.json");
        assert!(main_py.contains("invalid json input:"));
        assert!(main_py.contains("payload.get('plugin_id', 'unknown')"));
        assert!(output.join("README.md").exists());
        assert!(output.join("sample-input.json").exists());
        assert!(output.join("sample-input.v2.json").exists());
        assert!(readme.contains("sample-input.v2.json"));
        assert!(readme.contains("V2 shadow preview"));
        assert!(readme.contains("plugin_id=sample-plugin"));
        assert!(sample_input.contains("\"plugin_id\":\"sample-plugin\""));
        assert!(shadow_sample_input.contains("\"plugin_id\":\"sample-plugin\""));
        assert!(shadow_sample_input.contains("\"api_version\":\"patchgate.plugin.v2-shadow\""));

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
        let shadow_sample_input =
            fs::read_to_string(output.join("sample-input.v2.json")).expect("sample-input.v2.json");
        assert!(package_json.contains("\"name\": \"sample-node-plugin\""));
        assert!(index_js.contains("invalid json input:"));
        assert!(index_js.contains("payload.plugin_id ?? \"sample-node-plugin\""));
        assert!(sample_input.contains("\"plugin_id\":\"sample-node-plugin\""));
        assert!(shadow_sample_input.contains("\"api_version\":\"patchgate.plugin.v2-shadow\""));

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
        assert!(output.join("sample-input.v2.json").exists());

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
