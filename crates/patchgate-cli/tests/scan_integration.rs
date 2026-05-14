use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
const TRUST_BASE_POLICY: &str = include_str!("fixtures/fork_pr_trust/base-policy.toml");
const TRUST_OVERLAY_LOWERS_THRESHOLD: &str =
    include_str!("fixtures/fork_pr_trust/overlay-lowers-threshold.toml");

struct TestRepo {
    root: PathBuf,
}

impl TestRepo {
    fn create() -> TestResult<Self> {
        let mut root = std::env::temp_dir();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        root.push(format!(
            "patchgate-cli-it-{}-{ts}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;

        let repo = Self { root };
        repo.git(&["init", "-q"])?;
        repo.git(&["config", "user.email", "patchgate-test@example.com"])?;
        repo.git(&["config", "user.name", "Patchgate Test"])?;
        repo.write_file("src/lib.rs", "pub fn answer() -> i32 { 41 }\n")?;
        repo.git(&["add", "."])?;
        repo.git(&["commit", "-qm", "init"])?;
        Ok(repo)
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn write_file(&self, rel: &str, content: &str) -> TestResult<()> {
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    fn append_line(&self, rel: &str, line: &str) -> TestResult<()> {
        let path = self.root.join(rel);
        let previous = fs::read_to_string(&path)?;
        fs::write(path, format!("{previous}{line}\n"))?;
        Ok(())
    }

    fn git(&self, args: &[&str]) -> TestResult<()> {
        let status = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("git command failed: {:?}", args).into())
        }
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn scan_json_integration_flow_is_stable() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line("src/lib.rs", "pub fn another() -> i32 { 1 }")?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--format",
            "json",
            "--mode",
            "warn",
            "--no-cache",
        ],
    )?;
    assert!(
        output.status.success(),
        "scan should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    let report: serde_json::Value = serde_json::from_str(&stdout)?;

    assert!(report.get("score").is_some());
    assert!(report.get("threshold").is_some());
    assert!(report.get("checks").is_some());
    assert!(report.get("findings").is_some());
    assert!(report.get("policy_authority").is_some());

    Ok(())
}

#[test]
fn scan_writes_markdown_report_file() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line("src/lib.rs", "pub fn changed() -> i32 { 2 }")?;
    let output_path = repo.root().join("artifacts/comment.md");

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "warn",
            "--no-cache",
            "--github-comment",
            output_path.to_str().ok_or("invalid output path utf8")?,
        ],
    )?;
    assert!(
        output.status.success(),
        "scan should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let markdown = fs::read_to_string(output_path)?;
    assert!(markdown.contains("<!-- patchgate:report -->"));
    assert!(markdown.contains("### Priority findings"));

    Ok(())
}

#[test]
fn scan_github_publish_path_returns_publish_error_without_required_env() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line("src/lib.rs", "pub fn changed_again() -> i32 { 3 }")?;

    let output = Command::new(env!("CARGO_BIN_EXE_patchgate"))
        .current_dir(repo.root())
        .arg("scan")
        .arg("--scope")
        .arg("worktree")
        .arg("--mode")
        .arg("warn")
        .arg("--no-cache")
        .arg("--github-publish")
        .env_remove("GITHUB_REPOSITORY")
        .env_remove("GITHUB_EVENT_PATH")
        .env_remove("GITHUB_REF")
        .env_remove("GITHUB_SHA")
        .env_remove("GITHUB_TOKEN")
        .output()?;
    assert_eq!(output.status.code(), Some(6));

    Ok(())
}

#[test]
fn scan_github_publish_dry_run_writes_payload_file() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line("src/lib.rs", "pub fn changed_for_dry_run() -> i32 { 10 }")?;
    let payload_path = repo.root().join("artifacts/github-dry-run.json");

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "warn",
            "--format",
            "json",
            "--no-cache",
            "--github-publish",
            "--github-dry-run",
            "--github-repo",
            "example/repo",
            "--github-pr",
            "123",
            "--github-sha",
            "deadbeef",
            "--github-dry-run-output",
            payload_path
                .to_str()
                .ok_or("invalid payload output path utf8")?,
        ],
    )?;
    assert!(
        output.status.success(),
        "dry-run publish should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = fs::read_to_string(payload_path)?;
    assert!(payload.contains("\"check_run_payload\""));
    assert!(payload.contains("\"auth_mode\": \"token\""));

    Ok(())
}

#[test]
fn scan_github_publish_dry_run_can_suppress_comment() -> TestResult<()> {
    let repo = TestRepo::create()?;
    let payload_path = repo.root().join("artifacts/github-dry-run-suppressed.json");

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "warn",
            "--format",
            "json",
            "--no-cache",
            "--github-publish",
            "--github-dry-run",
            "--github-repo",
            "example/repo",
            "--github-pr",
            "456",
            "--github-sha",
            "cafebabe",
            "--github-suppress-comment-no-change",
            "--github-dry-run-output",
            payload_path
                .to_str()
                .ok_or("invalid payload output path utf8")?,
        ],
    )?;
    assert!(
        output.status.success(),
        "dry-run publish should succeed on no-change: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = fs::read_to_string(payload_path)?;
    assert!(payload.contains("\"suppressed_comment_reason\""));

    Ok(())
}

#[test]
fn scan_generic_ci_publish_writes_payload_file() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line(
        "src/lib.rs",
        "pub fn changed_for_generic_ci() -> i32 { 11 }",
    )?;
    let payload_path = repo.root().join("artifacts/ci-generic.json");

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "warn",
            "--format",
            "json",
            "--no-cache",
            "--publish",
            "--ci-provider",
            "generic",
            "--ci-generic-output",
            payload_path
                .to_str()
                .ok_or("invalid generic ci output path utf8")?,
        ],
    )?;
    assert!(
        output.status.success(),
        "generic publish should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = fs::read_to_string(payload_path)?;
    assert!(payload.contains("\"provider\": \"generic\""));
    assert!(payload.contains("\"summary\""));

    Ok(())
}

#[test]
fn scan_generic_ci_publish_fails_without_output_path() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line(
        "src/lib.rs",
        "pub fn changed_for_generic_ci_missing_output() -> i32 { 12 }",
    )?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "warn",
            "--format",
            "json",
            "--no-cache",
            "--publish",
            "--ci-provider",
            "generic",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(6),
        "generic publish without output path should be publish error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("generic CI publish requires output path"),
        "stderr should explain missing output path, got: {stderr}"
    );

    Ok(())
}

#[test]
fn scan_accepts_bridge_outputs_from_cli_overrides() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2

[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/v2-migration-alpha.md"

[integrations.ci]
provider = "generic"
generic_schema = "v1"
"#,
    )?;
    repo.write_file("docs/v2-migration-alpha.md", "# v2 migration\n")?;
    repo.append_line(
        "src/lib.rs",
        "pub fn changed_for_bridge_override() -> i32 { 13 }",
    )?;
    let payload_path = repo.root().join("artifacts/provider-dual.json");
    let audit_v2_path = repo.root().join("artifacts/scan-audit-v2.jsonl");

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "warn",
            "--format",
            "json",
            "--no-cache",
            "--publish",
            "--ci-provider",
            "generic",
            "--ci-generic-schema",
            "dual",
            "--ci-generic-output",
            payload_path
                .to_str()
                .ok_or("invalid generic ci output path utf8")?,
            "--audit-log-v2-output",
            audit_v2_path
                .to_str()
                .ok_or("invalid audit v2 output path utf8")?,
        ],
    )?;
    assert!(
        output.status.success(),
        "bridge override scan should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = fs::read_to_string(payload_path)?;
    assert!(payload.contains("\"bridge_format\""));

    let audit_v2 = fs::read_to_string(audit_v2_path)?;
    assert!(audit_v2.contains("\"audit_format\":\"patchgate.audit.v2\""));

    Ok(())
}

#[test]
fn enforce_scan_rejects_fork_overlay_that_lowers_policy() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file("policy.toml", TRUST_BASE_POLICY)?;
    repo.git(&["add", "policy.toml"])?;
    repo.git(&["commit", "-qm", "add trusted policy"])?;

    repo.write_file("policy.toml", TRUST_OVERLAY_LOWERS_THRESHOLD)?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "enforce",
            "--format",
            "json",
            "--base-ref",
            "HEAD",
            "--no-cache",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "policy overlay must fail gate, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    let report: serde_json::Value = serde_json::from_str(&stdout)?;
    let rejected = report
        .pointer("/policy_authority/pr_overlay/rejected_keys")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing rejected_keys")?;
    assert!(rejected
        .iter()
        .any(|value| value.as_str() == Some("output.fail_threshold")));
    let findings = report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing findings")?;
    assert!(findings.iter().any(|finding| {
        finding.get("category").and_then(serde_json::Value::as_str) == Some("policy_authority")
    }));

    Ok(())
}

#[test]
fn scan_uses_trusted_mode_when_local_policy_downgrades_to_warn() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2
[output]
mode = "enforce"
fail_threshold = 80
"#,
    )?;
    repo.git(&["add", "policy.toml"])?;
    repo.git(&["commit", "-qm", "add trusted enforce policy"])?;

    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2
[output]
mode = "warn"
fail_threshold = 0
"#,
    )?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--format",
            "json",
            "--base-ref",
            "HEAD",
            "--no-cache",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "trusted enforce mode must win over local downgrade: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    let report: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(
        report.get("mode").and_then(serde_json::Value::as_str),
        Some("enforce")
    );
    let rejected = report
        .pointer("/policy_authority/pr_overlay/rejected_keys")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing rejected_keys")?;
    assert!(rejected
        .iter()
        .any(|value| value.as_str() == Some("policy.unallowlisted.output")));

    Ok(())
}

#[test]
fn enforce_scan_reports_invalid_pr_policy_overlay_as_authority_failure() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2
[output]
fail_threshold = 80
"#,
    )?;
    repo.git(&["add", "policy.toml"])?;
    repo.git(&["commit", "-qm", "add trusted policy"])?;

    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2
[output
"#,
    )?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "enforce",
            "--format",
            "json",
            "--base-ref",
            "HEAD",
            "--no-cache",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "invalid PR policy overlay must be reported as authority failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    let report: serde_json::Value = serde_json::from_str(&stdout)?;
    let failures = report
        .pointer("/policy_authority/diagnostics")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing diagnostics")?;
    assert!(failures.iter().any(|value| {
        value
            .as_str()
            .is_some_and(|message| message.contains("pr_overlay_invalid"))
    }));
    let rejected = report
        .pointer("/policy_authority/pr_overlay/rejected_keys")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing rejected_keys")?;
    assert!(rejected
        .iter()
        .any(|value| value.as_str() == Some("policy.parse")));

    Ok(())
}

#[test]
fn enforce_scan_errors_when_trusted_ref_lacks_policy_file() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2
[output]
fail_threshold = 80
"#,
    )?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "enforce",
            "--format",
            "json",
            "--base-ref",
            "HEAD",
            "--no-cache",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(3),
        "missing trusted policy file should be a config error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("trusted policy ref `HEAD` exists but `policy.toml` is missing"));

    Ok(())
}

#[test]
fn scan_errors_when_explicit_config_file_is_missing() -> TestResult<()> {
    let repo = TestRepo::create()?;

    let output = run_patchgate(
        repo.root(),
        &[
            "--config",
            "missing-policy.toml",
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "warn",
            "--format",
            "json",
            "--no-cache",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(3),
        "missing explicit config should be a config error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("missing-policy.toml"));
    assert!(stderr.contains("does not exist"));

    Ok(())
}

#[test]
fn enforce_scan_rejects_policy_changing_cli_override() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2
[output]
fail_threshold = 80
"#,
    )?;
    repo.git(&["add", "policy.toml"])?;
    repo.git(&["commit", "-qm", "add trusted policy"])?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "enforce",
            "--format",
            "json",
            "--no-cache",
            "--threshold",
            "10",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "enforce CLI policy override must be rejected as input: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("enforce mode does not accept policy-changing CLI overrides"));

    Ok(())
}

#[test]
fn enforce_scan_ignores_untrusted_local_authority_relaxation() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file(
        "policy.toml",
        r#"
policy_version = 2

[output]
fail_threshold = 0

[policy_authority]
enforce_trusted_policy_required = false
allow_untrusted_local_enforce = true
"#,
    )?;
    repo.append_line(
        "src/lib.rs",
        "pub fn local_only_policy_change() -> i32 { 14 }",
    )?;

    let output = run_patchgate(
        repo.root(),
        &[
            "scan",
            "--scope",
            "worktree",
            "--mode",
            "enforce",
            "--format",
            "json",
            "--no-cache",
        ],
    )?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "local policy must not relax enforce authority: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout)?;
    let report: serde_json::Value = serde_json::from_str(&stdout)?;
    assert_eq!(
        report
            .pointer("/policy_authority/trusted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let findings = report
        .get("findings")
        .and_then(serde_json::Value::as_array)
        .ok_or("missing findings")?;
    assert!(findings.iter().any(|finding| {
        finding.get("category").and_then(serde_json::Value::as_str) == Some("policy_authority")
    }));

    Ok(())
}

fn run_patchgate(repo: &Path, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_patchgate"))
        .current_dir(repo)
        .args(args)
        .output()?)
}
