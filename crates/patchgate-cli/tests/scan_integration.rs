use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

fn run_patchgate(repo: &Path, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_patchgate"))
        .current_dir(repo)
        .args(args)
        .output()?)
}
