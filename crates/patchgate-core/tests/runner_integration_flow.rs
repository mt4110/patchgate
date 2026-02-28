use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use patchgate_config::Config;
use patchgate_core::{Context, Runner, ScopeMode};

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
            "patchgate-core-it-{}-{ts}-{seq}",
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
fn runner_scan_path_returns_report_for_worktree_changes() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line("src/lib.rs", "pub fn added() -> i32 { 1 }")?;

    let runner = Runner::new(Config::default());
    let report = runner.run(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Worktree,
        },
        "warn",
    )?;

    assert_eq!(report.mode, "warn");
    assert_eq!(report.scope, "worktree");
    assert_eq!(report.checks.len(), 3);
    assert!(report.duration_ms > 0);
    assert!(!report.fingerprint.is_empty());
    Ok(())
}
