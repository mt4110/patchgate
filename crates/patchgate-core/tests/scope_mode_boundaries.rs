use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use patchgate_config::Config;
use patchgate_core::{Context, Runner, ScopeMode};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

struct TestRepo {
    root: PathBuf,
}

impl TestRepo {
    fn create() -> TestResult<Self> {
        let mut root = std::env::temp_dir();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        root.push(format!("patchgate-scope-test-{}-{ts}", std::process::id()));
        fs::create_dir_all(&root)?;

        let repo = Self { root };
        repo.git(&["init", "-q"])?;
        repo.git(&["config", "user.email", "patchgate-test@example.com"])?;
        repo.git(&["config", "user.name", "Patchgate Test"])?;

        repo.write_file("staged.txt", "base\n")?;
        repo.write_file("worktree.txt", "base\n")?;
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
        let mut file = OpenOptions::new().append(true).open(path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    fn git(&self, args: &[&str]) -> TestResult<String> {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .output()?;
        if output.status.success() {
            Ok(String::from_utf8(output.stdout)?)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(format!("git {:?} failed: {stderr}", args).into())
        }
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn file_set(paths: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    paths.into_iter().collect()
}

#[test]
fn scope_modes_respect_staged_worktree_repo_boundaries() -> TestResult<()> {
    let repo = TestRepo::create()?;

    repo.append_line("staged.txt", "staged-change")?;
    repo.git(&["add", "staged.txt"])?;

    repo.append_line("worktree.txt", "worktree-change")?;

    let runner = Runner::new(Config::default());

    let staged = runner.collect_diff(&Context {
        repo_root: repo.root().to_path_buf(),
        scope: ScopeMode::Staged,
    })?;
    let worktree = runner.collect_diff(&Context {
        repo_root: repo.root().to_path_buf(),
        scope: ScopeMode::Worktree,
    })?;
    let repo_scope = runner.collect_diff(&Context {
        repo_root: repo.root().to_path_buf(),
        scope: ScopeMode::Repo,
    })?;

    assert_eq!(
        file_set(staged.files.into_iter().map(|f| f.path)),
        file_set(["staged.txt".to_string()])
    );
    assert_eq!(
        file_set(worktree.files.into_iter().map(|f| f.path)),
        file_set(["worktree.txt".to_string()])
    );
    assert_eq!(
        file_set(repo_scope.files.into_iter().map(|f| f.path)),
        file_set(["staged.txt".to_string(), "worktree.txt".to_string()])
    );

    Ok(())
}

#[test]
fn all_scopes_return_empty_on_clean_repo() -> TestResult<()> {
    let repo = TestRepo::create()?;
    let runner = Runner::new(Config::default());

    for scope in [ScopeMode::Staged, ScopeMode::Worktree, ScopeMode::Repo] {
        let diff = runner.collect_diff(&Context {
            repo_root: repo.root().to_path_buf(),
            scope,
        })?;
        assert!(
            diff.files.is_empty(),
            "expected clean diff for scope {}",
            scope.as_str()
        );
    }

    Ok(())
}
