use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use patchgate_config::Config;
use patchgate_core::{Context, DiffOptions, Runner, ScopeMode};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

struct TestRepo {
    root: PathBuf,
}

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

impl TestRepo {
    fn create() -> TestResult<Self> {
        let mut root = std::env::temp_dir();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        root.push(format!(
            "patchgate-scope-test-{}-{ts}-{seq}",
            std::process::id()
        ));
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

    fn write_bytes(&self, rel: &str, content: &[u8]) -> TestResult<()> {
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

#[test]
fn raw_file_limit_stops_before_patch_materialization() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.append_line("worktree.txt", "large-diff-preflight")?;

    let runner = Runner::new(Config::default());
    let diff = runner.collect_diff_with_options(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Worktree,
        },
        &DiffOptions {
            stop_after_raw_file_limit: Some(0),
            ..DiffOptions::default()
        },
    )?;

    assert_eq!(diff.files.len(), 1);
    assert_eq!(diff.files[0].path, "worktree.txt");
    assert_eq!(diff.files[0].added, 0);
    assert!(diff.files[0].added_lines.is_empty());

    Ok(())
}

#[test]
fn pr_scope_uses_merge_base_to_head_range() -> TestResult<()> {
    let repo = TestRepo::create()?;
    let base = repo.git(&["rev-parse", "HEAD"])?.trim().to_string();

    repo.git(&["checkout", "-qb", "feature/diff-correctness"])?;
    repo.write_file("pr.txt", "base\nfeature\n")?;
    repo.git(&["add", "pr.txt"])?;
    repo.git(&["commit", "-qm", "feature change"])?;
    let head = repo.git(&["rev-parse", "HEAD"])?.trim().to_string();

    let runner = Runner::new(Config::default());
    let diff = runner.collect_diff_with_options(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Pr,
        },
        &DiffOptions {
            base_ref: Some(base.clone()),
            head_ref: Some(head),
            ..DiffOptions::default()
        },
    )?;

    assert_eq!(diff.merge_base.as_deref(), Some(base.as_str()));
    assert_eq!(
        file_set(diff.files.into_iter().map(|f| f.path)),
        file_set(["pr.txt".to_string()])
    );

    Ok(())
}

#[test]
fn pr_scope_fetches_missing_refs_heads_base() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.git(&["branch", "-M", "main"])?;
    let remote_root = repo.root().with_extension("origin.git");
    let remote_root_arg = remote_root.to_string_lossy().to_string();
    let output = Command::new("git")
        .args(["init", "--bare", "-q", remote_root_arg.as_str()])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git init --bare failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    repo.git(&["remote", "add", "origin", remote_root_arg.as_str()])?;
    repo.git(&["push", "-u", "origin", "main"])?;
    let base = repo.git(&["rev-parse", "HEAD"])?.trim().to_string();

    repo.git(&["checkout", "-qb", "feature/fetch-base"])?;
    repo.write_file("remote-pr.txt", "base\nfeature\n")?;
    repo.git(&["add", "remote-pr.txt"])?;
    repo.git(&["commit", "-qm", "feature change"])?;
    let head = repo.git(&["rev-parse", "HEAD"])?.trim().to_string();
    repo.git(&["branch", "-D", "main"])?;
    repo.git(&["update-ref", "-d", "refs/remotes/origin/main"])?;

    let runner = Runner::new(Config::default());
    let diff = runner.collect_diff_with_options(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Pr,
        },
        &DiffOptions {
            base_ref: Some("refs/heads/main".to_string()),
            head_ref: Some(head),
            ..DiffOptions::default()
        },
    )?;
    let _ = fs::remove_dir_all(remote_root);

    assert_eq!(diff.base_ref.as_deref(), Some("refs/heads/main"));
    assert_eq!(diff.merge_base.as_deref(), Some(base.as_str()));
    assert_eq!(
        file_set(diff.files.into_iter().map(|f| f.path)),
        file_set(["remote-pr.txt".to_string()])
    );

    Ok(())
}

#[cfg(unix)]
#[test]
fn special_path_and_binary_fixtures_cannot_bypass_gate() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file("fixtures/has\ttab.txt", "base\n")?;
    repo.write_bytes("fixtures/blob.bin", b"\0base")?;
    repo.git(&["add", "."])?;
    repo.git(&["commit", "-qm", "fixtures"])?;

    repo.append_line("fixtures/has\ttab.txt", "changed")?;
    repo.write_bytes("fixtures/blob.bin", b"\0changed\xff")?;

    let runner = Runner::new(Config::default());
    let report = runner.run(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Worktree,
        },
        "enforce",
    )?;
    let finding_ids = file_set(report.findings.iter().map(|finding| finding.id.clone()));

    assert!(report.should_fail);
    assert!(finding_ids.contains("DIFF-001"));
    assert!(finding_ids.contains("DIFF-004"));

    Ok(())
}

#[test]
fn binary_fixture_cannot_bypass_gate_on_all_platforms() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_bytes("fixtures/blob.bin", b"\0base")?;
    repo.git(&["add", "fixtures/blob.bin"])?;
    repo.git(&["commit", "-qm", "binary fixture"])?;

    repo.write_bytes("fixtures/blob.bin", b"\0changed\xff")?;

    let runner = Runner::new(Config::default());
    let report = runner.run(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Worktree,
        },
        "enforce",
    )?;
    let finding_ids = file_set(report.findings.iter().map(|finding| finding.id.clone()));

    assert!(report.should_fail);
    assert!(finding_ids.contains("DIFF-004"));

    Ok(())
}

#[test]
fn worktree_lfs_pointer_fixture_is_classified() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file("fixtures/blob.dat", "base\n")?;
    repo.git(&["add", "fixtures/blob.dat"])?;
    repo.git(&["commit", "-qm", "add lfs candidate"])?;

    repo.write_file(
        "fixtures/blob.dat",
        "version https://git-lfs.github.com/spec/v1\noid sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsize 123\n",
    )?;

    let runner = Runner::new(Config::default());
    let report = runner.run(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Worktree,
        },
        "warn",
    )?;
    let finding_ids = file_set(report.findings.iter().map(|finding| finding.id.clone()));

    assert!(finding_ids.contains("DIFF-009"));

    Ok(())
}

#[test]
fn submodule_fixture_cannot_bypass_gate() -> TestResult<()> {
    let repo = TestRepo::create()?;
    let first_pointer = repo.git(&["rev-parse", "HEAD"])?.trim().to_string();

    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{first_pointer},fixtures/submodule"),
    ])?;
    repo.git(&["commit", "-qm", "add gitlink fixture"])?;

    repo.write_file("marker.txt", "next\n")?;
    repo.git(&["add", "marker.txt"])?;
    repo.git(&["commit", "-qm", "create second commit pointer"])?;
    let second_pointer = repo.git(&["rev-parse", "HEAD"])?.trim().to_string();

    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{second_pointer},fixtures/submodule"),
    ])?;

    let runner = Runner::new(Config::default());
    let report = runner.run(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Staged,
        },
        "enforce",
    )?;
    let finding_ids = file_set(report.findings.iter().map(|finding| finding.id.clone()));

    assert!(report.should_fail);
    assert!(finding_ids.contains("DIFF-005"));

    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_escape_fixture_cannot_bypass_gate() -> TestResult<()> {
    let repo = TestRepo::create()?;
    let link_path = repo.root().join("fixtures/outside-link");
    fs::create_dir_all(link_path.parent().expect("link parent"))?;
    std::os::unix::fs::symlink("../../outside", &link_path)?;
    repo.git(&["add", "fixtures/outside-link"])?;

    let runner = Runner::new(Config::default());
    let report = runner.run(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Staged,
        },
        "enforce",
    )?;
    let finding_ids = file_set(report.findings.iter().map(|finding| finding.id.clone()));

    assert!(report.should_fail);
    assert!(finding_ids.contains("DIFF-006"));

    Ok(())
}

#[cfg(unix)]
#[test]
fn worktree_safe_symlink_change_stays_non_escape() -> TestResult<()> {
    let repo = TestRepo::create()?;
    repo.write_file("docs/one.md", "one\n")?;
    repo.write_file("docs/two.md", "two\n")?;
    let link_path = repo.root().join("docs/link");
    std::os::unix::fs::symlink("one.md", &link_path)?;
    repo.git(&["add", "."])?;
    repo.git(&["commit", "-qm", "add safe symlink"])?;

    fs::remove_file(&link_path)?;
    std::os::unix::fs::symlink("two.md", &link_path)?;

    let runner = Runner::new(Config::default());
    let report = runner.run(
        &Context {
            repo_root: repo.root().to_path_buf(),
            scope: ScopeMode::Worktree,
        },
        "warn",
    )?;
    let finding_ids = file_set(report.findings.iter().map(|finding| finding.id.clone()));

    assert!(finding_ids.contains("DIFF-008"));
    assert!(!finding_ids.contains("DIFF-006"));

    Ok(())
}
