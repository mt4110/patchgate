use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_CASE: &str = "default-worktree";
const DEFAULT_OUTPUT: &str = "target/benchmarks/patchgate_baseline.jsonl";
const DEFAULT_PROFILE_OUTPUT: &str = "target/benchmarks/scan_profile.json";
const DEFAULT_MAX_REGRESSION_PCT: f64 = 30.0;
const DEFAULT_SYNTHETIC_LINES: usize = 1;
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
enum BenchSubcommand {
    Record,
    Compare,
    Profile,
}

#[derive(Debug, Clone)]
struct BenchOptions {
    subcommand: BenchSubcommand,
    case_name: String,
    repo: PathBuf,
    output: PathBuf,
    profile_output: PathBuf,
    report_output: Option<PathBuf>,
    max_regression_pct: f64,
    require_baseline: bool,
    append_on_pass: bool,
    synthetic_files: Option<usize>,
    synthetic_lines: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BenchSample {
    case_name: String,
    unix_ts: u64,
    duration_ms: u128,
    changed_files: usize,
    score: u64,
    threshold: u64,
    fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchCompareReport {
    case_name: String,
    baseline_duration_ms: u128,
    current_duration_ms: u128,
    duration_delta_pct: f64,
    baseline_changed_files: usize,
    current_changed_files: usize,
    max_regression_pct: f64,
    regressed: bool,
    fingerprint: String,
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return Ok(());
    };

    if command != "bench" {
        bail!("unsupported command `{}`", command.to_string_lossy());
    }

    let options = parse_bench_options(args.collect())?;
    match options.subcommand {
        BenchSubcommand::Record => {
            let sample = run_bench_sample(&options)?;
            append_sample(&options.output, &sample)?;
            println!(
                "recorded benchmark: case={} duration_ms={} changed_files={} output={}",
                sample.case_name,
                sample.duration_ms,
                sample.changed_files,
                options.output.display()
            );
        }
        BenchSubcommand::Compare => {
            let sample = run_bench_sample(&options)?;
            let previous = load_latest_sample(&options.output, &sample.case_name)?;
            if let Some(prev) = previous {
                validate_workload_identity(&prev, &sample)?;
                print_comparison(&prev, &sample);
                let regressed = is_duration_regressed(&prev, &sample, options.max_regression_pct);
                if let Some(path) = options.report_output.as_ref() {
                    write_compare_report(
                        path,
                        &prev,
                        &sample,
                        options.max_regression_pct,
                        regressed,
                    )?;
                }
                if regressed {
                    bail!(
                        "benchmark regression: duration exceeded {:.1}% threshold",
                        options.max_regression_pct
                    );
                }
                if options.append_on_pass {
                    append_sample(&options.output, &sample)?;
                }
            } else {
                if options.require_baseline {
                    bail!(
                        "no baseline found for case `{}` in {}",
                        sample.case_name,
                        options.output.display()
                    );
                }
                println!(
                    "no baseline found for case `{}` in {}. recording first sample.",
                    sample.case_name,
                    options.output.display()
                );
                append_sample(&options.output, &sample)?;
            }
        }
        BenchSubcommand::Profile => {
            run_profile_sample(&options)?;
        }
    }

    Ok(())
}

fn print_help() {
    eprintln!(
        "usage:\n  cargo run -p xtask -- bench record [--case NAME] [--repo PATH] [--output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- bench compare [--case NAME] [--repo PATH] [--output PATH] [--max-regression-pct N] [--require-baseline] [--append-on-pass] [--report-output PATH] [--synthetic-files N] [--synthetic-lines N]\n  cargo run -p xtask -- bench profile [--repo PATH] [--profile-output PATH] [--synthetic-files N] [--synthetic-lines N]"
    );
}

fn parse_bench_options(args: Vec<OsString>) -> Result<BenchOptions> {
    let mut iter = args.into_iter();
    let Some(sub) = iter.next() else {
        bail!("missing bench subcommand (`record` or `compare`)");
    };
    let subcommand = match sub.to_string_lossy().as_ref() {
        "record" => BenchSubcommand::Record,
        "compare" => BenchSubcommand::Compare,
        "profile" => BenchSubcommand::Profile,
        other => bail!("unsupported bench subcommand `{other}`"),
    };

    let mut case_name = DEFAULT_CASE.to_string();
    let mut repo = std::env::current_dir().context("failed to get current directory")?;
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut profile_output = PathBuf::from(DEFAULT_PROFILE_OUTPUT);
    let mut report_output = None;
    let mut max_regression_pct = DEFAULT_MAX_REGRESSION_PCT;
    let mut require_baseline = false;
    let mut append_on_pass = false;
    let mut synthetic_files = None;
    let mut synthetic_lines = DEFAULT_SYNTHETIC_LINES;

    while let Some(flag) = iter.next() {
        match flag.to_string_lossy().as_ref() {
            "--case" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --case"))?;
                case_name = value.to_string_lossy().to_string();
            }
            "--repo" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --repo"))?;
                repo = PathBuf::from(value);
            }
            "--output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --output"))?;
                output = PathBuf::from(value);
            }
            "--max-regression-pct" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --max-regression-pct"))?;
                max_regression_pct = value
                    .to_string_lossy()
                    .parse::<f64>()
                    .context("failed to parse --max-regression-pct")?;
            }
            "--require-baseline" => {
                require_baseline = true;
            }
            "--append-on-pass" => {
                append_on_pass = true;
            }
            "--profile-output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --profile-output"))?;
                profile_output = PathBuf::from(value);
            }
            "--report-output" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --report-output"))?;
                report_output = Some(PathBuf::from(value));
            }
            "--synthetic-files" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --synthetic-files"))?;
                synthetic_files = Some(
                    value
                        .to_string_lossy()
                        .parse::<usize>()
                        .context("failed to parse --synthetic-files")?,
                );
            }
            "--synthetic-lines" => {
                let value = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --synthetic-lines"))?;
                synthetic_lines = value
                    .to_string_lossy()
                    .parse::<usize>()
                    .context("failed to parse --synthetic-lines")?;
            }
            other => bail!("unsupported flag `{other}`"),
        }
    }

    Ok(BenchOptions {
        subcommand,
        case_name,
        repo,
        output,
        profile_output,
        report_output,
        max_regression_pct,
        require_baseline,
        append_on_pass,
        synthetic_files,
        synthetic_lines,
    })
}

fn run_bench_sample(options: &BenchOptions) -> Result<BenchSample> {
    if let Some(files) = options.synthetic_files {
        return run_synthetic_bench_sample(&options.case_name, files, options.synthetic_lines);
    }
    run_repo_bench_sample(&options.repo, &options.case_name)
}

fn run_synthetic_bench_sample(
    case_name: &str,
    files: usize,
    extra_lines: usize,
) -> Result<BenchSample> {
    let repo = SyntheticRepo::create(files, extra_lines)?;
    run_repo_bench_sample(repo.path(), case_name)
}

fn run_repo_bench_sample(repo: &Path, case_name: &str) -> Result<BenchSample> {
    let changed_files = changed_file_count(repo)?;
    let report = run_patchgate_scan(repo)?;
    let unix_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();

    Ok(BenchSample {
        case_name: case_name.to_string(),
        unix_ts,
        duration_ms: report.duration_ms,
        changed_files,
        score: report.score,
        threshold: report.threshold,
        fingerprint: report.fingerprint,
    })
}

fn run_profile_sample(options: &BenchOptions) -> Result<()> {
    if let Some(files) = options.synthetic_files {
        let repo = SyntheticRepo::create(files, options.synthetic_lines)?;
        run_patchgate_scan_with_profile(repo.path(), &options.profile_output)?;
    } else {
        run_patchgate_scan_with_profile(&options.repo, &options.profile_output)?;
    }
    println!("scan profile written: {}", options.profile_output.display());
    Ok(())
}

struct SyntheticRepo {
    root: PathBuf,
}

impl SyntheticRepo {
    fn create(files: usize, extra_lines: usize) -> Result<Self> {
        let mut root = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        root.push(format!(
            "patchgate-bench-synth-{}-{ts}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;

        init_git_repo(&root)?;
        for i in 0..files {
            let rel = synthetic_file_path(i);
            let abs = root.join(&rel);
            if let Some(parent) = abs.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&abs, "export const value = 1;\n")?;
        }
        run_git(&root, &["add", "."])?;
        run_git(&root, &["commit", "-qm", "baseline"])?;

        for i in 0..files {
            let rel = synthetic_file_path(i);
            let abs = root.join(&rel);
            let mut content = fs::read_to_string(&abs)?;
            for _ in 0..extra_lines.max(1) {
                content.push_str("export const changed = true;\n");
            }
            fs::write(&abs, content)?;
        }

        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for SyntheticRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn synthetic_file_path(index: usize) -> String {
    let package = index / 200;
    format!("packages/pkg-{package:03}/src/file-{index:05}.ts")
}

fn init_git_repo(path: &Path) -> Result<()> {
    run_git(path, &["init", "-q"])?;
    run_git(
        path,
        &["config", "user.email", "patchgate-bench@example.com"],
    )?;
    run_git(path, &["config", "user.name", "Patchgate Bench"])?;
    Ok(())
}

fn run_git(path: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .with_context(|| format!("failed to run git {:?}", args))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn changed_file_count(repo: &Path) -> Result<usize> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--find-renames", "--no-color"])
        .current_dir(repo)
        .output()
        .context("failed to run git diff --name-only")?;
    if !output.status.success() {
        bail!(
            "git diff --name-only failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count())
}

#[derive(Debug, Deserialize)]
struct ScanReport {
    duration_ms: u128,
    score: u64,
    threshold: u64,
    fingerprint: String,
}

fn run_patchgate_scan(repo: &Path) -> Result<ScanReport> {
    let repo_arg = repo
        .to_str()
        .ok_or_else(|| anyhow!("invalid repo path utf8 for scan command"))?;
    let output = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "patchgate-cli",
            "--",
            "--repo",
            repo_arg,
            "scan",
            "--mode",
            "warn",
            "--scope",
            "worktree",
            "--format",
            "json",
            "--no-cache",
        ])
        .current_dir(workspace_root())
        .output()
        .context("failed to run patchgate scan")?;

    if !output.status.success() {
        bail!(
            "patchgate scan failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    serde_json::from_slice::<ScanReport>(&output.stdout)
        .context("failed to parse patchgate scan json output")
}

fn run_patchgate_scan_with_profile(repo: &Path, profile_output: &Path) -> Result<()> {
    let repo_arg = repo
        .to_str()
        .ok_or_else(|| anyhow!("invalid repo path utf8 for scan command"))?;
    if let Some(parent) = profile_output.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let output = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "patchgate-cli",
            "--",
            "--repo",
            repo_arg,
            "scan",
            "--mode",
            "warn",
            "--scope",
            "worktree",
            "--format",
            "json",
            "--no-cache",
            "--profile-output",
            profile_output
                .to_str()
                .ok_or_else(|| anyhow!("invalid profile output path"))?,
        ])
        .current_dir(workspace_root())
        .output()
        .context("failed to run patchgate scan with profile")?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "patchgate scan with profile failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn append_sample(path: &Path, sample: &BenchSample) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    let json = serde_json::to_string(sample).context("encode benchmark sample")?;
    writeln!(file, "{json}").context("append benchmark sample")?;
    Ok(())
}

fn load_latest_sample(path: &Path, case_name: &str) -> Result<Option<BenchSample>> {
    if !path.exists() {
        return Ok(None);
    }

    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut last: Option<BenchSample> = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let sample: BenchSample =
            serde_json::from_str(&line).context("failed to decode benchmark jsonl line")?;
        if sample.case_name == case_name {
            last = Some(sample);
        }
    }
    Ok(last)
}

fn validate_workload_identity(previous: &BenchSample, current: &BenchSample) -> Result<()> {
    if previous.fingerprint != current.fingerprint {
        bail!(
            "benchmark workload mismatch: fingerprint changed (baseline={}, current={})",
            previous.fingerprint,
            current.fingerprint
        );
    }
    if previous.changed_files != current.changed_files {
        bail!(
            "benchmark workload mismatch: changed_files changed (baseline={}, current={})",
            previous.changed_files,
            current.changed_files
        );
    }
    Ok(())
}

fn print_comparison(previous: &BenchSample, current: &BenchSample) {
    let duration_delta = signed_delta(previous.duration_ms as f64, current.duration_ms as f64);
    let file_delta = signed_delta(previous.changed_files as f64, current.changed_files as f64);
    println!(
        "benchmark compare: case={}\n- duration_ms: {} -> {} ({:+.2}%)\n- changed_files: {} -> {} ({:+.2}%)",
        current.case_name,
        previous.duration_ms,
        current.duration_ms,
        duration_delta,
        previous.changed_files,
        current.changed_files,
        file_delta
    );
}

fn write_compare_report(
    path: &Path,
    previous: &BenchSample,
    current: &BenchSample,
    max_regression_pct: f64,
    regressed: bool,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let report = BenchCompareReport {
        case_name: current.case_name.clone(),
        baseline_duration_ms: previous.duration_ms,
        current_duration_ms: current.duration_ms,
        duration_delta_pct: signed_delta(previous.duration_ms as f64, current.duration_ms as f64),
        baseline_changed_files: previous.changed_files,
        current_changed_files: current.changed_files,
        max_regression_pct,
        regressed,
        fingerprint: current.fingerprint.clone(),
    };
    fs::write(path, serde_json::to_string_pretty(&report)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn signed_delta(previous: f64, current: f64) -> f64 {
    if previous == 0.0 {
        return if current == 0.0 { 0.0 } else { 100.0 };
    }
    ((current - previous) / previous) * 100.0
}

fn is_duration_regressed(
    previous: &BenchSample,
    current: &BenchSample,
    max_regression_pct: f64,
) -> bool {
    signed_delta(previous.duration_ms as f64, current.duration_ms as f64) > max_regression_pct
}

#[cfg(test)]
mod tests {
    use super::{validate_workload_identity, BenchSample};

    fn sample(case_name: &str, changed_files: usize, fingerprint: &str) -> BenchSample {
        BenchSample {
            case_name: case_name.to_string(),
            unix_ts: 0,
            duration_ms: 10,
            changed_files,
            score: 100,
            threshold: 70,
            fingerprint: fingerprint.to_string(),
        }
    }

    #[test]
    fn workload_identity_requires_same_fingerprint_and_changed_files() {
        let prev = sample("ci-worktree", 0, "abc");
        let same = sample("ci-worktree", 0, "abc");
        validate_workload_identity(&prev, &same).expect("same workload must pass");

        let mismatch_fp = sample("ci-worktree", 0, "def");
        assert!(
            validate_workload_identity(&prev, &mismatch_fp).is_err(),
            "fingerprint mismatch should fail"
        );

        let mismatch_files = sample("ci-worktree", 1, "abc");
        assert!(
            validate_workload_identity(&prev, &mismatch_files).is_err(),
            "changed_files mismatch should fail"
        );
    }
}
