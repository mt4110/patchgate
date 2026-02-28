use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_CASE: &str = "default-worktree";
const DEFAULT_OUTPUT: &str = "target/benchmarks/patchgate_baseline.jsonl";
const DEFAULT_MAX_REGRESSION_PCT: f64 = 30.0;

#[derive(Debug, Clone)]
enum BenchSubcommand {
    Record,
    Compare,
}

#[derive(Debug, Clone)]
struct BenchOptions {
    subcommand: BenchSubcommand,
    case_name: String,
    repo: PathBuf,
    output: PathBuf,
    max_regression_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchSample {
    case_name: String,
    unix_ts: u64,
    duration_ms: u64,
    changed_files: usize,
    score: u64,
    threshold: u64,
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
    let sample = run_bench_sample(&options.repo, &options.case_name)?;

    match options.subcommand {
        BenchSubcommand::Record => {
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
            let previous = load_latest_sample(&options.output, &sample.case_name)?;
            if let Some(prev) = previous {
                print_comparison(&prev, &sample);
                let regressed = is_duration_regressed(&prev, &sample, options.max_regression_pct);
                append_sample(&options.output, &sample)?;
                if regressed {
                    bail!(
                        "benchmark regression: duration exceeded {:.1}% threshold",
                        options.max_regression_pct
                    );
                }
            } else {
                println!(
                    "no baseline found for case `{}` in {}. recording first sample.",
                    sample.case_name,
                    options.output.display()
                );
                append_sample(&options.output, &sample)?;
            }
        }
    }

    Ok(())
}

fn print_help() {
    eprintln!(
        "usage:\n  cargo run -p xtask -- bench record [--case NAME] [--repo PATH] [--output PATH]\n  cargo run -p xtask -- bench compare [--case NAME] [--repo PATH] [--output PATH] [--max-regression-pct N]"
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
        other => bail!("unsupported bench subcommand `{other}`"),
    };

    let mut case_name = DEFAULT_CASE.to_string();
    let mut repo = std::env::current_dir().context("failed to get current directory")?;
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    let mut max_regression_pct = DEFAULT_MAX_REGRESSION_PCT;

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
            other => bail!("unsupported flag `{other}`"),
        }
    }

    Ok(BenchOptions {
        subcommand,
        case_name,
        repo,
        output,
        max_regression_pct,
    })
}

fn run_bench_sample(repo: &Path, case_name: &str) -> Result<BenchSample> {
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
    duration_ms: u64,
    score: u64,
    threshold: u64,
    fingerprint: String,
}

fn run_patchgate_scan(repo: &Path) -> Result<ScanReport> {
    let output = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "patchgate-cli",
            "--",
            "scan",
            "--mode",
            "warn",
            "--scope",
            "worktree",
            "--format",
            "json",
            "--no-cache",
        ])
        .current_dir(repo)
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
