use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result};

use crate::runner::ScopeMode;
use crate::{Check, Context, Finding, Severity};

pub struct EntropyGuard {
    pub enabled: bool,
    pub min_length: usize,
    pub threshold: f64,
    pub ignore_extensions: Vec<String>,
    pub allowlist: Vec<String>,
    pub max_file_bytes: u64,
    pub max_line_length: usize,
    pub max_tokens_per_file: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CharsetHint {
    Base64ish,
    Base64Urlish,
    Hexish,
    Alnum,
}

impl Check for EntropyGuard {
    fn id(&self) -> &'static str {
        "EG-001"
    }

    fn description(&self) -> &'static str {
        "Detects high-entropy strings that may be secrets"
    }

    fn run(&self, ctx: &crate::Context) -> Result<Vec<Finding>> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let files = get_target_files(ctx, self.max_file_bytes)?;
        let mut findings = vec![];

        for (path_string, content) in files {
            // Check ignore extensions
            if let Some(ext) = Path::new(&path_string).extension() {
                if let Some(ext_str) = ext.to_str() {
                    if self
                        .ignore_extensions
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(ext_str))
                    {
                        continue;
                    }
                }
            }

            // Allowlist check (naive substring match for file path, maybe?)
            // Usually allowlist is for token content, but file path ignore is also useful.
            // For now, let's implement token-based allowlist as requested.

            let mut token_count = 0;
            for (line_idx, line) in content.lines().enumerate() {
                // DoS protection: Skip very long lines
                if line.len() > self.max_line_length {
                    continue;
                }

                let line_num = line_idx + 1;
                // Runs extraction
                for (token, charset) in extract_runs(line) {
                    token_count += 1;
                    if token_count > self.max_tokens_per_file {
                        break;
                    }

                    if token.len() < self.min_length {
                        continue;
                    }

                    if self.allowlist.iter().any(|pattern| token.contains(pattern)) {
                        continue;
                    }

                    // Unique chars filter (heuristic)
                    if count_unique_chars(token) < 6 {
                        continue;
                    }

                    // Heuristics adjustments
                    let mut threshold = self.threshold;
                    if let CharsetHint::Hexish = charset {
                        // Hex needs higher entropy or it flags too many git hashes / random hex
                        threshold += 0.5;
                    }

                    let entropy = shannon_entropy(token);
                    if entropy > threshold {
                        findings.push(Finding {
                            id: self.id().to_string(),
                            title: "High-entropy token detected".to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Possible secret detected (entropy: {:.2}, len: {}). Content: {}",
                                entropy,
                                token.len(),
                                mask_token(token)
                            ),
                            location: Some(crate::model::Location {
                                file: path_string.clone(),
                                line: Some(line_num as u32),
                            }),
                            tags: vec!["entropy".to_string()],
                            details: Some(crate::model::FindingDetails {
                                entropy,
                                token_len: token.len(),
                                charset: format!("{:?}", charset),
                            }),
                        });
                    }
                }
                if token_count > self.max_tokens_per_file {
                    break;
                }
            }
        }

        Ok(findings)
    }
}

fn get_target_files(ctx: &Context, max_file_bytes: u64) -> Result<Vec<(String, String)>> {
    match ctx.scope {
        ScopeMode::Staged => {
            // git diff --cached --name-only --diff-filter=AM
            let output = Command::new("git")
                .arg("diff")
                .arg("--cached")
                .arg("--name-only")
                .arg("--diff-filter=AM")
                .current_dir(&ctx.repo_root)
                .output()
                .context("git diff --cached failed")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "git diff failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            let paths = String::from_utf8(output.stdout)?;
            let mut results = vec![];

            for path in paths.lines() {
                // Check size first: git cat-file -s :path
                let size_out = Command::new("git")
                    .arg("cat-file")
                    .arg("-s")
                    .arg(format!(":{}", path))
                    .current_dir(&ctx.repo_root)
                    .output();

                if let Ok(so) = size_out {
                    if so.status.success() {
                        let size_str = String::from_utf8_lossy(&so.stdout);
                        if let Ok(size) = size_str.trim().parse::<u64>() {
                            if size > max_file_bytes {
                                // Skip
                                continue;
                            }
                        }
                    }
                }

                // git show :path
                let show_out = Command::new("git")
                    .arg("show")
                    .arg(format!(":{}", path))
                    .current_dir(&ctx.repo_root)
                    .output();

                if let Ok(out) = show_out {
                    if out.status.success() {
                        // Check binary matches
                        if is_binary(&out.stdout) {
                            continue;
                        }
                        if let Ok(s) = String::from_utf8(out.stdout) {
                            results.push((path.to_string(), s));
                        }
                    }
                }
            }
            Ok(results)
        }
        ScopeMode::Worktree => {
            let output = Command::new("git")
                .arg("diff")
                .arg("--name-only")
                .arg("--diff-filter=AM")
                .current_dir(&ctx.repo_root)
                .output()
                .context("git diff failed")?;

            if !output.status.success() {
                return Err(anyhow::anyhow!(
                    "git diff failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }

            let paths = String::from_utf8(output.stdout)?;
            let mut results = vec![];

            for p in paths.lines() {
                let full_path = ctx.repo_root.join(p);
                if full_path.exists() && full_path.is_file() {
                    // Check size: fs::metadata
                    if let Ok(meta) = fs::metadata(&full_path) {
                        if meta.len() > max_file_bytes {
                            continue;
                        }
                    }

                    // Read file
                    let f = fs::File::open(&full_path)?;
                    let mut buffer = Vec::new();
                    // Double check with take to prevent TOCTOU race where file grows?
                    // Or just read max + 1
                    f.take(max_file_bytes + 1).read_to_end(&mut buffer)?;

                    if buffer.len() as u64 > max_file_bytes {
                        continue;
                    }

                    if is_binary(&buffer) {
                        continue;
                    }

                    if let Ok(s) = String::from_utf8(buffer) {
                        results.push((p.to_string(), s));
                    }
                }
            }
            Ok(results)
        }
        ScopeMode::Repo => {
            // TODO: Phase 2
            Ok(vec![])
        }
    }
}

// Simple heuristic for binary content
fn is_binary(data: &[u8]) -> bool {
    // Check first 1024 bytes for null byte
    data.iter().take(1024).any(|&b| b == 0)
}

fn shannon_entropy(s: &str) -> f64 {
    let mut map = HashMap::new();
    let len = s.len() as f64;
    for c in s.chars() {
        *map.entry(c).or_insert(0.0) += 1.0;
    }

    let mut entropy = 0.0;
    for count in map.values() {
        let p = count / len;
        entropy -= p * p.log2();
    }
    entropy
}

// Extract runs of allowed chars.
// Allowed = [A-Za-z0-9+/=_-]
fn extract_runs(line: &str) -> Vec<(&str, CharsetHint)> {
    let mut results = vec![];
    let mut start = None;

    // Allowed char predicate
    let is_allowed = |c: char| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
    };

    for (i, c) in line.char_indices() {
        if is_allowed(c) {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            if let Some(s) = start {
                let token = &line[s..i];
                results.push((token, detect_charset(token)));
                start = None;
            }
        }
    }
    if let Some(s) = start {
        let token = &line[s..];
        results.push((token, detect_charset(token)));
    }
    results
}

fn detect_charset(s: &str) -> CharsetHint {
    let has_hex = s.chars().all(|c| c.is_ascii_hexdigit());
    let has_b64 = s.chars().any(|c| c == '+' || c == '/');
    let has_b64url = s.chars().any(|c| c == '-' || c == '_');

    if has_hex && s.len() > 8 {
        // simple heuristic
        CharsetHint::Hexish
    } else if has_b64 {
        CharsetHint::Base64ish
    } else if has_b64url {
        CharsetHint::Base64Urlish
    } else {
        CharsetHint::Alnum
    }
}

fn count_unique_chars(s: &str) -> usize {
    let mut chars = s.chars().collect::<Vec<_>>();
    chars.sort();
    chars.dedup();
    chars.len()
}

fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        return "***".to_string();
    }
    let start = &token[..4];
    let end = &token[token.len() - 4..];
    format!("{}...{}", start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy() {
        let low = "wvwwwvwvvwwv"; // Repetitive
        let high = "7Fz2X9kL1mN4pQ3r"; // Randomish

        let e_low = shannon_entropy(low);
        let e_high = shannon_entropy(high);

        assert!(e_high > e_low);
        assert!(e_high > 3.0); // usually > 3.5 for this length
    }

    #[test]
    fn test_mask() {
        assert_eq!(mask_token("secret"), "***");
        assert_eq!(mask_token("1234567890"), "1234...7890");
    }

    #[test]
    fn test_extract_runs() {
        // allowed: A-Za-z0-9+/=_-
        // "foo": alnum
        // "bar=baz": alnum+ext
        // "url": alnum
        // "https": alnum
        // "//example.com/foo_bar": / . is not allowed! wait. dot is NOT allowed in our charset [A-Za-z0-9+/=_-]
        // So "example.com" -> example, com

        // Let's test precisely our logic
        // "foo bar=baz" -> ["foo", "bar=baz"]
        let runs = extract_runs("foo bar=baz");
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].0, "foo");
        assert_eq!(runs[1].0, "bar=baz");

        // UUID: "123e4567-e89b-12d3-a456-426614174000" (has hyphens, should be one run)
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let runs = extract_runs(uuid);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].0, uuid);

        // Base64
        let b64 = "SGVsbG8gV29ybGQ=";
        let runs = extract_runs(b64);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].0, b64);
        matches!(runs[0].1, CharsetHint::Base64ish);
    }

    #[test]
    fn test_detect_charset() {
        assert!(matches!(
            detect_charset("abcdef123456"),
            CharsetHint::Hexish
        )); // len > 8
        assert!(matches!(detect_charset("abc"), CharsetHint::Alnum)); // Hex but short -> Alnum (logic check: all hexdigit is true, but len <= 8... wait logic says if has_hex && len > 8 then Hexish. else if b64... else Alnum. So short hex is Alnum? No, `has_hex` is true for "abc". Ah code: `if has_hex && s.len() > 8`. So "abc" -> Alnum. Correct.)
        assert!(matches!(
            detect_charset("SGVsbG8+V29ybGQ="),
            CharsetHint::Base64ish
        ));
        assert!(matches!(
            detect_charset(
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
            ),
            CharsetHint::Alnum
        )); // Just alnum? No, base64url usually has -_ but this one might just be alnum if padless? verify "eyJ..." is alnum.
        assert!(matches!(detect_charset("a-b_c"), CharsetHint::Base64Urlish));
    }
}
