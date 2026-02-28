use anyhow::{Context as _, Result};
use patchgate_core::Report;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};

const MARKER: &str = "<!-- patchgate:report -->";

#[derive(Debug, Clone)]
pub struct PublishRequest {
    pub repo: String,
    pub pr_number: u64,
    pub head_sha: String,
    pub token: String,
    pub check_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublishResult {
    pub comment_url: Option<String>,
    pub check_run_url: Option<String>,
}

pub fn publish_report(
    report: &Report,
    markdown: &str,
    req: &PublishRequest,
) -> Result<PublishResult> {
    let client = github_client(&req.token)?;

    let body = format!("{}\n\n{}", MARKER, markdown);
    let comment_url = upsert_pr_comment(&client, &req.repo, req.pr_number, &body)?;

    let check_run_url = publish_check_run(&client, report, req, markdown)?;

    Ok(PublishResult {
        comment_url,
        check_run_url,
    })
}

fn github_client(token: &str) -> Result<Client> {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("patchgate/0.2"));
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    let auth = format!("Bearer {token}");
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth).context("failed to build auth header")?,
    );

    Client::builder()
        .default_headers(headers)
        .build()
        .context("failed to build github client")
}

#[derive(Debug, Deserialize)]
struct IssueComment {
    id: u64,
    body: Option<String>,
    html_url: Option<String>,
}

fn upsert_pr_comment(
    client: &Client,
    repo: &str,
    pr_number: u64,
    body: &str,
) -> Result<Option<String>> {
    let comments_url =
        format!("https://api.github.com/repos/{repo}/issues/{pr_number}/comments?per_page=100");

    let comments: Vec<IssueComment> = client
        .get(&comments_url)
        .send()
        .context("failed to list issue comments")?
        .error_for_status()
        .context("github returned error listing issue comments")?
        .json()
        .context("failed to decode issue comments")?;

    if let Some(existing) = comments
        .iter()
        .find(|c| c.body.as_deref().is_some_and(|b| b.contains(MARKER)))
    {
        let update_url = format!(
            "https://api.github.com/repos/{repo}/issues/comments/{}",
            existing.id
        );
        let updated: IssueComment = client
            .patch(&update_url)
            .json(&serde_json::json!({ "body": body }))
            .send()
            .context("failed to update issue comment")?
            .error_for_status()
            .context("github returned error updating issue comment")?
            .json()
            .context("failed to decode updated issue comment")?;
        return Ok(updated.html_url);
    }

    let created: IssueComment = client
        .post(format!(
            "https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        ))
        .json(&serde_json::json!({ "body": body }))
        .send()
        .context("failed to create issue comment")?
        .error_for_status()
        .context("github returned error creating issue comment")?
        .json()
        .context("failed to decode created issue comment")?;

    Ok(created.html_url)
}

#[derive(Debug, Deserialize)]
struct CheckRunResponse {
    html_url: Option<String>,
}

fn publish_check_run(
    client: &Client,
    report: &Report,
    req: &PublishRequest,
    markdown: &str,
) -> Result<Option<String>> {
    let conclusion = if report.should_fail {
        "failure"
    } else if report.findings.is_empty() {
        "success"
    } else {
        "neutral"
    };

    let status_line = format!(
        "Score {}/100 (threshold {}, mode {})",
        report.score, report.threshold, report.mode
    );

    let payload = serde_json::json!({
        "name": req.check_name,
        "head_sha": req.head_sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "patchgate quality gate",
            "summary": status_line,
            "text": truncate(markdown, 65000)
        }
    });

    let check: CheckRunResponse = client
        .post(format!(
            "https://api.github.com/repos/{}/check-runs",
            req.repo
        ))
        .json(&payload)
        .send()
        .context("failed to create check run")?
        .error_for_status()
        .context("github returned error creating check run")?
        .json()
        .context("failed to decode check run response")?;

    Ok(check.html_url)
}

fn truncate(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncate_keeps_short_text() {
        let s = "abc";
        assert_eq!(truncate(s, 10), "abc");
    }

    #[test]
    fn truncate_cuts_long_text() {
        let s = "abcdef";
        assert_eq!(truncate(s, 4), "abcd");
    }
}
