use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use patchgate_core::{Report, ReviewPriority, Severity};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const MARKER: &str = "<!-- patchgate:report -->";
const DEFAULT_API_BASE_URL: &str = "https://api.github.com";
const PRIORITY_LABEL_PREFIX: &str = "patchgate:priority/";

#[derive(Debug, Clone)]
pub enum PublishAuth {
    Token {
        token: String,
    },
    App {
        installation_token: String,
        app_id: Option<String>,
    },
}

impl PublishAuth {
    pub fn mode(&self) -> &'static str {
        match self {
            PublishAuth::Token { .. } => "token",
            PublishAuth::App { .. } => "app",
        }
    }

    fn token(&self) -> &str {
        match self {
            PublishAuth::Token { token } => token,
            PublishAuth::App {
                installation_token, ..
            } => installation_token,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff_base_ms: 300,
            backoff_max_ms: 3_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PublishRequest {
    pub repo: String,
    pub pr_number: u64,
    pub head_sha: String,
    pub auth: PublishAuth,
    pub check_name: String,
    pub retry_policy: RetryPolicy,
    pub publish_comment: bool,
    pub publish_check_run: bool,
    pub apply_priority_label: bool,
    pub dry_run: bool,
    pub suppressed_comment_reason: Option<String>,
    pub api_base_url: String,
}

impl PublishRequest {
    pub fn new(
        repo: String,
        pr_number: u64,
        head_sha: String,
        auth: PublishAuth,
        check_name: String,
    ) -> Self {
        Self {
            repo,
            pr_number,
            head_sha,
            auth,
            check_name,
            retry_policy: RetryPolicy::default(),
            publish_comment: true,
            publish_check_run: true,
            apply_priority_label: false,
            dry_run: false,
            suppressed_comment_reason: None,
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublishResult {
    pub comment_url: Option<String>,
    pub check_run_url: Option<String>,
    pub comment_error: Option<String>,
    pub check_run_error: Option<String>,
    pub label_error: Option<String>,
    pub applied_labels: Vec<String>,
    pub degraded_mode: Option<String>,
    pub skipped_comment: bool,
    pub skipped_comment_reason: Option<String>,
    pub dry_run_payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct PublishOpError {
    message: String,
    retryable: bool,
    rate_limited: bool,
    status_code: Option<u16>,
}

impl PublishOpError {
    fn new(message: impl Into<String>, retryable: bool, rate_limited: bool) -> Self {
        Self {
            message: message.into(),
            retryable,
            rate_limited,
            status_code: None,
        }
    }

    fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = Some(status_code);
        self
    }
}

pub fn publish_report(
    report: &Report,
    markdown: &str,
    req: &PublishRequest,
) -> Result<PublishResult> {
    let body = ensure_comment_marker(markdown);
    let check_payload = build_check_run_payload(report, req, markdown);
    let priority_label = priority_label_name(report.review_priority).to_string();

    if req.dry_run {
        let mut dry_run = PublishResult::default();
        if let Some(reason) = req.suppressed_comment_reason.as_ref() {
            dry_run.skipped_comment = true;
            dry_run.skipped_comment_reason = Some(reason.clone());
        }
        dry_run.dry_run_payload = Some(serde_json::json!({
            "repo": req.repo.as_str(),
            "pr_number": req.pr_number,
            "head_sha": req.head_sha.as_str(),
            "auth_mode": req.auth.mode(),
            "publish_comment": req.publish_comment,
            "publish_check_run": req.publish_check_run,
            "apply_priority_label": req.apply_priority_label,
            "comment_payload": {
                "marker": MARKER,
                "body": body,
            },
            "check_run_payload": check_payload,
            "priority_label": priority_label,
            "suppressed_comment_reason": req.suppressed_comment_reason.as_deref(),
            "retry_policy": &req.retry_policy,
        }));
        return Ok(dry_run);
    }

    let client = github_client(&req.auth)?;
    let mut result = PublishResult::default();
    let mut primary_attempted = 0usize;
    let mut primary_succeeded = 0usize;

    if req.publish_check_run {
        primary_attempted += 1;
        match with_retry(&req.retry_policy, || {
            upsert_check_run(&client, report, req, &check_payload)
        }) {
            Ok(url) => {
                result.check_run_url = url;
                primary_succeeded += 1;
            }
            Err(err) => {
                if err.rate_limited {
                    result.degraded_mode = Some("comment_only".to_string());
                }
                result.check_run_error = Some(err.message);
            }
        }
    }

    if req.publish_comment {
        if let Some(reason) = req.suppressed_comment_reason.as_ref() {
            result.skipped_comment = true;
            result.skipped_comment_reason = Some(reason.clone());
        } else {
            primary_attempted += 1;
            match with_retry(&req.retry_policy, || {
                upsert_pr_comment(&client, req, body.as_str())
            }) {
                Ok(url) => {
                    result.comment_url = url;
                    primary_succeeded += 1;
                }
                Err(err) => {
                    if err.rate_limited && result.degraded_mode.is_none() {
                        result.degraded_mode = Some("check_only".to_string());
                    }
                    result.comment_error = Some(err.message);
                }
            }
        }
    }

    if req.apply_priority_label {
        match with_retry(&req.retry_policy, || {
            apply_pr_label(&client, req, priority_label.as_str())
        }) {
            Ok(labels) => {
                result.applied_labels = labels;
            }
            Err(err) => {
                result.label_error = Some(err.message);
            }
        }
    }

    if primary_attempted > 0 && primary_succeeded == 0 {
        return Err(anyhow!(
            "failed to publish all requested GitHub outputs: comment_error=`{}` check_run_error=`{}`",
            result.comment_error.as_deref().unwrap_or("not requested"),
            result.check_run_error.as_deref().unwrap_or("not requested"),
        ));
    }

    Ok(result)
}

fn with_retry<T, F>(policy: &RetryPolicy, mut f: F) -> std::result::Result<T, PublishOpError>
where
    F: FnMut() -> std::result::Result<T, PublishOpError>,
{
    let attempts = policy.max_attempts.max(1);
    let mut last_err: Option<PublishOpError> = None;

    for attempt in 0..attempts {
        match f() {
            Ok(value) => return Ok(value),
            Err(err) => {
                let should_retry = err.retryable && attempt + 1 < attempts;
                last_err = Some(err);
                if should_retry {
                    let delay = backoff_delay_ms(policy, attempt);
                    sleep(Duration::from_millis(delay));
                    continue;
                }
                break;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        PublishOpError::new("publish operation failed with unknown error", false, false)
    }))
}

fn backoff_delay_ms(policy: &RetryPolicy, attempt: u8) -> u64 {
    let exp = 2u64.saturating_pow(attempt as u32);
    let delay = policy.backoff_base_ms.saturating_mul(exp);
    delay.min(policy.backoff_max_ms)
}

fn github_client(auth: &PublishAuth) -> Result<Client> {
    let mut headers = HeaderMap::new();
    let user_agent = format!("patchgate/{}", env!("CARGO_PKG_VERSION"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&user_agent).context("failed to build user-agent header")?,
    );
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    let auth_header = format!("Bearer {}", auth.token());
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&auth_header).context("failed to build auth header")?,
    );

    Client::builder()
        .default_headers(headers)
        .build()
        .context("failed to build github client")
}

#[derive(Debug, Deserialize, Clone)]
struct IssueComment {
    id: u64,
    body: Option<String>,
    html_url: Option<String>,
}

fn upsert_pr_comment(
    client: &Client,
    req: &PublishRequest,
    body: &str,
) -> std::result::Result<Option<String>, PublishOpError> {
    let comments = list_all_marker_comments(client, req)?;

    if let Some(target) = comments.iter().max_by_key(|c| c.id) {
        if target
            .body
            .as_deref()
            .is_some_and(|existing| is_same_comment_content(existing, body))
        {
            return Ok(target.html_url.clone());
        }

        let update_url = format!(
            "{}/repos/{}/issues/comments/{}",
            req.api_base_url, req.repo, target.id
        );
        let updated: std::result::Result<IssueComment, PublishOpError> = send_json(
            client
                .patch(update_url)
                .json(&serde_json::json!({ "body": body })),
            "update issue comment",
        );
        match updated {
            Ok(updated) => return Ok(updated.html_url),
            Err(err) => {
                if !is_comment_update_fallback_candidate(&err) {
                    return Err(err);
                }
            }
        }
    }

    let created: IssueComment = send_json(
        client
            .post(format!(
                "{}/repos/{}/issues/{}/comments",
                req.api_base_url, req.repo, req.pr_number
            ))
            .json(&serde_json::json!({ "body": body })),
        "create issue comment",
    )?;

    Ok(created.html_url)
}

fn list_all_marker_comments(
    client: &Client,
    req: &PublishRequest,
) -> std::result::Result<Vec<IssueComment>, PublishOpError> {
    let mut page = 1u32;
    let mut matched = Vec::new();

    loop {
        let params = vec![
            ("per_page".to_string(), "100".to_string()),
            ("page".to_string(), page.to_string()),
        ];
        let comments: Vec<IssueComment> = send_json(
            client
                .get(format!(
                    "{}/repos/{}/issues/{}/comments",
                    req.api_base_url, req.repo, req.pr_number
                ))
                .query(&params),
            "list issue comments",
        )?;

        for comment in &comments {
            if comment
                .body
                .as_deref()
                .is_some_and(|text| text.contains(MARKER))
            {
                matched.push(comment.clone());
            }
        }

        if comments.len() < 100 {
            break;
        }
        page = page.saturating_add(1);
    }

    Ok(matched)
}

#[derive(Debug, Deserialize)]
struct CheckRunsResponse {
    check_runs: Vec<CheckRunItem>,
}

#[derive(Debug, Deserialize)]
struct CheckRunItem {
    id: u64,
    html_url: Option<String>,
}

fn upsert_check_run(
    client: &Client,
    _report: &Report,
    req: &PublishRequest,
    payload: &serde_json::Value,
) -> std::result::Result<Option<String>, PublishOpError> {
    let existing: CheckRunsResponse = send_json(
        client
            .get(format!(
                "{}/repos/{}/commits/{}/check-runs",
                req.api_base_url, req.repo, req.head_sha
            ))
            .query(&[("check_name", req.check_name.as_str()), ("per_page", "100")]),
        "list check runs",
    )?;

    if let Some(run) = existing.check_runs.iter().max_by_key(|r| r.id) {
        let update_payload = check_run_update_payload(payload);
        let updated: std::result::Result<CheckRunItem, PublishOpError> = send_json(
            client
                .patch(format!(
                    "{}/repos/{}/check-runs/{}",
                    req.api_base_url, req.repo, run.id
                ))
                .json(&update_payload),
            "update check run",
        );
        match updated {
            Ok(updated) => return Ok(updated.html_url),
            Err(err) => {
                if !is_check_run_update_fallback_candidate(&err) {
                    return Err(err);
                }
            }
        }
    }

    let created: CheckRunItem = send_json(
        client
            .post(format!(
                "{}/repos/{}/check-runs",
                req.api_base_url, req.repo
            ))
            .json(payload),
        "create check run",
    )?;

    Ok(created.html_url)
}

fn check_run_update_payload(payload: &serde_json::Value) -> serde_json::Value {
    let mut update_payload = payload.clone();
    if let Some(obj) = update_payload.as_object_mut() {
        obj.remove("head_sha");
    }
    update_payload
}

#[derive(Debug, Deserialize)]
struct LabelItem {
    name: String,
}

fn apply_pr_label(
    client: &Client,
    req: &PublishRequest,
    label: &str,
) -> std::result::Result<Vec<String>, PublishOpError> {
    let current_labels = list_all_issue_labels(client, req)?;
    let next_labels = merge_priority_label_names(&current_labels, label);

    let labels: Vec<LabelItem> = send_json(
        client
            .put(format!(
                "{}/repos/{}/issues/{}/labels",
                req.api_base_url, req.repo, req.pr_number
            ))
            .json(&serde_json::json!({ "labels": next_labels })),
        "set issue labels",
    )?;

    Ok(labels.into_iter().map(|l| l.name).collect())
}

fn list_all_issue_labels(
    client: &Client,
    req: &PublishRequest,
) -> std::result::Result<Vec<LabelItem>, PublishOpError> {
    let mut page = 1u32;
    let mut labels = Vec::new();

    loop {
        let params = vec![
            ("per_page".to_string(), "100".to_string()),
            ("page".to_string(), page.to_string()),
        ];
        let page_labels: Vec<LabelItem> = send_json(
            client
                .get(format!(
                    "{}/repos/{}/issues/{}/labels",
                    req.api_base_url, req.repo, req.pr_number
                ))
                .query(&params),
            "list issue labels",
        )?;
        let page_count = page_labels.len();
        labels.extend(page_labels);

        if page_count < 100 {
            break;
        }

        page = page.saturating_add(1);
    }

    Ok(labels)
}

fn merge_priority_label_names(existing: &[LabelItem], target: &str) -> Vec<String> {
    let mut merged = Vec::new();
    for label in existing {
        if label.name.starts_with(PRIORITY_LABEL_PREFIX) {
            continue;
        }
        if merged.iter().any(|current| current == &label.name) {
            continue;
        }
        merged.push(label.name.clone());
    }

    if !merged.iter().any(|current| current == target) {
        merged.push(target.to_string());
    }

    merged
}

fn send_json<T: DeserializeOwned>(
    request: RequestBuilder,
    operation: &str,
) -> std::result::Result<T, PublishOpError> {
    let response = request.send().map_err(|err| {
        PublishOpError::new(
            format!("{operation}: request failed: {err}"),
            err.is_timeout() || err.is_connect(),
            false,
        )
    })?;

    decode_json_response(response, operation)
}

fn decode_json_response<T: DeserializeOwned>(
    response: Response,
    operation: &str,
) -> std::result::Result<T, PublishOpError> {
    let status = response.status();
    let headers = response.headers().clone();

    if status.is_success() {
        response.json::<T>().map_err(|err| {
            PublishOpError::new(
                format!("{operation}: decode response failed: {err}"),
                false,
                false,
            )
        })
    } else {
        let body = response
            .text()
            .unwrap_or_else(|_| "<unreadable body>".to_string());
        Err(http_status_error(
            operation,
            status,
            &headers,
            body.as_str(),
        ))
    }
}

fn http_status_error(
    operation: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &str,
) -> PublishOpError {
    let body_excerpt = truncate(body, 400);
    let rate_limited = is_rate_limited(status, headers);
    let retryable =
        rate_limited || status.is_server_error() || status == StatusCode::REQUEST_TIMEOUT;

    PublishOpError::new(
        format!(
            "{operation}: github api returned {}: {}",
            status.as_u16(),
            body_excerpt
        ),
        retryable,
        rate_limited,
    )
    .with_status_code(status.as_u16())
}

fn is_rate_limited(status: StatusCode, headers: &HeaderMap) -> bool {
    if status == StatusCode::TOO_MANY_REQUESTS {
        return true;
    }

    if status != StatusCode::FORBIDDEN {
        return false;
    }

    headers
        .get("x-ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "0")
}

fn build_check_run_payload(
    report: &Report,
    req: &PublishRequest,
    markdown: &str,
) -> serde_json::Value {
    let conclusion = check_run_conclusion(report);
    let status_line = format!(
        "Score {}/100 (threshold {}, mode {})",
        report.score, report.threshold, report.mode
    );

    serde_json::json!({
        "name": req.check_name.as_str(),
        "head_sha": req.head_sha.as_str(),
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "patchgate quality gate",
            "summary": status_line,
            "text": truncate(markdown, 65000)
        }
    })
}

fn check_run_conclusion(report: &Report) -> &'static str {
    if report.mode == "enforce" && report.should_fail {
        return "failure";
    }

    if report.findings.is_empty() {
        return "success";
    }

    let has_critical = report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical);
    let has_high = report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::High);

    if has_critical && report.mode == "warn" {
        return "action_required";
    }

    if has_high || has_critical {
        return "neutral";
    }

    if report.mode == "enforce" {
        "success"
    } else {
        "neutral"
    }
}

fn priority_label_name(priority: ReviewPriority) -> &'static str {
    match priority {
        ReviewPriority::P0 => "patchgate:priority/p0",
        ReviewPriority::P1 => "patchgate:priority/p1",
        ReviewPriority::P2 => "patchgate:priority/p2",
        ReviewPriority::P3 => "patchgate:priority/p3",
    }
}

fn truncate(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

fn ensure_comment_marker(markdown: &str) -> String {
    if markdown.contains(MARKER) {
        markdown.to_string()
    } else {
        format!("{MARKER}\n\n{markdown}")
    }
}

fn is_same_comment_content(existing: &str, incoming: &str) -> bool {
    normalize_comment(existing) == normalize_comment(incoming)
}

fn normalize_comment(input: &str) -> &str {
    input.trim()
}

fn is_comment_update_fallback_candidate(err: &PublishOpError) -> bool {
    matches!(err.status_code, Some(403 | 404))
}

fn is_check_run_update_fallback_candidate(err: &PublishOpError) -> bool {
    matches!(err.status_code, Some(403 | 404))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use patchgate_core::{CheckId, CheckScore, Finding, Report, ReportMeta, ReviewPriority};

    use super::{
        backoff_delay_ms, check_run_conclusion, check_run_update_payload, ensure_comment_marker,
        is_check_run_update_fallback_candidate, is_comment_update_fallback_candidate,
        is_same_comment_content, merge_priority_label_names, priority_label_name, with_retry,
        LabelItem, PublishOpError, RetryPolicy, MARKER,
    };

    fn sample_report(mode: &str, penalty: u8, findings: Vec<Finding>) -> Report {
        Report::new(
            findings,
            vec![CheckScore {
                check: CheckId::TestGap,
                label: "Test coverage gap".to_string(),
                penalty,
                max_penalty: 40,
                triggered: penalty > 0,
            }],
            ReportMeta {
                threshold: 70,
                mode: mode.to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        )
    }

    fn finding(id: &str, severity: patchgate_core::Severity) -> Finding {
        Finding {
            id: id.to_string(),
            rule_id: id.to_string(),
            category: "test".to_string(),
            docs_url: "https://example.com".to_string(),
            check: CheckId::TestGap,
            title: id.to_string(),
            message: "message".to_string(),
            severity,
            penalty: 1,
            location: None,
            tags: vec![],
        }
    }

    #[test]
    fn ensure_comment_marker_is_added_once() {
        let no_marker = "## report";
        let with_marker = format!("{MARKER}\n\n## report");
        assert!(ensure_comment_marker(no_marker).starts_with(MARKER));
        assert_eq!(ensure_comment_marker(&with_marker), with_marker);
    }

    #[test]
    fn check_run_conclusion_matrix() {
        let enforce_fail = sample_report("enforce", 40, vec![]);
        assert_eq!(check_run_conclusion(&enforce_fail), "failure");

        let warn_no_findings = sample_report("warn", 0, vec![]);
        assert_eq!(check_run_conclusion(&warn_no_findings), "success");

        let warn_critical = sample_report(
            "warn",
            10,
            vec![finding("TG-001", patchgate_core::Severity::Critical)],
        );
        assert_eq!(check_run_conclusion(&warn_critical), "action_required");

        let enforce_with_high = sample_report(
            "enforce",
            10,
            vec![finding("TG-002", patchgate_core::Severity::High)],
        );
        assert_eq!(check_run_conclusion(&enforce_with_high), "neutral");

        let enforce_with_medium = sample_report(
            "enforce",
            5,
            vec![finding("TG-003", patchgate_core::Severity::Medium)],
        );
        assert_eq!(check_run_conclusion(&enforce_with_medium), "success");
    }

    #[test]
    fn retry_retries_only_retryable_errors() {
        let counter = AtomicUsize::new(0);
        let policy = RetryPolicy {
            max_attempts: 3,
            backoff_base_ms: 0,
            backoff_max_ms: 0,
        };
        let result = with_retry(&policy, || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Err(PublishOpError::new("temporary", true, false))
            } else {
                Ok(42)
            }
        })
        .expect("must eventually succeed");

        assert_eq!(result, 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn retry_stops_on_non_retryable_error() {
        let counter = AtomicUsize::new(0);
        let policy = RetryPolicy {
            max_attempts: 5,
            backoff_base_ms: 0,
            backoff_max_ms: 0,
        };
        let err = with_retry(&policy, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Err::<(), PublishOpError>(PublishOpError::new("fatal", false, false))
        })
        .expect_err("must fail");

        assert!(err.message.contains("fatal"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backoff_is_capped() {
        let policy = RetryPolicy {
            max_attempts: 5,
            backoff_base_ms: 100,
            backoff_max_ms: 250,
        };
        assert_eq!(backoff_delay_ms(&policy, 0), 100);
        assert_eq!(backoff_delay_ms(&policy, 1), 200);
        assert_eq!(backoff_delay_ms(&policy, 2), 250);
    }

    #[test]
    fn comment_content_normalization_ignores_outer_whitespace() {
        assert!(is_same_comment_content(" abc\n", "abc"));
        assert!(!is_same_comment_content("abc", "abcd"));
    }

    #[test]
    fn priority_labels_match_review_priority() {
        assert_eq!(
            priority_label_name(ReviewPriority::P0),
            "patchgate:priority/p0"
        );
        assert_eq!(
            priority_label_name(ReviewPriority::P1),
            "patchgate:priority/p1"
        );
        assert_eq!(
            priority_label_name(ReviewPriority::P2),
            "patchgate:priority/p2"
        );
        assert_eq!(
            priority_label_name(ReviewPriority::P3),
            "patchgate:priority/p3"
        );
    }

    #[test]
    fn merge_priority_label_names_removes_stale_priority_labels() {
        let existing = vec![
            LabelItem {
                name: "bug".to_string(),
            },
            LabelItem {
                name: "patchgate:priority/p3".to_string(),
            },
            LabelItem {
                name: "patchgate:priority/p1".to_string(),
            },
            LabelItem {
                name: "needs-review".to_string(),
            },
        ];

        let merged = merge_priority_label_names(&existing, "patchgate:priority/p0");
        assert!(merged.iter().any(|name| name == "bug"));
        assert!(merged.iter().any(|name| name == "needs-review"));
        assert!(merged.iter().any(|name| name == "patchgate:priority/p0"));
        assert!(!merged.iter().any(|name| name == "patchgate:priority/p3"));
        assert!(!merged.iter().any(|name| name == "patchgate:priority/p1"));
    }

    #[test]
    fn check_run_update_fallback_is_only_for_permission_or_missing_run() {
        let fallback = PublishOpError::new("forbidden", false, false).with_status_code(403);
        assert!(is_check_run_update_fallback_candidate(&fallback));

        let missing = PublishOpError::new("missing", false, false).with_status_code(404);
        assert!(is_check_run_update_fallback_candidate(&missing));

        let conflict = PublishOpError::new("conflict", false, false).with_status_code(409);
        assert!(!is_check_run_update_fallback_candidate(&conflict));
    }

    #[test]
    fn comment_update_fallback_is_only_for_permission_or_missing_comment() {
        let fallback = PublishOpError::new("forbidden", false, false).with_status_code(403);
        assert!(is_comment_update_fallback_candidate(&fallback));

        let missing = PublishOpError::new("missing", false, false).with_status_code(404);
        assert!(is_comment_update_fallback_candidate(&missing));

        let conflict = PublishOpError::new("conflict", false, false).with_status_code(409);
        assert!(!is_comment_update_fallback_candidate(&conflict));
    }

    #[test]
    fn check_run_update_payload_omits_head_sha() {
        let create_payload = serde_json::json!({
            "name": "patchgate",
            "head_sha": "abc123",
            "status": "completed",
            "conclusion": "neutral",
        });

        let update_payload = check_run_update_payload(&create_payload);
        assert!(update_payload.get("head_sha").is_none());
        assert_eq!(
            update_payload
                .get("name")
                .and_then(serde_json::Value::as_str),
            Some("patchgate")
        );
    }
}
