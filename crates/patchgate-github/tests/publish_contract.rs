use patchgate_core::{CheckId, CheckScore, Finding, Report, ReportMeta, Severity};
use patchgate_github::{publish_report, PublishAuth, PublishRequest};

fn sample_report() -> Report {
    Report::new(
        vec![Finding {
            id: "TG-001".to_string(),
            rule_id: "TG-001".to_string(),
            category: "test_coverage".to_string(),
            docs_url: "https://example.com/rules/tg-001".to_string(),
            check: CheckId::TestGap,
            title: "No test changes detected".to_string(),
            message: "production files changed without tests".to_string(),
            severity: Severity::High,
            penalty: 10,
            location: None,
            tags: vec!["test-gap".to_string()],
        }],
        vec![CheckScore {
            check: CheckId::TestGap,
            label: "Test coverage gap".to_string(),
            penalty: 10,
            max_penalty: 35,
            triggered: true,
        }],
        ReportMeta {
            threshold: 70,
            mode: "warn".to_string(),
            scope: "worktree".to_string(),
            fingerprint: "fp".to_string(),
            duration_ms: 1,
            skipped_by_cache: false,
        },
    )
}

#[test]
fn publish_report_dry_run_exposes_payload() {
    let report = sample_report();
    let mut req = PublishRequest::new(
        "example/repo".to_string(),
        123,
        "deadbeef".to_string(),
        PublishAuth::Token {
            token: "dummy-token".to_string(),
        },
        "patchgate".to_string(),
    );
    req.dry_run = true;

    let result = publish_report(&report, "## patchgate report", &req).expect("dry-run publish");
    let payload = result.dry_run_payload.expect("dry-run payload must exist");

    assert_eq!(payload["repo"], "example/repo");
    assert_eq!(payload["pr_number"], 123);
    assert_eq!(payload["auth_mode"], "token");
    assert!(payload["check_run_payload"].is_object());
}

#[test]
fn publish_report_dry_run_preserves_suppressed_comment_reason() {
    let report = sample_report();
    let mut req = PublishRequest::new(
        "example/repo".to_string(),
        123,
        "deadbeef".to_string(),
        PublishAuth::Token {
            token: "dummy-token".to_string(),
        },
        "patchgate".to_string(),
    );
    req.dry_run = true;
    req.suppressed_comment_reason = Some("suppressed for test".to_string());

    let result = publish_report(&report, "## patchgate report", &req).expect("dry-run publish");
    assert!(result.skipped_comment);
    assert_eq!(
        result.skipped_comment_reason.as_deref(),
        Some("suppressed for test")
    );
}
