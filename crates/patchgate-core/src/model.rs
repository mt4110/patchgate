use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    TestGap,
    DangerousChange,
    DependencyUpdate,
}

impl CheckId {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckId::TestGap => "test_gap",
            CheckId::DangerousChange => "dangerous_change",
            CheckId::DependencyUpdate => "dependency_update",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CheckId::TestGap => "Test coverage gap",
            CheckId::DangerousChange => "Dangerous file changes",
            CheckId::DependencyUpdate => "Dependency update risk",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub docs_url: String,
    pub check: CheckId,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub penalty: u8,
    pub location: Option<Location>,
    pub tags: Vec<String>,
}

impl Finding {
    pub fn pr_template_hint(&self) -> String {
        format!(
            "- [ ] `{}` ({}) {}",
            self.rule_id, self.category, self.title
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckScore {
    pub check: CheckId,
    pub label: String,
    pub penalty: u8,
    pub max_penalty: u8,
    pub triggered: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPriority {
    P0,
    P1,
    P2,
    P3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub checks: Vec<CheckScore>,
    pub score: u8,
    pub threshold: u8,
    pub should_fail: bool,
    pub mode: String,
    pub scope: String,
    pub review_priority: ReviewPriority,
    pub fingerprint: String,
    pub duration_ms: u128,
    pub skipped_by_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMeta {
    pub threshold: u8,
    pub mode: String,
    pub scope: String,
    pub fingerprint: String,
    pub duration_ms: u128,
    pub skipped_by_cache: bool,
}

impl Report {
    pub fn new(findings: Vec<Finding>, checks: Vec<CheckScore>, meta: ReportMeta) -> Self {
        let total_penalty: u16 = checks.iter().map(|c| c.penalty as u16).sum();
        let capped_penalty = total_penalty.min(100) as u8;
        let score = 100u8.saturating_sub(capped_penalty);
        let should_fail = score < meta.threshold;
        let review_priority = review_priority_from_score(score);

        Self {
            findings,
            checks,
            score,
            threshold: meta.threshold,
            should_fail,
            mode: meta.mode,
            scope: meta.scope,
            review_priority,
            fingerprint: meta.fingerprint,
            duration_ms: meta.duration_ms,
            skipped_by_cache: meta.skipped_by_cache,
        }
    }
}

pub fn review_priority_from_score(score: u8) -> ReviewPriority {
    if score <= 40 {
        ReviewPriority::P0
    } else if score <= 65 {
        ReviewPriority::P1
    } else if score <= 85 {
        ReviewPriority::P2
    } else {
        ReviewPriority::P3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_check(check: CheckId, penalty: u8, max_penalty: u8) -> CheckScore {
        CheckScore {
            check,
            label: check.label().to_string(),
            penalty,
            max_penalty,
            triggered: penalty > 0,
        }
    }

    #[test]
    fn review_priority_boundaries_are_stable() {
        assert_eq!(review_priority_from_score(0), ReviewPriority::P0);
        assert_eq!(review_priority_from_score(40), ReviewPriority::P0);
        assert_eq!(review_priority_from_score(41), ReviewPriority::P1);
        assert_eq!(review_priority_from_score(65), ReviewPriority::P1);
        assert_eq!(review_priority_from_score(66), ReviewPriority::P2);
        assert_eq!(review_priority_from_score(85), ReviewPriority::P2);
        assert_eq!(review_priority_from_score(86), ReviewPriority::P3);
        assert_eq!(review_priority_from_score(100), ReviewPriority::P3);
    }

    #[test]
    fn report_score_is_capped_and_non_negative() {
        let report = Report::new(
            Vec::new(),
            vec![
                sample_check(CheckId::TestGap, 80, 80),
                sample_check(CheckId::DangerousChange, 70, 70),
            ],
            ReportMeta {
                threshold: 70,
                mode: "warn".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );

        assert_eq!(report.score, 0);
        assert_eq!(report.review_priority, ReviewPriority::P0);
    }

    #[test]
    fn threshold_failure_boundary_is_strictly_less_than() {
        let report_equal_threshold = Report::new(
            Vec::new(),
            vec![sample_check(CheckId::TestGap, 30, 35)],
            ReportMeta {
                threshold: 70,
                mode: "enforce".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );
        assert_eq!(report_equal_threshold.score, 70);
        assert!(!report_equal_threshold.should_fail);

        let report_below_threshold = Report::new(
            Vec::new(),
            vec![sample_check(CheckId::TestGap, 31, 35)],
            ReportMeta {
                threshold: 70,
                mode: "enforce".to_string(),
                scope: "staged".to_string(),
                fingerprint: "fp".to_string(),
                duration_ms: 1,
                skipped_by_cache: false,
            },
        );
        assert_eq!(report_below_threshold.score, 69);
        assert!(report_below_threshold.should_fail);
    }
}
