//! Validation tests for exposure checker.
//!
//! VALIDATION MODULE: Tests that defenses work as intended.

use pretty_assertions::assert_eq;
use rsentinel::checker::exposure::{ReportSummary, compute_grade};
use rsentinel::checker::{ExposureReport, Finding, Severity};

/// Helper to create test reports
fn make_report(target: &str, findings: Vec<Finding>) -> ExposureReport {
    let summary = ReportSummary {
        total_findings: findings.len(),
        critical_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        high_count: findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        medium_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count(),
        low_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count(),
        info_count: findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count(),
    };

    let grade = compute_grade(&summary);
    ExposureReport {
        target: target.to_string(),
        scan_time: "2024-01-01T00:00:00Z".to_string(),
        findings,
        summary,
        grade,
    }
}

/// Helper to create test findings
fn make_finding(severity: Severity, title: &str) -> Finding {
    Finding {
        severity,
        title: title.to_string(),
        description: format!("Description for {}", title),
        affected_asset: "test-asset".to_string(),
        remediation: "Test remediation".to_string(),
        references: vec![],
    }
}

/// Test severity ordering is correct for prioritization.
#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

/// Test CVSS to severity mapping follows industry standards.
#[test]
fn test_cvss_severity_mapping() {
    // CVSS 3.0 severity ranges
    assert_eq!(Severity::from_cvss(10.0), Severity::Critical); // 9.0-10.0
    assert_eq!(Severity::from_cvss(9.0), Severity::Critical);
    assert_eq!(Severity::from_cvss(8.9), Severity::High); // 7.0-8.9
    assert_eq!(Severity::from_cvss(7.0), Severity::High);
    assert_eq!(Severity::from_cvss(6.9), Severity::Medium); // 4.0-6.9
    assert_eq!(Severity::from_cvss(4.0), Severity::Medium);
    assert_eq!(Severity::from_cvss(3.9), Severity::Low); // 0.1-3.9
    assert_eq!(Severity::from_cvss(0.1), Severity::Low);
    assert_eq!(Severity::from_cvss(0.0), Severity::Info); // 0.0 = Info
}

/// Test that report summary correctly counts findings by severity.
#[test]
fn test_report_summary_counts() {
    let findings = vec![
        make_finding(Severity::Critical, "Crit1"),
        make_finding(Severity::Critical, "Crit2"),
        make_finding(Severity::High, "High1"),
        make_finding(Severity::Medium, "Med1"),
        make_finding(Severity::Medium, "Med2"),
        make_finding(Severity::Medium, "Med3"),
        make_finding(Severity::Low, "Low1"),
        make_finding(Severity::Info, "Info1"),
    ];

    let report = make_report("test", findings);

    assert_eq!(report.summary.total_findings, 8);
    assert_eq!(report.summary.critical_count, 2);
    assert_eq!(report.summary.high_count, 1);
    assert_eq!(report.summary.medium_count, 3);
    assert_eq!(report.summary.low_count, 1);
    assert_eq!(report.summary.info_count, 1);
}

/// Test has_critical detection.
#[test]
fn test_has_critical_detection() {
    let with_critical = make_report(
        "test",
        vec![make_finding(Severity::Critical, "Critical Issue")],
    );
    assert!(with_critical.has_critical());

    let without_critical = make_report(
        "test",
        vec![
            make_finding(Severity::High, "High Issue"),
            make_finding(Severity::Medium, "Medium Issue"),
        ],
    );
    assert!(!without_critical.has_critical());
}

/// Test has_high_or_critical detection.
#[test]
fn test_has_high_or_critical_detection() {
    let with_high = make_report("test", vec![make_finding(Severity::High, "High Issue")]);
    assert!(with_high.has_high_or_critical());

    let with_critical = make_report(
        "test",
        vec![make_finding(Severity::Critical, "Critical Issue")],
    );
    assert!(with_critical.has_high_or_critical());

    let with_medium_only = make_report(
        "test",
        vec![
            make_finding(Severity::Medium, "Medium Issue"),
            make_finding(Severity::Low, "Low Issue"),
        ],
    );
    assert!(!with_medium_only.has_high_or_critical());
}

/// Test empty report handling.
#[test]
fn test_empty_report() {
    let report = make_report("test", vec![]);

    assert_eq!(report.summary.total_findings, 0);
    assert!(!report.has_critical());
    assert!(!report.has_high_or_critical());
}

/// Test finding serialization/deserialization.
#[test]
fn test_finding_serialization() {
    let finding = Finding {
        severity: Severity::High,
        title: "Test Finding".to_string(),
        description: "Test description".to_string(),
        affected_asset: "192.0.2.1:443".to_string(),
        remediation: "Fix it".to_string(),
        references: vec!["https://example.com".to_string()],
    };

    let json = serde_json::to_string(&finding).expect("serialize");
    let deserialized: Finding = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(deserialized.severity, Severity::High);
    assert_eq!(deserialized.title, "Test Finding");
    assert_eq!(deserialized.affected_asset, "192.0.2.1:443");
}

/// Test report JSON output for integration.
#[test]
fn test_report_json_output() {
    let report = make_report(
        "test-target",
        vec![make_finding(Severity::High, "Test Issue")],
    );

    let json = serde_json::to_string_pretty(&report).expect("serialize report");

    // Verify JSON contains expected fields
    assert!(json.contains("test-target"));
    assert!(json.contains("Test Issue"));
    assert!(json.contains("High"));
}
