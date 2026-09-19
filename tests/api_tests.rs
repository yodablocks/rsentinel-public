//! API client validation tests.
//!
//! VALIDATION MODULE: Tests rate limiting and API response handling.

use rsentinel::api::{RateLimiter, CveDbClient};
use rsentinel::api::cvedb::CveInfo;

/// Test rate limiter allows initial request.
#[test]
fn test_rate_limiter_initial_allow() {
    let limiter = RateLimiter::new(10);
    assert!(limiter.try_acquire(), "First request should be allowed");
}

/// Test rate limiter with custom rate.
#[test]
fn test_rate_limiter_custom_rate() {
    let limiter = RateLimiter::new(5);
    // First few should succeed
    for _ in 0..5 {
        assert!(limiter.try_acquire());
    }
}

/// Test default rate limiter configuration.
#[test]
fn test_rate_limiter_default() {
    let limiter = RateLimiter::default();
    assert!(limiter.try_acquire());
}

/// Test CVE severity filtering - high severity.
#[test]
fn test_cve_filter_high_severity() {
    let cves = vec![
        make_cve("CVE-2024-0001", 9.8),  // Critical
        make_cve("CVE-2024-0002", 7.5),  // High
        make_cve("CVE-2024-0003", 4.0),  // Medium
        make_cve("CVE-2024-0004", 2.0),  // Low
    ];

    let high_sev = CveDbClient::filter_high_severity(&cves);

    assert_eq!(high_sev.len(), 2);
    assert!(high_sev.iter().any(|c| c.cve_id == "CVE-2024-0001"));
    assert!(high_sev.iter().any(|c| c.cve_id == "CVE-2024-0002"));
}

/// Test CVE severity filtering - critical only.
#[test]
fn test_cve_filter_critical() {
    let cves = vec![
        make_cve("CVE-2024-0001", 9.8),  // Critical
        make_cve("CVE-2024-0002", 8.9),  // High (not critical)
        make_cve("CVE-2024-0003", 9.0),  // Critical (boundary)
    ];

    let critical = CveDbClient::filter_critical(&cves);

    assert_eq!(critical.len(), 2);
    assert!(critical.iter().any(|c| c.cve_id == "CVE-2024-0001"));
    assert!(critical.iter().any(|c| c.cve_id == "CVE-2024-0003"));
}

/// Test CVE EPSS filtering.
#[test]
fn test_cve_filter_high_epss() {
    let cves = vec![
        make_cve_with_epss("CVE-2024-0001", 5.0, 0.95),  // High EPSS
        make_cve_with_epss("CVE-2024-0002", 9.0, 0.10),  // Low EPSS
        make_cve_with_epss("CVE-2024-0003", 7.0, 0.80),  // Medium-High EPSS
    ];

    let high_epss = CveDbClient::filter_high_epss(&cves, 0.7);

    assert_eq!(high_epss.len(), 2);
    assert!(high_epss.iter().any(|c| c.cve_id == "CVE-2024-0001"));
    assert!(high_epss.iter().any(|c| c.cve_id == "CVE-2024-0003"));
}

/// Test empty CVE list handling.
#[test]
fn test_cve_filter_empty() {
    let cves: Vec<CveInfo> = vec![];

    assert!(CveDbClient::filter_high_severity(&cves).is_empty());
    assert!(CveDbClient::filter_critical(&cves).is_empty());
    assert!(CveDbClient::filter_high_epss(&cves, 0.5).is_empty());
}

/// Test CVE with missing CVSS (should be treated as 0.0).
#[test]
fn test_cve_missing_cvss() {
    let cves = vec![
        CveInfo {
            cve_id: "CVE-2024-0001".to_string(),
            summary: None,
            cvss: None,  // Missing CVSS
            cvss_version: None,
            references: vec![],
            published_time: None,
            last_modified_time: None,
            epss: None,
            cpes: vec![],
        },
    ];

    // Should not appear in high severity (treated as 0.0)
    assert!(CveDbClient::filter_high_severity(&cves).is_empty());
}

// Helper to create test CVE data
fn make_cve(id: &str, cvss: f32) -> CveInfo {
    CveInfo {
        cve_id: id.to_string(),
        summary: Some(format!("Test CVE {}", id)),
        cvss: Some(cvss),
        cvss_version: Some("3.1".to_string()),
        references: vec![],
        published_time: None,
        last_modified_time: None,
        epss: None,
        cpes: vec![],
    }
}

fn make_cve_with_epss(id: &str, cvss: f32, epss: f32) -> CveInfo {
    CveInfo {
        cve_id: id.to_string(),
        summary: Some(format!("Test CVE {}", id)),
        cvss: Some(cvss),
        cvss_version: Some("3.1".to_string()),
        references: vec![],
        published_time: None,
        last_modified_time: None,
        epss: Some(epss),
        cpes: vec![],
    }
}
