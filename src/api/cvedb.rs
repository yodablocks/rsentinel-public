//! CVE Database client for vulnerability lookups.
//!
//! DETECTION MODULE: Identifies known vulnerabilities affecting infrastructure.

use crate::api::RateLimiter;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const CVEDB_API_BASE: &str = "https://cvedb.shodan.io";

#[derive(Error, Debug)]
pub enum CveDbError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("CVE not found: {0}")]
    NotFound(String),

    #[error("API error: {0}")]
    ApiError(String),
}

/// CVE information from the database.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CveInfo {
    pub cve_id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub cvss: Option<f32>,
    #[serde(default)]
    pub cvss_version: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub published_time: Option<String>,
    #[serde(default)]
    pub last_modified_time: Option<String>,
    #[serde(default)]
    pub epss: Option<f32>,
    #[serde(default)]
    pub cpes: Vec<String>,
}

/// Client for CVE database lookups.
pub struct CveDbClient {
    client: Client,
    rate_limiter: RateLimiter,
}

impl CveDbClient {
    /// Create a new CVE database client.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            rate_limiter: RateLimiter::new(2), // 2 requests/sec for CVEDB
        }
    }

    /// Look up a specific CVE by ID.
    pub async fn lookup_cve(&self, cve_id: &str) -> Result<CveInfo, CveDbError> {
        self.rate_limiter.acquire().await;

        let url = format!("{}/cve/{}", CVEDB_API_BASE, cve_id);
        let response = self.client.get(&url).send().await?;

        match response.status().as_u16() {
            200 => Ok(response.json().await?),
            404 => Err(CveDbError::NotFound(cve_id.to_string())),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(CveDbError::ApiError(error_text))
            }
        }
    }

    /// Look up multiple CVEs and return found ones.
    pub async fn lookup_cves(&self, cve_ids: &[String]) -> Vec<CveInfo> {
        let mut results = Vec::new();

        for cve_id in cve_ids {
            match self.lookup_cve(cve_id).await {
                Ok(info) => results.push(info),
                Err(e) => tracing::debug!("CVE lookup failed for {}: {}", cve_id, e),
            }
        }

        results
    }

    /// Check if any CVEs have high severity (CVSS >= 7.0).
    #[allow(dead_code)]
        pub fn filter_high_severity(cves: &[CveInfo]) -> Vec<&CveInfo> {
        cves.iter()
            .filter(|cve| cve.cvss.unwrap_or(0.0) >= 7.0)
            .collect()
    }

    /// Check if any CVEs have critical severity (CVSS >= 9.0).
    #[allow(dead_code)]
        pub fn filter_critical(cves: &[CveInfo]) -> Vec<&CveInfo> {
        cves.iter()
            .filter(|cve| cve.cvss.unwrap_or(0.0) >= 9.0)
            .collect()
    }

    /// Get EPSS (Exploit Prediction Scoring System) high-risk CVEs.
    #[allow(dead_code)]
        pub fn filter_high_epss(cves: &[CveInfo], threshold: f32) -> Vec<&CveInfo> {
        cves.iter()
            .filter(|cve| cve.epss.unwrap_or(0.0) >= threshold)
            .collect()
    }
}

impl Default for CveDbClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let _client = CveDbClient::new();
    }

    #[test]
    fn test_filter_high_severity() {
        let cves = vec![
            CveInfo {
                cve_id: "CVE-2021-1234".to_string(),
                summary: None,
                cvss: Some(9.8),
                cvss_version: None,
                references: vec![],
                published_time: None,
                last_modified_time: None,
                epss: None,
                cpes: vec![],
            },
            CveInfo {
                cve_id: "CVE-2021-5678".to_string(),
                summary: None,
                cvss: Some(4.0),
                cvss_version: None,
                references: vec![],
                published_time: None,
                last_modified_time: None,
                epss: None,
                cpes: vec![],
            },
        ];

        let high_sev = CveDbClient::filter_high_severity(&cves);
        assert_eq!(high_sev.len(), 1);
        assert_eq!(high_sev[0].cve_id, "CVE-2021-1234");
    }

    #[test]
    fn test_filter_critical() {
        let cves = vec![
            CveInfo {
                cve_id: "CVE-2021-CRIT".to_string(),
                summary: None,
                cvss: Some(9.5),
                cvss_version: None,
                references: vec![],
                published_time: None,
                last_modified_time: None,
                epss: None,
                cpes: vec![],
            },
        ];

        let critical = CveDbClient::filter_critical(&cves);
        assert_eq!(critical.len(), 1);
    }
}
