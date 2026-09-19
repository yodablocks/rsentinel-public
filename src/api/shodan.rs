//! Shodan API client for detecting exposed services.
//!
//! DETECTION MODULE: Identifies exposed AI/agent infrastructure endpoints.

use crate::api::RateLimiter;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SHODAN_API_BASE: &str = "https://api.shodan.io";

#[derive(Error, Debug)]
pub enum ShodanError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("API key invalid or missing")]
    InvalidApiKey,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("API error: {0}")]
    ApiError(String),
}

/// Shodan host information response.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HostInfo {
    pub ip_str: String,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub vulns: Vec<String>,
    #[serde(default)]
    pub data: Vec<ServiceBanner>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub country_code: Option<String>,
    pub last_update: Option<String>,
}

/// Service banner data from Shodan.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServiceBanner {
    pub port: u16,
    pub transport: String,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub http: Option<HttpInfo>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct HttpInfo {
    pub status: Option<u16>,
    pub title: Option<String>,
    pub server: Option<String>,
}

/// Search results from Shodan.
#[derive(Debug, Deserialize)]
pub struct SearchResult {
    pub matches: Vec<SearchMatch>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SearchMatch {
    pub ip_str: String,
    pub port: u16,
    #[serde(default)]
    pub hostnames: Vec<String>,
    pub org: Option<String>,
}

/// Client for interacting with Shodan API.
pub struct ShodanClient {
    client: Client,
    api_key: String,
    rate_limiter: RateLimiter,
}

impl ShodanClient {
    /// Create a new Shodan client with the given API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            api_key: api_key.into(),
            rate_limiter: RateLimiter::default(),
        }
    }

    /// Get information about a specific IP address.
    pub async fn host_info(&self, ip: &str) -> Result<HostInfo, ShodanError> {
        self.rate_limiter.acquire().await;

        let url = format!("{}/shodan/host/{}", SHODAN_API_BASE, ip);
        let response = self
            .client
            .get(&url)
            .query(&[("key", &self.api_key)])
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Search Shodan for exposed services matching a query.
    ///
    /// Example queries for AI infrastructure detection:
    /// - `"claude" port:443`
    /// - `"anthropic" http.title`
    /// - `product:"nginx" "api" port:8080`
    pub async fn search(&self, query: &str) -> Result<SearchResult, ShodanError> {
        self.rate_limiter.acquire().await;

        let url = format!("{}/shodan/host/search", SHODAN_API_BASE);
        let response = self
            .client
            .get(&url)
            .query(&[("key", &self.api_key), ("query", &query.to_string())])
            .send()
            .await?;

        self.handle_response(response).await
    }

    /// Search for potentially exposed AI/agent endpoints.
    pub async fn search_ai_endpoints(&self) -> Result<Vec<SearchMatch>, ShodanError> {
        let queries = [
            r#"http.title:"claude" port:443,8080,8443"#,
            r#"http.title:"anthropic" port:443"#,
            r#""x-anthropic" port:443"#,
            r#"http.html:"ai-agent" port:443,8080"#,
        ];

        let mut all_matches = Vec::new();

        for query in queries {
            match self.search(query).await {
                Ok(result) => all_matches.extend(result.matches),
                Err(ShodanError::RateLimitExceeded) => {
                    tracing::warn!("Rate limit hit during AI endpoint search");
                    break;
                }
                Err(e) => tracing::debug!("Query failed: {}", e),
            }
        }

        Ok(all_matches)
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ShodanError> {
        match response.status().as_u16() {
            200 => Ok(response.json().await?),
            401 => Err(ShodanError::InvalidApiKey),
            429 => Err(ShodanError::RateLimitExceeded),
            _ => {
                let error_text = response.text().await.unwrap_or_default();
                Err(ShodanError::ApiError(error_text))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ShodanClient::new("test_api_key");
        assert!(!client.api_key.is_empty());
    }

    #[test]
    fn test_deserialize_host_info() {
        let json = r#"{
            "ip_str": "1.2.3.4",
            "ports": [80, 443],
            "hostnames": ["example.com"],
            "vulns": ["CVE-2021-1234"],
            "data": [],
            "org": "Test Org"
        }"#;

        let host: HostInfo = serde_json::from_str(json).unwrap();
        assert_eq!(host.ip_str, "1.2.3.4");
        assert_eq!(host.ports, vec![80, 443]);
        assert_eq!(host.vulns, vec!["CVE-2021-1234"]);
    }
}
