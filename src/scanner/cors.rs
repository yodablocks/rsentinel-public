//! CORS misconfiguration detection using curl.
//!
//! DETECTION MODULE: Checks for permissive CORS policies that could allow cross-origin attacks.

use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CorsError {
    #[error("curl not found - install curl to use this scanner")]
    NotInstalled,

    #[error("connection failed: {0}")]
    ConnectionFailed(String),
}

/// CORS scan results.
#[derive(Debug, Clone)]
pub struct CorsScanResult {
    pub target: String,
    /// The value of Access-Control-Allow-Origin, if present.
    pub allow_origin: Option<String>,
    /// Whether Access-Control-Allow-Credentials is true.
    pub allow_credentials: bool,
}

/// CORS misconfiguration scanner using curl subprocess.
pub struct CorsScanner {
    pub timeout: u32,
}

impl CorsScanner {
    pub fn new() -> Self {
        Self { timeout: 10 }
    }

    /// Send a request with a crafted Origin header and inspect CORS response headers.
    pub fn scan(&self, host: &str) -> Result<CorsScanResult, CorsError> {
        self.check_curl_installed()?;

        let url = if host.starts_with("http://") || host.starts_with("https://") {
            host.to_string()
        } else {
            format!("https://{}", host)
        };

        let output = Command::new("curl")
            .args([
                "-sI",
                "-H",
                "Origin: https://evil.com",
                "-m",
                &self.timeout.to_string(),
                &url,
            ])
            .output()
            .map_err(|e| CorsError::ConnectionFailed(e.to_string()))?;

        if !output.status.success() && output.stdout.is_empty() {
            return Err(CorsError::ConnectionFailed(format!(
                "curl exited with status {}",
                output.status
            )));
        }

        let raw_headers = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(parse_cors_headers(host, &raw_headers))
    }

    fn check_curl_installed(&self) -> Result<(), CorsError> {
        Command::new("curl")
            .arg("--version")
            .output()
            .map_err(|_| CorsError::NotInstalled)?;
        Ok(())
    }
}

impl Default for CorsScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse raw HTTP response headers into a CorsScanResult.
pub fn parse_cors_headers(host: &str, raw_headers: &str) -> CorsScanResult {
    let mut allow_origin: Option<String> = None;
    let mut allow_credentials = false;

    for line in raw_headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("access-control-allow-origin:") {
            let value = line[line.find(':').unwrap() + 1..].trim().to_string();
            allow_origin = Some(value);
        } else if lower.starts_with("access-control-allow-credentials:") {
            let value = line[line.find(':').unwrap() + 1..].trim().to_lowercase();
            allow_credentials = value == "true";
        }
    }

    CorsScanResult {
        target: host.to_string(),
        allow_origin,
        allow_credentials,
    }
}

/// Generate security findings from CORS scan results.
pub fn generate_cors_findings(result: &CorsScanResult) -> Vec<crate::checker::Finding> {
    use crate::checker::Severity;

    let mut findings = Vec::new();
    let asset = result.target.clone();

    match &result.allow_origin {
        Some(origin) if origin == "*" && result.allow_credentials => {
            findings.push(crate::checker::Finding {
                severity: Severity::High,
                title: "CORS Wildcard with Credentials Allowed".to_string(),
                description: format!(
                    "Host {} returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. \
                     Browsers will reject this combination, but it indicates a dangerous misconfiguration.",
                    asset
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. Never combine wildcard origin with credentials\n\
                    2. Use an explicit allowlist of trusted origins\n\
                    3. Validate the Origin header server-side"
                    .to_string(),
                references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS".to_string()],
            });
        }
        Some(origin) if origin == "*" => {
            findings.push(crate::checker::Finding {
                severity: Severity::Medium,
                title: "CORS Wildcard Origin Allowed".to_string(),
                description: format!(
                    "Host {} returns Access-Control-Allow-Origin: *. Any website can make cross-origin requests.",
                    asset
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. Replace wildcard with an explicit allowlist of trusted origins\n\
                    2. If public API, ensure no sensitive data is exposed without authentication"
                    .to_string(),
                references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS".to_string()],
            });
        }
        Some(origin) if origin.contains("evil.com") && result.allow_credentials => {
            findings.push(crate::checker::Finding {
                severity: Severity::Critical,
                title: "CORS Origin Reflected with Credentials".to_string(),
                description: format!(
                    "Host {} reflects the attacker-controlled Origin header and allows credentials. \
                     An attacker can steal authenticated data via a malicious website.",
                    asset
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. IMMEDIATELY fix CORS configuration\n\
                    2. Validate Origin against a strict allowlist\n\
                    3. Never reflect arbitrary origins with credentials\n\
                    4. Audit for data exfiltration"
                    .to_string(),
                references: vec![
                    "https://portswigger.net/web-security/cors".to_string(),
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS".to_string(),
                ],
            });
        }
        Some(origin) if origin.contains("evil.com") => {
            findings.push(crate::checker::Finding {
                severity: Severity::Medium,
                title: "CORS Origin Reflected".to_string(),
                description: format!(
                    "Host {} reflects the attacker-controlled Origin header in Access-Control-Allow-Origin. \
                     Without credentials this is lower risk, but indicates a misconfigured CORS policy.",
                    asset
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. Validate Origin against a strict allowlist\n\
                    2. Do not blindly reflect the Origin header\n\
                    3. Return a fixed origin or omit the header for untrusted origins"
                    .to_string(),
                references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS".to_string()],
            });
        }
        _ => {
            findings.push(crate::checker::Finding {
                severity: Severity::Info,
                title: "CORS Policy Properly Configured or Absent".to_string(),
                description: format!(
                    "Host {} does not reflect arbitrary origins. CORS policy appears properly configured or is not set.",
                    asset
                ),
                affected_asset: asset.clone(),
                remediation: "INFO:\n\
                    No action needed. Continue to validate CORS configuration as part of regular security reviews."
                    .to_string(),
                references: vec![],
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::Severity;

    #[test]
    fn test_parse_cors_origin_reflected_with_credentials() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Access-Control-Allow-Origin: https://evil.com\r\n\
            Access-Control-Allow-Credentials: true\r\n\r\n";

        let result = parse_cors_headers("example.com", raw);
        assert_eq!(result.allow_origin.as_deref(), Some("https://evil.com"));
        assert!(result.allow_credentials);

        let findings = generate_cors_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(
            findings[0]
                .title
                .contains("Origin Reflected with Credentials")
        );
    }

    #[test]
    fn test_parse_cors_wildcard_with_credentials() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Credentials: true\r\n\r\n";

        let result = parse_cors_headers("example.com", raw);
        assert_eq!(result.allow_origin.as_deref(), Some("*"));
        assert!(result.allow_credentials);

        let findings = generate_cors_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_parse_cors_origin_reflected_no_credentials() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Access-Control-Allow-Origin: https://evil.com\r\n\r\n";

        let result = parse_cors_headers("example.com", raw);
        assert_eq!(result.allow_origin.as_deref(), Some("https://evil.com"));
        assert!(!result.allow_credentials);

        let findings = generate_cors_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("Origin Reflected"));
    }

    #[test]
    fn test_parse_cors_wildcard_no_credentials() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Access-Control-Allow-Origin: *\r\n\r\n";

        let result = parse_cors_headers("example.com", raw);
        let findings = generate_cors_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("Wildcard"));
    }

    #[test]
    fn test_parse_cors_absent() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

        let result = parse_cors_headers("example.com", raw);
        assert!(result.allow_origin.is_none());
        assert!(!result.allow_credentials);

        let findings = generate_cors_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_parse_cors_specific_origin() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Access-Control-Allow-Origin: https://trusted.com\r\n\r\n";

        let result = parse_cors_headers("example.com", raw);
        assert_eq!(result.allow_origin.as_deref(), Some("https://trusted.com"));

        let findings = generate_cors_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
