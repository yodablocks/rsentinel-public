//! Technology fingerprinting via HTTP response headers.
//!
//! DETECTION MODULE: Detects server and framework version disclosure in HTTP headers.

use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TechDetectError {
    #[error("curl not found - install curl to use this scanner")]
    NotInstalled,

    #[error("connection failed: {0}")]
    ConnectionFailed(String),
}

/// Technology fingerprint scan results.
#[derive(Debug, Clone)]
pub struct TechDetectResult {
    pub target: String,
    pub server: Option<String>,
    pub x_powered_by: Option<String>,
    pub x_generator: Option<String>,
    pub x_aspnet_version: Option<String>,
    pub x_aspnetmvc_version: Option<String>,
}

/// Technology fingerprinting scanner using curl subprocess.
pub struct TechDetectScanner {
    pub timeout: u32,
}

impl TechDetectScanner {
    pub fn new() -> Self {
        Self { timeout: 10 }
    }

    /// Fetch response headers and extract technology information.
    pub fn scan(&self, host: &str) -> Result<TechDetectResult, TechDetectError> {
        self.check_curl_installed()?;

        let url = if host.starts_with("http://") || host.starts_with("https://") {
            host.to_string()
        } else {
            format!("https://{}", host)
        };

        let output = Command::new("curl")
            .args(["-sI", "-m", &self.timeout.to_string(), &url])
            .output()
            .map_err(|e| TechDetectError::ConnectionFailed(e.to_string()))?;

        if !output.status.success() && output.stdout.is_empty() {
            return Err(TechDetectError::ConnectionFailed(format!(
                "curl exited with status {}",
                output.status
            )));
        }

        let raw_headers = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(parse_tech_headers(host, &raw_headers))
    }

    fn check_curl_installed(&self) -> Result<(), TechDetectError> {
        Command::new("curl")
            .arg("--version")
            .output()
            .map_err(|_| TechDetectError::NotInstalled)?;
        Ok(())
    }
}

impl Default for TechDetectScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse raw HTTP response headers into a TechDetectResult.
pub fn parse_tech_headers(host: &str, raw_headers: &str) -> TechDetectResult {
    let mut server = None;
    let mut x_powered_by = None;
    let mut x_generator = None;
    let mut x_aspnet_version = None;
    let mut x_aspnetmvc_version = None;

    for line in raw_headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            server = Some(line[line.find(':').unwrap() + 1..].trim().to_string());
        } else if lower.starts_with("x-powered-by:") {
            x_powered_by = Some(line[line.find(':').unwrap() + 1..].trim().to_string());
        } else if lower.starts_with("x-generator:") {
            x_generator = Some(line[line.find(':').unwrap() + 1..].trim().to_string());
        } else if lower.starts_with("x-aspnet-version:") {
            x_aspnet_version = Some(line[line.find(':').unwrap() + 1..].trim().to_string());
        } else if lower.starts_with("x-aspnetmvc-version:") {
            x_aspnetmvc_version = Some(line[line.find(':').unwrap() + 1..].trim().to_string());
        }
    }

    TechDetectResult {
        target: host.to_string(),
        server,
        x_powered_by,
        x_generator,
        x_aspnet_version,
        x_aspnetmvc_version,
    }
}

/// Returns true if the value looks like it contains a version number.
fn has_version(value: &str) -> bool {
    value.chars().any(|c| c.is_ascii_digit())
}

/// Generate security findings from technology fingerprint results.
pub fn generate_tech_findings(result: &TechDetectResult) -> Vec<crate::checker::Finding> {
    use crate::checker::Severity;

    let mut findings = Vec::new();
    let asset = result.target.clone();

    if let Some(ref server) = result.server {
        let severity = if has_version(server) {
            Severity::Medium
        } else {
            Severity::Low
        };
        findings.push(crate::checker::Finding {
            severity,
            title: format!("Server Header Disclosed: {}", server),
            description: format!(
                "Host {} discloses the Server header: {}. {}",
                asset,
                server,
                if has_version(server) {
                    "Version information helps attackers identify known vulnerabilities."
                } else {
                    "Server software is disclosed without version details."
                }
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Remove or minimize the Server header value\n\
                2. Configure the web server to suppress version information\n\
                3. Use a reverse proxy to strip server headers"
                .to_string(),
            references: vec![
                "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
            ],
        });
    }

    if let Some(ref powered_by) = result.x_powered_by {
        findings.push(crate::checker::Finding {
            severity: Severity::Medium,
            title: format!("X-Powered-By Header Disclosed: {}", powered_by),
            description: format!(
                "Host {} discloses the X-Powered-By header: {}. This reveals the backend technology stack.",
                asset, powered_by
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Remove the X-Powered-By header entirely\n\
                2. In Express.js: app.disable('x-powered-by')\n\
                3. In PHP: expose_php = Off in php.ini\n\
                4. Use a reverse proxy to strip the header"
                .to_string(),
            references: vec!["https://owasp.org/www-project-web-security-testing-guide/".to_string()],
        });
    }

    // Other tech headers — Low severity
    let other_headers: Vec<(&str, &Option<String>)> = vec![
        ("X-Generator", &result.x_generator),
        ("X-AspNet-Version", &result.x_aspnet_version),
        ("X-AspNetMvc-Version", &result.x_aspnetmvc_version),
    ];

    for (header_name, value) in other_headers {
        if let Some(val) = value {
            findings.push(crate::checker::Finding {
                severity: Severity::Low,
                title: format!("{} Header Disclosed: {}", header_name, val),
                description: format!(
                    "Host {} discloses the {} header: {}. This reveals technology details.",
                    asset, header_name, val
                ),
                affected_asset: asset.clone(),
                remediation: format!(
                    "HARDENING:\n\
                    1. Remove the {} header from responses\n\
                    2. Configure the application or reverse proxy to suppress technology headers",
                    header_name
                ),
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
    fn test_parse_server_with_version() {
        let raw = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.51\r\n\r\n";
        let result = parse_tech_headers("example.com", raw);
        assert_eq!(result.server.as_deref(), Some("Apache/2.4.51"));

        let findings = generate_tech_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("Apache/2.4.51"));
    }

    #[test]
    fn test_parse_server_without_version() {
        let raw = "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        let result = parse_tech_headers("example.com", raw);

        let findings = generate_tech_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_parse_x_powered_by() {
        let raw = "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1.2\r\n\r\n";
        let result = parse_tech_headers("example.com", raw);
        assert_eq!(result.x_powered_by.as_deref(), Some("PHP/8.1.2"));

        let findings = generate_tech_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_parse_multiple_tech_headers() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Server: Apache/2.4.51\r\n\
            X-Powered-By: PHP/8.1.2\r\n\
            X-Generator: WordPress 6.0\r\n\
            X-AspNet-Version: 4.0.30319\r\n\
            X-AspNetMvc-Version: 5.2\r\n\r\n";

        let result = parse_tech_headers("example.com", raw);
        assert!(result.server.is_some());
        assert!(result.x_powered_by.is_some());
        assert!(result.x_generator.is_some());
        assert!(result.x_aspnet_version.is_some());
        assert!(result.x_aspnetmvc_version.is_some());

        let findings = generate_tech_findings(&result);
        assert_eq!(findings.len(), 5);
        // Server(Medium) + X-Powered-By(Medium) + 3 Low
        let medium_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count();
        let low_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count();
        assert_eq!(medium_count, 2);
        assert_eq!(low_count, 3);
    }

    #[test]
    fn test_parse_no_tech_headers() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let result = parse_tech_headers("example.com", raw);
        assert!(result.server.is_none());
        assert!(result.x_powered_by.is_none());

        let findings = generate_tech_findings(&result);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_only_generator() {
        let raw = "HTTP/1.1 200 OK\r\nX-Generator: Drupal 9\r\n\r\n";
        let result = parse_tech_headers("example.com", raw);

        let findings = generate_tech_findings(&result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0].title.contains("X-Generator"));
    }
}
