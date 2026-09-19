//! HTTP security headers analysis using curl.
//!
//! DETECTION MODULE: Checks for missing or misconfigured HTTP security headers.

use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeadersError {
    #[error("curl not found - install curl to use this scanner")]
    NotInstalled,

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

}

/// Aggregated HTTP security headers scan results.
#[derive(Debug, Clone)]
pub struct HeadersScanResult {
    pub target: String,
    pub has_content_security_policy: bool,
    pub has_x_frame_options: bool,
    pub has_x_content_type_options: bool,
    pub has_referrer_policy: bool,
    pub has_permissions_policy: bool,
    pub cookies_without_secure: Vec<String>,
    pub cookies_without_httponly: Vec<String>,
    pub cookies_without_samesite: Vec<String>,
}

/// HTTP security headers scanner using curl subprocess.
pub struct HeadersScanner {
    pub timeout: u32,
}

impl HeadersScanner {
    pub fn new() -> Self {
        Self { timeout: 10 }
    }

    /// Run a full HTTP security headers check on the given host.
    pub fn scan(&self, host: &str) -> Result<HeadersScanResult, HeadersError> {
        self.check_curl_installed()?;

        let url = if host.starts_with("http://") || host.starts_with("https://") {
            host.to_string()
        } else {
            format!("https://{}", host)
        };

        let output = Command::new("curl")
            .args(["-sI", "-m", &self.timeout.to_string(), &url])
            .output()
            .map_err(|e| HeadersError::ConnectionFailed(e.to_string()))?;

        if !output.status.success() && output.stdout.is_empty() {
            return Err(HeadersError::ConnectionFailed(format!(
                "curl exited with status {}",
                output.status
            )));
        }

        let raw_headers = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(parse_headers(host, &raw_headers))
    }

    fn check_curl_installed(&self) -> Result<(), HeadersError> {
        Command::new("curl")
            .arg("--version")
            .output()
            .map_err(|_| HeadersError::NotInstalled)?;
        Ok(())
    }
}

impl Default for HeadersScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse raw HTTP response headers into a HeadersScanResult.
pub fn parse_headers(host: &str, raw_headers: &str) -> HeadersScanResult {
    let lower = raw_headers.to_lowercase();

    let has_content_security_policy = lower.contains("content-security-policy:");
    let has_x_frame_options = lower.contains("x-frame-options:");
    let has_x_content_type_options = lower.contains("x-content-type-options:");
    let has_referrer_policy = lower.contains("referrer-policy:");
    let has_permissions_policy = lower.contains("permissions-policy:");

    // Parse Set-Cookie headers for flag checks
    let mut cookies_without_secure = Vec::new();
    let mut cookies_without_httponly = Vec::new();
    let mut cookies_without_samesite = Vec::new();

    for line in raw_headers.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with("set-cookie:") {
            let cookie_value = line[line.find(':').unwrap() + 1..].trim().to_string();
            let cookie_name = cookie_value.split(';').next().unwrap_or("").split('=').next().unwrap_or("unknown").trim().to_string();

            if !line_lower.contains("secure") {
                cookies_without_secure.push(cookie_name.clone());
            }
            if !line_lower.contains("httponly") {
                cookies_without_httponly.push(cookie_name.clone());
            }
            if !line_lower.contains("samesite") {
                cookies_without_samesite.push(cookie_name.clone());
            }
        }
    }

    HeadersScanResult {
        target: host.to_string(),
        has_content_security_policy,
        has_x_frame_options,
        has_x_content_type_options,
        has_referrer_policy,
        has_permissions_policy,
        cookies_without_secure,
        cookies_without_httponly,
        cookies_without_samesite,
    }
}

/// Generate security findings from HTTP headers scan results.
pub fn generate_headers_findings(result: &HeadersScanResult) -> Vec<crate::checker::Finding> {
    use crate::checker::Severity;

    let mut findings = Vec::new();
    let asset = result.target.clone();

    if !result.has_content_security_policy {
        findings.push(crate::checker::Finding {
            severity: Severity::Medium,
            title: "Content-Security-Policy Header Missing".to_string(),
            description: format!(
                "No Content-Security-Policy header found on {}. This header helps prevent XSS and data injection attacks.",
                asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add a Content-Security-Policy header\n\
                2. Start with a restrictive policy and loosen as needed\n\
                3. Use report-uri or report-to for monitoring violations"
                .to_string(),
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy".to_string()],
        });
    }

    if !result.has_x_frame_options {
        findings.push(crate::checker::Finding {
            severity: Severity::Medium,
            title: "X-Frame-Options Header Missing".to_string(),
            description: format!(
                "No X-Frame-Options header found on {}. This header prevents clickjacking attacks.",
                asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add X-Frame-Options: DENY or SAMEORIGIN\n\
                2. Also consider using CSP frame-ancestors directive"
                .to_string(),
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options".to_string()],
        });
    }

    if !result.has_x_content_type_options {
        findings.push(crate::checker::Finding {
            severity: Severity::Low,
            title: "X-Content-Type-Options Header Missing".to_string(),
            description: format!(
                "No X-Content-Type-Options header found on {}. This header prevents MIME-type sniffing.",
                asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add X-Content-Type-Options: nosniff\n\
                2. Ensure Content-Type headers are set correctly on all responses"
                .to_string(),
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options".to_string()],
        });
    }

    if !result.has_referrer_policy {
        findings.push(crate::checker::Finding {
            severity: Severity::Low,
            title: "Referrer-Policy Header Missing".to_string(),
            description: format!(
                "No Referrer-Policy header found on {}. This header controls referrer information sent with requests.",
                asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add Referrer-Policy: strict-origin-when-cross-origin\n\
                2. Use no-referrer for maximum privacy"
                .to_string(),
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy".to_string()],
        });
    }

    if !result.has_permissions_policy {
        findings.push(crate::checker::Finding {
            severity: Severity::Low,
            title: "Permissions-Policy Header Missing".to_string(),
            description: format!(
                "No Permissions-Policy header found on {}. This header controls browser feature access.",
                asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add Permissions-Policy header to restrict browser features\n\
                2. Disable unnecessary features like camera, microphone, geolocation"
                .to_string(),
            references: vec!["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy".to_string()],
        });
    }

    // Cookie findings
    for cookie in &result.cookies_without_secure {
        findings.push(crate::checker::Finding {
            severity: Severity::Medium,
            title: format!("Cookie Missing Secure Flag: {}", cookie),
            description: format!(
                "Cookie '{}' on {} does not have the Secure flag set. It may be sent over unencrypted connections.",
                cookie, asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add the Secure flag to this cookie\n\
                2. Ensure the cookie is only sent over HTTPS"
                .to_string(),
            references: vec![],
        });
    }

    for cookie in &result.cookies_without_httponly {
        findings.push(crate::checker::Finding {
            severity: Severity::Medium,
            title: format!("Cookie Missing HttpOnly Flag: {}", cookie),
            description: format!(
                "Cookie '{}' on {} does not have the HttpOnly flag set. It can be accessed by JavaScript.",
                cookie, asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add the HttpOnly flag to this cookie\n\
                2. This prevents client-side scripts from accessing the cookie"
                .to_string(),
            references: vec![],
        });
    }

    for cookie in &result.cookies_without_samesite {
        findings.push(crate::checker::Finding {
            severity: Severity::Low,
            title: format!("Cookie Missing SameSite Flag: {}", cookie),
            description: format!(
                "Cookie '{}' on {} does not have the SameSite attribute set. It may be vulnerable to CSRF attacks.",
                cookie, asset
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add SameSite=Lax or SameSite=Strict to this cookie\n\
                2. This helps prevent cross-site request forgery"
                .to_string(),
            references: vec![],
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_headers_all_present() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Content-Security-Policy: default-src 'self'\r\n\
            X-Frame-Options: DENY\r\n\
            X-Content-Type-Options: nosniff\r\n\
            Referrer-Policy: strict-origin-when-cross-origin\r\n\
            Permissions-Policy: geolocation=()\r\n\r\n";

        let result = parse_headers("example.com", raw);
        assert!(result.has_content_security_policy);
        assert!(result.has_x_frame_options);
        assert!(result.has_x_content_type_options);
        assert!(result.has_referrer_policy);
        assert!(result.has_permissions_policy);
    }

    #[test]
    fn test_parse_headers_none_present() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

        let result = parse_headers("example.com", raw);
        assert!(!result.has_content_security_policy);
        assert!(!result.has_x_frame_options);
        assert!(!result.has_x_content_type_options);
        assert!(!result.has_referrer_policy);
        assert!(!result.has_permissions_policy);
    }

    #[test]
    fn test_parse_headers_cookies_flags() {
        let raw = "HTTP/1.1 200 OK\r\n\
            Set-Cookie: session=abc123; Path=/\r\n\
            Set-Cookie: safe=xyz; Secure; HttpOnly; SameSite=Strict\r\n\r\n";

        let result = parse_headers("example.com", raw);
        assert_eq!(result.cookies_without_secure, vec!["session"]);
        assert_eq!(result.cookies_without_httponly, vec!["session"]);
        assert_eq!(result.cookies_without_samesite, vec!["session"]);
    }

    #[test]
    fn test_parse_headers_no_cookies() {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";

        let result = parse_headers("example.com", raw);
        assert!(result.cookies_without_secure.is_empty());
        assert!(result.cookies_without_httponly.is_empty());
        assert!(result.cookies_without_samesite.is_empty());
    }

    #[test]
    fn test_generate_findings_all_missing() {
        let result = HeadersScanResult {
            target: "example.com".to_string(),
            has_content_security_policy: false,
            has_x_frame_options: false,
            has_x_content_type_options: false,
            has_referrer_policy: false,
            has_permissions_policy: false,
            cookies_without_secure: vec![],
            cookies_without_httponly: vec![],
            cookies_without_samesite: vec![],

        };

        let findings = generate_headers_findings(&result);
        assert_eq!(findings.len(), 5);
        assert!(findings.iter().any(|f| f.title.contains("Content-Security-Policy")));
        assert!(findings.iter().any(|f| f.title.contains("X-Frame-Options")));
        assert!(findings.iter().any(|f| f.title.contains("X-Content-Type-Options")));
        assert!(findings.iter().any(|f| f.title.contains("Referrer-Policy")));
        assert!(findings.iter().any(|f| f.title.contains("Permissions-Policy")));
    }

    #[test]
    fn test_generate_findings_all_present() {
        let result = HeadersScanResult {
            target: "example.com".to_string(),
            has_content_security_policy: true,
            has_x_frame_options: true,
            has_x_content_type_options: true,
            has_referrer_policy: true,
            has_permissions_policy: true,
            cookies_without_secure: vec![],
            cookies_without_httponly: vec![],
            cookies_without_samesite: vec![],

        };

        let findings = generate_headers_findings(&result);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_generate_findings_cookie_flags() {
        let result = HeadersScanResult {
            target: "example.com".to_string(),
            has_content_security_policy: true,
            has_x_frame_options: true,
            has_x_content_type_options: true,
            has_referrer_policy: true,
            has_permissions_policy: true,
            cookies_without_secure: vec!["session".to_string()],
            cookies_without_httponly: vec!["session".to_string()],
            cookies_without_samesite: vec!["session".to_string()],

        };

        let findings = generate_headers_findings(&result);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().any(|f| f.title.contains("Secure Flag")));
        assert!(findings.iter().any(|f| f.title.contains("HttpOnly Flag")));
        assert!(findings.iter().any(|f| f.title.contains("SameSite Flag")));
    }

    #[test]
    fn test_generate_findings_severities() {
        use crate::checker::Severity;

        let result = HeadersScanResult {
            target: "example.com".to_string(),
            has_content_security_policy: false,
            has_x_frame_options: false,
            has_x_content_type_options: false,
            has_referrer_policy: false,
            has_permissions_policy: false,
            cookies_without_secure: vec!["s".to_string()],
            cookies_without_httponly: vec!["s".to_string()],
            cookies_without_samesite: vec!["s".to_string()],

        };

        let findings = generate_headers_findings(&result);
        let medium_count = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low_count = findings.iter().filter(|f| f.severity == Severity::Low).count();
        // CSP, X-Frame-Options, Secure cookie, HttpOnly cookie = 4 medium
        assert_eq!(medium_count, 4);
        // X-Content-Type-Options, Referrer-Policy, Permissions-Policy, SameSite cookie = 4 low
        assert_eq!(low_count, 4);
    }
}
