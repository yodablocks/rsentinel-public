//! Sensitive path exposure detection using curl.
//!
//! DETECTION MODULE: Probes common sensitive paths for accessibility.

use std::collections::HashMap;
use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PathsError {
    #[error("curl not found - install curl to use this scanner")]
    NotInstalled,

    #[error("connection failed: {0}")]
    ConnectionFailed(String),
}

/// A single path probe result.
#[derive(Debug, Clone)]
pub struct PathProbe {
    pub path: String,
    pub status_code: u16,
}

/// Sensitive path scan results.
#[derive(Debug, Clone)]
pub struct PathsScanResult {
    pub target: String,
    pub probes: Vec<PathProbe>,
}

/// Sensitive path exposure scanner using curl subprocess.
pub struct PathsScanner {
    pub timeout: u32,
}

/// The list of sensitive paths to probe.
pub const SENSITIVE_PATHS: &[&str] = &[
    ".env",
    ".git/config",
    ".git/HEAD",
    ".DS_Store",
    "wp-login.php",
    "admin/",
    "phpmyadmin/",
    "server-status",
    ".htaccess",
    ".well-known/security.txt",
    "robots.txt",
    "backup.sql",
    ".aws/credentials",
];

impl PathsScanner {
    pub fn new() -> Self {
        Self { timeout: 10 }
    }

    /// Probe all sensitive paths on the given host.
    pub fn scan(&self, host: &str) -> Result<PathsScanResult, PathsError> {
        self.check_curl_installed()?;

        let base_url = if host.starts_with("http://") || host.starts_with("https://") {
            host.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", host.trim_end_matches('/'))
        };

        let mut probes = Vec::new();
        for path in SENSITIVE_PATHS {
            let url = format!("{}/{}", base_url, path);
            let output = Command::new("curl")
                .args([
                    "-sI", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    "-m", &self.timeout.to_string(),
                    &url,
                ])
                .output()
                .map_err(|e| PathsError::ConnectionFailed(e.to_string()))?;

            let code_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let status_code = code_str.parse::<u16>().unwrap_or(0);

            probes.push(PathProbe {
                path: path.to_string(),
                status_code,
            });
        }

        Ok(PathsScanResult {
            target: host.to_string(),
            probes,
        })
    }

    fn check_curl_installed(&self) -> Result<(), PathsError> {
        Command::new("curl")
            .arg("--version")
            .output()
            .map_err(|_| PathsError::NotInstalled)?;
        Ok(())
    }
}

impl Default for PathsScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate findings from a PathsScanResult. Also usable with mock data via `generate_paths_findings_from_map`.
pub fn generate_paths_findings(result: &PathsScanResult) -> Vec<crate::checker::Finding> {
    let map: HashMap<String, u16> = result
        .probes
        .iter()
        .map(|p| (p.path.clone(), p.status_code))
        .collect();
    generate_paths_findings_from_map(&result.target, &map)
}

/// Core finding generation from a path->status_code map (testable without curl).
pub fn generate_paths_findings_from_map(
    target: &str,
    statuses: &HashMap<String, u16>,
) -> Vec<crate::checker::Finding> {
    use crate::checker::Severity;

    let mut findings = Vec::new();
    let asset = target.to_string();

    // Critical credential / config files
    let critical_paths = [".env", ".git/config", ".aws/credentials", "backup.sql"];
    // Admin panels
    let admin_paths = ["wp-login.php", "admin/", "phpmyadmin/"];
    // Informational good-practice paths
    let info_good_paths = [".well-known/security.txt"];

    for (path, &code) in statuses {
        if code == 200 && critical_paths.contains(&path.as_str()) {
            findings.push(crate::checker::Finding {
                severity: Severity::Critical,
                title: format!("Sensitive File Accessible: {}", path),
                description: format!(
                    "The file /{} on {} returned HTTP 200. This file likely contains credentials or sensitive configuration.",
                    path, asset
                ),
                affected_asset: format!("{}/{}", asset, path),
                remediation: "HARDENING:\n\
                    1. IMMEDIATELY block public access to this file\n\
                    2. Add server rules to deny access (e.g., .htaccess, nginx location block)\n\
                    3. Rotate any credentials that may have been exposed\n\
                    4. Remove the file from the web root if not needed"
                    .to_string(),
                references: vec!["https://owasp.org/www-project-web-security-testing-guide/".to_string()],
            });
        } else if code == 200 && admin_paths.contains(&path.as_str()) {
            findings.push(crate::checker::Finding {
                severity: Severity::High,
                title: format!("Admin Panel Accessible: {}", path),
                description: format!(
                    "The path /{} on {} returned HTTP 200. An admin panel is publicly accessible.",
                    path, asset
                ),
                affected_asset: format!("{}/{}", asset, path),
                remediation: "HARDENING:\n\
                    1. Restrict access to admin panels via IP allowlist or VPN\n\
                    2. Ensure strong authentication is in place\n\
                    3. Consider renaming or hiding admin paths\n\
                    4. Implement rate limiting and brute-force protection"
                    .to_string(),
                references: vec!["https://owasp.org/www-project-web-security-testing-guide/".to_string()],
            });
        } else if code == 200 && info_good_paths.contains(&path.as_str()) {
            findings.push(crate::checker::Finding {
                severity: Severity::Info,
                title: format!("Security Contact Found: {}", path),
                description: format!(
                    "The path /{} on {} returned HTTP 200. Having a security.txt is good practice.",
                    path, asset
                ),
                affected_asset: format!("{}/{}", asset, path),
                remediation: "INFO:\n\
                    Good practice. Ensure the file is kept up to date with valid contact information."
                    .to_string(),
                references: vec!["https://securitytxt.org/".to_string()],
            });
        } else if code == 403 {
            // Path exists but is blocked — medium
            let is_sensitive = critical_paths.contains(&path.as_str())
                || admin_paths.contains(&path.as_str());
            if is_sensitive {
                findings.push(crate::checker::Finding {
                    severity: Severity::Medium,
                    title: format!("Sensitive Path Exists (Blocked): {}", path),
                    description: format!(
                        "The path /{} on {} returned HTTP 403. The resource exists but is currently blocked.",
                        path, asset
                    ),
                    affected_asset: format!("{}/{}", asset, path),
                    remediation: "HARDENING:\n\
                        1. Verify the block is intentional and correctly configured\n\
                        2. Consider returning 404 instead of 403 to avoid information leakage\n\
                        3. Remove the resource from the web root if not needed"
                        .to_string(),
                    references: vec![],
                });
            }
        }
    }

    // Sort findings by severity (most severe first) for consistent output
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::Severity;

    fn make_map(entries: &[(&str, u16)]) -> HashMap<String, u16> {
        entries.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn test_critical_env_accessible() {
        let map = make_map(&[(".env", 200)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains(".env"));
    }

    #[test]
    fn test_critical_git_config_accessible() {
        let map = make_map(&[(".git/config", 200)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_critical_aws_credentials_accessible() {
        let map = make_map(&[(".aws/credentials", 200)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_critical_backup_sql_accessible() {
        let map = make_map(&[("backup.sql", 200)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_admin_panel_accessible() {
        let map = make_map(&[("admin/", 200), ("wp-login.php", 200)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::High));
    }

    #[test]
    fn test_sensitive_path_blocked_403() {
        let map = make_map(&[(".env", 403), ("admin/", 403)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Medium));
    }

    #[test]
    fn test_security_txt_found() {
        let map = make_map(&[(".well-known/security.txt", 200)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_404_produces_no_findings() {
        let map = make_map(&[(".env", 404), ("admin/", 404), (".git/config", 404)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_sensitive_403_no_finding() {
        // robots.txt returning 403 should not produce a finding
        let map = make_map(&[("robots.txt", 403)]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_mixed_results() {
        let map = make_map(&[
            (".env", 200),
            ("admin/", 200),
            (".git/config", 403),
            (".well-known/security.txt", 200),
            ("robots.txt", 404),
        ]);
        let findings = generate_paths_findings_from_map("example.com", &map);
        // .env=Critical, admin/=High, .git/config=Medium(403), security.txt=Info
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].severity, Severity::Medium);
        assert_eq!(findings[3].severity, Severity::Info);
    }
}
