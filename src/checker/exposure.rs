//! Exposure checker and hardening recommendations.
//!
//! HARDENING MODULE: Analyzes detected exposures and provides remediation guidance.

use crate::api::shodan::{HostInfo, SearchMatch};
use crate::api::{CveDbClient, ShodanClient};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Severity levels for security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_cvss(cvss: f32) -> Self {
        match cvss {
            c if c >= 9.0 => Severity::Critical,
            c if c >= 7.0 => Severity::High,
            c if c >= 4.0 => Severity::Medium,
            c if c >= 0.1 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

/// A security finding with remediation guidance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_asset: String,
    pub remediation: String,
    pub references: Vec<String>,
}

/// Complete exposure report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureReport {
    pub target: String,
    pub scan_time: String,
    pub findings: Vec<Finding>,
    pub summary: ReportSummary,
    pub grade: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// Compute a security grade from severity counts.
/// Score = 100 - (critical*20) - (high*10) - (medium*5) - (low*2), clamped 0-100.
pub fn compute_grade(summary: &ReportSummary) -> String {
    let score: i32 = 100
        - (summary.critical_count as i32 * 20)
        - (summary.high_count as i32 * 10)
        - (summary.medium_count as i32 * 5)
        - (summary.low_count as i32 * 2);
    let score = score.clamp(0, 100);
    match score {
        100 => "A+".to_string(),
        90..=99 => "A".to_string(),
        80..=89 => "B".to_string(),
        70..=79 => "C".to_string(),
        60..=69 => "D".to_string(),
        _ => "F".to_string(),
    }
}

impl ExposureReport {
    fn new(target: impl Into<String>, findings: Vec<Finding>) -> Self {
        let target = target.into();
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

        Self {
            target,
            scan_time: chrono::Utc::now().to_rfc3339(),
            findings,
            summary,
            grade,
        }
    }

    /// Check if any critical findings exist.
    pub fn has_critical(&self) -> bool {
        self.summary.critical_count > 0
    }

    /// Check if any high or critical findings exist.
    #[allow(dead_code)]
    pub fn has_high_or_critical(&self) -> bool {
        self.summary.critical_count > 0 || self.summary.high_count > 0
    }
}

/// Main exposure checker that combines detection with hardening recommendations.
pub struct ExposureChecker {
    shodan: ShodanClient,
    cvedb: CveDbClient,
}

impl ExposureChecker {
    /// Create a new exposure checker with a Shodan API key.
    pub fn new(shodan_api_key: impl Into<String>) -> Self {
        Self {
            shodan: ShodanClient::new(shodan_api_key),
            cvedb: CveDbClient::new(),
        }
    }

    /// Check a specific IP address for exposures.
    pub async fn check_ip(&self, ip: &str) -> anyhow::Result<ExposureReport> {
        let mut findings = Vec::new();

        // Get host information from Shodan
        match self.shodan.host_info(ip).await {
            Ok(host) => {
                findings.extend(self.analyze_host(&host).await);
            }
            Err(e) => {
                tracing::warn!("Could not retrieve Shodan data for {}: {}", ip, e);
            }
        }

        Ok(ExposureReport::new(ip, findings))
    }

    /// Analyze exposed AI endpoints found via search.
    pub async fn check_ai_exposure(&self) -> anyhow::Result<ExposureReport> {
        let matches = self.shodan.search_ai_endpoints().await?;
        let mut findings = Vec::new();

        for m in &matches {
            findings.extend(self.analyze_search_match(m));
        }

        Ok(ExposureReport::new("AI Endpoint Scan", findings))
    }

    /// Analyze a Shodan host and generate findings with remediation.
    async fn analyze_host(&self, host: &HostInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for exposed high-risk ports
        findings.extend(self.check_exposed_ports(host));

        // Check for known vulnerabilities
        if !host.vulns.is_empty() {
            findings.extend(
                self.analyze_vulnerabilities(&host.ip_str, &host.vulns)
                    .await,
            );
        }

        // Check for exposed services that shouldn't be public
        findings.extend(self.check_service_exposure(host));

        findings
    }

    /// Check for exposed high-risk ports.
    fn check_exposed_ports(&self, host: &HostInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        // High-risk ports that typically shouldn't be internet-facing
        let high_risk_ports: HashSet<u16> = [
            22,    // SSH (should use VPN/bastion)
            23,    // Telnet
            3306,  // MySQL
            5432,  // PostgreSQL
            6379,  // Redis
            27017, // MongoDB
            9200,  // Elasticsearch
            2375,  // Docker API (unencrypted)
            2376,  // Docker API
            8080,  // Common dev/proxy port
            8443,  // Alternative HTTPS
            9000,  // Various admin interfaces
        ]
        .into_iter()
        .collect();

        for port in &host.ports {
            if high_risk_ports.contains(port) {
                findings.push(self.create_port_finding(*port, &host.ip_str));
            }
        }

        findings
    }

    fn create_port_finding(&self, port: u16, ip: &str) -> Finding {
        let (severity, title, remediation) = match port {
            22 => (
                Severity::Medium,
                "SSH Exposed to Internet",
                "HARDENING:\n\
                 1. Use a VPN or bastion host for SSH access\n\
                 2. Implement IP allowlisting via firewall\n\
                 3. Use SSH keys only (disable password auth)\n\
                 4. Enable fail2ban or similar brute-force protection\n\
                 5. Consider using a non-standard port",
            ),
            23 => (
                Severity::Critical,
                "Telnet Exposed (Unencrypted)",
                "HARDENING:\n\
                 1. IMMEDIATELY disable Telnet service\n\
                 2. Replace with SSH for remote access\n\
                 3. Block port 23 at firewall level\n\
                 4. Audit for any credentials transmitted over Telnet",
            ),
            3306 => (
                Severity::High,
                "MySQL Database Exposed",
                "HARDENING:\n\
                 1. Block port 3306 from public internet\n\
                 2. Use VPN or SSH tunnel for database access\n\
                 3. Ensure bind-address is set to 127.0.0.1 or private IP\n\
                 4. Review and restrict database user privileges\n\
                 5. Enable TLS for database connections",
            ),
            5432 => (
                Severity::High,
                "PostgreSQL Database Exposed",
                "HARDENING:\n\
                 1. Block port 5432 from public internet\n\
                 2. Configure pg_hba.conf to restrict access\n\
                 3. Use VPN or SSH tunnel for remote access\n\
                 4. Enable SSL in postgresql.conf\n\
                 5. Review database user permissions",
            ),
            6379 => (
                Severity::Critical,
                "Redis Exposed (Often No Auth)",
                "HARDENING:\n\
                 1. IMMEDIATELY block port 6379 from internet\n\
                 2. Enable Redis AUTH with strong password\n\
                 3. Bind to localhost or private network only\n\
                 4. Enable TLS if remote access is required\n\
                 5. Disable dangerous commands (FLUSHALL, CONFIG, etc.)",
            ),
            27017 => (
                Severity::Critical,
                "MongoDB Exposed",
                "HARDENING:\n\
                 1. Block port 27017 from public internet\n\
                 2. Enable authentication (--auth flag)\n\
                 3. Bind to localhost: bindIp: 127.0.0.1\n\
                 4. Enable TLS/SSL for connections\n\
                 5. Create specific users with minimal privileges",
            ),
            9200 => (
                Severity::High,
                "Elasticsearch Exposed",
                "HARDENING:\n\
                 1. Block port 9200 from public internet\n\
                 2. Enable X-Pack security features\n\
                 3. Set network.host to private IP\n\
                 4. Implement authentication and TLS\n\
                 5. Use reverse proxy with auth for any web access",
            ),
            2375 | 2376 => (
                Severity::Critical,
                "Docker API Exposed",
                "HARDENING:\n\
                 1. NEVER expose Docker API to internet\n\
                 2. Use TLS client certificates if remote access needed\n\
                 3. Block ports 2375/2376 at firewall\n\
                 4. Use SSH tunneling for remote Docker access\n\
                 5. Consider using Docker contexts with SSH",
            ),
            8080 => (
                Severity::Medium,
                "Development/Proxy Port Exposed",
                "HARDENING:\n\
                 1. Review if this service should be public\n\
                 2. Ensure proper authentication is enabled\n\
                 3. Use HTTPS (port 443) for production\n\
                 4. Implement rate limiting\n\
                 5. Review access logs regularly",
            ),
            _ => (
                Severity::Low,
                "Potentially Sensitive Port Exposed",
                "HARDENING:\n\
                 1. Review if this port should be publicly accessible\n\
                 2. Implement firewall rules to restrict access\n\
                 3. Ensure the service has proper authentication\n\
                 4. Monitor access logs for suspicious activity",
            ),
        };

        Finding {
            severity,
            title: title.to_string(),
            description: format!("Port {} is exposed to the internet on {}", port, ip),
            affected_asset: format!("{}:{}", ip, port),
            remediation: remediation.to_string(),
            references: vec![
                "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
            ],
        }
    }

    /// Analyze CVEs and provide remediation.
    async fn analyze_vulnerabilities(&self, ip: &str, vuln_ids: &[String]) -> Vec<Finding> {
        let cve_infos = self.cvedb.lookup_cves(vuln_ids).await;
        let mut findings = Vec::new();

        for cve in cve_infos {
            let severity = Severity::from_cvss(cve.cvss.unwrap_or(0.0));

            findings.push(Finding {
                severity,
                title: format!("Vulnerability: {}", cve.cve_id),
                description: cve
                    .summary
                    .clone()
                    .unwrap_or_else(|| "No description available".to_string()),
                affected_asset: ip.to_string(),
                remediation: format!(
                    "HARDENING:\n\
                     1. Check if patch is available for {}\n\
                     2. Apply vendor patches immediately\n\
                     3. If no patch, implement compensating controls:\n\
                        - Network segmentation\n\
                        - WAF rules if applicable\n\
                        - Disable affected feature if possible\n\
                     4. Monitor for exploitation attempts\n\
                     5. CVSS Score: {:.1}",
                    cve.cve_id,
                    cve.cvss.unwrap_or(0.0)
                ),
                references: cve.references,
            });
        }

        findings
    }

    /// Check for exposed services based on banner data.
    fn check_service_exposure(&self, host: &HostInfo) -> Vec<Finding> {
        let mut findings = Vec::new();

        for banner in &host.data {
            // Check for exposed admin interfaces
            if let Some(http) = &banner.http
                && let Some(title) = &http.title
            {
                let title_lower = title.to_lowercase();

                if title_lower.contains("admin") || title_lower.contains("dashboard") {
                    findings.push(Finding {
                        severity: Severity::High,
                        title: "Admin Interface Exposed".to_string(),
                        description: format!("Admin interface '{}' is publicly accessible", title),
                        affected_asset: format!("{}:{}", host.ip_str, banner.port),
                        remediation: "HARDENING:\n\
                                1. Place admin interfaces behind VPN\n\
                                2. Implement IP allowlisting\n\
                                3. Enable MFA for admin access\n\
                                4. Use strong authentication\n\
                                5. Consider using a separate subdomain with restricted access"
                            .to_string(),
                        references: vec![],
                    });
                }

                // Check for exposed AI/agent interfaces
                if title_lower.contains("claude")
                    || title_lower.contains("anthropic")
                    || title_lower.contains("ai agent")
                    || title_lower.contains("llm")
                {
                    findings.push(Finding {
                            severity: Severity::Critical,
                            title: "AI/Agent Interface Exposed".to_string(),
                            description: format!("AI interface '{}' is publicly accessible", title),
                            affected_asset: format!("{}:{}", host.ip_str, banner.port),
                            remediation: "HARDENING:\n\
                                1. IMMEDIATELY restrict access to AI endpoints\n\
                                2. Implement API authentication (API keys, OAuth)\n\
                                3. Add rate limiting to prevent abuse\n\
                                4. Use VPN or IP allowlisting\n\
                                5. Monitor for prompt injection attempts\n\
                                6. Implement output filtering\n\
                                7. Log all interactions for audit".to_string(),
                            references: vec![
                                "https://owasp.org/www-project-top-10-for-large-language-model-applications/".to_string(),
                            ],
                        });
                }
            }

            // Check for version disclosure
            if let Some(version) = &banner.version
                && !version.is_empty()
            {
                findings.push(Finding {
                    severity: Severity::Low,
                    title: "Service Version Disclosed".to_string(),
                    description: format!(
                        "Service {} version {} is disclosed on port {}",
                        banner.product.as_deref().unwrap_or("unknown"),
                        version,
                        banner.port
                    ),
                    affected_asset: format!("{}:{}", host.ip_str, banner.port),
                    remediation: "HARDENING:\n\
                            1. Configure service to hide version information\n\
                            2. For nginx: server_tokens off;\n\
                            3. For Apache: ServerTokens Prod\n\
                            4. This reduces reconnaissance value for attackers"
                        .to_string(),
                    references: vec![],
                });
            }
        }

        findings
    }

    /// Analyze a search match from Shodan.
    fn analyze_search_match(&self, m: &SearchMatch) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Any match from AI endpoint search is concerning
        findings.push(Finding {
            severity: Severity::High,
            title: "Potential AI Endpoint Detected".to_string(),
            description: format!(
                "Detected potential AI/agent endpoint at {}:{}\nOrg: {}\nHostnames: {}",
                m.ip_str,
                m.port,
                m.org.as_deref().unwrap_or("unknown"),
                m.hostnames.join(", ")
            ),
            affected_asset: format!("{}:{}", m.ip_str, m.port),
            remediation: "HARDENING:\n\
                1. Verify if this is an authorized AI endpoint\n\
                2. If not needed publicly, restrict access immediately\n\
                3. Implement proper authentication\n\
                4. Add rate limiting and abuse prevention\n\
                5. Enable comprehensive logging\n\
                6. Consider using a CDN/WAF for protection"
                .to_string(),
            references: vec![],
        });

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(Severity::from_cvss(9.8), Severity::Critical);
        assert_eq!(Severity::from_cvss(7.5), Severity::High);
        assert_eq!(Severity::from_cvss(5.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(2.0), Severity::Low);
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
    }

    #[test]
    fn test_report_summary() {
        let findings = vec![
            Finding {
                severity: Severity::Critical,
                title: "Test".into(),
                description: "Test".into(),
                affected_asset: "test".into(),
                remediation: "Test".into(),
                references: vec![],
            },
            Finding {
                severity: Severity::High,
                title: "Test2".into(),
                description: "Test".into(),
                affected_asset: "test".into(),
                remediation: "Test".into(),
                references: vec![],
            },
        ];

        let report = ExposureReport::new("test", findings);
        assert_eq!(report.summary.total_findings, 2);
        assert_eq!(report.summary.critical_count, 1);
        assert_eq!(report.summary.high_count, 1);
        assert!(report.has_critical());
        assert!(report.has_high_or_critical());
    }
}
