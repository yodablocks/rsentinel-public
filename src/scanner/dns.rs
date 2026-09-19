//! DNS security analysis using dig.
//!
//! DETECTION MODULE: Checks DNS configuration for security issues including
//! SPF, DMARC, DKIM, DNSSEC, and zone transfer vulnerabilities.

use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("dig not found - install dig (dnsutils/bind-utils) to use this scanner")]
    NotInstalled,

    #[error("DNS query failed: {0}")]
    QueryFailed(String),

}

/// Aggregated DNS security scan results.
#[derive(Debug, Clone)]
pub struct DnsScanResult {
    pub domain: String,
    pub has_spf: bool,
    pub spf_record: Option<String>,
    pub spf_too_permissive: bool,
    pub has_dmarc: bool,
    pub dmarc_record: Option<String>,
    pub dmarc_policy_none: bool,
    pub has_dkim: bool,
    pub dnssec_enabled: bool,
    pub zone_transfer_allowed: bool,
    pub zone_transfer_nameserver: Option<String>,
}

/// DNS security scanner using dig subprocess.
pub struct DnsScanner;

impl DnsScanner {
    pub fn new() -> Self {
        Self
    }

    fn check_dig_installed(&self) -> Result<(), DnsError> {
        Command::new("dig")
            .arg("-v")
            .output()
            .map_err(|_| DnsError::NotInstalled)?;
        Ok(())
    }

    fn run_dig(&self, args: &[&str]) -> Result<String, DnsError> {
        let output = Command::new("dig")
            .args(args)
            .arg("+time=5")
            .arg("+tries=1")
            .output()
            .map_err(|e| DnsError::QueryFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(DnsError::QueryFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a full DNS security check on the given domain.
    pub fn scan(&self, domain: &str) -> Result<DnsScanResult, DnsError> {
        self.check_dig_installed()?;

        let spf_output = self.run_dig(&["TXT", domain])?;
        let (has_spf, spf_record, spf_too_permissive) = parse_spf(&spf_output);

        let dmarc_output = self.run_dig(&["TXT", &format!("_dmarc.{}", domain)])?;
        let (has_dmarc, dmarc_record, dmarc_policy_none) = parse_dmarc(&dmarc_output);

        let (has_dkim, _dkim_selector) = self.check_dkim(domain)?;

        let dnssec_output = self.run_dig(&["+dnssec", domain])?;
        let dnssec_enabled = parse_dnssec(&dnssec_output);

        let (zone_transfer_allowed, zone_transfer_nameserver) = self.check_zone_transfer(domain)?;

        Ok(DnsScanResult {
            domain: domain.to_string(),
            has_spf,
            spf_record,
            spf_too_permissive,
            has_dmarc,
            dmarc_record,
            dmarc_policy_none,
            has_dkim,
            dnssec_enabled,
            zone_transfer_allowed,
            zone_transfer_nameserver,
        })
    }

    /// Check common DKIM selectors for the domain.
    fn check_dkim(&self, domain: &str) -> Result<(bool, Option<String>), DnsError> {
        let selectors = ["default", "google", "selector1", "selector2"];
        for selector in &selectors {
            let query = format!("{}._domainkey.{}", selector, domain);
            let output = self.run_dig(&["TXT", &query])?;
            if parse_has_txt_answer(&output) {
                return Ok((true, Some(selector.to_string())));
            }
        }
        Ok((false, None))
    }

    /// Check if zone transfers are allowed by querying nameservers.
    fn check_zone_transfer(&self, domain: &str) -> Result<(bool, Option<String>), DnsError> {
        let ns_output = self.run_dig(&["NS", domain])?;
        let nameservers = parse_nameservers(&ns_output);

        for ns in &nameservers {
            let axfr_output = self.run_dig(&["AXFR", domain, &format!("@{}", ns)])?;
            if parse_zone_transfer_success(&axfr_output) {
                return Ok((true, Some(ns.clone())));
            }
        }
        Ok((false, None))
    }
}

// --- Parse helpers (public for testing) ---

/// Parse SPF from dig TXT output. Returns (has_spf, record, too_permissive).
pub fn parse_spf(output: &str) -> (bool, Option<String>, bool) {
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("v=spf1") && !line.trim_start().starts_with(';') {
            let permissive = lower.contains("+all");
            // Extract the TXT value
            let record = extract_txt_value(line);
            return (true, record, permissive);
        }
    }
    (false, None, false)
}

/// Parse DMARC from dig TXT output. Returns (has_dmarc, record, policy_none).
pub fn parse_dmarc(output: &str) -> (bool, Option<String>, bool) {
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("v=dmarc1") && !line.trim_start().starts_with(';') {
            let policy_none = lower.contains("p=none");
            let record = extract_txt_value(line);
            return (true, record, policy_none);
        }
    }
    (false, None, false)
}

/// Check if dig output contains RRSIG records or the `ad` flag (DNSSEC).
pub fn parse_dnssec(output: &str) -> bool {
    for line in output.lines() {
        // Check for `ad` flag in the flags line
        if line.contains("flags:") && line.contains(" ad") {
            return true;
        }
        // Check for RRSIG in answer section
        if line.contains("RRSIG") && !line.trim_start().starts_with(';') {
            return true;
        }
    }
    false
}

/// Check if a TXT answer is present (non-empty answer section).
pub fn parse_has_txt_answer(output: &str) -> bool {
    let mut in_answer = false;
    for line in output.lines() {
        if line.contains(";; ANSWER SECTION:") {
            in_answer = true;
            continue;
        }
        if in_answer {
            if line.starts_with(";;") || line.is_empty() {
                break;
            }
            if line.contains("TXT") {
                return true;
            }
        }
    }
    false
}

/// Parse nameservers from dig NS output.
pub fn parse_nameservers(output: &str) -> Vec<String> {
    let mut nameservers = Vec::new();
    let mut in_answer = false;
    for line in output.lines() {
        if line.contains(";; ANSWER SECTION:") {
            in_answer = true;
            continue;
        }
        if in_answer {
            if line.starts_with(";;") || line.is_empty() {
                break;
            }
            if line.contains("NS") {
                if let Some(ns) = line.split_whitespace().last() {
                    nameservers.push(ns.trim_end_matches('.').to_string());
                }
            }
        }
    }
    nameservers
}

/// Check if AXFR output contains actual zone records (zone transfer succeeded).
pub fn parse_zone_transfer_success(output: &str) -> bool {
    let mut record_count = 0;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with(";;") {
            continue;
        }
        // A real DNS record line in AXFR output (contains record type keywords)
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 4 {
            record_count += 1;
        }
        if record_count > 1 {
            return true;
        }
    }
    false
}

/// Extract TXT record value from a dig answer line.
fn extract_txt_value(line: &str) -> Option<String> {
    if let Some(idx) = line.find("TXT") {
        let after = &line[idx + 3..];
        let trimmed = after.trim().trim_matches('"');
        if !trimmed.is_empty() {
            return Some(trimmed.replace("\" \"", ""));
        }
    }
    None
}

/// Generate security findings from DNS scan results.
pub fn generate_dns_findings(result: &DnsScanResult) -> Vec<crate::checker::Finding> {
    use crate::checker::{Finding, Severity};

    let mut findings = Vec::new();
    let domain = &result.domain;

    if !result.has_spf {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "No SPF Record Found".to_string(),
            description: format!(
                "Domain {} does not have an SPF (Sender Policy Framework) TXT record. \
                 This allows anyone to send email appearing to come from this domain.",
                domain
            ),
            affected_asset: domain.clone(),
            remediation: "HARDENING:\n\
                1. Add a TXT record with SPF policy (e.g., \"v=spf1 include:_spf.google.com -all\")\n\
                2. List all authorized mail servers\n\
                3. Use -all (hard fail) to reject unauthorized senders"
                .to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc7208".to_string()],
        });
    } else if result.spf_too_permissive {
        findings.push(Finding {
            severity: Severity::High,
            title: "SPF Record Too Permissive (+all)".to_string(),
            description: format!(
                "Domain {} has an SPF record with +all, which allows ANY server to send email \
                 on behalf of this domain. SPF record: {}",
                domain,
                result.spf_record.as_deref().unwrap_or("unknown")
            ),
            affected_asset: domain.clone(),
            remediation: "HARDENING:\n\
                1. Change +all to -all (hard fail) or ~all (soft fail)\n\
                2. Explicitly list authorized mail servers\n\
                3. Test changes with ~all before switching to -all"
                .to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc7208".to_string()],
        });
    }

    if !result.has_dmarc {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "No DMARC Record Found".to_string(),
            description: format!(
                "Domain {} does not have a DMARC record at _dmarc.{}. \
                 Without DMARC, email receivers cannot verify the authenticity of messages.",
                domain, domain
            ),
            affected_asset: domain.clone(),
            remediation: "HARDENING:\n\
                1. Add a TXT record at _dmarc.domain with DMARC policy\n\
                2. Start with p=none and rua= for monitoring\n\
                3. Gradually move to p=quarantine then p=reject"
                .to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc7489".to_string()],
        });
    } else if result.dmarc_policy_none {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "DMARC Policy Set to None".to_string(),
            description: format!(
                "Domain {} has a DMARC record with p=none, which only monitors but does not \
                 reject spoofed emails. Record: {}",
                domain,
                result.dmarc_record.as_deref().unwrap_or("unknown")
            ),
            affected_asset: domain.clone(),
            remediation: "HARDENING:\n\
                1. After monitoring period, change p=none to p=quarantine\n\
                2. Eventually move to p=reject for full protection\n\
                3. Ensure SPF and DKIM are properly configured first"
                .to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc7489".to_string()],
        });
    }

    if !result.has_dkim {
        findings.push(Finding {
            severity: Severity::Low,
            title: "No DKIM Record Found".to_string(),
            description: format!(
                "No DKIM record found for domain {} using common selectors \
                 (default, google, selector1, selector2). DKIM provides email \
                 authentication via cryptographic signatures.",
                domain
            ),
            affected_asset: domain.clone(),
            remediation: "HARDENING:\n\
                1. Configure DKIM signing on your mail server\n\
                2. Publish the DKIM public key as a TXT record\n\
                3. Use a selector name and add at selector._domainkey.domain"
                .to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc6376".to_string()],
        });
    }

    if !result.dnssec_enabled {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "DNSSEC Not Enabled".to_string(),
            description: format!(
                "Domain {} does not have DNSSEC enabled. Without DNSSEC, DNS responses \
                 can be spoofed, enabling cache poisoning and man-in-the-middle attacks.",
                domain
            ),
            affected_asset: domain.clone(),
            remediation: "HARDENING:\n\
                1. Enable DNSSEC at your DNS provider/registrar\n\
                2. Sign your zone with DNSSEC keys\n\
                3. Add DS records to the parent zone\n\
                4. Monitor DNSSEC validation status"
                .to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc4033".to_string()],
        });
    }

    if result.zone_transfer_allowed {
        findings.push(Finding {
            severity: Severity::High,
            title: "DNS Zone Transfer Allowed (AXFR)".to_string(),
            description: format!(
                "Domain {} allows zone transfers (AXFR) from nameserver {}. \
                 This exposes the entire DNS zone, revealing all subdomains and records.",
                domain,
                result.zone_transfer_nameserver.as_deref().unwrap_or("unknown")
            ),
            affected_asset: domain.clone(),
            remediation: "HARDENING:\n\
                1. Restrict AXFR to authorized secondary nameservers only\n\
                2. Use TSIG keys for zone transfer authentication\n\
                3. Configure allow-transfer ACLs on your DNS server\n\
                4. Verify with: dig AXFR domain @nameserver"
                .to_string(),
            references: vec!["https://www.rfc-editor.org/rfc/rfc5936".to_string()],
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_SPF_OUTPUT: &str = "\
; <<>> DiG 9.18.1 <<>> TXT example.com
;; ANSWER SECTION:
example.com.  300  IN  TXT  \"v=spf1 include:_spf.google.com -all\"
";

    const MOCK_SPF_PERMISSIVE: &str = "\
; <<>> DiG 9.18.1 <<>> TXT example.com
;; ANSWER SECTION:
example.com.  300  IN  TXT  \"v=spf1 +all\"
";

    const MOCK_NO_SPF: &str = "\
; <<>> DiG 9.18.1 <<>> TXT example.com
;; ANSWER SECTION:
example.com.  300  IN  TXT  \"google-site-verification=abc123\"
";

    const MOCK_DMARC_OUTPUT: &str = "\
; <<>> DiG 9.18.1 <<>> TXT _dmarc.example.com
;; ANSWER SECTION:
_dmarc.example.com.  300  IN  TXT  \"v=DMARC1; p=reject; rua=mailto:dmarc@example.com\"
";

    const MOCK_DMARC_NONE: &str = "\
; <<>> DiG 9.18.1 <<>> TXT _dmarc.example.com
;; ANSWER SECTION:
_dmarc.example.com.  300  IN  TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"
";

    const MOCK_DNSSEC_ENABLED: &str = "\
; <<>> DiG 9.18.1 <<>> +dnssec example.com
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2
;; ANSWER SECTION:
example.com.  300  IN  A  93.184.216.34
example.com.  300  IN  RRSIG  A 13 2 300 20240101000000 20231201000000 12345 example.com. abc123==
";

    const MOCK_DNSSEC_DISABLED: &str = "\
; <<>> DiG 9.18.1 <<>> +dnssec example.com
;; flags: qr rd ra; QUERY: 1, ANSWER: 1
;; ANSWER SECTION:
example.com.  300  IN  A  93.184.216.34
";

    const MOCK_NS_OUTPUT: &str = "\
; <<>> DiG 9.18.1 <<>> NS example.com
;; ANSWER SECTION:
example.com.  300  IN  NS  ns1.example.com.
example.com.  300  IN  NS  ns2.example.com.
";

    const MOCK_AXFR_SUCCESS: &str = "\
example.com.  300  IN  SOA  ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
example.com.  300  IN  NS  ns1.example.com.
example.com.  300  IN  A  93.184.216.34
mail.example.com.  300  IN  A  93.184.216.35
";

    const MOCK_AXFR_FAIL: &str = "\
; <<>> DiG 9.18.1 <<>> AXFR example.com @ns1.example.com
; Transfer failed.
";

    const MOCK_DKIM_FOUND: &str = "\
; <<>> DiG 9.18.1 <<>> TXT google._domainkey.example.com
;; ANSWER SECTION:
google._domainkey.example.com.  300  IN  TXT  \"v=DKIM1; k=rsa; p=MIGf...\"
";

    const MOCK_DKIM_NOT_FOUND: &str = "\
; <<>> DiG 9.18.1 <<>> TXT default._domainkey.example.com
;; AUTHORITY SECTION:
example.com.  300  IN  SOA  ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400
";

    #[test]
    fn test_parse_spf_found() {
        let (has, record, permissive) = parse_spf(MOCK_SPF_OUTPUT);
        assert!(has);
        assert!(record.is_some());
        assert!(!permissive);
        assert!(record.unwrap().contains("v=spf1"));
    }

    #[test]
    fn test_parse_spf_permissive() {
        let (has, _record, permissive) = parse_spf(MOCK_SPF_PERMISSIVE);
        assert!(has);
        assert!(permissive);
    }

    #[test]
    fn test_parse_spf_not_found() {
        let (has, record, permissive) = parse_spf(MOCK_NO_SPF);
        assert!(!has);
        assert!(record.is_none());
        assert!(!permissive);
    }

    #[test]
    fn test_parse_dmarc_found() {
        let (has, record, policy_none) = parse_dmarc(MOCK_DMARC_OUTPUT);
        assert!(has);
        assert!(record.is_some());
        assert!(!policy_none);
    }

    #[test]
    fn test_parse_dmarc_policy_none() {
        let (has, _record, policy_none) = parse_dmarc(MOCK_DMARC_NONE);
        assert!(has);
        assert!(policy_none);
    }

    #[test]
    fn test_parse_dnssec_enabled() {
        assert!(parse_dnssec(MOCK_DNSSEC_ENABLED));
    }

    #[test]
    fn test_parse_dnssec_disabled() {
        assert!(!parse_dnssec(MOCK_DNSSEC_DISABLED));
    }

    #[test]
    fn test_parse_nameservers() {
        let ns = parse_nameservers(MOCK_NS_OUTPUT);
        assert_eq!(ns.len(), 2);
        assert!(ns.contains(&"ns1.example.com".to_string()));
        assert!(ns.contains(&"ns2.example.com".to_string()));
    }

    #[test]
    fn test_parse_zone_transfer_success() {
        assert!(parse_zone_transfer_success(MOCK_AXFR_SUCCESS));
    }

    #[test]
    fn test_parse_zone_transfer_fail() {
        assert!(!parse_zone_transfer_success(MOCK_AXFR_FAIL));
    }

    #[test]
    fn test_parse_dkim_found() {
        assert!(parse_has_txt_answer(MOCK_DKIM_FOUND));
    }

    #[test]
    fn test_parse_dkim_not_found() {
        assert!(!parse_has_txt_answer(MOCK_DKIM_NOT_FOUND));
    }

    #[test]
    fn test_generate_findings_all_bad() {
        let result = DnsScanResult {
            domain: "example.com".to_string(),
            has_spf: false,
            spf_record: None,
            spf_too_permissive: false,
            has_dmarc: false,
            dmarc_record: None,
            dmarc_policy_none: false,
            has_dkim: false,

            dnssec_enabled: false,
            zone_transfer_allowed: true,
            zone_transfer_nameserver: Some("ns1.example.com".to_string()),
        };

        let findings = generate_dns_findings(&result);
        // no SPF, no DMARC, no DKIM, no DNSSEC, zone transfer = 5
        assert_eq!(findings.len(), 5);

        use crate::checker::Severity;
        assert!(findings.iter().any(|f| f.title.contains("SPF") && f.severity == Severity::Medium));
        assert!(findings.iter().any(|f| f.title.contains("DMARC") && f.severity == Severity::Medium));
        assert!(findings.iter().any(|f| f.title.contains("DKIM") && f.severity == Severity::Low));
        assert!(findings.iter().any(|f| f.title.contains("DNSSEC") && f.severity == Severity::Medium));
        assert!(findings.iter().any(|f| f.title.contains("Zone Transfer") && f.severity == Severity::High));
    }

    #[test]
    fn test_generate_findings_all_good() {
        let result = DnsScanResult {
            domain: "example.com".to_string(),
            has_spf: true,
            spf_record: Some("v=spf1 -all".to_string()),
            spf_too_permissive: false,
            has_dmarc: true,
            dmarc_record: Some("v=DMARC1; p=reject".to_string()),
            dmarc_policy_none: false,
            has_dkim: true,

            dnssec_enabled: true,
            zone_transfer_allowed: false,
            zone_transfer_nameserver: None,
        };

        let findings = generate_dns_findings(&result);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_generate_findings_spf_permissive() {
        let result = DnsScanResult {
            domain: "example.com".to_string(),
            has_spf: true,
            spf_record: Some("v=spf1 +all".to_string()),
            spf_too_permissive: true,
            has_dmarc: true,
            dmarc_record: Some("v=DMARC1; p=reject".to_string()),
            dmarc_policy_none: false,
            has_dkim: true,

            dnssec_enabled: true,
            zone_transfer_allowed: false,
            zone_transfer_nameserver: None,
        };

        let findings = generate_dns_findings(&result);
        assert_eq!(findings.len(), 1);
        use crate::checker::Severity;
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.contains("Permissive"));
    }

    #[test]
    fn test_generate_findings_dmarc_none() {
        let result = DnsScanResult {
            domain: "example.com".to_string(),
            has_spf: true,
            spf_record: Some("v=spf1 -all".to_string()),
            spf_too_permissive: false,
            has_dmarc: true,
            dmarc_record: Some("v=DMARC1; p=none".to_string()),
            dmarc_policy_none: true,
            has_dkim: true,

            dnssec_enabled: true,
            zone_transfer_allowed: false,
            zone_transfer_nameserver: None,
        };

        let findings = generate_dns_findings(&result);
        assert_eq!(findings.len(), 1);
        use crate::checker::Severity;
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("Policy Set to None"));
    }
}
