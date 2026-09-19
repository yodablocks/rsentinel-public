//! SSL/TLS analysis using openssl s_client.
//!
//! DETECTION MODULE: Checks certificate health, protocol support, cipher strength, and HSTS.

use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SslError {
    #[error("openssl not found - install with: brew install openssl")]
    NotInstalled,

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

}

/// Certificate information.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub self_signed: bool,
}

/// Protocol support details.
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    pub name: String,
    pub enabled: bool,
}

/// Aggregated SSL/TLS scan results.
#[derive(Debug, Clone)]
pub struct SslScanResult {
    pub target: String,
    pub port: u16,
    pub cert: Option<CertInfo>,
    pub protocols: Vec<ProtocolInfo>,
    pub weak_ciphers: Vec<String>,
    pub chain_valid: bool,
    pub hsts: bool,
}

/// SSL/TLS scanner using openssl subprocess.
pub struct SslScanner;

impl SslScanner {
    pub fn new() -> Self {
        Self
    }

    /// Run a full SSL/TLS check on the given host and port.
    pub fn scan(&self, host: &str, port: u16) -> Result<SslScanResult, SslError> {
        self.check_openssl_installed()?;

        let cert = self.fetch_cert_info(host, port)?;
        let protocols = self.check_protocols(host, port);
        let weak_ciphers = self.check_weak_ciphers(host, port);
        let chain_valid = self.check_chain(host, port);
        let hsts = self.check_hsts(host, port);

        Ok(SslScanResult {
            target: host.to_string(),
            port,
            cert: Some(cert),
            protocols,
            weak_ciphers,
            chain_valid,
            hsts,
        })
    }

    fn check_openssl_installed(&self) -> Result<(), SslError> {
        Command::new("openssl")
            .arg("version")
            .output()
            .map_err(|_| SslError::NotInstalled)?;
        Ok(())
    }

    fn connect_cmd(&self, host: &str, port: u16, extra_args: &[&str]) -> Command {
        let mut cmd = Command::new("openssl");
        cmd.arg("s_client")
            .arg("-connect")
            .arg(format!("{}:{}", host, port));
        for arg in extra_args {
            cmd.arg(arg);
        }
        cmd.stdin(std::process::Stdio::null());
        cmd
    }

    fn fetch_cert_info(&self, host: &str, port: u16) -> Result<CertInfo, SslError> {
        // Get certificate details via openssl
        let output = self
            .connect_cmd(host, port, &["-servername", host])
            .output()
            .map_err(|e| SslError::ConnectionFailed(e.to_string()))?;

        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        if combined.contains("connect:errno=") || combined.contains("no peer certificate") {
            return Err(SslError::ConnectionFailed(
                "Could not establish TLS connection".to_string(),
            ));
        }

        let subject = parse_field(&combined, "subject=");
        let issuer = parse_field(&combined, "issuer=");
        let self_signed = subject == issuer || combined.contains("self-signed");

        // Get dates via openssl x509
        let dates_output = self
            .connect_cmd(host, port, &["-servername", host])
            .arg("-|")
            .output();

        // Alternatively pipe the cert through openssl x509 -dates
        let cert_pem = extract_pem(&combined);
        let (_not_before, not_after, days_until_expiry) = if let Some(pem) = &cert_pem {
            parse_cert_dates(pem)
        } else {
            // Fallback: parse from s_client output if present
            let _ = dates_output;
            (String::new(), String::new(), -1)
        };

        Ok(CertInfo {
            subject,
            issuer,
            not_after,
            days_until_expiry,
            self_signed,
        })
    }

    fn check_protocols(&self, host: &str, port: u16) -> Vec<ProtocolInfo> {
        let protocols = vec![
            ("ssl3", "-ssl3", true),
            ("tls1", "-tls1", true),
            ("tls1_1", "-tls1_1", true),
            ("tls1_2", "-tls1_2", false),
            ("tls1_3", "-tls1_3", false),
        ];

        protocols
            .into_iter()
            .map(|(name, flag, _weak)| {
                let enabled = self
                    .connect_cmd(host, port, &[flag, "-servername", host])
                    .output()
                    .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stderr).contains("no protocols available"))
                    .unwrap_or(false);

                ProtocolInfo {
                    name: name.to_string(),
                    enabled,
                }
            })
            .collect()
    }

    fn check_weak_ciphers(&self, host: &str, port: u16) -> Vec<String> {
        let weak_patterns = ["RC4", "DES", "MD5", "NULL", "EXPORT", "anon"];
        let mut found = Vec::new();

        for pattern in &weak_patterns {
            // Use -tls1_2 to prevent TLS 1.3 from negotiating a strong cipher
            // that bypasses the -cipher filter (TLS 1.3 uses -ciphersuites instead)
            let result = self
                .connect_cmd(host, port, &["-cipher", pattern, "-tls1_2", "-servername", host])
                .output();

            if let Ok(output) = result {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let combined = format!("{}\n{}", stdout, stderr);

                // Check that the connection actually succeeded with a weak cipher
                let handshake_ok = output.status.success()
                    && !combined.contains("no ciphers available")
                    && !combined.contains("handshake failure")
                    && !combined.contains("no cipher match")
                    && !combined.contains("Cipher is (NONE)");

                if handshake_ok {
                    // Verify the negotiated cipher actually contains the weak pattern
                    let negotiated_weak = combined.lines()
                        .any(|line| {
                            line.contains("Cipher is") && {
                                let upper = line.to_uppercase();
                                let pat = pattern.to_uppercase();
                                upper.contains(&pat) && !upper.contains("Cipher is (NONE)")
                            }
                        });

                    if negotiated_weak {
                        found.push(pattern.to_string());
                    }
                }
            }
        }

        found
    }

    fn check_chain(&self, host: &str, port: u16) -> bool {
        let output = self
            .connect_cmd(host, port, &["-servername", host, "-verify_return_error"])
            .output();

        match output {
            Ok(o) => {
                let combined = format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                combined.contains("Verify return code: 0") || combined.contains("verify return:1")
            }
            Err(_) => false,
        }
    }

    fn check_hsts(&self, host: &str, _port: u16) -> bool {
        // Use curl to check HSTS header
        let output = Command::new("curl")
            .args(["-sI", "-m", "10", &format!("https://{}", host)])
            .output();

        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_lowercase();
                stdout.contains("strict-transport-security")
            }
            Err(_) => false,
        }
    }
}

impl Default for SslScanner {
    fn default() -> Self {
        Self::new()
    }
}

// --- Parsing helpers ---

fn parse_field(text: &str, prefix: &str) -> String {
    text.lines()
        .find(|line| line.trim().starts_with(prefix))
        .map(|line| line.trim().trim_start_matches(prefix).trim().to_string())
        .unwrap_or_default()
}

fn extract_pem(text: &str) -> Option<String> {
    let start = text.find("-----BEGIN CERTIFICATE-----")?;
    let end = text.find("-----END CERTIFICATE-----")? + "-----END CERTIFICATE-----".len();
    Some(text[start..end].to_string())
}

fn parse_cert_dates(pem: &str) -> (String, String, i64) {
    let child = Command::new("openssl")
        .args(["x509", "-noout", "-dates"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    if let Ok(mut proc) = child {
        use std::io::Write;
        if let Some(mut stdin) = proc.stdin.take() {
            let _ = stdin.write_all(pem.as_bytes());
            // drop stdin to close pipe so openssl reads EOF
        }

        if let Ok(output) = proc.wait_with_output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let not_before = parse_field(&stdout, "notBefore=");
            let not_after = parse_field(&stdout, "notAfter=");
            let days = parse_days_until(&not_after);
            return (not_before, not_after, days);
        }
    }

    (String::new(), String::new(), -1)
}

fn parse_days_until(date_str: &str) -> i64 {
    if date_str.is_empty() {
        return -1;
    }

    // openssl date format: "Mon DD HH:MM:SS YYYY GMT" e.g. "Jan 15 12:00:00 2025 GMT"
    // Try macOS date first, then GNU date as fallback
    let attempts: Vec<Vec<&str>> = vec![
        vec!["-j", "-f", "%b %d %H:%M:%S %Y %Z", date_str, "+%s"],
        vec!["-d", date_str, "+%s"],
    ];

    for args in &attempts {
        if let Ok(output) = Command::new("date")
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            if let Ok(epoch_str) = std::str::from_utf8(&output.stdout) {
                if let Ok(epoch) = epoch_str.trim().parse::<i64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    return (epoch - now) / 86400;
                }
            }
        }
    }

    -1
}

/// Generate security findings from SSL scan results.
pub fn generate_ssl_findings(result: &SslScanResult) -> Vec<crate::checker::Finding> {
    use crate::checker::Severity;

    let mut findings = Vec::new();
    let asset = format!("{}:{}", result.target, result.port);

    // Certificate findings
    if let Some(ref cert) = result.cert {
        if cert.days_until_expiry < 0 && cert.days_until_expiry != -1 {
            findings.push(crate::checker::Finding {
                severity: Severity::Critical,
                title: "SSL Certificate Expired".to_string(),
                description: format!(
                    "Certificate for {} expired {} days ago.\nSubject: {}\nExpiry: {}",
                    result.target,
                    -cert.days_until_expiry,
                    cert.subject,
                    cert.not_after
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. Renew the certificate immediately\n\
                    2. Set up automated renewal (e.g., certbot)\n\
                    3. Monitor certificate expiry with alerting"
                    .to_string(),
                references: vec![],
            });
        } else if cert.days_until_expiry >= 0 && cert.days_until_expiry < 30 {
            findings.push(crate::checker::Finding {
                severity: Severity::High,
                title: "SSL Certificate Expiring Soon (<30 days)".to_string(),
                description: format!(
                    "Certificate for {} expires in {} days.\nSubject: {}\nExpiry: {}",
                    result.target, cert.days_until_expiry, cert.subject, cert.not_after
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. Renew the certificate before expiry\n\
                    2. Set up automated renewal\n\
                    3. Configure expiry monitoring and alerting"
                    .to_string(),
                references: vec![],
            });
        } else if cert.days_until_expiry >= 30 && cert.days_until_expiry < 90 {
            findings.push(crate::checker::Finding {
                severity: Severity::Medium,
                title: "SSL Certificate Expiring (<90 days)".to_string(),
                description: format!(
                    "Certificate for {} expires in {} days.\nSubject: {}\nExpiry: {}",
                    result.target, cert.days_until_expiry, cert.subject, cert.not_after
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. Plan certificate renewal\n\
                    2. Set up automated renewal if not already configured"
                    .to_string(),
                references: vec![],
            });
        }

        if cert.self_signed {
            findings.push(crate::checker::Finding {
                severity: Severity::High,
                title: "Self-Signed Certificate Detected".to_string(),
                description: format!(
                    "Certificate for {} is self-signed.\nSubject: {}\nIssuer: {}",
                    result.target, cert.subject, cert.issuer
                ),
                affected_asset: asset.clone(),
                remediation: "HARDENING:\n\
                    1. Replace with a certificate from a trusted CA\n\
                    2. Use Let's Encrypt for free trusted certificates\n\
                    3. Self-signed certs cause browser warnings and may indicate MITM"
                    .to_string(),
                references: vec![],
            });
        }
    }

    // Protocol findings
    for proto in &result.protocols {
        match proto.name.as_str() {
            "ssl3" if proto.enabled => {
                findings.push(crate::checker::Finding {
                    severity: Severity::Critical,
                    title: "SSLv3 Enabled (POODLE vulnerable)".to_string(),
                    description: format!("SSLv3 is enabled on {}", result.target),
                    affected_asset: asset.clone(),
                    remediation: "HARDENING:\n\
                        1. Disable SSLv3 immediately\n\
                        2. SSLv3 is vulnerable to POODLE attack\n\
                        3. Ensure TLS 1.2+ is available before disabling"
                        .to_string(),
                    references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2014-3566".to_string()],
                });
            }
            "tls1" if proto.enabled => {
                findings.push(crate::checker::Finding {
                    severity: Severity::High,
                    title: "TLS 1.0 Enabled (Deprecated)".to_string(),
                    description: format!("TLS 1.0 is still enabled on {}", result.target),
                    affected_asset: asset.clone(),
                    remediation: "HARDENING:\n\
                        1. Disable TLS 1.0\n\
                        2. TLS 1.0 is deprecated per RFC 8996\n\
                        3. Ensure TLS 1.2+ is supported before disabling"
                        .to_string(),
                    references: vec!["https://datatracker.ietf.org/doc/rfc8996/".to_string()],
                });
            }
            "tls1_1" if proto.enabled => {
                findings.push(crate::checker::Finding {
                    severity: Severity::High,
                    title: "TLS 1.1 Enabled (Deprecated)".to_string(),
                    description: format!("TLS 1.1 is still enabled on {}", result.target),
                    affected_asset: asset.clone(),
                    remediation: "HARDENING:\n\
                        1. Disable TLS 1.1\n\
                        2. TLS 1.1 is deprecated per RFC 8996\n\
                        3. Ensure TLS 1.2+ is supported before disabling"
                        .to_string(),
                    references: vec!["https://datatracker.ietf.org/doc/rfc8996/".to_string()],
                });
            }
            "tls1_2" if !proto.enabled => {
                findings.push(crate::checker::Finding {
                    severity: Severity::High,
                    title: "TLS 1.2 Not Supported".to_string(),
                    description: format!("TLS 1.2 is not supported on {}", result.target),
                    affected_asset: asset.clone(),
                    remediation: "HARDENING:\n\
                        1. Enable TLS 1.2 support\n\
                        2. TLS 1.2 is the minimum recommended protocol\n\
                        3. Many clients require TLS 1.2 as minimum"
                        .to_string(),
                    references: vec![],
                });
            }
            "tls1_3" if !proto.enabled => {
                findings.push(crate::checker::Finding {
                    severity: Severity::Medium,
                    title: "TLS 1.3 Not Supported".to_string(),
                    description: format!("TLS 1.3 is not supported on {}", result.target),
                    affected_asset: asset.clone(),
                    remediation: "HARDENING:\n\
                        1. Enable TLS 1.3 for improved security and performance\n\
                        2. TLS 1.3 removes legacy cryptographic algorithms\n\
                        3. Provides faster handshakes (1-RTT and 0-RTT)"
                        .to_string(),
                    references: vec!["https://datatracker.ietf.org/doc/rfc8446/".to_string()],
                });
            }
            _ => {}
        }
    }

    // Chain validation
    if !result.chain_valid {
        findings.push(crate::checker::Finding {
            severity: Severity::High,
            title: "Certificate Chain Invalid".to_string(),
            description: format!(
                "Certificate chain validation failed for {}",
                result.target
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Ensure all intermediate certificates are installed\n\
                2. Verify certificate chain order is correct\n\
                3. Check that root CA is trusted"
                .to_string(),
            references: vec![],
        });
    }

    // Weak ciphers
    for cipher in &result.weak_ciphers {
        findings.push(crate::checker::Finding {
            severity: Severity::Medium,
            title: format!("Weak Cipher Suite Supported: {}", cipher),
            description: format!(
                "{} cipher suite is accepted by {}",
                cipher, result.target
            ),
            affected_asset: asset.clone(),
            remediation: format!(
                "HARDENING:\n\
                1. Disable {} cipher suites in server configuration\n\
                2. Use only strong ciphers (AES-GCM, ChaCha20-Poly1305)\n\
                3. Follow Mozilla SSL Configuration Generator recommendations",
                cipher
            ),
            references: vec![
                "https://ssl-config.mozilla.org/".to_string(),
            ],
        });
    }

    // HSTS
    if !result.hsts {
        findings.push(crate::checker::Finding {
            severity: Severity::Low,
            title: "HSTS Not Enabled".to_string(),
            description: format!(
                "Strict-Transport-Security header not found on {}",
                result.target
            ),
            affected_asset: asset.clone(),
            remediation: "HARDENING:\n\
                1. Add Strict-Transport-Security header\n\
                2. Recommended: max-age=31536000; includeSubDomains\n\
                3. Consider HSTS preload submission"
                .to_string(),
            references: vec!["https://hstspreload.org/".to_string()],
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_field() {
        let text = "depth=0\nsubject=CN = example.com\nissuer=CN = Let's Encrypt\n";
        assert_eq!(parse_field(text, "subject="), "CN = example.com");
        assert_eq!(parse_field(text, "issuer="), "CN = Let's Encrypt");
        assert_eq!(parse_field(text, "missing="), "");
    }

    #[test]
    fn test_extract_pem() {
        let text = "some header\n-----BEGIN CERTIFICATE-----\nABC123\n-----END CERTIFICATE-----\nfooter";
        let pem = extract_pem(text).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
        assert!(pem.contains("ABC123"));
    }

    #[test]
    fn test_extract_pem_missing() {
        assert!(extract_pem("no cert here").is_none());
    }

    #[test]
    fn test_generate_findings_expired_cert() {
        let result = SslScanResult {
            target: "example.com".to_string(),
            port: 443,
            cert: Some(CertInfo {
                subject: "CN = example.com".to_string(),
                issuer: "CN = Let's Encrypt".to_string(),

                not_after: "Jan  1 00:00:00 2024 GMT".to_string(),
                days_until_expiry: -10,
                self_signed: false,
            }),
            protocols: vec![],
            weak_ciphers: vec![],
            chain_valid: true,
            hsts: true,
        };

        let findings = generate_ssl_findings(&result);
        assert!(findings.iter().any(|f| f.title.contains("Expired")));
    }

    #[test]
    fn test_generate_findings_self_signed() {
        let result = SslScanResult {
            target: "example.com".to_string(),
            port: 443,
            cert: Some(CertInfo {
                subject: "CN = example.com".to_string(),
                issuer: "CN = example.com".to_string(),

                not_after: String::new(),
                days_until_expiry: 365,
                self_signed: true,
            }),
            protocols: vec![],
            weak_ciphers: vec![],
            chain_valid: true,
            hsts: true,
        };

        let findings = generate_ssl_findings(&result);
        assert!(findings.iter().any(|f| f.title.contains("Self-Signed")));
    }

    #[test]
    fn test_generate_findings_weak_protocol() {
        let result = SslScanResult {
            target: "example.com".to_string(),
            port: 443,
            cert: None,
            protocols: vec![
                ProtocolInfo { name: "ssl3".to_string(), enabled: true },
                ProtocolInfo { name: "tls1".to_string(), enabled: true },
                ProtocolInfo { name: "tls1_2".to_string(), enabled: true },
                ProtocolInfo { name: "tls1_3".to_string(), enabled: false },
            ],
            weak_ciphers: vec!["RC4".to_string()],
            chain_valid: true,
            hsts: false,
        };

        let findings = generate_ssl_findings(&result);
        assert!(findings.iter().any(|f| f.title.contains("SSLv3")));
        assert!(findings.iter().any(|f| f.title.contains("TLS 1.0")));
        assert!(findings.iter().any(|f| f.title.contains("TLS 1.3 Not")));
        assert!(findings.iter().any(|f| f.title.contains("RC4")));
        assert!(findings.iter().any(|f| f.title.contains("HSTS")));
    }

    #[test]
    fn test_generate_findings_chain_invalid() {
        let result = SslScanResult {
            target: "example.com".to_string(),
            port: 443,
            cert: None,
            protocols: vec![],
            weak_ciphers: vec![],
            chain_valid: false,
            hsts: true,
        };

        let findings = generate_ssl_findings(&result);
        assert!(findings.iter().any(|f| f.title.contains("Chain Invalid")));
    }

    #[test]
    fn test_generate_findings_expiry_30_days() {
        let result = SslScanResult {
            target: "example.com".to_string(),
            port: 443,
            cert: Some(CertInfo {
                subject: "CN = example.com".to_string(),
                issuer: "CN = CA".to_string(),

                not_after: String::new(),
                days_until_expiry: 15,
                self_signed: false,
            }),
            protocols: vec![],
            weak_ciphers: vec![],
            chain_valid: true,
            hsts: true,
        };

        let findings = generate_ssl_findings(&result);
        assert!(findings.iter().any(|f| f.title.contains("<30 days")));
    }

    #[test]
    fn test_generate_findings_expiry_90_days() {
        let result = SslScanResult {
            target: "example.com".to_string(),
            port: 443,
            cert: Some(CertInfo {
                subject: "CN = example.com".to_string(),
                issuer: "CN = CA".to_string(),

                not_after: String::new(),
                days_until_expiry: 60,
                self_signed: false,
            }),
            protocols: vec![],
            weak_ciphers: vec![],
            chain_valid: true,
            hsts: true,
        };

        let findings = generate_ssl_findings(&result);
        assert!(findings.iter().any(|f| f.title.contains("<90 days")));
    }
}
