//! rsentinel: Security detection and hardening tool for AI infrastructure.
//!
//! Follows ZK-Defense methodology:
//! - Threat Identification
//! - Detection & Assessment
//! - Hardening & Remediation
//! - Validation & Testing

mod api;
mod checker;
mod scanner;

use crate::checker::{ExposureChecker, ExposureReport, Severity, Finding};
use crate::checker::exposure::{ReportSummary, compute_grade};
use crate::scanner::NmapScanner;
use crate::scanner::ssl::{SslScanner, generate_ssl_findings};
use crate::scanner::headers::{HeadersScanner, generate_headers_findings};
use crate::scanner::dns::{DnsScanner, generate_dns_findings};
use crate::scanner::cors::{CorsScanner, generate_cors_findings};
use crate::scanner::paths::{PathsScanner, generate_paths_findings};
use crate::scanner::techdetect::{TechDetectScanner, generate_tech_findings};
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BANNER: &str = r#"
    ____  _____ _____ _   _ _____ ___ _   _ _____ _
   |  _ \/ ____| ____| \ | |_   _|_ _| \ | | ____| |
   | |_) \___ \|  _| |  \| | | |  | ||  \| |  _| | |
   |  _ < ___) | |___| |\  | | |  | || |\  | |___| |___
   |_| \_\____/|_____|_| \_| |_| |___|_| \_|_____|_____|
"#;

#[derive(Parser)]
#[command(name = "rsentinel")]
#[command(about = "Security detection and hardening tool for AI/Claude agent infrastructure")]
#[command(version)]
#[command(before_help = BANNER)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Shodan API key (or set SHODAN_API_KEY env var)
    #[arg(long, env = "SHODAN_API_KEY", global = true)]
    api_key: Option<String>,

    /// Output report as JSON instead of box-drawing format
    #[arg(long, global = true)]
    json: bool,

    /// Suppress progress lines (still shows final report)
    #[arg(short = 'Q', long, global = true)]
    quiet: bool,

    /// Exit with code 1 if any finding meets or exceeds this severity
    #[arg(long, global = true, value_name = "LEVEL")]
    fail_on: Option<String>,

    /// Export report as self-contained HTML file
    #[arg(long, global = true, value_name = "PATH")]
    html: Option<String>,

    /// Output report in SARIF v2.1.0 format (for GitHub Security tab)
    #[arg(long, global = true)]
    sarif: bool,

    /// Output report as Markdown
    #[arg(long, global = true)]
    markdown: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Check a specific IP address for exposures (requires Shodan API)
    CheckIp {
        /// Target IP address to check
        ip: String,
    },
    /// Scan for exposed AI/agent endpoints (requires Shodan API)
    ScanAi,
    /// Scan ports directly using nmap (FREE - no API needed)
    Scan {
        /// Target IP address or hostname to scan
        target: String,
        /// Quick scan (fewer ports, faster)
        #[arg(short, long)]
        quick: bool,
    },
    /// Check SSL/TLS configuration of a host (FREE - no API needed)
    SslCheck {
        /// Target hostname to check (e.g., example.com)
        host: String,
        /// Port to check (default: 443)
        #[arg(short, long, default_value = "443")]
        port: u16,
    },
    /// Check HTTP security headers of a host (FREE - no API needed)
    HeadersCheck {
        /// Target hostname to check (e.g., example.com)
        host: String,
    },
    /// Check DNS security configuration of a domain (FREE - no API needed)
    DnsCheck {
        /// Target domain to check (e.g., example.com)
        domain: String,
    },
    /// Check CORS misconfiguration of a host (FREE - no API needed)
    CorsCheck {
        /// Target hostname to check (e.g., example.com)
        host: String,
    },
    /// Probe for sensitive exposed paths (FREE - no API needed)
    PathsCheck {
        /// Target hostname to check (e.g., example.com)
        host: String,
    },
    /// Fingerprint technologies via response headers (FREE - no API needed)
    TechCheck {
        /// Target hostname to check (e.g., example.com)
        host: String,
    },
    /// Run all free scanners against a target (full audit)
    Audit {
        /// Target hostname or IP address
        target: String,
        /// SSL check port (default: 443)
        #[arg(short, long, default_value = "443")]
        port: u16,
        /// Quick nmap scan (fewer ports, faster)
        #[arg(short, long)]
        quick: bool,
    },
    /// Output a sample hardening report (demo mode)
    Demo,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load .env file if present
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();
    let json = cli.json;
    let quiet = cli.quiet;
    let fail_on = cli.fail_on.clone();
    let html_path = cli.html.clone();
    let sarif = cli.sarif;
    let markdown = cli.markdown;
    let verbose = !json && !quiet && !sarif && !markdown;

    let report: Option<ExposureReport>;

    match cli.command {
        Commands::CheckIp { ip } => {
            let api_key = cli.api_key.ok_or_else(|| {
                anyhow::anyhow!("Shodan API key required. Set --api-key or SHODAN_API_KEY env var")
            })?;

            let checker = ExposureChecker::new(api_key);
            let r = checker.check_ip(&ip).await?;
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::ScanAi => {
            let api_key = cli.api_key.ok_or_else(|| {
                anyhow::anyhow!("Shodan API key required. Set --api-key or SHODAN_API_KEY env var")
            })?;

            let checker = ExposureChecker::new(api_key);
            let r = checker.check_ai_exposure().await?;
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::Scan { target, quick } => {
            if verbose { println!("🔍 Scanning {} with nmap (no API calls)...\n", target); }

            let scanner = NmapScanner::new();
            let result = if quick {
                scanner.quick_scan(&target)?
            } else {
                scanner.scan(&target)?
            };

            let r = generate_nmap_report(&target, &result);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }

            if verbose { println!("⏱  Scan completed in {:.2} seconds", result.scan_time_seconds); }
            report = Some(r);
        }
        Commands::SslCheck { host, port } => {
            if verbose { println!("🔒 Checking SSL/TLS on {}:{}...\n", host, port); }

            let scanner = SslScanner::new();
            let result = scanner.scan(&host, port)?;
            let r = generate_ssl_report(&host, port, &result);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::HeadersCheck { host } => {
            if verbose { println!("🔒 Checking HTTP security headers on {}...\n", host); }

            let scanner = HeadersScanner::new();
            let result = scanner.scan(&host)?;
            let r = generate_headers_report(&host, &result);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::DnsCheck { domain } => {
            if verbose { println!("🔍 Checking DNS security for {}...\n", domain); }

            let scanner = DnsScanner::new();
            let result = scanner.scan(&domain)?;
            let r = generate_dns_report(&domain, &result);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::CorsCheck { host } => {
            if verbose { println!("🔍 Checking CORS configuration on {}...\n", host); }

            let scanner = CorsScanner::new();
            let result = scanner.scan(&host)?;
            let r = generate_cors_report(&host, &result);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::PathsCheck { host } => {
            if verbose { println!("🔍 Probing sensitive paths on {}...\n", host); }

            let scanner = PathsScanner::new();
            let result = scanner.scan(&host)?;
            let r = generate_paths_report(&host, &result);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::TechCheck { host } => {
            if verbose { println!("🔍 Fingerprinting technologies on {}...\n", host); }

            let scanner = TechDetectScanner::new();
            let result = scanner.scan(&host)?;
            let r = generate_tech_report(&host, &result);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::Audit { target, port, quick } => {
            if verbose { println!("🛡  Running full security audit on {}\n", target); }
            let mut all_findings: Vec<Finding> = Vec::new();
            // Track per-scanner results: (name, Result<Vec<Finding>>)
            let mut scanner_results: Vec<(&str, Result<Vec<Finding>, String>)> = Vec::new();

            // [1/7] Port scan (nmap)
            if verbose { println!("[1/7] Port scan (nmap)..."); }
            match (|| {
                let scanner = NmapScanner::new();
                if quick { scanner.quick_scan(&target) } else { scanner.scan(&target) }
            })() {
                Ok(result) => {
                    let r = generate_nmap_report(&target, &result);
                    let findings = r.findings;
                    if verbose { println!("      ✓ Found {} port findings\n", findings.len()); }
                    scanner_results.push(("Port Scan", Ok(findings)));
                }
                Err(e) => {
                    eprintln!("      ⚠ Port scan failed: {}\n", e);
                    scanner_results.push(("Port Scan", Err(e.to_string())));
                }
            }

            // [2/7] SSL/TLS check
            if verbose { println!("[2/7] SSL/TLS check on port {}...", port); }
            match SslScanner::new().scan(&target, port) {
                Ok(result) => {
                    let findings = generate_ssl_findings(&result);
                    if verbose { println!("      ✓ Found {} SSL/TLS findings\n", findings.len()); }
                    scanner_results.push(("SSL/TLS", Ok(findings)));
                }
                Err(e) => {
                    eprintln!("      ⚠ SSL/TLS check failed: {}\n", e);
                    scanner_results.push(("SSL/TLS", Err(e.to_string())));
                }
            }

            // [3/7] HTTP security headers
            if verbose { println!("[3/7] HTTP security headers..."); }
            match HeadersScanner::new().scan(&target) {
                Ok(result) => {
                    let findings = generate_headers_findings(&result);
                    if verbose { println!("      ✓ Found {} header findings\n", findings.len()); }
                    scanner_results.push(("Headers", Ok(findings)));
                }
                Err(e) => {
                    eprintln!("      ⚠ Headers check failed: {}\n", e);
                    scanner_results.push(("Headers", Err(e.to_string())));
                }
            }

            // [4/7] DNS security
            if verbose { println!("[4/7] DNS security..."); }
            match DnsScanner::new().scan(&target) {
                Ok(result) => {
                    let findings = generate_dns_findings(&result);
                    if verbose { println!("      ✓ Found {} DNS findings\n", findings.len()); }
                    scanner_results.push(("DNS", Ok(findings)));
                }
                Err(e) => {
                    eprintln!("      ⚠ DNS check failed: {}\n", e);
                    scanner_results.push(("DNS", Err(e.to_string())));
                }
            }

            // [5/7] CORS check
            if verbose { println!("[5/7] CORS configuration..."); }
            match CorsScanner::new().scan(&target) {
                Ok(result) => {
                    let findings = generate_cors_findings(&result);
                    if verbose { println!("      ✓ Found {} CORS findings\n", findings.len()); }
                    scanner_results.push(("CORS", Ok(findings)));
                }
                Err(e) => {
                    eprintln!("      ⚠ CORS check failed: {}\n", e);
                    scanner_results.push(("CORS", Err(e.to_string())));
                }
            }

            // [6/7] Sensitive paths
            if verbose { println!("[6/7] Sensitive path exposure..."); }
            match PathsScanner::new().scan(&target) {
                Ok(result) => {
                    let findings = generate_paths_findings(&result);
                    if verbose { println!("      ✓ Found {} path findings\n", findings.len()); }
                    scanner_results.push(("Paths", Ok(findings)));
                }
                Err(e) => {
                    eprintln!("      ⚠ Paths check failed: {}\n", e);
                    scanner_results.push(("Paths", Err(e.to_string())));
                }
            }

            // [7/7] Technology fingerprinting
            if verbose { println!("[7/7] Technology fingerprinting..."); }
            match TechDetectScanner::new().scan(&target) {
                Ok(result) => {
                    let findings = generate_tech_findings(&result);
                    if verbose { println!("      ✓ Found {} tech findings\n", findings.len()); }
                    scanner_results.push(("Tech Detect", Ok(findings)));
                }
                Err(e) => {
                    eprintln!("      ⚠ Tech detection failed: {}\n", e);
                    scanner_results.push(("Tech Detect", Err(e.to_string())));
                }
            }

            // Collect all findings and print dashboard
            for (_, result) in &scanner_results {
                if let Ok(findings) = result {
                    all_findings.extend(findings.clone());
                }
            }

            if verbose {
                print_audit_dashboard(&scanner_results);
            }

            let r = generate_audit_report(&target, all_findings);
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
        Commands::Demo => {
            if verbose { println!("Running demo with sample findings...\n"); }
            let r = build_demo_report();
            if json { print_json(&r) } else if sarif { print_sarif(&r) } else if markdown { print_markdown(&r) } else { print_report(&r) }
            report = Some(r);
        }
    }

    // Write HTML report if requested
    if let (Some(path), Some(r)) = (html_path, &report) {
        write_html_report(r, &path)?;
        if verbose { println!("HTML report written to {}", path); }
    }

    // Check --fail-on threshold
    if let (Some(ref level), Some(r)) = (fail_on, &report) {
        let threshold = match level.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            other => {
                eprintln!("Unknown severity level for --fail-on: {}. Use critical, high, medium, or low.", other);
                std::process::exit(2);
            }
        };
        let dominated = r.findings.iter().any(|f| f.severity >= threshold);
        if dominated {
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Generate an exposure report from nmap scan results.
fn generate_nmap_report(target: &str, result: &scanner::ScanResult) -> ExposureReport {
    let mut findings = Vec::new();

    for port_info in &result.ports {
        if let Some(finding) = create_port_finding(target, port_info) {
            findings.push(finding);
        }
    }

    let summary = ReportSummary {
        total_findings: findings.len(),
        critical_count: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
        high_count: findings.iter().filter(|f| f.severity == Severity::High).count(),
        medium_count: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
        low_count: findings.iter().filter(|f| f.severity == Severity::Low).count(),
        info_count: findings.iter().filter(|f| f.severity == Severity::Info).count(),
    };

    let grade = compute_grade(&summary);
    ExposureReport {
        target: target.to_string(),
        scan_time: chrono::Utc::now().to_rfc3339(),
        findings,
        summary,
        grade,
    }
}

/// Create a finding for a detected open port.
fn create_port_finding(ip: &str, port_info: &scanner::PortInfo) -> Option<Finding> {
    let port = port_info.port;
    let service = &port_info.service;
    let version_info = port_info.version.as_deref().unwrap_or("");

    let (severity, title, remediation) = match port {
        22 => (
            Severity::Medium,
            "SSH Exposed to Internet",
            "HARDENING:\n\
             1. Use a VPN or bastion host for SSH access\n\
             2. Implement IP allowlisting via firewall\n\
             3. Use SSH keys only (disable password auth)\n\
             4. Enable fail2ban or similar brute-force protection\n\
             5. Consider using a non-standard port"
        ),
        23 => (
            Severity::Critical,
            "Telnet Exposed (Unencrypted)",
            "HARDENING:\n\
             1. IMMEDIATELY disable Telnet service\n\
             2. Replace with SSH for remote access\n\
             3. Block port 23 at firewall level\n\
             4. Audit for any credentials transmitted over Telnet"
        ),
        21 => (
            Severity::High,
            "FTP Exposed",
            "HARDENING:\n\
             1. Replace FTP with SFTP or SCP\n\
             2. If FTP required, enable TLS (FTPS)\n\
             3. Restrict access via firewall\n\
             4. Use strong credentials and disable anonymous access"
        ),
        80 => (
            Severity::Low,
            "HTTP Exposed (Unencrypted)",
            "HARDENING:\n\
             1. Redirect all HTTP traffic to HTTPS\n\
             2. Enable HSTS headers\n\
             3. Ensure sensitive data never transmitted over HTTP\n\
             4. Consider disabling HTTP entirely if not needed"
        ),
        443 => (
            Severity::Info,
            "HTTPS Exposed",
            "INFO:\n\
             1. HTTPS is generally safe for public services\n\
             2. Ensure TLS 1.2+ is enforced\n\
             3. Use strong cipher suites\n\
             4. Keep certificates up to date"
        ),
        3306 => (
            Severity::High,
            "MySQL Database Exposed",
            "HARDENING:\n\
             1. Block port 3306 from public internet\n\
             2. Use VPN or SSH tunnel for database access\n\
             3. Ensure bind-address is set to 127.0.0.1 or private IP\n\
             4. Review and restrict database user privileges\n\
             5. Enable TLS for database connections"
        ),
        5432 => (
            Severity::High,
            "PostgreSQL Database Exposed",
            "HARDENING:\n\
             1. Block port 5432 from public internet\n\
             2. Configure pg_hba.conf to restrict access\n\
             3. Use VPN or SSH tunnel for remote access\n\
             4. Enable SSL in postgresql.conf\n\
             5. Review database user permissions"
        ),
        6379 => (
            Severity::Critical,
            "Redis Exposed (Often No Auth)",
            "HARDENING:\n\
             1. IMMEDIATELY block port 6379 from internet\n\
             2. Enable Redis AUTH with strong password\n\
             3. Bind to localhost or private network only\n\
             4. Enable TLS if remote access is required\n\
             5. Disable dangerous commands (FLUSHALL, CONFIG, etc.)"
        ),
        27017 => (
            Severity::Critical,
            "MongoDB Exposed",
            "HARDENING:\n\
             1. Block port 27017 from public internet\n\
             2. Enable authentication (--auth flag)\n\
             3. Bind to localhost: bindIp: 127.0.0.1\n\
             4. Enable TLS/SSL for connections\n\
             5. Create specific users with minimal privileges"
        ),
        9200 => (
            Severity::High,
            "Elasticsearch Exposed",
            "HARDENING:\n\
             1. Block port 9200 from public internet\n\
             2. Enable X-Pack security features\n\
             3. Set network.host to private IP\n\
             4. Implement authentication and TLS\n\
             5. Use reverse proxy with auth for any web access"
        ),
        2375 | 2376 => (
            Severity::Critical,
            "Docker API Exposed",
            "HARDENING:\n\
             1. NEVER expose Docker API to internet\n\
             2. Use TLS client certificates if remote access needed\n\
             3. Block ports 2375/2376 at firewall\n\
             4. Use SSH tunneling for remote Docker access\n\
             5. Consider using Docker contexts with SSH"
        ),
        8080 | 8443 => (
            Severity::Medium,
            "Web Application Port Exposed",
            "HARDENING:\n\
             1. Review if this service should be public\n\
             2. Ensure proper authentication is enabled\n\
             3. Use HTTPS with valid certificates\n\
             4. Implement rate limiting\n\
             5. Review access logs regularly"
        ),
        3389 => (
            Severity::High,
            "RDP Exposed (Remote Desktop)",
            "HARDENING:\n\
             1. Block RDP from public internet\n\
             2. Use VPN for remote access\n\
             3. Enable Network Level Authentication (NLA)\n\
             4. Use strong passwords and MFA\n\
             5. Keep systems patched (BlueKeep, etc.)"
        ),
        445 => (
            Severity::Critical,
            "SMB Exposed",
            "HARDENING:\n\
             1. IMMEDIATELY block port 445 from internet\n\
             2. SMB should never be internet-facing\n\
             3. Disable SMBv1\n\
             4. Use VPN for file sharing needs\n\
             5. Patch for EternalBlue and similar vulnerabilities"
        ),
        _ => {
            // For unknown ports, create a generic info finding
            return Some(Finding {
                severity: Severity::Info,
                title: format!("Open Port Detected: {}/{}", port, port_info.protocol),
                description: format!(
                    "Port {} ({}) is open on {}\nService: {}\nVersion: {}",
                    port, port_info.protocol, ip, service, version_info
                ),
                affected_asset: format!("{}:{}", ip, port),
                remediation: "REVIEW:\n\
                    1. Verify this port should be publicly accessible\n\
                    2. Ensure the service has proper authentication\n\
                    3. Keep the service updated\n\
                    4. Monitor access logs".to_string(),
                references: vec![],
            });
        }
    };

    Some(Finding {
        severity,
        title: title.to_string(),
        description: format!(
            "Port {} is open on {}\nService: {}\nVersion: {}",
            port, ip, service, version_info
        ),
        affected_asset: format!("{}:{}", ip, port),
        remediation: remediation.to_string(),
        references: vec![
            "https://owasp.org/www-project-web-security-testing-guide/".to_string(),
        ],
    })
}

/// Build summary and grade from findings, returning (summary, grade).
fn build_summary(findings: &[Finding]) -> (ReportSummary, String) {
    let summary = ReportSummary {
        total_findings: findings.len(),
        critical_count: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
        high_count: findings.iter().filter(|f| f.severity == Severity::High).count(),
        medium_count: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
        low_count: findings.iter().filter(|f| f.severity == Severity::Low).count(),
        info_count: findings.iter().filter(|f| f.severity == Severity::Info).count(),
    };
    let grade = compute_grade(&summary);
    (summary, grade)
}

/// Generate an exposure report from SSL/TLS scan results.
fn generate_ssl_report(host: &str, port: u16, result: &scanner::ssl::SslScanResult) -> ExposureReport {
    let findings = generate_ssl_findings(result);
    let (summary, grade) = build_summary(&findings);
    ExposureReport { target: format!("{}:{}", host, port), scan_time: chrono::Utc::now().to_rfc3339(), findings, summary, grade }
}

/// Generate an exposure report from HTTP headers scan results.
fn generate_headers_report(host: &str, result: &scanner::headers::HeadersScanResult) -> ExposureReport {
    let findings = generate_headers_findings(result);
    let (summary, grade) = build_summary(&findings);
    ExposureReport { target: host.to_string(), scan_time: chrono::Utc::now().to_rfc3339(), findings, summary, grade }
}

/// Generate an exposure report from DNS scan results.
fn generate_dns_report(domain: &str, result: &scanner::dns::DnsScanResult) -> ExposureReport {
    let findings = generate_dns_findings(result);
    let (summary, grade) = build_summary(&findings);
    ExposureReport { target: domain.to_string(), scan_time: chrono::Utc::now().to_rfc3339(), findings, summary, grade }
}

/// Generate an exposure report from CORS scan results.
fn generate_cors_report(host: &str, result: &scanner::cors::CorsScanResult) -> ExposureReport {
    let findings = generate_cors_findings(result);
    let (summary, grade) = build_summary(&findings);
    ExposureReport { target: host.to_string(), scan_time: chrono::Utc::now().to_rfc3339(), findings, summary, grade }
}

/// Generate an exposure report from sensitive paths scan results.
fn generate_paths_report(host: &str, result: &scanner::paths::PathsScanResult) -> ExposureReport {
    let findings = generate_paths_findings(result);
    let (summary, grade) = build_summary(&findings);
    ExposureReport { target: host.to_string(), scan_time: chrono::Utc::now().to_rfc3339(), findings, summary, grade }
}

/// Generate an exposure report from technology fingerprint results.
fn generate_tech_report(host: &str, result: &scanner::techdetect::TechDetectResult) -> ExposureReport {
    let findings = generate_tech_findings(result);
    let (summary, grade) = build_summary(&findings);
    ExposureReport { target: host.to_string(), scan_time: chrono::Utc::now().to_rfc3339(), findings, summary, grade }
}

/// Generate a combined audit report from all scanner findings.
fn generate_audit_report(target: &str, findings: Vec<Finding>) -> ExposureReport {
    let (summary, grade) = build_summary(&findings);
    ExposureReport { target: target.to_string(), scan_time: chrono::Utc::now().to_rfc3339(), findings, summary, grade }
}

fn print_json(report: &ExposureReport) {
    println!("{}", serde_json::to_string_pretty(report).unwrap());
}

fn print_report(report: &ExposureReport) {
    println!("\n╔═════════════════════════════════════════════════════════════╗");
    println!("║             RSENTINEL SECURITY EXPOSURE REPORT              ║");
    println!("╚═════════════════════════════════════════════════════════════╝\n");

    println!("Target: {}", report.target);
    println!("Scan Time: {}", report.scan_time);
    println!();

    println!("┌─────────────────────────────────────────────────────────────┐");
    println!("│ SUMMARY                                                     │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│ Total Findings: {:3}                                         │", report.summary.total_findings);
    println!("│ Critical:       {:3}                                         │", report.summary.critical_count);
    println!("│ High:           {:3}                                         │", report.summary.high_count);
    println!("│ Medium:         {:3}                                         │", report.summary.medium_count);
    println!("│ Low:            {:3}                                         │", report.summary.low_count);
    println!("│ Info:           {:3}                                         │", report.summary.info_count);
    println!("└─────────────────────────────────────────────────────────────┘\n");

    if report.findings.is_empty() {
        println!("✓ No exposures detected.\n");
        return;
    }

    for (i, finding) in report.findings.iter().enumerate() {
        let severity_icon = match finding.severity {
            Severity::Critical => "🔴 CRITICAL",
            Severity::High => "🟠 HIGH",
            Severity::Medium => "🟡 MEDIUM",
            Severity::Low => "🔵 LOW",
            Severity::Info => "⚪ INFO",
        };

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Finding #{}: {} - {}", i + 1, severity_icon, finding.title);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        println!("Affected Asset: {}", finding.affected_asset);
        println!();
        println!("Description:");
        println!("{}", finding.description);
        println!();
        println!("Remediation:");
        println!("{}", finding.remediation);

        if !finding.references.is_empty() {
            println!();
            println!("References:");
            for r in &finding.references {
                println!("  • {}", r);
            }
        }
        println!();
    }

    if report.has_critical() {
        println!("⚠️  CRITICAL ISSUES DETECTED - IMMEDIATE ACTION REQUIRED ⚠️\n");
    }

    // Severity summary one-liner
    println!(
        "\x1b[91m{} critical\x1b[0m, \x1b[33m{} high\x1b[0m, \x1b[93m{} medium\x1b[0m, \x1b[94m{} low\x1b[0m, \x1b[37m{} info\x1b[0m",
        report.summary.critical_count,
        report.summary.high_count,
        report.summary.medium_count,
        report.summary.low_count,
        report.summary.info_count,
    );

    // Security grade
    let grade_color = match report.grade.as_str() {
        "A+" | "A" => "\x1b[92m", // green
        "B" => "\x1b[93m",        // yellow
        "C" => "\x1b[33m",        // orange
        "D" => "\x1b[91m",        // red
        _ => "\x1b[91;1m",        // bold red for F
    };
    println!("Security Grade: {}{}  \x1b[0m", grade_color, report.grade);
    println!();
}

fn print_sarif(report: &ExposureReport) {
    let results: Vec<serde_json::Value> = report.findings.iter().map(|f| {
        let level = match f.severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        };
        serde_json::json!({
            "ruleId": f.title.replace(' ', "-").to_lowercase(),
            "level": level,
            "message": { "text": f.description },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": f.affected_asset }
                }
            }],
            "properties": {
                "severity": format!("{:?}", f.severity),
                "remediation": f.remediation,
            }
        })
    }).collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rsentinel",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/yodablocks/rsentinel"
                }
            },
            "results": results,
            "properties": {
                "grade": report.grade,
            }
        }]
    });

    println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
}

fn print_audit_dashboard(results: &[(&str, Result<Vec<Finding>, String>)]) {
    println!("\n┌──────────────────┬────────┬────────────────────┐");
    println!("│ Scanner          │ Status │ Findings           │");
    println!("├──────────────────┼────────┼────────────────────┤");
    for (name, result) in results {
        match result {
            Err(_) => {
                println!(
                    "│ {:<16} │ \x1b[91mERROR\x1b[0m  │ scanner failed     │",
                    name
                );
            }
            Ok(findings) => {
                let has_crit = findings.iter().any(|f| f.severity == Severity::Critical);
                let has_high = findings.iter().any(|f| f.severity == Severity::High);
                let has_med = findings.iter().any(|f| f.severity == Severity::Medium);
                let (status, color) = if has_crit || has_high {
                    ("FAIL", "\x1b[91m")
                } else if has_med {
                    ("WARN", "\x1b[93m")
                } else {
                    ("PASS", "\x1b[92m")
                };
                // Build findings summary
                let mut parts: Vec<String> = Vec::new();
                let crit = findings.iter().filter(|f| f.severity == Severity::Critical).count();
                let high = findings.iter().filter(|f| f.severity == Severity::High).count();
                let med = findings.iter().filter(|f| f.severity == Severity::Medium).count();
                let low = findings.iter().filter(|f| f.severity == Severity::Low).count();
                let info = findings.iter().filter(|f| f.severity == Severity::Info).count();
                if crit > 0 { parts.push(format!("{} critical", crit)); }
                if high > 0 { parts.push(format!("{} high", high)); }
                if med > 0 { parts.push(format!("{} medium", med)); }
                if low > 0 { parts.push(format!("{} low", low)); }
                if info > 0 { parts.push(format!("{} info", info)); }
                let summary = if parts.is_empty() { "none".to_string() } else { parts.join(", ") };
                println!(
                    "│ {:<16} │ {}{:<4}\x1b[0m   │ {:<18} │",
                    name, color, status, summary
                );
            }
        }
    }
    println!("└──────────────────┴────────┴────────────────────┘\n");
}

fn print_markdown(report: &ExposureReport) {
    println!("# rsentinel Security Report\n");
    println!("- **Target:** {}", report.target);
    println!("- **Date:** {}", report.scan_time);
    println!("- **Grade:** {}\n", report.grade);

    println!("## Summary\n");
    println!("| Severity | Count |");
    println!("|----------|-------|");
    println!("| Critical | {} |", report.summary.critical_count);
    println!("| High     | {} |", report.summary.high_count);
    println!("| Medium   | {} |", report.summary.medium_count);
    println!("| Low      | {} |", report.summary.low_count);
    println!("| Info     | {} |", report.summary.info_count);
    println!("| **Total** | **{}** |\n", report.summary.total_findings);

    if report.findings.is_empty() {
        println!("No findings.\n");
        return;
    }

    println!("## Findings\n");
    for (i, f) in report.findings.iter().enumerate() {
        let sev = match f.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        println!("### #{} [{}] {}\n", i + 1, sev, f.title);
        println!("**Asset:** {}\n", f.affected_asset);
        println!("{}\n", f.description);
        println!("**Remediation:**\n");
        println!("{}\n", f.remediation);
        if !f.references.is_empty() {
            println!("**References:**\n");
            for r in &f.references {
                println!("- {}", r);
            }
            println!();
        }
    }
}

fn write_html_report(report: &ExposureReport, path: &str) -> anyhow::Result<()> {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("<title>rsentinel Security Report</title>\n<style>\n");
    html.push_str(r#"
body { background: #1a1a2e; color: #e0e0e0; font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 2rem; }
h1 { color: #00d4ff; text-align: center; border-bottom: 2px solid #00d4ff; padding-bottom: 1rem; }
.meta { text-align: center; color: #888; margin-bottom: 2rem; }
.summary { display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; margin-bottom: 2rem; }
.badge { padding: 0.5rem 1.2rem; border-radius: 6px; font-weight: bold; font-size: 1.1rem; }
.critical { background: #ff1744; color: #fff; }
.high { background: #ff9100; color: #000; }
.medium { background: #ffd600; color: #000; }
.low { background: #2979ff; color: #fff; }
.info { background: #546e7a; color: #fff; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th { background: #16213e; color: #00d4ff; padding: 0.8rem; text-align: left; }
td { padding: 0.8rem; border-bottom: 1px solid #2a2a4a; vertical-align: top; }
tr:hover { background: #16213e; }
.sev-cell { font-weight: bold; text-transform: uppercase; }
pre { background: #0f0f23; padding: 1rem; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }
"#);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str("<h1>RSENTINEL SECURITY EXPOSURE REPORT</h1>\n");
    html.push_str(&format!("<div class=\"meta\">Target: {} | Scan Time: {} | Grade: {}</div>\n", report.target, report.scan_time, report.grade));

    // Summary badges
    html.push_str("<div class=\"summary\">\n");
    html.push_str(&format!("<span class=\"badge critical\">{} Critical</span>\n", report.summary.critical_count));
    html.push_str(&format!("<span class=\"badge high\">{} High</span>\n", report.summary.high_count));
    html.push_str(&format!("<span class=\"badge medium\">{} Medium</span>\n", report.summary.medium_count));
    html.push_str(&format!("<span class=\"badge low\">{} Low</span>\n", report.summary.low_count));
    html.push_str(&format!("<span class=\"badge info\">{} Info</span>\n", report.summary.info_count));
    html.push_str("</div>\n");

    // Findings table
    html.push_str("<table>\n<tr><th>#</th><th>Severity</th><th>Title</th><th>Asset</th><th>Description</th><th>Remediation</th></tr>\n");
    for (i, f) in report.findings.iter().enumerate() {
        let sev_class = match f.severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        let desc_escaped = f.description.replace('<', "&lt;").replace('>', "&gt;");
        let rem_escaped = f.remediation.replace('<', "&lt;").replace('>', "&gt;");
        html.push_str(&format!(
            "<tr><td>{}</td><td class=\"sev-cell {}\">{:?}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td><td><pre>{}</pre></td></tr>\n",
            i + 1, sev_class, f.severity, f.title, f.affected_asset, desc_escaped, rem_escaped
        ));
    }
    html.push_str("</table>\n</body>\n</html>\n");

    std::fs::write(path, html)?;
    Ok(())
}

fn build_demo_report() -> ExposureReport {
    let findings = vec![
        Finding {
            severity: Severity::Critical,
            title: "Redis Exposed (Often No Auth)".to_string(),
            description: "Port 6379 is exposed to the internet on 192.0.2.1".to_string(),
            affected_asset: "192.0.2.1:6379".to_string(),
            remediation: "HARDENING:\n\
                1. IMMEDIATELY block port 6379 from internet\n\
                2. Enable Redis AUTH with strong password\n\
                3. Bind to localhost or private network only\n\
                4. Enable TLS if remote access is required\n\
                5. Disable dangerous commands (FLUSHALL, CONFIG, etc.)".to_string(),
            references: vec!["https://redis.io/docs/management/security/".to_string()],
        },
        Finding {
            severity: Severity::Critical,
            title: "AI/Agent Interface Exposed".to_string(),
            description: "AI interface 'Claude Agent Dashboard' is publicly accessible".to_string(),
            affected_asset: "192.0.2.1:8080".to_string(),
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
        },
        Finding {
            severity: Severity::High,
            title: "Vulnerability: CVE-2024-1234".to_string(),
            description: "Example vulnerability affecting the target system".to_string(),
            affected_asset: "192.0.2.1".to_string(),
            remediation: "HARDENING:\n\
                1. Check if patch is available for CVE-2024-1234\n\
                2. Apply vendor patches immediately\n\
                3. If no patch, implement compensating controls:\n\
                   - Network segmentation\n\
                   - WAF rules if applicable\n\
                   - Disable affected feature if possible\n\
                4. Monitor for exploitation attempts\n\
                5. CVSS Score: 8.5".to_string(),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1234".to_string()],
        },
        Finding {
            severity: Severity::Medium,
            title: "SSH Exposed to Internet".to_string(),
            description: "Port 22 is exposed to the internet on 192.0.2.1".to_string(),
            affected_asset: "192.0.2.1:22".to_string(),
            remediation: "HARDENING:\n\
                1. Use a VPN or bastion host for SSH access\n\
                2. Implement IP allowlisting via firewall\n\
                3. Use SSH keys only (disable password auth)\n\
                4. Enable fail2ban or similar brute-force protection\n\
                5. Consider using a non-standard port".to_string(),
            references: vec![],
        },
    ];

    let summary = ReportSummary {
        total_findings: findings.len(),
        critical_count: 2,
        high_count: 1,
        medium_count: 1,
        low_count: 0,
        info_count: 0,
    };
    let grade = compute_grade(&summary);

    ExposureReport {
        target: "demo-target.example.com".to_string(),
        scan_time: chrono::Utc::now().to_rfc3339(),
        findings,
        summary,
        grade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: capture print_report output by building a report and formatting it
    /// the same way print_report does, then check box alignment.
    fn report_output(findings: Vec<Finding>) -> String {
        let summary = ReportSummary {
            total_findings: findings.len(),
            critical_count: findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            high_count: findings.iter().filter(|f| f.severity == Severity::High).count(),
            medium_count: findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            low_count: findings.iter().filter(|f| f.severity == Severity::Low).count(),
            info_count: findings.iter().filter(|f| f.severity == Severity::Info).count(),
        };
        let grade = compute_grade(&summary);
        let report = ExposureReport {
            target: "test.example.com".to_string(),
            scan_time: "2026-01-29T00:00:00Z".to_string(),
            findings,
            summary,
            grade,
        };
        // Build the same strings print_report would produce
        format_report(&report)
    }

    /// Replicate the box-drawing lines from print_report as format strings.
    fn format_report(report: &ExposureReport) -> String {
        let mut out = String::new();
        out.push_str(&format!("╔═════════════════════════════════════════════════════════════╗\n"));
        out.push_str(&format!("║             RSENTINEL SECURITY EXPOSURE REPORT              ║\n"));
        out.push_str(&format!("╚═════════════════════════════════════════════════════════════╝\n"));
        out.push_str(&format!("┌─────────────────────────────────────────────────────────────┐\n"));
        out.push_str(&format!("│ SUMMARY                                                     │\n"));
        out.push_str(&format!("├─────────────────────────────────────────────────────────────┤\n"));
        out.push_str(&format!("│ Total Findings: {:3}                                         │\n", report.summary.total_findings));
        out.push_str(&format!("│ Critical:       {:3}                                         │\n", report.summary.critical_count));
        out.push_str(&format!("│ High:           {:3}                                         │\n", report.summary.high_count));
        out.push_str(&format!("│ Medium:         {:3}                                         │\n", report.summary.medium_count));
        out.push_str(&format!("│ Low:            {:3}                                         │\n", report.summary.low_count));
        out.push_str(&format!("│ Info:           {:3}                                         │\n", report.summary.info_count));
        out.push_str(&format!("└─────────────────────────────────────────────────────────────┘\n"));
        out
    }

    #[test]
    fn test_header_box_alignment() {
        let top    = "╔═════════════════════════════════════════════════════════════╗";
        let middle = "║             RSENTINEL SECURITY EXPOSURE REPORT              ║";
        let bottom = "╚═════════════════════════════════════════════════════════════╝";

        // All three lines must have the same display width
        assert_eq!(
            top.chars().count(),
            middle.chars().count(),
            "Header top and middle have different char counts: top={}, middle={}",
            top.chars().count(),
            middle.chars().count()
        );
        assert_eq!(
            top.chars().count(),
            bottom.chars().count(),
            "Header top and bottom have different char counts: top={}, bottom={}",
            top.chars().count(),
            bottom.chars().count()
        );
    }

    #[test]
    fn test_summary_box_alignment() {
        let border   = "┌─────────────────────────────────────────────────────────────┐";
        let header   = "│ SUMMARY                                                     │";
        let divider  = "├─────────────────────────────────────────────────────────────┤";
        let total    = format!("│ Total Findings: {:3}                                         │", 999);
        let critical = format!("│ Critical:       {:3}                                         │", 999);
        let high     = format!("│ High:           {:3}                                         │", 999);
        let medium   = format!("│ Medium:         {:3}                                         │", 999);
        let low      = format!("│ Low:            {:3}                                         │", 999);
        let info     = format!("│ Info:           {:3}                                         │", 999);
        let bottom   = "└─────────────────────────────────────────────────────────────┘";

        let expected_len = border.chars().count();
        let lines: Vec<(&str, String)> = vec![
            ("border",   border.to_string()),
            ("header",   header.to_string()),
            ("divider",  divider.to_string()),
            ("total",    total),
            ("critical", critical),
            ("high",     high),
            ("medium",   medium),
            ("low",      low),
            ("info",     info),
            ("bottom",   bottom.to_string()),
        ];

        for (name, line) in &lines {
            assert_eq!(
                line.chars().count(),
                expected_len,
                "Summary line '{}' has {} chars, expected {}: \"{}\"",
                name,
                line.chars().count(),
                expected_len,
                line
            );
        }
    }

    #[test]
    fn test_summary_box_with_zero_findings() {
        let output = report_output(vec![]);
        assert!(output.contains("Total Findings:   0"));
        assert!(output.contains("Critical:         0"));
    }

    #[test]
    fn test_summary_box_with_many_findings() {
        // Ensure 3-digit counts still fit in the box
        let summary = ReportSummary {
            total_findings: 100,
            critical_count: 100,
            high_count: 100,
            medium_count: 100,
            low_count: 100,
            info_count: 100,
        };
        let grade = compute_grade(&summary);
        let output = format_report(&ExposureReport {
            target: "test".to_string(),
            scan_time: "now".to_string(),
            findings: vec![],
            summary,
            grade,
        });

        // Every line with │ bookends should be the same length
        let box_lines: Vec<&str> = output
            .lines()
            .filter(|l| l.starts_with('│') || l.starts_with('┌') || l.starts_with('├') || l.starts_with('└'))
            .collect();

        let first_len = box_lines[0].chars().count();
        for line in &box_lines {
            assert_eq!(
                line.chars().count(),
                first_len,
                "Misaligned line (len {}): \"{}\"",
                line.chars().count(),
                line
            );
        }
    }

    #[test]
    fn test_header_and_summary_boxes_same_width() {
        let header_top = "╔═════════════════════════════════════════════════════════════╗";
        let summary_top = "┌─────────────────────────────────────────────────────────────┐";
        assert_eq!(
            header_top.chars().count(),
            summary_top.chars().count(),
            "Header box and summary box have different widths"
        );
    }
}
