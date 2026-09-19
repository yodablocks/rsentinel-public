//! rsentinel library for security detection and hardening.
//!
//! This library provides tools for:
//! - **Detection**: Scanning for exposed services and vulnerabilities via Shodan/CVEDB/nmap
//! - **Hardening**: Generating remediation recommendations for findings
//! - **Validation**: Testing security controls

pub mod api;
pub mod checker;
pub mod scanner;

pub use api::{CveDbClient, RateLimiter, ShodanClient};
pub use checker::{ExposureChecker, ExposureReport, Finding, Severity};
pub use scanner::{CertInfo, ProtocolInfo, SslError, SslScanResult, SslScanner};
pub use scanner::{DnsError, DnsScanResult, DnsScanner};
pub use scanner::{HeadersError, HeadersScanResult, HeadersScanner};
pub use scanner::{NmapScanner, PortInfo, ScanResult};
