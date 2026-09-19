//! Nmap-based port scanner for local scanning.
//!
//! DETECTION MODULE: Scans ports directly without API calls.

use std::process::Command;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NmapError {
    #[error("nmap not found - install with: brew install nmap")]
    NotInstalled,

    #[error("nmap execution failed: {0}")]
    ExecutionFailed(String),

    #[error("permission denied - some scans require sudo")]
    PermissionDenied,
}

/// Information about an open port.
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub version: Option<String>,
}

/// Result of an nmap scan.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ports: Vec<PortInfo>,
    pub scan_time_seconds: f32,
}

/// Nmap scanner for direct port scanning.
pub struct NmapScanner {
    /// Ports to scan (default: common high-risk ports)
    ports: Vec<u16>,
    /// Enable service version detection
    version_detection: bool,
    /// Scan timeout in seconds
    timeout: u32,
}

impl NmapScanner {
    /// Create a new scanner with default settings.
    pub fn new() -> Self {
        Self {
            ports: vec![
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                993, 995, 1433, 1521, 2375, 2376, 3306, 3389,
                5432, 5900, 6379, 8080, 8443, 9000, 9200, 27017,
            ],
            version_detection: true,
            timeout: 120,
        }
    }

    /// Scan a target IP address or hostname.
    pub fn scan(&self, target: &str) -> Result<ScanResult, NmapError> {
        // Check if nmap is available
        self.check_nmap_installed()?;

        // Build port list
        let port_list: String = self.ports.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Build nmap command
        let mut args = vec![
            "-Pn".to_string(),           // Skip host discovery (assume online)
            "-T4".to_string(),           // Aggressive timing
            format!("-p{}", port_list),  // Ports to scan
            "--open".to_string(),        // Only show open ports
        ];

        if self.version_detection {
            args.push("-sV".to_string());        // Version detection
            args.push("--version-light".to_string()); // Light version scan (faster)
        }

        args.push(format!("--host-timeout={}s", self.timeout));
        args.push(target.to_string());

        // Execute nmap
        let output = Command::new("nmap")
            .args(&args)
            .output()
            .map_err(|e| NmapError::ExecutionFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("permission") || stderr.contains("root") {
                return Err(NmapError::PermissionDenied);
            }
            return Err(NmapError::ExecutionFailed(stderr.to_string()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_output(target, &stdout)
    }

    /// Quick scan of most common dangerous ports on an IP address or hostname.
    pub fn quick_scan(&self, target: &str) -> Result<ScanResult, NmapError> {
        self.check_nmap_installed()?;

        // Only scan the most critical ports
        let port_arg = "-p22,23,80,443,3306,5432,6379,8080,27017".to_string();

        let args = vec![
            "-Pn".to_string(),
            "-T4".to_string(),
            port_arg,
            "--open".to_string(),
            target.to_string(),
        ];

        let output = Command::new("nmap")
            .args(&args)
            .output()
            .map_err(|e| NmapError::ExecutionFailed(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_output(target, &stdout)
    }

    fn check_nmap_installed(&self) -> Result<(), NmapError> {
        Command::new("nmap")
            .arg("--version")
            .output()
            .map_err(|_| NmapError::NotInstalled)?;
        Ok(())
    }

    fn parse_output(&self, _target: &str, output: &str) -> Result<ScanResult, NmapError> {
        let mut ports = Vec::new();
        let mut scan_time = 0.0f32;

        for line in output.lines() {
            // Parse port lines: "22/tcp   open  ssh     OpenSSH 8.9"
            if line.contains("/tcp") || line.contains("/udp") {
                if let Some(port_info) = self.parse_port_line(line) {
                    ports.push(port_info);
                }
            }

            // Parse scan time
            if line.contains("scanned in") {
                if let Some(time) = self.parse_scan_time(line) {
                    scan_time = time;
                }
            }
        }

        Ok(ScanResult {
            ports,
            scan_time_seconds: scan_time,
        })
    }

    fn parse_port_line(&self, line: &str) -> Option<PortInfo> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        // Parse "22/tcp"
        let port_proto: Vec<&str> = parts[0].split('/').collect();
        if port_proto.len() != 2 {
            return None;
        }

        let port: u16 = port_proto[0].parse().ok()?;
        let protocol = port_proto[1].to_string();
        let service = parts.get(2).unwrap_or(&"unknown").to_string();

        // Version is everything after service name
        let version = if parts.len() > 3 {
            Some(parts[3..].join(" "))
        } else {
            None
        };

        Some(PortInfo {
            port,
            protocol,
            service,
            version,
        })
    }

    fn parse_scan_time(&self, line: &str) -> Option<f32> {
        // "Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds"
        let parts: Vec<&str> = line.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "in" && i + 1 < parts.len() {
                return parts[i + 1].parse().ok();
            }
        }
        None
    }
}

impl Default for NmapScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_line() {
        let scanner = NmapScanner::new();

        let line = "22/tcp   open  ssh     OpenSSH 8.9p1";
        let port_info = scanner.parse_port_line(line).unwrap();

        assert_eq!(port_info.port, 22);
        assert_eq!(port_info.protocol, "tcp");
        assert_eq!(port_info.service, "ssh");
        assert!(port_info.version.unwrap().contains("OpenSSH"));
    }

    #[test]
    fn test_parse_port_line_no_version() {
        let scanner = NmapScanner::new();

        let line = "80/tcp   open  http";
        let port_info = scanner.parse_port_line(line).unwrap();

        assert_eq!(port_info.port, 80);
        assert_eq!(port_info.service, "http");
        assert!(port_info.version.is_none());
    }
}
