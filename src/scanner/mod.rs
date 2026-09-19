//! Local port scanning using nmap.
//!
//! DETECTION MODULE: Direct port scanning without API dependencies.

pub mod cors;
pub mod dns;
pub mod headers;
pub mod nmap;
pub mod paths;
pub mod ssl;
pub mod techdetect;

#[allow(unused_imports)]
pub use cors::{CorsError, CorsScanResult, CorsScanner};
#[allow(unused_imports)]
pub use dns::{DnsError, DnsScanResult, DnsScanner};
#[allow(unused_imports)]
pub use headers::{HeadersError, HeadersScanResult, HeadersScanner};
pub use nmap::{NmapScanner, PortInfo, ScanResult};
#[allow(unused_imports)]
pub use paths::{PathsError, PathsScanResult, PathsScanner};
#[allow(unused_imports)]
pub use ssl::{CertInfo, ProtocolInfo, SslError, SslScanResult, SslScanner};
#[allow(unused_imports)]
pub use techdetect::{TechDetectError, TechDetectResult, TechDetectScanner};
