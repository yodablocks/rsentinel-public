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

pub use nmap::{NmapScanner, ScanResult, PortInfo};
#[allow(unused_imports)]
pub use ssl::{SslScanner, SslScanResult, CertInfo, ProtocolInfo, SslError};
#[allow(unused_imports)]
pub use headers::{HeadersScanner, HeadersScanResult, HeadersError};
#[allow(unused_imports)]
pub use dns::{DnsScanner, DnsScanResult, DnsError};
#[allow(unused_imports)]
pub use cors::{CorsScanner, CorsScanResult, CorsError};
#[allow(unused_imports)]
pub use paths::{PathsScanner, PathsScanResult, PathsError};
#[allow(unused_imports)]
pub use techdetect::{TechDetectScanner, TechDetectResult, TechDetectError};
