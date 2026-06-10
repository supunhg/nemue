// Vulnerability detection framework
pub mod credentials;
pub mod exploits;
pub mod framework;
pub mod infodisclosure;
pub mod nvd;
pub mod scripts;
pub mod webvulns;

pub use credentials::DefaultCredentials;
pub use exploits::ExploitDatabase;
pub use framework::{ScriptEngine, VulnCategory, VulnResult, VulnScript, VulnSeverity};
pub use infodisclosure::InfoDisclosureScripts;
pub use nvd::{CvssV3Metrics, CvssV3Severity, NvdCveEntry, NvdDatabase};
pub use scripts::VulnScripts;
pub use webvulns::WebVulnScripts;
