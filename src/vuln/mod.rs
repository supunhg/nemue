// Vulnerability detection framework
pub mod framework;
pub mod scripts;
pub mod credentials;
pub mod exploits;
pub mod webvulns;
pub mod nvd;
pub mod infodisclosure;

pub use framework::{VulnScript, VulnCategory, VulnSeverity, VulnResult, ScriptEngine};
pub use credentials::DefaultCredentials;
pub use exploits::ExploitDatabase;
pub use scripts::VulnScripts;
pub use webvulns::WebVulnScripts;
pub use nvd::{NvdDatabase, NvdCveEntry, CvssV3Metrics, CvssV3Severity};
pub use infodisclosure::InfoDisclosureScripts;
