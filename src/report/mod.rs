pub mod generator;

pub use generator::{
    ReportGenerator, ReportTemplate, ScanReport, ReportMetadata,
    ScanSummary, Finding, Severity, Recommendation, Priority,
    Appendix, DateRange,
};
