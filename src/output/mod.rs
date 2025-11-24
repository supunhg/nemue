mod json;
mod xml;
pub mod display;

use anyhow::{anyhow, Result};
use crate::scanner::ScanResults;

pub use display::DisplayFormatter;

pub enum OutputFormat {
    Json,
    Xml,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "xml" => Ok(OutputFormat::Xml),
            _ => Err(anyhow!("Unknown output format: {}. Use 'json' or 'xml'", s)),
        }
    }
}

pub struct ResultFormatter {
    format: OutputFormat,
}

impl ResultFormatter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    pub fn format(&self, results: &ScanResults) -> Result<String> {
        match self.format {
            OutputFormat::Json => json::format(results),
            OutputFormat::Xml => xml::format(results),
        }
    }
}
