use anyhow::Result;
use crate::scanner::ScanResults;

pub fn format(results: &ScanResults) -> Result<String> {
    let json = serde_json::to_string_pretty(results)?;
    Ok(json)
}
