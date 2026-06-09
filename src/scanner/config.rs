// Configuration file support for Nemue
// Reads from ~/.config/nemue/config.toml

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NemueConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_timing")]
    pub timing: String,
    #[serde(default = "default_scan_type")]
    pub scan_type: String,
    #[serde(default = "default_rate")]
    pub rate: u32,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub version_detect: bool,
    #[serde(default)]
    pub os_detect: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timing: default_timing(),
            scan_type: default_scan_type(),
            rate: default_rate(),
            timeout_ms: default_timeout(),
            version_detect: false,
            os_detect: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_true")]
    pub color: bool,
    #[serde(default = "default_true")]
    pub progress: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            color: true,
            progress: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    #[serde(default = "default_true")]
    pub adaptive_rate: bool,
    #[serde(default = "default_buffer_pool")]
    pub buffer_pool_size: usize,
    #[serde(default = "default_concurrent_targets")]
    pub max_concurrent_targets: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            adaptive_rate: true,
            buffer_pool_size: default_buffer_pool(),
            max_concurrent_targets: default_concurrent_targets(),
        }
    }
}

fn default_timing() -> String { "T3".to_string() }
fn default_scan_type() -> String { "connect".to_string() }
fn default_rate() -> u32 { 1000 }
fn default_timeout() -> u64 { 1000 }
fn default_format() -> String { "json".to_string() }
fn default_true() -> bool { true }
fn default_buffer_pool() -> usize { 1000 }
fn default_concurrent_targets() -> usize { num_cpus::get().max(2) }

impl NemueConfig {
    /// Load config from default location (~/.config/nemue/config.toml)
    pub fn load() -> Self {
        let config_path = Self::config_path();
        if config_path.exists() {
            match std::fs::read_to_string(&config_path) {
                Ok(contents) => match toml::from_str(&contents) {
                    Ok(config) => return config,
                    Err(e) => {
                        eprintln!("Warning: Invalid config file: {}", e);
                    }
                },
                Err(e) => {
                    eprintln!("Warning: Cannot read config file: {}", e);
                }
            }
        }
        Self::default()
    }

    /// Get the default config file path
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nemue")
            .join("config.toml")
    }

    /// Create a default config file
    pub fn create_default() -> Result<(), std::io::Error> {
        let config_path = Self::config_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let default_config = Self::default();
        let toml = toml::to_string_pretty(&default_config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&config_path, toml)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NemueConfig::default();
        assert_eq!(config.scan.timing, "T3");
        assert_eq!(config.scan.scan_type, "connect");
        assert_eq!(config.scan.rate, 1000);
        assert_eq!(config.output.format, "json");
        assert!(config.output.color);
        assert!(config.performance.adaptive_rate);
    }

    #[test]
    fn test_config_serialization() {
        let config = NemueConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("timing"));
        assert!(toml_str.contains("scan_type"));
        let _: NemueConfig = toml::from_str(&toml_str).unwrap();
    }
}
