use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::scanner::ScanResults;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CompressionAlgorithm {
    Gzip,
    Zstd,
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionAlgorithm::Gzip => write!(f, "gzip"),
            CompressionAlgorithm::Zstd => write!(f, "zstd"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    pub algorithm: CompressionAlgorithm,
    pub level: u32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            algorithm: CompressionAlgorithm::Gzip,
            level: 6,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionStats {
    pub original_size: usize,
    pub compressed_size: usize,
    pub ratio: f64,
    pub algorithm: CompressionAlgorithm,
}

pub struct ScanCompressor {
    config: CompressionConfig,
}

impl ScanCompressor {
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }

    pub fn with_gzip(level: u32) -> Self {
        Self::new(CompressionConfig {
            algorithm: CompressionAlgorithm::Gzip,
            level: level.min(9),
        })
    }

    pub fn with_zstd(level: i32) -> Self {
        Self::new(CompressionConfig {
            algorithm: CompressionAlgorithm::Zstd,
            level: level.max(0) as u32,
        })
    }

    pub fn compress(&self, results: &ScanResults) -> Result<(Vec<u8>, CompressionStats)> {
        let json = serde_json::to_vec(results)?;
        let original_size = json.len();

        let compressed = match self.config.algorithm {
            CompressionAlgorithm::Gzip => self.compress_gzip(&json)?,
            CompressionAlgorithm::Zstd => self.compress_zstd(&json)?,
        };

        let compressed_size = compressed.len();
        let ratio = if original_size > 0 {
            1.0 - (compressed_size as f64 / original_size as f64)
        } else {
            0.0
        };

        Ok((
            compressed,
            CompressionStats {
                original_size,
                compressed_size,
                ratio,
                algorithm: self.config.algorithm,
            },
        ))
    }

    pub fn decompress(&self, data: &[u8]) -> Result<ScanResults> {
        let json = match self.config.algorithm {
            CompressionAlgorithm::Gzip => self.decompress_gzip(data)?,
            CompressionAlgorithm::Zstd => self.decompress_zstd(data)?,
        };

        let results: ScanResults = serde_json::from_slice(&json)?;
        Ok(results)
    }

    pub fn compress_to_writer<W: Write>(
        &self,
        results: &ScanResults,
        writer: &mut W,
    ) -> Result<CompressionStats> {
        let json = serde_json::to_vec(results)?;
        let original_size = json.len();

        match self.config.algorithm {
            CompressionAlgorithm::Gzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(writer, flate2::Compression::new(self.config.level));
                encoder.write_all(&json)?;
                encoder.finish()?;
            }
            CompressionAlgorithm::Zstd => {
                let mut encoder = zstd::Encoder::new(writer, self.config.level as i32)?;
                encoder.write_all(&json)?;
                encoder.finish()?;
            }
        }

        Ok(CompressionStats {
            original_size,
            compressed_size: 0,
            ratio: 0.0,
            algorithm: self.config.algorithm,
        })
    }

    pub fn decompress_from_reader<R: Read>(&self, reader: &mut R) -> Result<ScanResults> {
        let mut decompressed = Vec::new();

        match self.config.algorithm {
            CompressionAlgorithm::Gzip => {
                let mut decoder = flate2::read::GzDecoder::new(reader);
                decoder.read_to_end(&mut decompressed)?;
            }
            CompressionAlgorithm::Zstd => {
                let mut decoder = zstd::Decoder::new(reader)?;
                decoder.read_to_end(&mut decompressed)?;
            }
        }

        let results: ScanResults = serde_json::from_slice(&decompressed)?;
        Ok(results)
    }

    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(self.config.level));
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::encode_all(data, self.config.level as i32)
            .map_err(|e| anyhow!("Zstd compression failed: {}", e))
    }

    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::decode_all(data).map_err(|e| anyhow!("Zstd decompression failed: {}", e))
    }

    pub fn algorithm(&self) -> CompressionAlgorithm {
        self.config.algorithm
    }
}

impl Default for ScanCompressor {
    fn default() -> Self {
        Self::new(CompressionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{PortState, Protocol, ScanResult, ScanResults};
    use chrono::Utc;
    use std::net::IpAddr;

    fn create_test_results(count: usize) -> ScanResults {
        let results: Vec<ScanResult> = (0..count)
            .map(|i| ScanResult {
                target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                port: (80 + i) as u16,
                state: PortState::Open,
                protocol: Protocol::TCP,
                service: Some(format!("service-{}", i)),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            })
            .collect();

        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: count,
            results,
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_gzip_roundtrip() {
        let compressor = ScanCompressor::with_gzip(6);
        let results = create_test_results(10);

        let (compressed, stats) = compressor.compress(&results).unwrap();
        assert!(stats.compressed_size < stats.original_size);
        assert!(stats.ratio > 0.0);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed.results.len(), 10);
        assert_eq!(decompressed.results[0].port, 80);
    }

    #[test]
    fn test_zstd_roundtrip() {
        let compressor = ScanCompressor::with_zstd(3);
        let results = create_test_results(10);

        let (compressed, stats) = compressor.compress(&results).unwrap();
        assert!(stats.compressed_size < stats.original_size);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(decompressed.results.len(), 10);
    }

    #[test]
    fn test_gzip_compression_ratio() {
        let compressor = ScanCompressor::with_gzip(9);
        let results = create_test_results(100);

        let (_, stats) = compressor.compress(&results).unwrap();
        assert!(stats.ratio > 0.3, "Expected >30% compression, got {:.1}%", stats.ratio * 100.0);
    }

    #[test]
    fn test_zstd_compression_ratio() {
        let compressor = ScanCompressor::with_zstd(9);
        let results = create_test_results(100);

        let (_, stats) = compressor.compress(&results).unwrap();
        assert!(stats.ratio > 0.3, "Expected >30% compression, got {:.1}%", stats.ratio * 100.0);
    }

    #[test]
    fn test_empty_results() {
        let compressor = ScanCompressor::with_gzip(6);
        let results = create_test_results(0);

        let (compressed, stats) = compressor.compress(&results).unwrap();
        assert!(stats.original_size > 0);

        let decompressed = compressor.decompress(&compressed).unwrap();
        assert!(decompressed.results.is_empty());
    }

    #[test]
    fn test_streaming_gzip() {
        let compressor = ScanCompressor::with_gzip(6);
        let results = create_test_results(5);

        let mut buffer = Vec::new();
        compressor
            .compress_to_writer(&results, &mut buffer)
            .unwrap();
        assert!(!buffer.is_empty());

        let mut cursor = std::io::Cursor::new(buffer);
        let decompressed = compressor.decompress_from_reader(&mut cursor).unwrap();
        assert_eq!(decompressed.results.len(), 5);
    }

    #[test]
    fn test_streaming_zstd() {
        let compressor = ScanCompressor::with_zstd(3);
        let results = create_test_results(5);

        let mut buffer = Vec::new();
        compressor
            .compress_to_writer(&results, &mut buffer)
            .unwrap();
        assert!(!buffer.is_empty());

        let mut cursor = std::io::Cursor::new(buffer);
        let decompressed = compressor.decompress_from_reader(&mut cursor).unwrap();
        assert_eq!(decompressed.results.len(), 5);
    }

    #[test]
    fn test_different_algorithms_produce_different_output() {
        let results = create_test_results(50);

        let gzip = ScanCompressor::with_gzip(6);
        let zstd = ScanCompressor::with_zstd(3);

        let (gzip_data, _) = gzip.compress(&results).unwrap();
        let (zstd_data, _) = zstd.compress(&results).unwrap();

        assert_ne!(gzip_data, zstd_data);
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(CompressionAlgorithm::Gzip.to_string(), "gzip");
        assert_eq!(CompressionAlgorithm::Zstd.to_string(), "zstd");
    }

    #[test]
    fn test_stats_serialization() {
        let stats = CompressionStats {
            original_size: 1000,
            compressed_size: 300,
            ratio: 0.7,
            algorithm: CompressionAlgorithm::Gzip,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: CompressionStats = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.original_size, 1000);
        assert_eq!(deserialized.algorithm, CompressionAlgorithm::Gzip);
    }
}
