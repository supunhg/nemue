// Fuzzer Output & Reporting - Real-time stats, progress, and multiple output formats
// Comprehensive reporting for fuzzing operations

use anyhow::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

use super::engine::{FuzzResult, FuzzMode};
use super::subdomain::SubdomainResult;
use super::cloud::CloudStorageResult;

/// Fuzzer report containing all results and statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzReport {
    /// Scan metadata
    pub metadata: ScanMetadata,
    /// Web fuzzing results
    pub fuzz_results: Vec<FuzzResult>,
    /// Subdomain enumeration results
    pub subdomain_results: Vec<SubdomainResult>,
    /// Cloud storage results
    pub cloud_results: Vec<CloudStorageResult>,
    /// Scan statistics
    pub stats: ScanStats,
}

/// Scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Scan ID
    pub scan_id: String,
    /// Target URL/domain
    pub target: String,
    /// Fuzzing mode
    pub mode: String,
    /// Start time
    pub start_time: DateTime<Utc>,
    /// End time
    pub end_time: Option<DateTime<Utc>>,
    /// Wordlist used
    pub wordlist_name: String,
    /// Wordlist size
    pub wordlist_size: usize,
    /// Configuration summary
    pub config: HashMap<String, String>,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total requests sent
    pub total_requests: usize,
    /// Successful responses (2xx)
    pub successful: usize,
    /// Redirects (3xx)
    pub redirects: usize,
    /// Client errors (4xx)
    pub client_errors: usize,
    /// Server errors (5xx)
    pub server_errors: usize,
    /// Total duration
    pub duration: Duration,
    /// Requests per second
    pub req_per_sec: f64,
    /// Average response time (ms)
    pub avg_response_time: u64,
    /// Median response time (ms)
    pub median_response_time: u64,
    /// Status code distribution
    pub status_distribution: HashMap<u16, usize>,
    /// Size distribution (bucketed)
    pub size_buckets: HashMap<String, usize>,
}

impl ScanStats {
    /// Create new scan statistics from results
    pub fn from_results(results: &[FuzzResult], duration: Duration) -> Self {
        let total = results.len();
        let successful = results.iter().filter(|r| r.status_code >= 200 && r.status_code < 300).count();
        let redirects = results.iter().filter(|r| r.status_code >= 300 && r.status_code < 400).count();
        let client_errors = results.iter().filter(|r| r.status_code >= 400 && r.status_code < 500).count();
        let server_errors = results.iter().filter(|r| r.status_code >= 500).count();

        let req_per_sec = if duration.as_secs() > 0 {
            total as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        // Calculate average response time
        let avg_response_time = if !results.is_empty() {
            results.iter().map(|r| r.response_time).sum::<u64>() / results.len() as u64
        } else {
            0
        };

        // Calculate median response time
        let mut times: Vec<u64> = results.iter().map(|r| r.response_time).collect();
        times.sort_unstable();
        let median_response_time = if !times.is_empty() {
            times[times.len() / 2]
        } else {
            0
        };

        // Status code distribution
        let mut status_distribution = HashMap::new();
        for result in results {
            *status_distribution.entry(result.status_code).or_insert(0) += 1;
        }

        // Size distribution (in buckets)
        let mut size_buckets = HashMap::new();
        for result in results {
            let bucket = Self::size_bucket(result.size);
            *size_buckets.entry(bucket).or_insert(0) += 1;
        }

        Self {
            total_requests: total,
            successful,
            redirects,
            client_errors,
            server_errors,
            duration,
            req_per_sec,
            avg_response_time,
            median_response_time,
            status_distribution,
            size_buckets,
        }
    }

    /// Get size bucket label
    fn size_bucket(size: usize) -> String {
        match size {
            0..=1024 => "0-1KB".to_string(),
            1025..=10240 => "1-10KB".to_string(),
            10241..=102400 => "10-100KB".to_string(),
            102401..=1048576 => "100KB-1MB".to_string(),
            _ => ">1MB".to_string(),
        }
    }
}

/// Output formatter for fuzzer results
pub struct FuzzOutput;

impl FuzzOutput {
    /// Format as plain text
    pub fn format_text(report: &FuzzReport) -> String {
        let mut output = String::new();

        output.push_str(&format!("╔═══════════════════════════════════════════════════════════════╗\n"));
        output.push_str(&format!("║           Nemue Fuzzer Report - {}           ║\n", report.metadata.scan_id));
        output.push_str(&format!("╚═══════════════════════════════════════════════════════════════╝\n\n"));

        // Metadata
        output.push_str(&format!("Target:     {}\n", report.metadata.target));
        output.push_str(&format!("Mode:       {}\n", report.metadata.mode));
        output.push_str(&format!("Started:    {}\n", report.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC")));
        if let Some(end) = report.metadata.end_time {
            output.push_str(&format!("Finished:   {}\n", end.format("%Y-%m-%d %H:%M:%S UTC")));
        }
        output.push_str(&format!("Wordlist:   {} ({} entries)\n\n", 
            report.metadata.wordlist_name, 
            report.metadata.wordlist_size));

        // Statistics
        output.push_str("═══ STATISTICS ═══\n");
        output.push_str(&format!("Total Requests:    {}\n", report.stats.total_requests));
        output.push_str(&format!("Successful (2xx):  {}\n", report.stats.successful));
        output.push_str(&format!("Redirects (3xx):   {}\n", report.stats.redirects));
        output.push_str(&format!("Client Errors:     {}\n", report.stats.client_errors));
        output.push_str(&format!("Server Errors:     {}\n", report.stats.server_errors));
        output.push_str(&format!("Duration:          {:.2}s\n", report.stats.duration.as_secs_f64()));
        output.push_str(&format!("Requests/sec:      {:.2}\n", report.stats.req_per_sec));
        output.push_str(&format!("Avg Response Time: {}ms\n", report.stats.avg_response_time));
        output.push_str(&format!("Median Time:       {}ms\n\n", report.stats.median_response_time));

        // Results
        if !report.fuzz_results.is_empty() {
            output.push_str("═══ FINDINGS ═══\n");
            for result in &report.fuzz_results {
                let status_emoji = match result.status_code {
                    200..=299 => "✓",
                    300..=399 => "↪",
                    400..=499 => "✗",
                    _ => "!",
                };
                
                output.push_str(&format!("{} [{}] {} ({} bytes, {}ms)\n",
                    status_emoji,
                    result.status_code,
                    result.path,
                    result.size,
                    result.response_time));
            }
        }

        if !report.subdomain_results.is_empty() {
            output.push_str("\n═══ SUBDOMAINS ═══\n");
            for subdomain in &report.subdomain_results {
                output.push_str(&format!("• {} → {:?}\n", subdomain.subdomain, subdomain.ips));
            }
        }

        if !report.cloud_results.is_empty() {
            output.push_str("\n═══ CLOUD STORAGE ═══\n");
            for cloud in &report.cloud_results {
                let access = if cloud.public_access { "PUBLIC" } else { "PRIVATE" };
                output.push_str(&format!("• {} [{}] - {} files\n", 
                    cloud.name, access, cloud.files.len()));
            }
        }

        output
    }

    /// Format as JSON
    pub fn format_json(report: &FuzzReport) -> Result<String> {
        Ok(serde_json::to_string_pretty(report)?)
    }

    /// Format as CSV
    pub fn format_csv(results: &[FuzzResult]) -> String {
        let mut output = String::new();
        
        // Header
        output.push_str("Path,Status,Size,Time(ms),Redirect,RedirectLocation\n");
        
        // Data
        for result in results {
            output.push_str(&format!("{},{},{},{},{},{}\n",
                result.path,
                result.status_code,
                result.size,
                result.response_time,
                result.is_redirect,
                result.redirect_location.as_ref().unwrap_or(&"-".to_string())));
        }

        output
    }

    /// Format as markdown
    pub fn format_markdown(report: &FuzzReport) -> String {
        let mut output = String::new();

        output.push_str(&format!("# Fuzzer Report: {}\n\n", report.metadata.target));
        
        output.push_str("## Scan Information\n\n");
        output.push_str(&format!("- **Target**: {}\n", report.metadata.target));
        output.push_str(&format!("- **Mode**: {}\n", report.metadata.mode));
        output.push_str(&format!("- **Started**: {}\n", report.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC")));
        output.push_str(&format!("- **Wordlist**: {} ({} entries)\n\n", 
            report.metadata.wordlist_name, 
            report.metadata.wordlist_size));

        output.push_str("## Statistics\n\n");
        output.push_str("| Metric | Value |\n");
        output.push_str("|--------|-------|\n");
        output.push_str(&format!("| Total Requests | {} |\n", report.stats.total_requests));
        output.push_str(&format!("| Successful (2xx) | {} |\n", report.stats.successful));
        output.push_str(&format!("| Redirects (3xx) | {} |\n", report.stats.redirects));
        output.push_str(&format!("| Client Errors (4xx) | {} |\n", report.stats.client_errors));
        output.push_str(&format!("| Server Errors (5xx) | {} |\n", report.stats.server_errors));
        output.push_str(&format!("| Duration | {:.2}s |\n", report.stats.duration.as_secs_f64()));
        output.push_str(&format!("| Requests/sec | {:.2} |\n\n", report.stats.req_per_sec));

        if !report.fuzz_results.is_empty() {
            output.push_str("## Findings\n\n");
            output.push_str("| Status | Path | Size | Time |\n");
            output.push_str("|--------|------|------|------|\n");
            for result in &report.fuzz_results {
                output.push_str(&format!("| {} | {} | {} bytes | {}ms |\n",
                    result.status_code,
                    result.path,
                    result.size,
                    result.response_time));
            }
        }

        output
    }

    /// Format as HTML
    pub fn format_html(report: &FuzzReport) -> String {
        let mut output = String::new();

        output.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        output.push_str("<title>Fuzzer Report</title>\n");
        output.push_str("<style>\n");
        output.push_str("body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }\n");
        output.push_str("h1 { color: #333; }\n");
        output.push_str(".stats { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; }\n");
        output.push_str("table { width: 100%; border-collapse: collapse; background: white; }\n");
        output.push_str("th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }\n");
        output.push_str("th { background: #4CAF50; color: white; }\n");
        output.push_str(".status-200 { color: green; }\n");
        output.push_str(".status-300 { color: orange; }\n");
        output.push_str(".status-400 { color: red; }\n");
        output.push_str(".status-500 { color: darkred; }\n");
        output.push_str("</style>\n</head>\n<body>\n");

        output.push_str(&format!("<h1>Fuzzer Report: {}</h1>\n", report.metadata.target));
        
        output.push_str("<div class='stats'>\n");
        output.push_str("<h2>Scan Statistics</h2>\n");
        output.push_str(&format!("<p><strong>Total Requests:</strong> {}</p>\n", report.stats.total_requests));
        output.push_str(&format!("<p><strong>Successful:</strong> {}</p>\n", report.stats.successful));
        output.push_str(&format!("<p><strong>Duration:</strong> {:.2}s</p>\n", report.stats.duration.as_secs_f64()));
        output.push_str(&format!("<p><strong>Requests/sec:</strong> {:.2}</p>\n", report.stats.req_per_sec));
        output.push_str("</div>\n");

        if !report.fuzz_results.is_empty() {
            output.push_str("<h2>Findings</h2>\n");
            output.push_str("<table>\n");
            output.push_str("<tr><th>Status</th><th>Path</th><th>Size</th><th>Time</th></tr>\n");
            for result in &report.fuzz_results {
                let status_class = match result.status_code {
                    200..=299 => "status-200",
                    300..=399 => "status-300",
                    400..=499 => "status-400",
                    _ => "status-500",
                };
                output.push_str(&format!("<tr><td class='{}'>{}</td><td>{}</td><td>{} bytes</td><td>{}ms</td></tr>\n",
                    status_class,
                    result.status_code,
                    result.path,
                    result.size,
                    result.response_time));
            }
            output.push_str("</table>\n");
        }

        output.push_str("</body>\n</html>");
        output
    }
}

/// Progress tracker for real-time updates
pub struct ProgressTracker {
    start_time: Instant,
    total_items: usize,
    processed: usize,
    successful: usize,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(total_items: usize) -> Self {
        Self {
            start_time: Instant::now(),
            total_items,
            processed: 0,
            successful: 0,
        }
    }

    /// Update progress
    pub fn update(&mut self, success: bool) {
        self.processed += 1;
        if success {
            self.successful += 1;
        }
    }

    /// Get current progress percentage
    pub fn progress(&self) -> f64 {
        if self.total_items == 0 {
            0.0
        } else {
            (self.processed as f64 / self.total_items as f64) * 100.0
        }
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Estimate remaining time
    pub fn eta(&self) -> Duration {
        if self.processed == 0 {
            return Duration::from_secs(0);
        }

        let elapsed = self.elapsed().as_secs_f64();
        let rate = self.processed as f64 / elapsed;
        let remaining = self.total_items - self.processed;
        
        Duration::from_secs_f64(remaining as f64 / rate)
    }

    /// Get current status line
    pub fn status_line(&self) -> String {
        format!("[{:.1}%] {}/{} | Found: {} | ETA: {}s",
            self.progress(),
            self.processed,
            self.total_items,
            self.successful,
            self.eta().as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_tracker() {
        let mut tracker = ProgressTracker::new(100);
        assert_eq!(tracker.progress(), 0.0);

        tracker.update(true);
        assert_eq!(tracker.progress(), 1.0);
        assert_eq!(tracker.successful, 1);

        tracker.update(false);
        assert_eq!(tracker.progress(), 2.0);
        assert_eq!(tracker.successful, 1);
    }

    #[test]
    fn test_size_bucket() {
        assert_eq!(ScanStats::size_bucket(512), "0-1KB");
        assert_eq!(ScanStats::size_bucket(5120), "1-10KB");
        assert_eq!(ScanStats::size_bucket(51200), "10-100KB");
        assert_eq!(ScanStats::size_bucket(512000), "100KB-1MB");
        assert_eq!(ScanStats::size_bucket(5120000), ">1MB");
    }

    #[test]
    fn test_scan_stats_from_empty() {
        let results = Vec::new();
        let stats = ScanStats::from_results(&results, Duration::from_secs(10));
        
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.successful, 0);
        assert_eq!(stats.avg_response_time, 0);
    }
}
