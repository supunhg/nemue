use anyhow::{anyhow, Result};
use futures::stream::{self, StreamExt};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::info;

use super::{
    Port, PortParser, PortState, RateLimiter, ScanResult, ScanResults,
    TargetParser,
};
use crate::protocols::tcp::TcpScanner;
use crate::protocols::udp::UdpScanner;
use crate::fingerprint::OsDetector;
use crate::service::ServiceDetector;

#[derive(Clone)]
pub struct ScanEngine {
    rate_limiter: RateLimiter,
    timeout: u64,
    enable_service_detection: bool,
    enable_os_detection: bool,
    use_raw_sockets: bool,
    max_concurrent_targets: usize,
}

impl ScanEngine {
    pub fn new(max_rate: u32, timeout: u64) -> Result<Self> {
        Ok(Self {
            rate_limiter: RateLimiter::new(max_rate),
            timeout,
            enable_service_detection: true,
            enable_os_detection: true,
            use_raw_sockets: false,
            max_concurrent_targets: num_cpus::get().max(2),
        })
    }

    pub fn with_options(max_rate: u32, timeout: u64, service_detection: bool, os_detection: bool) -> Result<Self> {
        Ok(Self {
            rate_limiter: RateLimiter::new(max_rate),
            timeout,
            enable_service_detection: service_detection,
            enable_os_detection: os_detection,
            use_raw_sockets: false,
            max_concurrent_targets: num_cpus::get().max(2),
        })
    }

    pub fn with_all_options(
        max_rate: u32, 
        timeout: u64, 
        service_detection: bool, 
        os_detection: bool,
        use_raw: bool
    ) -> Result<Self> {
        Ok(Self {
            rate_limiter: RateLimiter::new(max_rate),
            timeout,
            enable_service_detection: service_detection,
            enable_os_detection: os_detection,
            use_raw_sockets: use_raw,
            max_concurrent_targets: num_cpus::get().max(2),
        })
    }

    pub fn with_max_concurrent_targets(mut self, max: usize) -> Self {
        self.max_concurrent_targets = max;
        self
    }

    pub async fn scan(
        &self,
        target: &str,
        ports: &str,
        scan_type: &str,
    ) -> Result<ScanResults> {
        let scan_start = chrono::Utc::now();

        // Parse targets
        let targets = TargetParser::parse(target)?;
        info!("Parsed {} target(s)", targets.len());

        // Parse ports
        let port_list = PortParser::parse(ports)?;
        info!("Parsed {} port(s)", port_list.len());

        let target_count = targets.len();
        let port_count = port_list.len();

        // Scan targets in parallel
        let engine = Arc::new(self.clone());
        let port_list = Arc::new(port_list);

        let target_futures = targets.into_iter().map(|target_ip| {
            let engine = engine.clone();
            let port_list = port_list.clone();
            let scan_type = scan_type.to_string();
            async move {
                engine.scan_single_target(target_ip, &port_list, &scan_type).await
            }
        });

        let mut all_results = Vec::new();
        let mut os_fingerprints = Vec::new();

        let mut stream = stream::iter(target_futures)
            .buffer_unordered(engine.max_concurrent_targets);

        while let Some(result) = stream.next().await {
            match result {
                Ok((results, os_fp)) => {
                    all_results.extend(results);
                    if let Some(fp) = os_fp {
                        os_fingerprints.push(fp);
                    }
                }
                Err(e) => {
                    tracing::warn!("Target scan failed: {}", e);
                }
            }
        }

        let scan_end = chrono::Utc::now();

        Ok(ScanResults {
            scan_start,
            scan_end,
            target_count,
            port_count,
            results: all_results,
            os_fingerprints,
            script_results: Vec::new(),
        })
    }

    /// Scan a single target with all detection enabled
    async fn scan_single_target(
        &self,
        target_ip: IpAddr,
        port_list: &[Port],
        scan_type: &str,
    ) -> Result<(Vec<ScanResult>, Option<crate::fingerprint::OsFingerprint>)> {
        info!("Scanning target: {}", target_ip);

        let mut results = match scan_type {
            "syn" => self.syn_scan(target_ip, port_list).await?,
            "connect" => self.connect_scan(target_ip, port_list).await?,
            "udp" => self.udp_scan(target_ip, port_list).await?,
            _ => return Err(anyhow!("Unknown scan type: {}", scan_type)),
        };

        // Service detection on open ports
        if self.enable_service_detection {
            results = self.detect_services(target_ip, results).await;
        }

        // OS detection
        let os_fp = if self.enable_os_detection {
            self.detect_os(target_ip, &results).await
        } else {
            None
        };

        Ok((results, os_fp))
    }

    /// Scan with port exclusions
    pub async fn scan_with_exclusions(
        &self,
        target: &str,
        ports: &str,
        exclude_ports: &str,
        scan_type: &str,
    ) -> Result<ScanResults> {
        let scan_start = chrono::Utc::now();

        // Parse targets
        let targets = TargetParser::parse(target)?;
        info!("Parsed {} target(s)", targets.len());

        // Parse ports and exclusions
        let mut port_list = PortParser::parse(ports)?;
        let exclude_list = PortParser::parse(exclude_ports)?;

        // Filter out excluded ports
        port_list.retain(|port| !exclude_list.contains(port));

        info!("Parsed {} port(s) ({} excluded)", port_list.len(), exclude_list.len());

        let target_count = targets.len();
        let port_count = port_list.len();

        // Scan targets in parallel
        let engine = Arc::new(self.clone());
        let port_list = Arc::new(port_list);

        let target_futures = targets.into_iter().map(|target_ip| {
            let engine = engine.clone();
            let port_list = port_list.clone();
            let scan_type = scan_type.to_string();
            async move {
                engine.scan_single_target(target_ip, &port_list, &scan_type).await
            }
        });

        let mut all_results = Vec::new();
        let mut os_fingerprints = Vec::new();

        let mut stream = stream::iter(target_futures)
            .buffer_unordered(engine.max_concurrent_targets);

        while let Some(result) = stream.next().await {
            match result {
                Ok((results, os_fp)) => {
                    all_results.extend(results);
                    if let Some(fp) = os_fp {
                        os_fingerprints.push(fp);
                    }
                }
                Err(e) => {
                    tracing::warn!("Target scan failed: {}", e);
                }
            }
        }

        let scan_end = chrono::Utc::now();

        Ok(ScanResults {
            scan_start,
            scan_end,
            target_count,
            port_count,
            results: all_results,
            os_fingerprints,
            script_results: Vec::new(),
        })
    }

    async fn syn_scan(&self, target: IpAddr, ports: &[Port]) -> Result<Vec<ScanResult>> {
        info!("Performing SYN scan on {} ports", ports.len());
        
        let tcp_scanner = TcpScanner::with_raw_sockets(self.timeout, self.use_raw_sockets);
        let mut results = Vec::new();

        // Create semaphore for concurrent scanning
        let semaphore = Arc::new(Semaphore::new(100)); // Max 100 concurrent scans

        let mut tasks = Vec::new();

        for &port in ports {
            let permit = semaphore.clone().acquire_owned().await?;
            let tcp_scanner = tcp_scanner.clone();
            let rate_limiter = self.rate_limiter.clone();

            let task = tokio::spawn(async move {
                // Rate limiting
                rate_limiter.wait().await;

                let result = tcp_scanner.syn_scan(target, port.value()).await;
                drop(permit);
                result
            });

            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            if let Ok(Ok(result)) = task.await {
                results.push(result);
            }
        }

        info!(
            "SYN scan completed: {} ports scanned, {} open",
            results.len(),
            results.iter().filter(|r| r.state == PortState::Open).count()
        );

        Ok(results)
    }

    async fn connect_scan(&self, target: IpAddr, ports: &[Port]) -> Result<Vec<ScanResult>> {
        info!("Performing TCP Connect scan on {} ports", ports.len());

        let tcp_scanner = TcpScanner::new(self.timeout);
        let mut results = Vec::new();

        let semaphore = Arc::new(Semaphore::new(100));
        let mut tasks = Vec::new();

        for &port in ports {
            let permit = semaphore.clone().acquire_owned().await?;
            let tcp_scanner = tcp_scanner.clone();
            let rate_limiter = self.rate_limiter.clone();

            let task = tokio::spawn(async move {
                rate_limiter.wait().await;
                let result = tcp_scanner.connect_scan(target, port.value()).await;
                drop(permit);
                result
            });

            tasks.push(task);
        }

        for task in tasks {
            if let Ok(Ok(result)) = task.await {
                results.push(result);
            }
        }

        info!(
            "Connect scan completed: {} ports scanned, {} open",
            results.len(),
            results.iter().filter(|r| r.state == PortState::Open).count()
        );

        Ok(results)
    }

    async fn udp_scan(&self, target: IpAddr, ports: &[Port]) -> Result<Vec<ScanResult>> {
        info!("Performing UDP scan on {} ports", ports.len());

        let udp_scanner = UdpScanner::new(self.timeout);
        let mut results = Vec::new();

        // Create semaphore for concurrent scanning
        let semaphore = Arc::new(Semaphore::new(50)); // Lower concurrency for UDP

        let mut tasks = Vec::new();

        for &port in ports {
            let permit = semaphore.clone().acquire_owned().await?;
            let udp_scanner = udp_scanner.clone();
            let rate_limiter = self.rate_limiter.clone();

            let task = tokio::spawn(async move {
                rate_limiter.wait().await;
                let result = udp_scanner.scan(target, port.value()).await;
                drop(permit);
                result
            });

            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            if let Ok(Ok(result)) = task.await {
                results.push(result);
            }
        }

        info!(
            "UDP scan completed: {} ports scanned, {} open",
            results.len(),
            results.iter().filter(|r| r.state == PortState::Open).count()
        );

        Ok(results)
    }

    async fn detect_services(&self, target: IpAddr, mut results: Vec<ScanResult>) -> Vec<ScanResult> {
        info!("Performing service detection on {} open ports", 
            results.iter().filter(|r| r.state == PortState::Open).count());

        let service_detector = ServiceDetector::new(self.timeout);
        
        for result in &mut results {
            if result.state == PortState::Open {
                if let Ok(service_info) = service_detector.detect(target, result.port).await {
                    info!("Detected service on port {}: {} (confidence: {}%)", 
                        result.port, service_info.service, service_info.confidence);
                    result.service = Some(service_info.service.clone());
                    result.service_info = Some(service_info);
                }
            }
        }

        results
    }

    async fn detect_os(&self, target: IpAddr, results: &[ScanResult]) -> Option<crate::fingerprint::OsFingerprint> {
        // For now, we'll use a simple heuristic based on common port responses
        // In a full implementation, this would involve sending special TCP packets
        // and analyzing the responses
        
        let open_ports: Vec<u16> = results
            .iter()
            .filter(|r| r.state == PortState::Open)
            .map(|r| r.port)
            .collect();

        if open_ports.is_empty() {
            return None;
        }

        info!("Performing OS detection on {}", target);

        // Simplified OS detection - in reality, we'd send special probes
        // For now, use heuristics based on open ports and service info
        let os_detector = OsDetector::new();
        
        // Default TTL detection (would need raw sockets for real implementation)
        let ttl = self.estimate_ttl(&open_ports);
        let window_size = self.estimate_window_size(&open_ports);
        
        let mut fingerprint = os_detector.detect(ttl, window_size, vec![]);
        fingerprint.target = target;

        let os_name = fingerprint.os_family.as_ref()
            .map(|s| s.as_str())
            .unwrap_or("Unknown");
        
        info!("OS detected: {} (confidence: {}%)", os_name, fingerprint.confidence);

        Some(fingerprint)
    }

    fn estimate_ttl(&self, open_ports: &[u16]) -> u8 {
        // Heuristic: Windows typically has RDP (3389), Linux has SSH (22)
        if open_ports.contains(&3389) || open_ports.contains(&445) {
            128 // Windows
        } else if open_ports.contains(&22) {
            64 // Linux/Unix
        } else {
            64 // Default to Unix-like
        }
    }

    fn estimate_window_size(&self, open_ports: &[u16]) -> Option<u16> {
        // Heuristic based on common ports
        if open_ports.contains(&3389) {
            Some(64240) // Windows
        } else if open_ports.contains(&22) {
            Some(29200) // Linux
        } else {
            None
        }
    }
}
