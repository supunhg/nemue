// Trend analysis for historical scan comparison
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalyzer {
    scans: Vec<ScanSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSnapshot {
    pub scan_id: String,
    pub timestamp: DateTime<Utc>,
    pub metrics: ScanMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetrics {
    pub total_hosts: usize,
    pub hosts_up: usize,
    pub total_ports: usize,
    pub open_ports: usize,
    pub vulnerabilities: VulnerabilityMetrics,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityMetrics {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendReport {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_scans: usize,
    pub trends: HashMap<String, Trend>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trend {
    pub metric: String,
    pub direction: TrendDirection,
    pub change_percent: f64,
    pub current_value: f64,
    pub previous_value: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrendDirection {
    Improving,
    Worsening,
    Stable,
}

impl TrendAnalyzer {
    pub fn new() -> Self {
        Self {
            scans: Vec::new(),
        }
    }

    pub fn add_snapshot(&mut self, snapshot: ScanSnapshot) {
        self.scans.push(snapshot);
        self.scans.sort_by_key(|s| s.timestamp);
    }

    pub fn analyze(&self, days: i64) -> Option<TrendReport> {
        if self.scans.is_empty() {
            return None;
        }

        let now = Utc::now();
        let period_start = now - Duration::days(days);
        
        let recent_scans: Vec<&ScanSnapshot> = self.scans
            .iter()
            .filter(|s| s.timestamp >= period_start)
            .collect();

        if recent_scans.len() < 2 {
            return None;
        }

        let mut trends = HashMap::new();

        // Analyze vulnerability trends
        trends.insert(
            "critical_vulnerabilities".to_string(),
            self.calculate_trend(
                &recent_scans,
                |s| s.metrics.vulnerabilities.critical as f64,
                "Critical Vulnerabilities",
                true, // Lower is better
            ),
        );

        trends.insert(
            "high_vulnerabilities".to_string(),
            self.calculate_trend(
                &recent_scans,
                |s| s.metrics.vulnerabilities.high as f64,
                "High Vulnerabilities",
                true,
            ),
        );

        trends.insert(
            "risk_score".to_string(),
            self.calculate_trend(
                &recent_scans,
                |s| s.metrics.risk_score,
                "Risk Score",
                true,
            ),
        );

        trends.insert(
            "hosts_up".to_string(),
            self.calculate_trend(
                &recent_scans,
                |s| s.metrics.hosts_up as f64,
                "Active Hosts",
                false, // Higher might indicate discovery
            ),
        );

        let summary = self.generate_summary(&trends);

        Some(TrendReport {
            period_start,
            period_end: now,
            total_scans: recent_scans.len(),
            trends,
            summary,
        })
    }

    fn calculate_trend<F>(
        &self,
        scans: &[&ScanSnapshot],
        extractor: F,
        metric_name: &str,
        lower_is_better: bool,
    ) -> Trend
    where
        F: Fn(&ScanSnapshot) -> f64,
    {
        let latest = scans.last().unwrap();
        let previous = scans.first().unwrap();

        let current_value = extractor(latest);
        let previous_value = extractor(previous);

        let change_percent = if previous_value > 0.0 {
            ((current_value - previous_value) / previous_value) * 100.0
        } else {
            0.0
        };

        let direction = if change_percent.abs() < 5.0 {
            TrendDirection::Stable
        } else if lower_is_better {
            if change_percent < 0.0 {
                TrendDirection::Improving
            } else {
                TrendDirection::Worsening
            }
        } else {
            if change_percent > 0.0 {
                TrendDirection::Improving
            } else {
                TrendDirection::Worsening
            }
        };

        Trend {
            metric: metric_name.to_string(),
            direction,
            change_percent,
            current_value,
            previous_value,
        }
    }

    fn generate_summary(&self, trends: &HashMap<String, Trend>) -> String {
        let improving = trends.values().filter(|t| t.direction == TrendDirection::Improving).count();
        let worsening = trends.values().filter(|t| t.direction == TrendDirection::Worsening).count();
        let stable = trends.values().filter(|t| t.direction == TrendDirection::Stable).count();

        format!(
            "Trend Analysis: {} improving, {} stable, {} worsening",
            improving, stable, worsening
        )
    }

    pub fn get_snapshots(&self) -> &[ScanSnapshot] {
        &self.scans
    }
}

impl VulnerabilityMetrics {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_snapshot(days_ago: i64, critical: usize, high: usize, risk: f64) -> ScanSnapshot {
        ScanSnapshot {
            scan_id: format!("scan-{}", days_ago),
            timestamp: Utc::now() - Duration::days(days_ago),
            metrics: ScanMetrics {
                total_hosts: 10,
                hosts_up: 8,
                total_ports: 1000,
                open_ports: 50,
                vulnerabilities: VulnerabilityMetrics {
                    critical,
                    high,
                    medium: 10,
                    low: 5,
                    info: 2,
                },
                risk_score: risk,
            },
        }
    }

    #[test]
    fn test_trend_analyzer_creation() {
        let analyzer = TrendAnalyzer::new();
        assert_eq!(analyzer.scans.len(), 0);
    }

    #[test]
    fn test_add_snapshot() {
        let mut analyzer = TrendAnalyzer::new();
        let snapshot = create_snapshot(0, 5, 10, 7.5);
        
        analyzer.add_snapshot(snapshot);
        assert_eq!(analyzer.scans.len(), 1);
    }

    #[test]
    fn test_analyze_insufficient_data() {
        let analyzer = TrendAnalyzer::new();
        let report = analyzer.analyze(30);
        assert!(report.is_none());
    }

    #[test]
    fn test_analyze_with_data() {
        let mut analyzer = TrendAnalyzer::new();
        
        analyzer.add_snapshot(create_snapshot(7, 10, 15, 8.0));
        analyzer.add_snapshot(create_snapshot(0, 5, 10, 6.0));
        
        let report = analyzer.analyze(30);
        assert!(report.is_some());
        
        let report = report.unwrap();
        assert_eq!(report.total_scans, 2);
        assert!(!report.trends.is_empty());
    }

    #[test]
    fn test_improving_trend() {
        let mut analyzer = TrendAnalyzer::new();
        
        // Vulnerability count decreased (improving)
        analyzer.add_snapshot(create_snapshot(7, 10, 15, 8.0));
        analyzer.add_snapshot(create_snapshot(0, 5, 8, 6.0));
        
        let report = analyzer.analyze(30).unwrap();
        let crit_trend = report.trends.get("critical_vulnerabilities").unwrap();
        
        assert_eq!(crit_trend.direction, TrendDirection::Improving);
        assert!(crit_trend.change_percent < 0.0);
    }

    #[test]
    fn test_worsening_trend() {
        let mut analyzer = TrendAnalyzer::new();
        
        // Vulnerability count increased (worsening)
        analyzer.add_snapshot(create_snapshot(7, 5, 8, 6.0));
        analyzer.add_snapshot(create_snapshot(0, 10, 15, 8.0));
        
        let report = analyzer.analyze(30).unwrap();
        let crit_trend = report.trends.get("critical_vulnerabilities").unwrap();
        
        assert_eq!(crit_trend.direction, TrendDirection::Worsening);
        assert!(crit_trend.change_percent > 0.0);
    }

    #[test]
    fn test_stable_trend() {
        let mut analyzer = TrendAnalyzer::new();
        
        // Small change (stable)
        analyzer.add_snapshot(create_snapshot(7, 10, 15, 7.0));
        analyzer.add_snapshot(create_snapshot(0, 10, 15, 7.1));
        
        let report = analyzer.analyze(30).unwrap();
        let risk_trend = report.trends.get("risk_score").unwrap();
        
        assert_eq!(risk_trend.direction, TrendDirection::Stable);
    }

    #[test]
    fn test_vulnerability_metrics_total() {
        let metrics = VulnerabilityMetrics {
            critical: 5,
            high: 10,
            medium: 15,
            low: 8,
            info: 3,
        };

        assert_eq!(metrics.total(), 41);
    }

    #[test]
    fn test_summary_generation() {
        let mut analyzer = TrendAnalyzer::new();
        
        analyzer.add_snapshot(create_snapshot(7, 10, 15, 8.0));
        analyzer.add_snapshot(create_snapshot(0, 5, 10, 6.0));
        
        let report = analyzer.analyze(30).unwrap();
        assert!(report.summary.contains("improving"));
    }

    #[test]
    fn test_get_snapshots() {
        let mut analyzer = TrendAnalyzer::new();
        
        analyzer.add_snapshot(create_snapshot(7, 10, 15, 8.0));
        analyzer.add_snapshot(create_snapshot(0, 5, 10, 6.0));
        
        let snapshots = analyzer.get_snapshots();
        assert_eq!(snapshots.len(), 2);
    }
}
