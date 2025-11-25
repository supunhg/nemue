// Performance profiler for bottleneck identification
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileEntry {
    pub name: String,
    pub total_time: Duration,
    pub call_count: u64,
    pub avg_time: Duration,
    pub min_time: Duration,
    pub max_time: Duration,
}

pub struct Profiler {
    entries: Arc<RwLock<HashMap<String, ProfileData>>>,
}

struct ProfileData {
    total_time: Duration,
    call_count: u64,
    min_time: Duration,
    max_time: Duration,
}

impl Profiler {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn profile<F, R>(&self, name: &str, f: F) -> R
    where
        F: std::future::Future<Output = R>,
    {
        let start = Instant::now();
        let result = f.await;
        let elapsed = start.elapsed();

        self.record(name, elapsed).await;
        result
    }

    pub fn profile_sync<F, R>(&self, name: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();

        let entries = self.entries.clone();
        let name = name.to_string();
        tokio::spawn(async move {
            let mut map = entries.write().await;
            let entry = map.entry(name).or_insert(ProfileData {
                total_time: Duration::ZERO,
                call_count: 0,
                min_time: Duration::MAX,
                max_time: Duration::ZERO,
            });

            entry.total_time += elapsed;
            entry.call_count += 1;
            entry.min_time = entry.min_time.min(elapsed);
            entry.max_time = entry.max_time.max(elapsed);
        });

        result
    }

    async fn record(&self, name: &str, duration: Duration) {
        let mut entries = self.entries.write().await;
        let entry = entries.entry(name.to_string()).or_insert(ProfileData {
            total_time: Duration::ZERO,
            call_count: 0,
            min_time: Duration::MAX,
            max_time: Duration::ZERO,
        });

        entry.total_time += duration;
        entry.call_count += 1;
        entry.min_time = entry.min_time.min(duration);
        entry.max_time = entry.max_time.max(duration);
    }

    pub async fn snapshot(&self) -> Vec<ProfileEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .map(|(name, data)| {
                let avg_time = if data.call_count > 0 {
                    data.total_time / data.call_count as u32
                } else {
                    Duration::ZERO
                };

                ProfileEntry {
                    name: name.clone(),
                    total_time: data.total_time,
                    call_count: data.call_count,
                    avg_time,
                    min_time: if data.min_time == Duration::MAX {
                        Duration::ZERO
                    } else {
                        data.min_time
                    },
                    max_time: data.max_time,
                }
            })
            .collect()
    }

    pub async fn reset(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }

    pub async fn bottlenecks(&self, threshold_ms: u64) -> Vec<ProfileEntry> {
        let snapshot = self.snapshot().await;
        snapshot
            .into_iter()
            .filter(|e| e.avg_time.as_millis() as u64 > threshold_ms)
            .collect()
    }

    pub async fn report(&self) -> String {
        let mut snapshot = self.snapshot().await;
        snapshot.sort_by(|a, b| b.total_time.cmp(&a.total_time));

        let mut report = String::from("Performance Profile:\n");
        report.push_str(&format!("{:-<80}\n", ""));
        report.push_str(&format!(
            "{:<30} {:>10} {:>10} {:>10} {:>10}\n",
            "Function", "Calls", "Total (ms)", "Avg (ms)", "Max (ms)"
        ));
        report.push_str(&format!("{:-<80}\n", ""));

        for entry in snapshot {
            report.push_str(&format!(
                "{:<30} {:>10} {:>10.2} {:>10.2} {:>10.2}\n",
                entry.name,
                entry.call_count,
                entry.total_time.as_secs_f64() * 1000.0,
                entry.avg_time.as_secs_f64() * 1000.0,
                entry.max_time.as_secs_f64() * 1000.0,
            ));
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_profiler_basic() {
        let profiler = Profiler::new();
        
        profiler.profile("test_fn", async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }).await;

        let snapshot = profiler.snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].name, "test_fn");
        assert_eq!(snapshot[0].call_count, 1);
        assert!(snapshot[0].total_time >= Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_profiler_multiple_calls() {
        let profiler = Profiler::new();
        
        for _ in 0..5 {
            profiler.profile("loop_fn", async {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }).await;
        }

        let snapshot = profiler.snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].call_count, 5);
    }

    #[tokio::test]
    async fn test_profiler_reset() {
        let profiler = Profiler::new();
        
        profiler.profile("fn1", async {}).await;
        profiler.profile("fn2", async {}).await;
        
        assert_eq!(profiler.snapshot().await.len(), 2);
        
        profiler.reset().await;
        assert_eq!(profiler.snapshot().await.len(), 0);
    }

    #[tokio::test]
    async fn test_bottlenecks() {
        let profiler = Profiler::new();
        
        profiler.profile("fast", async {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }).await;
        
        profiler.profile("slow", async {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }).await;

        let bottlenecks = profiler.bottlenecks(10).await;
        assert_eq!(bottlenecks.len(), 1);
        assert_eq!(bottlenecks[0].name, "slow");
    }

    #[tokio::test]
    async fn test_profiler_report() {
        let profiler = Profiler::new();
        
        profiler.profile("test1", async {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }).await;

        let report = profiler.report().await;
        assert!(report.contains("Performance Profile"));
        assert!(report.contains("test1"));
    }
}
