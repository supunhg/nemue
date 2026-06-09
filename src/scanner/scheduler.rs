use chrono::{DateTime, Datelike, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Recurrence {
    Once,
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl std::fmt::Display for Recurrence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Recurrence::Once => write!(f, "once"),
            Recurrence::Hourly => write!(f, "hourly"),
            Recurrence::Daily => write!(f, "daily"),
            Recurrence::Weekly => write!(f, "weekly"),
            Recurrence::Monthly => write!(f, "monthly"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScheduleStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

impl std::fmt::Display for ScheduleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScheduleStatus::Pending => write!(f, "pending"),
            ScheduleStatus::Running => write!(f, "running"),
            ScheduleStatus::Completed => write!(f, "completed"),
            ScheduleStatus::Failed => write!(f, "failed"),
            ScheduleStatus::Skipped => write!(f, "skipped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScan {
    pub id: String,
    pub name: String,
    pub target: String,
    pub template: Option<String>,
    pub scheduled_at: DateTime<Utc>,
    pub recurrence: Recurrence,
    pub priority: u8,
    pub dependencies: Vec<String>,
    pub status: ScheduleStatus,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: Option<DateTime<Utc>>,
    pub run_count: u32,
    pub error_message: Option<String>,
}

impl ScheduledScan {
    pub fn new(name: &str, target: &str, scheduled_at: DateTime<Utc>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            target: target.to_string(),
            template: None,
            scheduled_at,
            recurrence: Recurrence::Once,
            priority: 5,
            dependencies: Vec::new(),
            status: ScheduleStatus::Pending,
            last_run: None,
            next_run: None,
            run_count: 0,
            error_message: None,
        }
    }

    pub fn with_template(mut self, template: &str) -> Self {
        self.template = Some(template.to_string());
        self
    }

    pub fn with_recurrence(mut self, recurrence: Recurrence) -> Self {
        self.recurrence = recurrence;
        self
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_dependency(mut self, scan_id: &str) -> Self {
        self.dependencies.push(scan_id.to_string());
        self
    }

    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        if self.status != ScheduleStatus::Pending {
            return false;
        }
        match self.next_run {
            Some(next) => now >= next,
            None => now >= self.scheduled_at,
        }
    }

    pub fn compute_next_run(&self) -> Option<DateTime<Utc>> {
        let base = self.last_run.unwrap_or(self.scheduled_at);
        match self.recurrence {
            Recurrence::Once => None,
            Recurrence::Hourly => Some(base + ChronoDuration::hours(1)),
            Recurrence::Daily => Some(base + ChronoDuration::days(1)),
            Recurrence::Weekly => Some(base + ChronoDuration::weeks(1)),
            Recurrence::Monthly => {
                let mut month = base.month() + 1;
                let mut year = base.year();
                if month > 12 {
                    month = 1;
                    year += 1;
                }
                let day = base.day().min(days_in_month(year, month));
                base.with_year(year)
                    .and_then(|d| d.with_month(month))
                    .and_then(|d| d.with_day(day))
            }
        }
    }

    pub fn mark_running(&mut self) {
        self.status = ScheduleStatus::Running;
    }

    pub fn mark_completed(&mut self) {
        self.status = ScheduleStatus::Completed;
        self.last_run = Some(Utc::now());
        self.run_count += 1;
        self.next_run = self.compute_next_run();
        if self.next_run.is_some() {
            self.status = ScheduleStatus::Pending;
        }
    }

    pub fn mark_failed(&mut self, error: &str) {
        self.status = ScheduleStatus::Failed;
        self.last_run = Some(Utc::now());
        self.run_count += 1;
        self.error_message = Some(error.to_string());
        self.next_run = self.compute_next_run();
        if self.next_run.is_some() {
            self.status = ScheduleStatus::Pending;
        }
    }

    pub fn is_recurring(&self) -> bool {
        self.recurrence != Recurrence::Once
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanScheduler {
    scans: Vec<ScheduledScan>,
    max_concurrent: usize,
}

impl ScanScheduler {
    pub fn new() -> Self {
        Self {
            scans: Vec::new(),
            max_concurrent: 4,
        }
    }

    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    pub fn schedule(&mut self, scan: ScheduledScan) -> String {
        let id = scan.id.clone();
        self.scans.push(scan);
        self.sort_queue();
        id
    }

    pub fn get(&self, id: &str) -> Option<&ScheduledScan> {
        self.scans.iter().find(|s| s.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut ScheduledScan> {
        self.scans.iter_mut().find(|s| s.id == id)
    }

    pub fn cancel(&mut self, id: &str) -> bool {
        if let Some(pos) = self.scans.iter().position(|s| s.id == id) {
            self.scans.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn pending(&self) -> Vec<&ScheduledScan> {
        self.scans
            .iter()
            .filter(|s| s.status == ScheduleStatus::Pending)
            .collect()
    }

    pub fn due_scans(&self, now: DateTime<Utc>) -> Vec<&ScheduledScan> {
        self.scans
            .iter()
            .filter(|s| s.is_due(now))
            .collect()
    }

    pub fn ready_to_run(&self, now: DateTime<Utc>) -> Vec<&ScheduledScan> {
        let due = self.due_scans(now);
        let completed_ids: std::collections::HashSet<&str> = self
            .scans
            .iter()
            .filter(|s| s.status == ScheduleStatus::Completed)
            .map(|s| s.id.as_str())
            .collect();

        due.into_iter()
            .filter(|s| {
                s.dependencies
                    .iter()
                    .all(|dep| completed_ids.contains(dep.as_str()))
            })
            .collect()
    }

    pub fn queue_size(&self) -> usize {
        self.scans.len()
    }

    pub fn pending_count(&self) -> usize {
        self.scans
            .iter()
            .filter(|s| s.status == ScheduleStatus::Pending)
            .count()
    }

    pub fn completed_count(&self) -> usize {
        self.scans
            .iter()
            .filter(|s| s.status == ScheduleStatus::Completed)
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.scans
            .iter()
            .filter(|s| s.status == ScheduleStatus::Failed)
            .count()
    }

    pub fn recurring_scans(&self) -> Vec<&ScheduledScan> {
        self.scans.iter().filter(|s| s.is_recurring()).collect()
    }

    pub fn by_priority(&self) -> Vec<&ScheduledScan> {
        let mut scans: Vec<&ScheduledScan> = self.scans.iter().collect();
        scans.sort_by(|a, b| a.priority.cmp(&b.priority));
        scans
    }

    fn sort_queue(&mut self) {
        self.scans.sort_by(|a, b| {
            a.scheduled_at
                .cmp(&b.scheduled_at)
                .then(a.priority.cmp(&b.priority))
        });
    }
}

impl Default for ScanScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduled_scan_creation() {
        let now = Utc::now();
        let scan = ScheduledScan::new("port-scan", "192.168.1.0/24", now);

        assert_eq!(scan.name, "port-scan");
        assert_eq!(scan.target, "192.168.1.0/24");
        assert_eq!(scan.recurrence, Recurrence::Once);
        assert_eq!(scan.priority, 5);
        assert_eq!(scan.status, ScheduleStatus::Pending);
        assert!(scan.dependencies.is_empty());
        assert!(scan.template.is_none());
        assert_eq!(scan.run_count, 0);
    }

    #[test]
    fn test_scheduled_scan_builder() {
        let now = Utc::now();
        let scan = ScheduledScan::new("test", "10.0.0.0/8", now)
            .with_template("stealth")
            .with_recurrence(Recurrence::Daily)
            .with_priority(1)
            .with_dependency("other-scan-id");

        assert_eq!(scan.template.as_deref(), Some("stealth"));
        assert_eq!(scan.recurrence, Recurrence::Daily);
        assert_eq!(scan.priority, 1);
        assert_eq!(scan.dependencies, vec!["other-scan-id"]);
        assert!(scan.is_recurring());
    }

    #[test]
    fn test_scheduled_scan_is_due() {
        let past = Utc::now() - ChronoDuration::hours(1);
        let future = Utc::now() + ChronoDuration::hours(1);
        let now = Utc::now();

        let past_scan = ScheduledScan::new("past", "10.0.0.1", past);
        assert!(past_scan.is_due(now));

        let future_scan = ScheduledScan::new("future", "10.0.0.1", future);
        assert!(!future_scan.is_due(now));
    }

    #[test]
    fn test_scheduled_scan_status_transitions() {
        let now = Utc::now();
        let mut scan = ScheduledScan::new("test", "10.0.0.1", now);

        assert_eq!(scan.status, ScheduleStatus::Pending);

        scan.mark_running();
        assert_eq!(scan.status, ScheduleStatus::Running);

        scan.mark_completed();
        assert_eq!(scan.status, ScheduleStatus::Completed);
        assert!(scan.last_run.is_some());
        assert_eq!(scan.run_count, 1);
    }

    #[test]
    fn test_recurring_scan_resets_to_pending() {
        let now = Utc::now();
        let mut scan = ScheduledScan::new("daily", "10.0.0.1", now)
            .with_recurrence(Recurrence::Daily);

        scan.mark_running();
        scan.mark_completed();
        assert_eq!(scan.status, ScheduleStatus::Pending);
        assert!(scan.next_run.is_some());
        assert!(scan.next_run.unwrap() > now);
    }

    #[test]
    fn test_once_scan_stays_completed() {
        let now = Utc::now();
        let mut scan = ScheduledScan::new("once", "10.0.0.1", now);

        scan.mark_running();
        scan.mark_completed();
        assert_eq!(scan.status, ScheduleStatus::Completed);
        assert!(scan.next_run.is_none());
    }

    #[test]
    fn test_failed_scan_with_recurring() {
        let now = Utc::now();
        let mut scan = ScheduledScan::new("fail", "10.0.0.1", now)
            .with_recurrence(Recurrence::Hourly);

        scan.mark_running();
        scan.mark_failed("connection timeout");
        assert_eq!(scan.status, ScheduleStatus::Pending);
        assert!(scan.next_run.is_some());
        assert_eq!(scan.error_message.as_deref(), Some("connection timeout"));
    }

    #[test]
    fn test_compute_next_run_hourly() {
        let base = Utc::now();
        let scan = ScheduledScan::new("t", "t", base)
            .with_recurrence(Recurrence::Hourly);
        let next = scan.compute_next_run().unwrap();
        assert_eq!(next, base + ChronoDuration::hours(1));
    }

    #[test]
    fn test_compute_next_run_daily() {
        let base = Utc::now();
        let scan = ScheduledScan::new("t", "t", base)
            .with_recurrence(Recurrence::Daily);
        let next = scan.compute_next_run().unwrap();
        assert_eq!(next, base + ChronoDuration::days(1));
    }

    #[test]
    fn test_compute_next_run_weekly() {
        let base = Utc::now();
        let scan = ScheduledScan::new("t", "t", base)
            .with_recurrence(Recurrence::Weekly);
        let next = scan.compute_next_run().unwrap();
        assert_eq!(next, base + ChronoDuration::weeks(1));
    }

    #[test]
    fn test_compute_next_run_once() {
        let base = Utc::now();
        let scan = ScheduledScan::new("t", "t", base);
        assert!(scan.compute_next_run().is_none());
    }

    #[test]
    fn test_recurrence_display() {
        assert_eq!(Recurrence::Once.to_string(), "once");
        assert_eq!(Recurrence::Hourly.to_string(), "hourly");
        assert_eq!(Recurrence::Daily.to_string(), "daily");
        assert_eq!(Recurrence::Weekly.to_string(), "weekly");
        assert_eq!(Recurrence::Monthly.to_string(), "monthly");
    }

    #[test]
    fn test_status_display() {
        assert_eq!(ScheduleStatus::Pending.to_string(), "pending");
        assert_eq!(ScheduleStatus::Running.to_string(), "running");
        assert_eq!(ScheduleStatus::Completed.to_string(), "completed");
        assert_eq!(ScheduleStatus::Failed.to_string(), "failed");
        assert_eq!(ScheduleStatus::Skipped.to_string(), "skipped");
    }

    #[test]
    fn test_scheduler_basic() {
        let mut sched = ScanScheduler::new();
        assert!(sched.queue_size() == 0);

        let now = Utc::now();
        let id = sched.schedule(ScheduledScan::new("scan1", "10.0.0.1", now));
        assert_eq!(sched.queue_size(), 1);
        assert!(sched.get(&id).is_some());
    }

    #[test]
    fn test_scheduler_cancel() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();
        let id = sched.schedule(ScheduledScan::new("scan1", "10.0.0.1", now));

        assert!(sched.cancel(&id));
        assert_eq!(sched.queue_size(), 0);
        assert!(!sched.cancel("nonexistent"));
    }

    #[test]
    fn test_scheduler_pending() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();

        sched.schedule(ScheduledScan::new("p1", "10.0.0.1", now));
        sched.schedule(ScheduledScan::new("p2", "10.0.0.2", now));

        let pending = sched.pending();
        assert_eq!(pending.len(), 2);

        let id_to_complete = pending[0].id.clone();
        sched.get_mut(&id_to_complete).unwrap().mark_running();
        sched.get_mut(&id_to_complete).unwrap().mark_completed();

        assert_eq!(sched.pending_count(), 1);
        assert_eq!(sched.completed_count(), 1);
    }

    #[test]
    fn test_scheduler_due_scans() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();
        let past = now - ChronoDuration::hours(1);
        let future = now + ChronoDuration::hours(1);

        sched.schedule(ScheduledScan::new("past", "10.0.0.1", past));
        sched.schedule(ScheduledScan::new("future", "10.0.0.2", future));

        let due = sched.due_scans(now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].name, "past");
    }

    #[test]
    fn test_scheduler_ready_to_run_with_dependencies() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();

        let dep_id = sched.schedule(ScheduledScan::new("dep", "10.0.0.1", now));
        sched.schedule(
            ScheduledScan::new("dependent", "10.0.0.2", now)
                .with_dependency(&dep_id),
        );

        // Before dep completes, dependent should not be ready
        let ready = sched.ready_to_run(now);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].name, "dep");

        // Complete the dependency
        sched.get_mut(&dep_id).unwrap().mark_running();
        sched.get_mut(&dep_id).unwrap().mark_completed();

        let ready = sched.ready_to_run(now);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].name, "dependent");
    }

    #[test]
    fn test_scheduler_by_priority() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();

        sched.schedule(ScheduledScan::new("low", "10.0.0.1", now).with_priority(10));
        sched.schedule(ScheduledScan::new("high", "10.0.0.2", now).with_priority(1));
        sched.schedule(ScheduledScan::new("medium", "10.0.0.3", now).with_priority(5));

        let by_pri = sched.by_priority();
        assert_eq!(by_pri[0].name, "high");
        assert_eq!(by_pri[1].name, "medium");
        assert_eq!(by_pri[2].name, "low");
    }

    #[test]
    fn test_scheduler_recurring_scans() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();

        sched.schedule(ScheduledScan::new("once", "10.0.0.1", now));
        sched.schedule(
            ScheduledScan::new("daily", "10.0.0.2", now)
                .with_recurrence(Recurrence::Daily),
        );
        sched.schedule(
            ScheduledScan::new("weekly", "10.0.0.3", now)
                .with_recurrence(Recurrence::Weekly),
        );

        let recurring = sched.recurring_scans();
        assert_eq!(recurring.len(), 2);
    }

    #[test]
    fn test_scheduler_failed_count() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();

        let id = sched.schedule(ScheduledScan::new("will-fail", "10.0.0.1", now));
        sched.get_mut(&id).unwrap().mark_running();
        sched.get_mut(&id).unwrap().mark_failed("error");

        // For non-recurring, stays failed
        assert_eq!(sched.failed_count(), 1);
    }

    #[test]
    fn test_scheduler_max_concurrent() {
        let sched = ScanScheduler::new().with_max_concurrent(8);
        assert_eq!(sched.max_concurrent, 8);
    }

    #[test]
    fn test_scheduler_serialization() {
        let mut sched = ScanScheduler::new();
        let now = Utc::now();
        let id = sched.schedule(
            ScheduledScan::new("test", "10.0.0.1", now)
                .with_template("quick")
                .with_recurrence(Recurrence::Daily),
        );

        let json = serde_json::to_string(&sched).unwrap();
        let loaded: ScanScheduler = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.queue_size(), 1);
        let scan = loaded.get(&id).unwrap();
        assert_eq!(scan.template.as_deref(), Some("quick"));
        assert_eq!(scan.recurrence, Recurrence::Daily);
    }

    #[test]
    fn test_days_in_month() {
        assert_eq!(days_in_month(2024, 1), 31);
        assert_eq!(days_in_month(2024, 2), 29); // leap year
        assert_eq!(days_in_month(2023, 2), 28); // non-leap
        assert_eq!(days_in_month(2024, 4), 30);
        assert_eq!(days_in_month(2024, 12), 31);
    }

    #[test]
    fn test_compute_next_run_monthly() {
        // Jan 15 -> Feb 15
        let base = chrono::NaiveDate::from_ymd_opt(2024, 1, 15)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let scan = ScheduledScan::new("t", "t", base)
            .with_recurrence(Recurrence::Monthly);
        let next = scan.compute_next_run().unwrap();
        assert_eq!(next.month(), 2);
        assert_eq!(next.day(), 15);

        // Dec -> Jan next year
        let dec = chrono::NaiveDate::from_ymd_opt(2024, 12, 15)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();
        let scan_dec = ScheduledScan::new("t", "t", dec)
            .with_recurrence(Recurrence::Monthly);
        let next_dec = scan_dec.compute_next_run().unwrap();
        assert_eq!(next_dec.year(), 2025);
        assert_eq!(next_dec.month(), 1);
    }
}
