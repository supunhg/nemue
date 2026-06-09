// Report scheduling with recurring generation, distribution, and archiving
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration, Timelike};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportScheduler {
    pub schedules: Vec<ReportSchedule>,
    pub distribution_lists: Vec<DistributionList>,
    pub archive: ReportArchive,
    pub generation_log: Vec<GenerationLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSchedule {
    pub id: String,
    pub name: String,
    pub report_type: ScheduledReportType,
    pub recurrence: Recurrence,
    pub next_run: DateTime<Utc>,
    pub enabled: bool,
    pub config: ScheduleConfig,
    pub created_at: DateTime<Utc>,
    pub last_run: Option<DateTime<Utc>>,
    pub distribution_list_id: Option<String>,
    pub archive_after: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScheduledReportType {
    FullScan,
    ExecutiveSummary,
    ComplianceReport,
    VulnerabilityTrend,
    CustomReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Recurrence {
    Once,
    Hourly,
    Daily,
    Weekly,
    Biweekly,
    Monthly,
    Quarterly,
    Custom { interval_hours: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    pub targets: Vec<String>,
    pub output_formats: Vec<OutputFormat>,
    pub include_sections: Vec<String>,
    pub severity_threshold: Option<String>,
    pub notify_on_completion: bool,
    pub notify_on_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Html,
    Pdf,
    Csv,
    Markdown,
    Xml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionList {
    pub id: String,
    pub name: String,
    pub recipients: Vec<Recipient>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    pub name: String,
    pub email: String,
    pub role: RecipientRole,
    pub format_preference: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecipientRole {
    Admin,
    Analyst,
    Manager,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportArchive {
    pub entries: Vec<ArchiveEntry>,
    pub retention_days: u64,
    pub max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub id: String,
    pub schedule_id: String,
    pub report_type: ScheduledReportType,
    pub generated_at: DateTime<Utc>,
    pub format: OutputFormat,
    pub size_bytes: u64,
    pub file_path: String,
    pub metadata: ArchiveMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMetadata {
    pub targets: Vec<String>,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub scan_duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationLogEntry {
    pub timestamp: DateTime<Utc>,
    pub schedule_id: String,
    pub status: GenerationStatus,
    pub duration_ms: u64,
    pub output_path: Option<String>,
    pub error_message: Option<String>,
    pub distributed_to: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GenerationStatus {
    Success,
    Failed,
    Skipped,
    InProgress,
}

impl ReportScheduler {
    pub fn new(retention_days: u64) -> Self {
        Self {
            schedules: Vec::new(),
            distribution_lists: Vec::new(),
            archive: ReportArchive {
                entries: Vec::new(),
                retention_days,
                max_entries: 10000,
            },
            generation_log: Vec::new(),
        }
    }

    pub fn add_schedule(&mut self, schedule: ReportSchedule) {
        self.schedules.push(schedule);
    }

    pub fn remove_schedule(&mut self, id: &str) -> bool {
        let len_before = self.schedules.len();
        self.schedules.retain(|s| s.id != id);
        self.schedules.len() < len_before
    }

    pub fn get_schedule(&self, id: &str) -> Option<&ReportSchedule> {
        self.schedules.iter().find(|s| s.id == id)
    }

    pub fn enable_schedule(&mut self, id: &str) -> bool {
        if let Some(s) = self.schedules.iter_mut().find(|s| s.id == id) {
            s.enabled = true;
            true
        } else {
            false
        }
    }

    pub fn disable_schedule(&mut self, id: &str) -> bool {
        if let Some(s) = self.schedules.iter_mut().find(|s| s.id == id) {
            s.enabled = false;
            true
        } else {
            false
        }
    }

    pub fn get_due_schedules(&self) -> Vec<&ReportSchedule> {
        let now = Utc::now();
        self.schedules.iter().filter(|s| s.enabled && s.next_run <= now).collect()
    }

    pub fn mark_executed(&mut self, schedule_id: &str, next_run: DateTime<Utc>) {
        if let Some(s) = self.schedules.iter_mut().find(|s| s.id == schedule_id) {
            s.last_run = Some(Utc::now());
            s.next_run = next_run;
        }
    }

    pub fn add_distribution_list(&mut self, list: DistributionList) {
        self.distribution_lists.push(list);
    }

    pub fn get_distribution_list(&self, id: &str) -> Option<&DistributionList> {
        self.distribution_lists.iter().find(|l| l.id == id)
    }

    pub fn archive_report(&mut self, entry: ArchiveEntry) {
        self.archive.entries.push(entry);
        self.cleanup_archive();
    }

    fn cleanup_archive(&mut self) {
        let cutoff = Utc::now() - Duration::days(self.archive.retention_days as i64);
        self.archive.entries.retain(|e| e.generated_at > cutoff);

        if self.archive.entries.len() > self.archive.max_entries {
            let excess = self.archive.entries.len() - self.archive.max_entries;
            self.archive.entries.drain(0..excess);
        }
    }

    pub fn log_generation(&mut self, entry: GenerationLogEntry) {
        self.generation_log.push(entry);
    }

    pub fn get_archive_entries(&self, report_type: Option<&ScheduledReportType>) -> Vec<&ArchiveEntry> {
        match report_type {
            Some(t) => self.archive.entries.iter().filter(|e| &e.report_type == t).collect(),
            None => self.archive.entries.iter().collect(),
        }
    }

    pub fn archive_stats(&self) -> ArchiveStats {
        let total_size: u64 = self.archive.entries.iter().map(|e| e.size_bytes).sum();
        let by_type = self.archive.entries.iter().fold(HashMap::new(), |mut acc, e| {
            *acc.entry(format!("{:?}", e.report_type)).or_insert(0usize) += 1;
            acc
        });

        ArchiveStats {
            total_entries: self.archive.entries.len(),
            total_size_bytes: total_size,
            entries_by_type: by_type,
            oldest_entry: self.archive.entries.first().map(|e| e.generated_at),
            newest_entry: self.archive.entries.last().map(|e| e.generated_at),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStats {
    pub total_entries: usize,
    pub total_size_bytes: u64,
    pub entries_by_type: HashMap<String, usize>,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
}

impl ReportSchedule {
    pub fn new(id: &str, name: &str, report_type: ScheduledReportType, recurrence: Recurrence) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            report_type,
            next_run: Utc::now(),
            recurrence,
            enabled: true,
            config: ScheduleConfig::default(),
            created_at: Utc::now(),
            last_run: None,
            distribution_list_id: None,
            archive_after: true,
        }
    }

    pub fn with_targets(mut self, targets: Vec<String>) -> Self {
        self.config.targets = targets;
        self
    }

    pub fn with_formats(mut self, formats: Vec<OutputFormat>) -> Self {
        self.config.output_formats = formats;
        self
    }

    pub fn with_distribution(mut self, list_id: &str) -> Self {
        self.distribution_list_id = Some(list_id.to_string());
        self
    }

    pub fn with_next_run(mut self, next_run: DateTime<Utc>) -> Self {
        self.next_run = next_run;
        self
    }

    pub fn calculate_next_run(&self) -> DateTime<Utc> {
        let base = self.last_run.unwrap_or_else(Utc::now);
        match &self.recurrence {
            Recurrence::Once => base + Duration::days(365 * 100),
            Recurrence::Hourly => base + Duration::hours(1),
            Recurrence::Daily => base + Duration::days(1),
            Recurrence::Weekly => base + Duration::weeks(1),
            Recurrence::Biweekly => base + Duration::weeks(2),
            Recurrence::Monthly => base + Duration::days(30),
            Recurrence::Quarterly => base + Duration::days(90),
            Recurrence::Custom { interval_hours } => base + Duration::hours(*interval_hours as i64),
        }
    }

    pub fn is_due(&self) -> bool {
        self.enabled && Utc::now() >= self.next_run
    }
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            output_formats: vec![OutputFormat::Html, OutputFormat::Json],
            include_sections: Vec::new(),
            severity_threshold: None,
            notify_on_completion: true,
            notify_on_failure: true,
        }
    }
}

impl DistributionList {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            recipients: Vec::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_recipient(&mut self, recipient: Recipient) {
        self.recipients.push(recipient);
    }

    pub fn remove_recipient(&mut self, email: &str) -> bool {
        let len_before = self.recipients.len();
        self.recipients.retain(|r| r.email != email);
        self.recipients.len() < len_before
    }

    pub fn get_recipients_by_role(&self, role: &RecipientRole) -> Vec<&Recipient> {
        self.recipients.iter().filter(|r| &r.role == role).collect()
    }

    pub fn recipient_count(&self) -> usize {
        self.recipients.len()
    }
}

impl ReportArchive {
    pub fn search(&self, query: &str) -> Vec<&ArchiveEntry> {
        let query_lower = query.to_lowercase();
        self.entries.iter().filter(|e| {
            e.file_path.to_lowercase().contains(&query_lower)
                || e.metadata.targets.iter().any(|t| t.to_lowercase().contains(&query_lower))
        }).collect()
    }

    pub fn entries_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&ArchiveEntry> {
        self.entries.iter().filter(|e| e.generated_at >= start && e.generated_at <= end).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_schedule(id: &str) -> ReportSchedule {
        ReportSchedule::new(id, "Weekly Scan Report", ScheduledReportType::FullScan, Recurrence::Weekly)
            .with_targets(vec!["192.168.1.0/24".to_string()])
            .with_formats(vec![OutputFormat::Html, OutputFormat::Pdf])
    }

    #[test]
    fn test_scheduler_creation() {
        let scheduler = ReportScheduler::new(90);
        assert!(scheduler.schedules.is_empty());
        assert_eq!(scheduler.archive.retention_days, 90);
    }

    #[test]
    fn test_add_and_get_schedule() {
        let mut scheduler = ReportScheduler::new(90);
        scheduler.add_schedule(sample_schedule("s1"));

        assert_eq!(scheduler.schedules.len(), 1);
        let s = scheduler.get_schedule("s1").unwrap();
        assert_eq!(s.name, "Weekly Scan Report");
    }

    #[test]
    fn test_remove_schedule() {
        let mut scheduler = ReportScheduler::new(90);
        scheduler.add_schedule(sample_schedule("s1"));
        scheduler.add_schedule(sample_schedule("s2"));

        assert!(scheduler.remove_schedule("s1"));
        assert_eq!(scheduler.schedules.len(), 1);
        assert!(!scheduler.remove_schedule("nonexistent"));
    }

    #[test]
    fn test_enable_disable_schedule() {
        let mut scheduler = ReportScheduler::new(90);
        scheduler.add_schedule(sample_schedule("s1"));

        assert!(scheduler.disable_schedule("s1"));
        assert!(!scheduler.get_schedule("s1").unwrap().enabled);

        assert!(scheduler.enable_schedule("s1"));
        assert!(scheduler.get_schedule("s1").unwrap().enabled);

        assert!(!scheduler.enable_schedule("nonexistent"));
    }

    #[test]
    fn test_get_due_schedules() {
        let mut scheduler = ReportScheduler::new(90);

        let past = Utc::now() - Duration::hours(1);
        let future = Utc::now() + Duration::hours(1);

        let due = ReportSchedule::new("s1", "Due", ScheduledReportType::FullScan, Recurrence::Daily)
            .with_next_run(past);
        let not_due = ReportSchedule::new("s2", "Not Due", ScheduledReportType::FullScan, Recurrence::Daily)
            .with_next_run(future);
        let disabled = {
            let mut s = ReportSchedule::new("s3", "Disabled", ScheduledReportType::FullScan, Recurrence::Daily);
            s.next_run = past;
            s.enabled = false;
            s
        };

        scheduler.add_schedule(due);
        scheduler.add_schedule(not_due);
        scheduler.add_schedule(disabled);

        let due_list = scheduler.get_due_schedules();
        assert_eq!(due_list.len(), 1);
        assert_eq!(due_list[0].id, "s1");
    }

    #[test]
    fn test_mark_executed() {
        let mut scheduler = ReportScheduler::new(90);
        scheduler.add_schedule(sample_schedule("s1"));

        let next = Utc::now() + Duration::weeks(1);
        scheduler.mark_executed("s1", next);

        let s = scheduler.get_schedule("s1").unwrap();
        assert!(s.last_run.is_some());
        assert!(s.next_run > Utc::now());
    }

    #[test]
    fn test_distribution_list() {
        let mut list = DistributionList::new("dl1", "Security Team");
        list.add_recipient(Recipient {
            name: "Alice".to_string(),
            email: "alice@example.com".to_string(),
            role: RecipientRole::Admin,
            format_preference: OutputFormat::Pdf,
        });
        list.add_recipient(Recipient {
            name: "Bob".to_string(),
            email: "bob@example.com".to_string(),
            role: RecipientRole::Analyst,
            format_preference: OutputFormat::Html,
        });

        assert_eq!(list.recipient_count(), 2);
        assert_eq!(list.get_recipients_by_role(&RecipientRole::Admin).len(), 1);

        assert!(list.remove_recipient("bob@example.com"));
        assert_eq!(list.recipient_count(), 1);
        assert!(!list.remove_recipient("nonexistent@example.com"));
    }

    #[test]
    fn test_scheduler_distribution_lists() {
        let mut scheduler = ReportScheduler::new(90);
        let list = DistributionList::new("dl1", "Team");
        scheduler.add_distribution_list(list);

        assert!(scheduler.get_distribution_list("dl1").is_some());
        assert!(scheduler.get_distribution_list("nonexistent").is_none());
    }

    #[test]
    fn test_archive_report() {
        let mut scheduler = ReportScheduler::new(90);
        scheduler.archive_report(ArchiveEntry {
            id: "a1".to_string(),
            schedule_id: "s1".to_string(),
            report_type: ScheduledReportType::FullScan,
            generated_at: Utc::now(),
            format: OutputFormat::Html,
            size_bytes: 1024,
            file_path: "/reports/scan-001.html".to_string(),
            metadata: ArchiveMetadata {
                targets: vec!["192.168.1.0/24".to_string()],
                total_findings: 15,
                critical_findings: 2,
                scan_duration_secs: 300,
            },
        });

        assert_eq!(scheduler.archive.entries.len(), 1);

        let stats = scheduler.archive_stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.total_size_bytes, 1024);
    }

    #[test]
    fn test_archive_cleanup_by_retention() {
        let mut scheduler = ReportScheduler::new(1);

        scheduler.archive_report(ArchiveEntry {
            id: "old".to_string(),
            schedule_id: "s1".to_string(),
            report_type: ScheduledReportType::FullScan,
            generated_at: Utc::now() - Duration::days(5),
            format: OutputFormat::Html,
            size_bytes: 512,
            file_path: "/reports/old.html".to_string(),
            metadata: ArchiveMetadata {
                targets: vec![],
                total_findings: 0,
                critical_findings: 0,
                scan_duration_secs: 0,
            },
        });
        scheduler.archive_report(ArchiveEntry {
            id: "new".to_string(),
            schedule_id: "s1".to_string(),
            report_type: ScheduledReportType::FullScan,
            generated_at: Utc::now(),
            format: OutputFormat::Html,
            size_bytes: 1024,
            file_path: "/reports/new.html".to_string(),
            metadata: ArchiveMetadata {
                targets: vec![],
                total_findings: 0,
                critical_findings: 0,
                scan_duration_secs: 0,
            },
        });

        assert_eq!(scheduler.archive.entries.len(), 1);
        assert_eq!(scheduler.archive.entries[0].id, "new");
    }

    #[test]
    fn test_archive_search() {
        let mut archive = ReportArchive {
            entries: Vec::new(),
            retention_days: 90,
            max_entries: 1000,
        };

        archive.entries.push(ArchiveEntry {
            id: "a1".to_string(),
            schedule_id: "s1".to_string(),
            report_type: ScheduledReportType::FullScan,
            generated_at: Utc::now(),
            format: OutputFormat::Html,
            size_bytes: 1024,
            file_path: "/reports/192-168-1-scan.html".to_string(),
            metadata: ArchiveMetadata {
                targets: vec!["192.168.1.0/24".to_string()],
                total_findings: 10,
                critical_findings: 1,
                scan_duration_secs: 120,
            },
        });
        archive.entries.push(ArchiveEntry {
            id: "a2".to_string(),
            schedule_id: "s2".to_string(),
            report_type: ScheduledReportType::ComplianceReport,
            generated_at: Utc::now(),
            format: OutputFormat::Pdf,
            size_bytes: 2048,
            file_path: "/reports/compliance-pci.pdf".to_string(),
            metadata: ArchiveMetadata {
                targets: vec!["10.0.0.0/8".to_string()],
                total_findings: 5,
                critical_findings: 0,
                scan_duration_secs: 60,
            },
        });

        let results = archive.search("192.168");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "a1");

        let all = archive.search("reports");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_archive_entries_in_range() {
        let mut archive = ReportArchive {
            entries: Vec::new(),
            retention_days: 90,
            max_entries: 1000,
        };

        let now = Utc::now();
        archive.entries.push(ArchiveEntry {
            id: "a1".to_string(),
            schedule_id: "s1".to_string(),
            report_type: ScheduledReportType::FullScan,
            generated_at: now - Duration::days(10),
            format: OutputFormat::Html,
            size_bytes: 1024,
            file_path: "/reports/old.html".to_string(),
            metadata: ArchiveMetadata {
                targets: vec![],
                total_findings: 0,
                critical_findings: 0,
                scan_duration_secs: 0,
            },
        });
        archive.entries.push(ArchiveEntry {
            id: "a2".to_string(),
            schedule_id: "s1".to_string(),
            report_type: ScheduledReportType::FullScan,
            generated_at: now - Duration::days(2),
            format: OutputFormat::Html,
            size_bytes: 1024,
            file_path: "/reports/recent.html".to_string(),
            metadata: ArchiveMetadata {
                targets: vec![],
                total_findings: 0,
                critical_findings: 0,
                scan_duration_secs: 0,
            },
        });

        let results = archive.entries_in_range(now - Duration::days(5), now);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "a2");
    }

    #[test]
    fn test_schedule_builder() {
        let schedule = ReportSchedule::new("s1", "Daily Compliance", ScheduledReportType::ComplianceReport, Recurrence::Daily)
            .with_targets(vec!["10.0.0.0/8".to_string()])
            .with_formats(vec![OutputFormat::Pdf])
            .with_distribution("dl1");

        assert_eq!(schedule.config.targets.len(), 1);
        assert_eq!(schedule.config.output_formats, vec![OutputFormat::Pdf]);
        assert_eq!(schedule.distribution_list_id, Some("dl1".to_string()));
    }

    #[test]
    fn test_schedule_is_due() {
        let mut schedule = sample_schedule("s1");
        schedule.next_run = Utc::now() - Duration::hours(1);
        assert!(schedule.is_due());

        schedule.enabled = false;
        assert!(!schedule.is_due());
    }

    #[test]
    fn test_calculate_next_run() {
        let schedule = ReportSchedule::new("s1", "Test", ScheduledReportType::FullScan, Recurrence::Daily);
        let next = schedule.calculate_next_run();
        assert!(next > Utc::now());
    }

    #[test]
    fn test_recurrence_types() {
        assert_ne!(Recurrence::Daily, Recurrence::Weekly);
        assert_ne!(Recurrence::Monthly, Recurrence::Quarterly);
        let custom1 = Recurrence::Custom { interval_hours: 6 };
        let custom2 = Recurrence::Custom { interval_hours: 12 };
        assert_ne!(custom1, custom2);
    }

    #[test]
    fn test_output_formats() {
        assert_ne!(OutputFormat::Html, OutputFormat::Pdf);
        assert_ne!(OutputFormat::Json, OutputFormat::Csv);
    }

    #[test]
    fn test_generation_log() {
        let mut scheduler = ReportScheduler::new(90);
        scheduler.log_generation(GenerationLogEntry {
            timestamp: Utc::now(),
            schedule_id: "s1".to_string(),
            status: GenerationStatus::Success,
            duration_ms: 1500,
            output_path: Some("/reports/output.html".to_string()),
            error_message: None,
            distributed_to: vec!["alice@example.com".to_string()],
        });

        assert_eq!(scheduler.generation_log.len(), 1);
        assert_eq!(scheduler.generation_log[0].status, GenerationStatus::Success);
    }

    #[test]
    fn test_schedule_report_types() {
        assert_ne!(ScheduledReportType::FullScan, ScheduledReportType::ExecutiveSummary);
        assert_ne!(ScheduledReportType::ComplianceReport, ScheduledReportType::VulnerabilityTrend);
    }

    #[test]
    fn test_archive_stats_by_type() {
        let mut scheduler = ReportScheduler::new(90);

        for i in 0..3 {
            scheduler.archive_report(ArchiveEntry {
                id: format!("a{}", i),
                schedule_id: "s1".to_string(),
                report_type: ScheduledReportType::FullScan,
                generated_at: Utc::now(),
                format: OutputFormat::Html,
                size_bytes: 100,
                file_path: format!("/reports/{}.html", i),
                metadata: ArchiveMetadata {
                    targets: vec![],
                    total_findings: 0,
                    critical_findings: 0,
                    scan_duration_secs: 0,
                },
            });
        }
        scheduler.archive_report(ArchiveEntry {
            id: "c1".to_string(),
            schedule_id: "s2".to_string(),
            report_type: ScheduledReportType::ComplianceReport,
            generated_at: Utc::now(),
            format: OutputFormat::Pdf,
            size_bytes: 200,
            file_path: "/reports/compliance.pdf".to_string(),
            metadata: ArchiveMetadata {
                targets: vec![],
                total_findings: 0,
                critical_findings: 0,
                scan_duration_secs: 0,
            },
        });

        let stats = scheduler.archive_stats();
        assert_eq!(stats.total_entries, 4);
        assert_eq!(stats.total_size_bytes, 500);
        assert_eq!(stats.entries_by_type.get("FullScan"), Some(&3));
        assert_eq!(stats.entries_by_type.get("ComplianceReport"), Some(&1));
    }

    #[test]
    fn test_get_archive_entries_filtered() {
        let mut scheduler = ReportScheduler::new(90);

        scheduler.archive_report(ArchiveEntry {
            id: "a1".to_string(),
            schedule_id: "s1".to_string(),
            report_type: ScheduledReportType::FullScan,
            generated_at: Utc::now(),
            format: OutputFormat::Html,
            size_bytes: 100,
            file_path: "/reports/scan.html".to_string(),
            metadata: ArchiveMetadata {
                targets: vec![],
                total_findings: 0,
                critical_findings: 0,
                scan_duration_secs: 0,
            },
        });
        scheduler.archive_report(ArchiveEntry {
            id: "c1".to_string(),
            schedule_id: "s2".to_string(),
            report_type: ScheduledReportType::ComplianceReport,
            generated_at: Utc::now(),
            format: OutputFormat::Pdf,
            size_bytes: 200,
            file_path: "/reports/compliance.pdf".to_string(),
            metadata: ArchiveMetadata {
                targets: vec![],
                total_findings: 0,
                critical_findings: 0,
                scan_duration_secs: 0,
            },
        });

        let all = scheduler.get_archive_entries(None);
        assert_eq!(all.len(), 2);

        let scans = scheduler.get_archive_entries(Some(&ScheduledReportType::FullScan));
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].id, "a1");
    }
}
