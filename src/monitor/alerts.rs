use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Critical => write!(f, "critical"),
            AlertSeverity::High => write!(f, "high"),
            AlertSeverity::Medium => write!(f, "medium"),
            AlertSeverity::Low => write!(f, "low"),
            AlertSeverity::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    Silenced,
}

impl std::fmt::Display for AlertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertStatus::Active => write!(f, "active"),
            AlertStatus::Acknowledged => write!(f, "acknowledged"),
            AlertStatus::Resolved => write!(f, "resolved"),
            AlertStatus::Silenced => write!(f, "silenced"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equal,
    NotEqual,
    GreaterThanOrEqual,
    LessThanOrEqual,
}

impl ComparisonOperator {
    pub fn evaluate(&self, left: f64, right: f64) -> bool {
        match self {
            ComparisonOperator::GreaterThan => left > right,
            ComparisonOperator::LessThan => left < right,
            ComparisonOperator::Equal => (left - right).abs() < f64::EPSILON,
            ComparisonOperator::NotEqual => (left - right).abs() >= f64::EPSILON,
            ComparisonOperator::GreaterThanOrEqual => left >= right,
            ComparisonOperator::LessThanOrEqual => left <= right,
        }
    }
}

impl std::fmt::Display for ComparisonOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonOperator::GreaterThan => write!(f, ">"),
            ComparisonOperator::LessThan => write!(f, "<"),
            ComparisonOperator::Equal => write!(f, "=="),
            ComparisonOperator::NotEqual => write!(f, "!="),
            ComparisonOperator::GreaterThanOrEqual => write!(f, ">="),
            ComparisonOperator::LessThanOrEqual => write!(f, "<="),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub metric_name: String,
    pub operator: ComparisonOperator,
    pub threshold: f64,
    pub severity: AlertSeverity,
    pub duration_seconds: u64,
    pub labels: HashMap<String, String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

impl AlertRule {
    pub fn new(
        name: &str,
        metric_name: &str,
        operator: ComparisonOperator,
        threshold: f64,
        severity: AlertSeverity,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            metric_name: metric_name.to_string(),
            operator,
            threshold,
            severity,
            duration_seconds: 0,
            labels: HashMap::new(),
            enabled: true,
            created_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_duration(mut self, seconds: u64) -> Self {
        self.duration_seconds = seconds;
        self
    }

    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }

    pub fn evaluate(&self, current_value: f64) -> bool {
        self.enabled && self.operator.evaluate(current_value, self.threshold)
    }

    pub fn condition_string(&self) -> String {
        format!(
            "{} {} {}",
            self.metric_name, self.operator, self.threshold
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertChannelType {
    Email,
    Slack,
    Webhook,
    PagerDuty,
    OpsGenie,
}

impl std::fmt::Display for AlertChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertChannelType::Email => write!(f, "email"),
            AlertChannelType::Slack => write!(f, "slack"),
            AlertChannelType::Webhook => write!(f, "webhook"),
            AlertChannelType::PagerDuty => write!(f, "pagerduty"),
            AlertChannelType::OpsGenie => write!(f, "opsgenie"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertChannel {
    pub id: String,
    pub name: String,
    pub channel_type: AlertChannelType,
    pub destination: String,
    pub enabled: bool,
    pub min_severity: AlertSeverity,
    pub metadata: HashMap<String, String>,
}

impl AlertChannel {
    pub fn new(name: &str, channel_type: AlertChannelType, destination: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            channel_type,
            destination: destination.to_string(),
            enabled: true,
            min_severity: AlertSeverity::Low,
            metadata: HashMap::new(),
        }
    }

    pub fn with_min_severity(mut self, severity: AlertSeverity) -> Self {
        self.min_severity = severity;
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn accepts_severity(&self, severity: AlertSeverity) -> bool {
        severity_rank(severity) >= severity_rank(self.min_severity)
    }
}

fn severity_rank(severity: AlertSeverity) -> u8 {
    match severity {
        AlertSeverity::Critical => 4,
        AlertSeverity::High => 3,
        AlertSeverity::Medium => 2,
        AlertSeverity::Low => 1,
        AlertSeverity::Info => 0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub id: String,
    pub name: String,
    pub levels: Vec<EscalationLevel>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationLevel {
    pub level: u32,
    pub delay_seconds: u64,
    pub channel_ids: Vec<String>,
}

impl EscalationPolicy {
    pub fn new(name: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            levels: Vec::new(),
            enabled: true,
        }
    }

    pub fn add_level(&mut self, delay_seconds: u64, channel_ids: Vec<String>) {
        let level = self.levels.len() as u32 + 1;
        self.levels.push(EscalationLevel {
            level,
            delay_seconds,
            channel_ids,
        });
    }

    pub fn total_escalation_time(&self) -> u64 {
        self.levels.iter().map(|l| l.delay_seconds).sum()
    }

    pub fn level_count(&self) -> usize {
        self.levels.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub message: String,
    pub metric_name: String,
    pub metric_value: f64,
    pub threshold: f64,
    pub labels: HashMap<String, String>,
    pub triggered_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub escalation_level: u32,
    pub notifications_sent: Vec<AlertNotification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNotification {
    pub channel_id: String,
    pub channel_type: AlertChannelType,
    pub sent_at: DateTime<Utc>,
    pub success: bool,
    pub error: Option<String>,
}

impl Alert {
    pub fn new(rule: &AlertRule, metric_value: f64) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: rule.severity,
            status: AlertStatus::Active,
            message: format!(
                "Alert: {} - {} = {} (threshold: {})",
                rule.name, rule.metric_name, metric_value, rule.threshold
            ),
            metric_name: rule.metric_name.clone(),
            metric_value,
            threshold: rule.threshold,
            labels: rule.labels.clone(),
            triggered_at: Utc::now(),
            acknowledged_at: None,
            resolved_at: None,
            escalation_level: 0,
            notifications_sent: Vec::new(),
        }
    }

    pub fn acknowledge(&mut self) {
        if self.status == AlertStatus::Active {
            self.status = AlertStatus::Acknowledged;
            self.acknowledged_at = Some(Utc::now());
        }
    }

    pub fn resolve(&mut self) {
        self.status = AlertStatus::Resolved;
        self.resolved_at = Some(Utc::now());
    }

    pub fn silence(&mut self) {
        if self.status == AlertStatus::Active || self.status == AlertStatus::Acknowledged {
            self.status = AlertStatus::Silenced;
        }
    }

    pub fn escalate(&mut self) {
        self.escalation_level += 1;
    }

    pub fn add_notification(&mut self, notification: AlertNotification) {
        self.notifications_sent.push(notification);
    }

    pub fn is_active(&self) -> bool {
        self.status == AlertStatus::Active
    }

    pub fn duration_seconds(&self) -> i64 {
        let end = self.resolved_at.unwrap_or_else(Utc::now);
        end.signed_duration_since(self.triggered_at)
            .num_seconds()
            .max(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertHistoryEntry {
    pub alert_id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

pub struct AlertManager {
    rules: HashMap<String, AlertRule>,
    channels: HashMap<String, AlertChannel>,
    escalation_policies: HashMap<String, EscalationPolicy>,
    active_alerts: HashMap<String, Alert>,
    history: Vec<AlertHistoryEntry>,
    max_history: usize,
}

impl AlertManager {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            channels: HashMap::new(),
            escalation_policies: HashMap::new(),
            active_alerts: HashMap::new(),
            history: Vec::new(),
            max_history: 5000,
        }
    }

    pub fn with_max_history(mut self, max: usize) -> Self {
        self.max_history = max;
        self
    }

    pub fn add_rule(&mut self, rule: AlertRule) -> String {
        let id = rule.id.clone();
        self.rules.insert(id.clone(), rule);
        id
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        self.rules.remove(rule_id).is_some()
    }

    pub fn get_rule(&self, rule_id: &str) -> Option<&AlertRule> {
        self.rules.get(rule_id)
    }

    pub fn list_rules(&self) -> Vec<&AlertRule> {
        self.rules.values().collect()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn add_channel(&mut self, channel: AlertChannel) -> String {
        let id = channel.id.clone();
        self.channels.insert(id.clone(), channel);
        id
    }

    pub fn remove_channel(&mut self, channel_id: &str) -> bool {
        self.channels.remove(channel_id).is_some()
    }

    pub fn get_channel(&self, channel_id: &str) -> Option<&AlertChannel> {
        self.channels.get(channel_id)
    }

    pub fn list_channels(&self) -> Vec<&AlertChannel> {
        self.channels.values().collect()
    }

    pub fn add_escalation_policy(&mut self, policy: EscalationPolicy) -> String {
        let id = policy.id.clone();
        self.escalation_policies.insert(id.clone(), policy);
        id
    }

    pub fn get_escalation_policy(&self, policy_id: &str) -> Option<&EscalationPolicy> {
        self.escalation_policies.get(policy_id)
    }

    pub fn evaluate_rules(&mut self, metric_name: &str, metric_value: f64) -> Vec<Alert> {
        let mut new_alerts = Vec::new();

        let matching_rules: Vec<AlertRule> = self
            .rules
            .values()
            .filter(|r| r.enabled && r.metric_name == metric_name && r.evaluate(metric_value))
            .cloned()
            .collect();

        for rule in matching_rules {
            let already_active = self
                .active_alerts
                .values()
                .any(|a| a.rule_id == rule.id && a.is_active());

            if !already_active {
                let alert = Alert::new(&rule, metric_value);
                let alert_id = alert.id.clone();
                let entry = AlertHistoryEntry {
                    alert_id: alert_id.clone(),
                    rule_name: alert.rule_name.clone(),
                    severity: alert.severity,
                    status: alert.status,
                    message: alert.message.clone(),
                    timestamp: alert.triggered_at,
                };
                self.active_alerts.insert(alert_id, alert.clone());
                self.add_history(entry);
                new_alerts.push(alert);
            }
        }

        new_alerts
    }

    pub fn acknowledge_alert(&mut self, alert_id: &str) -> bool {
        if let Some(alert) = self.active_alerts.get_mut(alert_id) {
            alert.acknowledge();
            let entry = AlertHistoryEntry {
                alert_id: alert_id.to_string(),
                rule_name: alert.rule_name.clone(),
                severity: alert.severity,
                status: alert.status,
                message: format!("Alert acknowledged: {}", alert.rule_name),
                timestamp: Utc::now(),
            };
            self.add_history(entry);
            true
        } else {
            false
        }
    }

    pub fn resolve_alert(&mut self, alert_id: &str) -> bool {
        if let Some(alert) = self.active_alerts.get_mut(alert_id) {
            alert.resolve();
            let entry = AlertHistoryEntry {
                alert_id: alert_id.to_string(),
                rule_name: alert.rule_name.clone(),
                severity: alert.severity,
                status: alert.status,
                message: format!("Alert resolved: {}", alert.rule_name),
                timestamp: Utc::now(),
            };
            self.add_history(entry);
            true
        } else {
            false
        }
    }

    pub fn silence_alert(&mut self, alert_id: &str) -> bool {
        if let Some(alert) = self.active_alerts.get_mut(alert_id) {
            alert.silence();
            true
        } else {
            false
        }
    }

    pub fn get_alert(&self, alert_id: &str) -> Option<&Alert> {
        self.active_alerts.get(alert_id)
    }

    pub fn active_alerts(&self) -> Vec<&Alert> {
        self.active_alerts
            .values()
            .filter(|a| a.is_active())
            .collect()
    }

    pub fn alerts_by_severity(&self, severity: AlertSeverity) -> Vec<&Alert> {
        self.active_alerts
            .values()
            .filter(|a| a.severity == severity)
            .collect()
    }

    pub fn active_alert_count(&self) -> usize {
        self.active_alerts.values().filter(|a| a.is_active()).count()
    }

    pub fn total_alert_count(&self) -> usize {
        self.active_alerts.len()
    }

    pub fn history(&self) -> &[AlertHistoryEntry] {
        &self.history
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    fn add_history(&mut self, entry: AlertHistoryEntry) {
        self.history.push(entry);
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    pub fn cleanup_resolved(&mut self) -> usize {
        let before = self.active_alerts.len();
        self.active_alerts
            .retain(|_, alert| alert.status != AlertStatus::Resolved);
        before - self.active_alerts.len()
    }
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_severity_display() {
        assert_eq!(AlertSeverity::Critical.to_string(), "critical");
        assert_eq!(AlertSeverity::High.to_string(), "high");
        assert_eq!(AlertSeverity::Medium.to_string(), "medium");
        assert_eq!(AlertSeverity::Low.to_string(), "low");
        assert_eq!(AlertSeverity::Info.to_string(), "info");
    }

    #[test]
    fn test_alert_status_display() {
        assert_eq!(AlertStatus::Active.to_string(), "active");
        assert_eq!(AlertStatus::Acknowledged.to_string(), "acknowledged");
        assert_eq!(AlertStatus::Resolved.to_string(), "resolved");
        assert_eq!(AlertStatus::Silenced.to_string(), "silenced");
    }

    #[test]
    fn test_comparison_operator_display() {
        assert_eq!(ComparisonOperator::GreaterThan.to_string(), ">");
        assert_eq!(ComparisonOperator::LessThan.to_string(), "<");
        assert_eq!(ComparisonOperator::Equal.to_string(), "==");
        assert_eq!(ComparisonOperator::NotEqual.to_string(), "!=");
        assert_eq!(ComparisonOperator::GreaterThanOrEqual.to_string(), ">=");
        assert_eq!(ComparisonOperator::LessThanOrEqual.to_string(), "<=");
    }

    #[test]
    fn test_comparison_operator_evaluate() {
        assert!(ComparisonOperator::GreaterThan.evaluate(5.0, 3.0));
        assert!(!ComparisonOperator::GreaterThan.evaluate(3.0, 5.0));
        assert!(ComparisonOperator::LessThan.evaluate(3.0, 5.0));
        assert!(ComparisonOperator::Equal.evaluate(5.0, 5.0));
        assert!(ComparisonOperator::NotEqual.evaluate(5.0, 3.0));
        assert!(ComparisonOperator::GreaterThanOrEqual.evaluate(5.0, 5.0));
        assert!(ComparisonOperator::LessThanOrEqual.evaluate(5.0, 5.0));
    }

    #[test]
    fn test_alert_rule_creation() {
        let rule = AlertRule::new(
            "high_cpu",
            "cpu_usage",
            ComparisonOperator::GreaterThan,
            90.0,
            AlertSeverity::Critical,
        )
        .with_description("CPU usage is too high")
        .with_duration(300)
        .with_label("host", "web1");

        assert_eq!(rule.name, "high_cpu");
        assert_eq!(rule.metric_name, "cpu_usage");
        assert_eq!(rule.threshold, 90.0);
        assert_eq!(rule.severity, AlertSeverity::Critical);
        assert_eq!(rule.duration_seconds, 300);
        assert!(rule.enabled);
        assert_eq!(rule.description, "CPU usage is too high");
        assert_eq!(rule.labels.get("host").unwrap(), "web1");
    }

    #[test]
    fn test_alert_rule_evaluate() {
        let rule = AlertRule::new(
            "high_mem",
            "memory_usage",
            ComparisonOperator::GreaterThan,
            80.0,
            AlertSeverity::High,
        );

        assert!(rule.evaluate(90.0));
        assert!(!rule.evaluate(70.0));
    }

    #[test]
    fn test_alert_rule_disabled() {
        let mut rule = AlertRule::new(
            "test",
            "metric",
            ComparisonOperator::GreaterThan,
            50.0,
            AlertSeverity::Medium,
        );
        rule.enabled = false;

        assert!(!rule.evaluate(100.0));
    }

    #[test]
    fn test_alert_rule_condition_string() {
        let rule = AlertRule::new(
            "test",
            "cpu",
            ComparisonOperator::GreaterThan,
            90.0,
            AlertSeverity::High,
        );
        assert_eq!(rule.condition_string(), "cpu > 90");
    }

    #[test]
    fn test_alert_channel_type_display() {
        assert_eq!(AlertChannelType::Email.to_string(), "email");
        assert_eq!(AlertChannelType::Slack.to_string(), "slack");
        assert_eq!(AlertChannelType::Webhook.to_string(), "webhook");
        assert_eq!(AlertChannelType::PagerDuty.to_string(), "pagerduty");
        assert_eq!(AlertChannelType::OpsGenie.to_string(), "opsgenie");
    }

    #[test]
    fn test_alert_channel_creation() {
        let channel = AlertChannel::new("email-critical", AlertChannelType::Email, "oncall@example.com")
            .with_min_severity(AlertSeverity::High)
            .with_metadata("smtp_server", "smtp.example.com");

        assert_eq!(channel.name, "email-critical");
        assert_eq!(channel.channel_type, AlertChannelType::Email);
        assert_eq!(channel.destination, "oncall@example.com");
        assert_eq!(channel.min_severity, AlertSeverity::High);
        assert!(channel.enabled);
    }

    #[test]
    fn test_alert_channel_accepts_severity() {
        let channel =
            AlertChannel::new("slack", AlertChannelType::Slack, "#alerts")
                .with_min_severity(AlertSeverity::Medium);

        assert!(!channel.accepts_severity(AlertSeverity::Info));
        assert!(!channel.accepts_severity(AlertSeverity::Low));
        assert!(channel.accepts_severity(AlertSeverity::Medium));
        assert!(channel.accepts_severity(AlertSeverity::High));
        assert!(channel.accepts_severity(AlertSeverity::Critical));
    }

    #[test]
    fn test_escalation_policy() {
        let mut policy = EscalationPolicy::new("on-call");
        policy.add_level(0, vec!["ch1".to_string()]);
        policy.add_level(300, vec!["ch2".to_string(), "ch3".to_string()]);
        policy.add_level(900, vec!["ch4".to_string()]);

        assert_eq!(policy.level_count(), 3);
        assert_eq!(policy.total_escalation_time(), 1200);
        assert!(policy.enabled);
    }

    #[test]
    fn test_alert_creation() {
        let rule = AlertRule::new(
            "disk_full",
            "disk_usage",
            ComparisonOperator::GreaterThan,
            95.0,
            AlertSeverity::Critical,
        )
        .with_label("mount", "/");

        let alert = Alert::new(&rule, 98.5);

        assert_eq!(alert.rule_name, "disk_full");
        assert_eq!(alert.severity, AlertSeverity::Critical);
        assert_eq!(alert.status, AlertStatus::Active);
        assert!(alert.is_active());
        assert_eq!(alert.metric_value, 98.5);
        assert_eq!(alert.threshold, 95.0);
        assert_eq!(alert.escalation_level, 0);
        assert!(alert.message.contains("disk_full"));
    }

    #[test]
    fn test_alert_lifecycle() {
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let mut alert = Alert::new(&rule, 1.0);

        assert_eq!(alert.status, AlertStatus::Active);
        assert!(alert.is_active());

        alert.acknowledge();
        assert_eq!(alert.status, AlertStatus::Acknowledged);
        assert!(alert.acknowledged_at.is_some());

        alert.resolve();
        assert_eq!(alert.status, AlertStatus::Resolved);
        assert!(alert.resolved_at.is_some());
        assert!(!alert.is_active());
    }

    #[test]
    fn test_alert_silence() {
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let mut alert = Alert::new(&rule, 1.0);
        alert.silence();
        assert_eq!(alert.status, AlertStatus::Silenced);
    }

    #[test]
    fn test_alert_escalate() {
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let mut alert = Alert::new(&rule, 1.0);
        alert.escalate();
        alert.escalate();
        assert_eq!(alert.escalation_level, 2);
    }

    #[test]
    fn test_alert_add_notification() {
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let mut alert = Alert::new(&rule, 1.0);
        alert.add_notification(AlertNotification {
            channel_id: "ch1".to_string(),
            channel_type: AlertChannelType::Email,
            sent_at: Utc::now(),
            success: true,
            error: None,
        });
        assert_eq!(alert.notifications_sent.len(), 1);
    }

    #[test]
    fn test_alert_duration() {
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let alert = Alert::new(&rule, 1.0);
        let duration = alert.duration_seconds();
        assert!(duration >= 0);
    }

    #[test]
    fn test_alert_manager_add_rule() {
        let mut mgr = AlertManager::new();
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let id = mgr.add_rule(rule);
        assert!(mgr.get_rule(&id).is_some());
        assert_eq!(mgr.rule_count(), 1);
    }

    #[test]
    fn test_alert_manager_remove_rule() {
        let mut mgr = AlertManager::new();
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let id = rule.id.clone();
        mgr.add_rule(rule);
        assert!(mgr.remove_rule(&id));
        assert!(mgr.get_rule(&id).is_none());
        assert!(!mgr.remove_rule("nonexistent"));
    }

    #[test]
    fn test_alert_manager_add_channel() {
        let mut mgr = AlertManager::new();
        let ch = AlertChannel::new("email", AlertChannelType::Email, "a@b.com");
        let id = mgr.add_channel(ch);
        assert!(mgr.get_channel(&id).is_some());
    }

    #[test]
    fn test_alert_manager_remove_channel() {
        let mut mgr = AlertManager::new();
        let ch = AlertChannel::new("ch", AlertChannelType::Slack, "#a");
        let id = ch.id.clone();
        mgr.add_channel(ch);
        assert!(mgr.remove_channel(&id));
    }

    #[test]
    fn test_alert_manager_evaluate_rules_triggers_alert() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "high_cpu",
            "cpu",
            ComparisonOperator::GreaterThan,
            90.0,
            AlertSeverity::Critical,
        ));

        let alerts = mgr.evaluate_rules("cpu", 95.0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(mgr.active_alert_count(), 1);
        assert_eq!(mgr.history_len(), 1);
    }

    #[test]
    fn test_alert_manager_evaluate_rules_no_trigger() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "high_cpu",
            "cpu",
            ComparisonOperator::GreaterThan,
            90.0,
            AlertSeverity::Critical,
        ));

        let alerts = mgr.evaluate_rules("cpu", 50.0);
        assert_eq!(alerts.len(), 0);
        assert_eq!(mgr.active_alert_count(), 0);
    }

    #[test]
    fn test_alert_manager_no_duplicate_alerts() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "r",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        ));

        let a1 = mgr.evaluate_rules("m", 5.0);
        assert_eq!(a1.len(), 1);

        let a2 = mgr.evaluate_rules("m", 10.0);
        assert_eq!(a2.len(), 0);
        assert_eq!(mgr.active_alert_count(), 1);
    }

    #[test]
    fn test_alert_manager_evaluate_different_metrics() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new("cpu_rule", "cpu", ComparisonOperator::GreaterThan, 90.0, AlertSeverity::High));
        mgr.add_rule(AlertRule::new("mem_rule", "mem", ComparisonOperator::GreaterThan, 80.0, AlertSeverity::Medium));

        let alerts = mgr.evaluate_rules("cpu", 95.0);
        assert_eq!(alerts.len(), 1);

        let alerts = mgr.evaluate_rules("mem", 85.0);
        assert_eq!(alerts.len(), 1);
        assert_eq!(mgr.active_alert_count(), 2);
    }

    #[test]
    fn test_alert_manager_disabled_rule() {
        let mut mgr = AlertManager::new();
        let mut rule = AlertRule::new(
            "r",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        );
        rule.enabled = false;
        mgr.add_rule(rule);

        let alerts = mgr.evaluate_rules("m", 100.0);
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn test_alert_manager_acknowledge() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "r",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        ));

        let alerts = mgr.evaluate_rules("m", 5.0);
        let alert_id = alerts[0].id.clone();

        assert!(mgr.acknowledge_alert(&alert_id));
        let alert = mgr.get_alert(&alert_id).unwrap();
        assert_eq!(alert.status, AlertStatus::Acknowledged);
        assert_eq!(mgr.history_len(), 2);
    }

    #[test]
    fn test_alert_manager_resolve() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "r",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        ));

        let alerts = mgr.evaluate_rules("m", 5.0);
        let alert_id = alerts[0].id.clone();

        assert!(mgr.resolve_alert(&alert_id));
        let alert = mgr.get_alert(&alert_id).unwrap();
        assert_eq!(alert.status, AlertStatus::Resolved);
        assert_eq!(mgr.history_len(), 2);
    }

    #[test]
    fn test_alert_manager_silence() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "r",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        ));

        let alerts = mgr.evaluate_rules("m", 5.0);
        let alert_id = alerts[0].id.clone();

        assert!(mgr.silence_alert(&alert_id));
        let alert = mgr.get_alert(&alert_id).unwrap();
        assert_eq!(alert.status, AlertStatus::Silenced);
    }

    #[test]
    fn test_alert_manager_acknowledge_nonexistent() {
        let mut mgr = AlertManager::new();
        assert!(!mgr.acknowledge_alert("nonexistent"));
    }

    #[test]
    fn test_alert_manager_resolve_nonexistent() {
        let mut mgr = AlertManager::new();
        assert!(!mgr.resolve_alert("nonexistent"));
    }

    #[test]
    fn test_alert_manager_active_alerts() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "r1",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        ));
        mgr.add_rule(AlertRule::new(
            "r2",
            "m",
            ComparisonOperator::GreaterThan,
            50.0,
            AlertSeverity::High,
        ));

        mgr.evaluate_rules("m", 60.0);
        assert_eq!(mgr.active_alerts().len(), 2);
    }

    #[test]
    fn test_alert_manager_alerts_by_severity() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "low",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        ));
        mgr.add_rule(AlertRule::new(
            "high",
            "m",
            ComparisonOperator::GreaterThan,
            50.0,
            AlertSeverity::High,
        ));

        mgr.evaluate_rules("m", 60.0);
        assert_eq!(mgr.alerts_by_severity(AlertSeverity::Low).len(), 1);
        assert_eq!(mgr.alerts_by_severity(AlertSeverity::High).len(), 1);
        assert_eq!(mgr.alerts_by_severity(AlertSeverity::Critical).len(), 0);
    }

    #[test]
    fn test_alert_manager_cleanup_resolved() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new(
            "r",
            "m",
            ComparisonOperator::GreaterThan,
            0.0,
            AlertSeverity::Low,
        ));

        let alerts = mgr.evaluate_rules("m", 5.0);
        let alert_id = alerts[0].id.clone();
        mgr.resolve_alert(&alert_id);

        let removed = mgr.cleanup_resolved();
        assert_eq!(removed, 1);
        assert_eq!(mgr.total_alert_count(), 0);
    }

    #[test]
    fn test_alert_manager_escalation_policy() {
        let mut mgr = AlertManager::new();
        let mut policy = EscalationPolicy::new("standard");
        policy.add_level(0, vec!["ch1".to_string()]);
        policy.add_level(600, vec!["ch2".to_string()]);
        let id = mgr.add_escalation_policy(policy);
        assert!(mgr.get_escalation_policy(&id).is_some());
    }

    #[test]
    fn test_alert_manager_list_rules() {
        let mut mgr = AlertManager::new();
        mgr.add_rule(AlertRule::new("a", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low));
        mgr.add_rule(AlertRule::new("b", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::High));
        assert_eq!(mgr.list_rules().len(), 2);
    }

    #[test]
    fn test_alert_manager_list_channels() {
        let mut mgr = AlertManager::new();
        mgr.add_channel(AlertChannel::new("a", AlertChannelType::Email, "a@b.com"));
        mgr.add_channel(AlertChannel::new("b", AlertChannelType::Slack, "#c"));
        assert_eq!(mgr.list_channels().len(), 2);
    }

    #[test]
    fn test_alert_manager_default() {
        let mgr = AlertManager::default();
        assert_eq!(mgr.rule_count(), 0);
        assert_eq!(mgr.active_alert_count(), 0);
    }

    #[test]
    fn test_alert_rule_serialization() {
        let rule = AlertRule::new("test", "cpu", ComparisonOperator::GreaterThan, 90.0, AlertSeverity::High)
            .with_label("env", "prod");

        let json = serde_json::to_string(&rule).unwrap();
        let loaded: AlertRule = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.threshold, 90.0);
    }

    #[test]
    fn test_alert_channel_serialization() {
        let ch = AlertChannel::new("slack", AlertChannelType::Slack, "#alerts");
        let json = serde_json::to_string(&ch).unwrap();
        let loaded: AlertChannel = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.name, "slack");
        assert_eq!(loaded.channel_type, AlertChannelType::Slack);
    }

    #[test]
    fn test_alert_serialization() {
        let rule = AlertRule::new("test", "m", ComparisonOperator::GreaterThan, 0.0, AlertSeverity::Low);
        let alert = Alert::new(&rule, 5.0);
        let json = serde_json::to_string(&alert).unwrap();
        let loaded: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.rule_name, "test");
        assert_eq!(loaded.status, AlertStatus::Active);
    }
}
