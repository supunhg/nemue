use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleCategory {
    ScanTrigger,
    Notification,
    Filter,
    Escalation,
    Custom,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleCategory::ScanTrigger => write!(f, "scan_trigger"),
            RuleCategory::Notification => write!(f, "notification"),
            RuleCategory::Filter => write!(f, "filter"),
            RuleCategory::Escalation => write!(f, "escalation"),
            RuleCategory::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RulePriority {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RulePriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RulePriority::Low => write!(f, "low"),
            RulePriority::Medium => write!(f, "medium"),
            RulePriority::High => write!(f, "high"),
            RulePriority::Critical => write!(f, "critical"),
        }
    }
}

impl RulePriority {
    pub fn value(&self) -> u8 {
        match self {
            RulePriority::Low => 1,
            RulePriority::Medium => 2,
            RulePriority::High => 3,
            RulePriority::Critical => 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleConditionType {
    PortOpen,
    PortClosed,
    ServiceDetected,
    OsDetected,
    ScanCompleted,
    ScanFailed,
    VulnerabilityFound,
    HighRiskScore,
    Custom(String),
}

impl std::fmt::Display for RuleConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleConditionType::PortOpen => write!(f, "port_open"),
            RuleConditionType::PortClosed => write!(f, "port_closed"),
            RuleConditionType::ServiceDetected => write!(f, "service_detected"),
            RuleConditionType::OsDetected => write!(f, "os_detected"),
            RuleConditionType::ScanCompleted => write!(f, "scan_completed"),
            RuleConditionType::ScanFailed => write!(f, "scan_failed"),
            RuleConditionType::VulnerabilityFound => write!(f, "vulnerability_found"),
            RuleConditionType::HighRiskScore => write!(f, "high_risk_score"),
            RuleConditionType::Custom(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub condition_type: RuleConditionType,
    pub field: String,
    pub operator: super::playbooks::ConditionOperator,
    pub value: String,
    pub negate: bool,
}

impl RuleCondition {
    pub fn new(
        condition_type: RuleConditionType,
        field: &str,
        operator: super::playbooks::ConditionOperator,
        value: &str,
    ) -> Self {
        Self {
            condition_type,
            field: field.to_string(),
            operator,
            value: value.to_string(),
            negate: false,
        }
    }

    pub fn with_negate(mut self) -> Self {
        self.negate = true;
        self
    }

    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        let actual = match context.get(&self.field) {
            Some(v) => v.as_str(),
            None => return self.negate,
        };

        let result = match &self.operator {
            super::playbooks::ConditionOperator::Equals => actual == self.value,
            super::playbooks::ConditionOperator::NotEquals => actual != self.value,
            super::playbooks::ConditionOperator::Contains => actual.contains(&self.value),
            super::playbooks::ConditionOperator::GreaterThan => {
                let a: f64 = actual.parse().unwrap_or(0.0);
                let b: f64 = self.value.parse().unwrap_or(0.0);
                a > b
            }
            super::playbooks::ConditionOperator::LessThan => {
                let a: f64 = actual.parse().unwrap_or(0.0);
                let b: f64 = self.value.parse().unwrap_or(0.0);
                a < b
            }
            super::playbooks::ConditionOperator::Regex => regex::Regex::new(&self.value)
                .map(|re| re.is_match(actual))
                .unwrap_or(false),
        };

        if self.negate {
            !result
        } else {
            result
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogicalOperator {
    And,
    Or,
}

impl std::fmt::Display for LogicalOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogicalOperator::And => write!(f, "AND"),
            LogicalOperator::Or => write!(f, "OR"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    TriggerScan {
        target: String,
        template: String,
        ports: Option<String>,
    },
    SendNotification {
        channel: String,
        message_template: String,
        severity: String,
    },
    SetVariable {
        key: String,
        value: String,
    },
    Escalate {
        level: String,
        recipients: Vec<String>,
    },
    LogEvent {
        level: String,
        message: String,
    },
    Custom {
        action_type: String,
        parameters: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleStatus {
    Active,
    Inactive,
    Disabled,
}

impl std::fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleStatus::Active => write!(f, "active"),
            RuleStatus::Inactive => write!(f, "inactive"),
            RuleStatus::Disabled => write!(f, "disabled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: RuleCategory,
    pub priority: RulePriority,
    pub conditions: Vec<RuleCondition>,
    pub logical_operator: LogicalOperator,
    pub actions: Vec<RuleAction>,
    pub cooldown_secs: u64,
    pub max_triggers: Option<u32>,
    pub trigger_count: u32,
    pub last_triggered: Option<chrono::DateTime<chrono::Utc>>,
    pub status: RuleStatus,
    pub tags: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ScanRule {
    pub fn new(name: &str, description: &str, category: RuleCategory) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            category,
            priority: RulePriority::Medium,
            conditions: Vec::new(),
            logical_operator: LogicalOperator::And,
            actions: Vec::new(),
            cooldown_secs: 0,
            max_triggers: None,
            trigger_count: 0,
            last_triggered: None,
            status: RuleStatus::Active,
            tags: Vec::new(),
            created_at: chrono::Utc::now(),
        }
    }

    pub fn with_priority(mut self, priority: RulePriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_condition(mut self, condition: RuleCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn with_logical_operator(mut self, op: LogicalOperator) -> Self {
        self.logical_operator = op;
        self
    }

    pub fn with_action(mut self, action: RuleAction) -> Self {
        self.actions.push(action);
        self
    }

    pub fn with_cooldown(mut self, secs: u64) -> Self {
        self.cooldown_secs = secs;
        self
    }

    pub fn with_max_triggers(mut self, max: u32) -> Self {
        self.max_triggers = Some(max);
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
        self
    }

    pub fn add_condition(&mut self, condition: RuleCondition) {
        self.conditions.push(condition);
    }

    pub fn add_action(&mut self, action: RuleAction) {
        self.actions.push(action);
    }

    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        if self.status != RuleStatus::Active {
            return false;
        }

        if let Some(max) = self.max_triggers {
            if self.trigger_count >= max {
                return false;
            }
        }

        if let Some(last) = self.last_triggered {
            let elapsed = chrono::Utc::now().signed_duration_since(last);
            if elapsed.num_seconds() < self.cooldown_secs as i64 {
                return false;
            }
        }

        if self.conditions.is_empty() {
            return false;
        }

        match self.logical_operator {
            LogicalOperator::And => self.conditions.iter().all(|c| c.evaluate(context)),
            LogicalOperator::Or => self.conditions.iter().any(|c| c.evaluate(context)),
        }
    }

    pub fn trigger(&mut self) {
        self.trigger_count += 1;
        self.last_triggered = Some(chrono::Utc::now());
    }

    pub fn activate(&mut self) {
        self.status = RuleStatus::Active;
    }

    pub fn deactivate(&mut self) {
        self.status = RuleStatus::Inactive;
    }

    pub fn disable(&mut self) {
        self.status = RuleStatus::Disabled;
    }

    pub fn is_active(&self) -> bool {
        self.status == RuleStatus::Active
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTemplate {
    pub name: String,
    pub description: String,
    pub category: RuleCategory,
    pub condition_templates: Vec<RuleCondition>,
    pub action_templates: Vec<RuleAction>,
    pub default_priority: RulePriority,
    pub default_cooldown_secs: u64,
    pub tags: Vec<String>,
}

impl RuleTemplate {
    pub fn new(name: &str, description: &str, category: RuleCategory) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            category,
            condition_templates: Vec::new(),
            action_templates: Vec::new(),
            default_priority: RulePriority::Medium,
            default_cooldown_secs: 0,
            tags: Vec::new(),
        }
    }

    pub fn with_condition(mut self, condition: RuleCondition) -> Self {
        self.condition_templates.push(condition);
        self
    }

    pub fn with_action(mut self, action: RuleAction) -> Self {
        self.action_templates.push(action);
        self
    }

    pub fn with_priority(mut self, priority: RulePriority) -> Self {
        self.default_priority = priority;
        self
    }

    pub fn with_cooldown(mut self, secs: u64) -> Self {
        self.default_cooldown_secs = secs;
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
        self
    }

    pub fn instantiate(&self, name: &str) -> ScanRule {
        let mut rule = ScanRule::new(name, &self.description, self.category.clone())
            .with_priority(self.default_priority.clone())
            .with_cooldown(self.default_cooldown_secs);

        for tag in &self.tags {
            rule = rule.with_tag(tag);
        }

        for cond in &self.condition_templates {
            rule.add_condition(cond.clone());
        }

        for action in &self.action_templates {
            rule.add_action(action.clone());
        }

        rule
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEngine {
    rules: Vec<ScanRule>,
    templates: HashMap<String, RuleTemplate>,
    evaluation_log: Vec<RuleEvaluationLog>,
    max_log_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEvaluationLog {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub rule_id: String,
    pub rule_name: String,
    pub matched: bool,
    pub triggered: bool,
    pub context_snapshot: HashMap<String, String>,
}

impl RuleEvaluationLog {
    pub fn new(
        rule_id: &str,
        rule_name: &str,
        matched: bool,
        triggered: bool,
        context: &HashMap<String, String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            matched,
            triggered,
            context_snapshot: context.clone(),
        }
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            templates: HashMap::new(),
            evaluation_log: Vec::new(),
            max_log_size: 1000,
        }
    }

    pub fn with_defaults() -> Self {
        let mut engine = Self::new();
        engine.register_default_templates();
        engine
    }

    pub fn with_max_log_size(mut self, max: usize) -> Self {
        self.max_log_size = max;
        self
    }

    pub fn add_rule(&mut self, rule: ScanRule) -> String {
        let id = rule.id.clone();
        self.rules.push(rule);
        id
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        if let Some(pos) = self.rules.iter().position(|r| r.id == rule_id) {
            self.rules.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn get_rule(&self, rule_id: &str) -> Option<&ScanRule> {
        self.rules.iter().find(|r| r.id == rule_id)
    }

    pub fn get_rule_mut(&mut self, rule_id: &str) -> Option<&mut ScanRule> {
        self.rules.iter_mut().find(|r| r.id == rule_id)
    }

    pub fn register_template(&mut self, template: RuleTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    pub fn get_template(&self, name: &str) -> Option<&RuleTemplate> {
        self.templates.get(name)
    }

    pub fn create_from_template(&mut self, template_name: &str, rule_name: &str) -> Option<String> {
        let template = self.templates.get(template_name)?.clone();
        let rule = template.instantiate(rule_name);
        let id = rule.id.clone();
        self.rules.push(rule);
        Some(id)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    pub fn active_rules(&self) -> Vec<&ScanRule> {
        self.rules.iter().filter(|r| r.is_active()).collect()
    }

    pub fn evaluate(&mut self, context: &HashMap<String, String>) -> Vec<String> {
        let mut triggered_ids = Vec::new();
        let mut logs = Vec::new();

        for rule in &mut self.rules {
            let matched = rule.evaluate(context);
            if matched {
                let log = RuleEvaluationLog::new(&rule.id, &rule.name, true, true, context);
                logs.push(log);
                rule.trigger();
                triggered_ids.push(rule.id.clone());
            } else if rule.is_active() {
                let log = RuleEvaluationLog::new(&rule.id, &rule.name, false, false, context);
                logs.push(log);
            }
        }

        for log in logs {
            self.add_log(log);
        }

        triggered_ids
    }

    pub fn get_triggered_rules(&self, context: &HashMap<String, String>) -> Vec<&ScanRule> {
        self.rules.iter().filter(|r| r.evaluate(context)).collect()
    }

    pub fn evaluation_log(&self) -> &[RuleEvaluationLog] {
        &self.evaluation_log
    }

    pub fn clear_log(&mut self) {
        self.evaluation_log.clear();
    }

    fn add_log(&mut self, log: RuleEvaluationLog) {
        self.evaluation_log.push(log);
        while self.evaluation_log.len() > self.max_log_size {
            self.evaluation_log.remove(0);
        }
    }

    fn register_default_templates(&mut self) {
        self.register_template(
            RuleTemplate::new(
                "open-port-alert",
                "Alert when a high-risk port is open",
                RuleCategory::Notification,
            )
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                super::playbooks::ConditionOperator::Equals,
                "22",
            ))
            .with_action(RuleAction::SendNotification {
                channel: "slack".to_string(),
                message_template: "SSH port 22 is open on {{target}}".to_string(),
                severity: "high".to_string(),
            })
            .with_priority(RulePriority::High)
            .with_cooldown(300)
            .with_tag("security"),
        );

        self.register_template(
            RuleTemplate::new(
                "vuln-escalation",
                "Escalate when vulnerability is found",
                RuleCategory::Escalation,
            )
            .with_condition(RuleCondition::new(
                RuleConditionType::VulnerabilityFound,
                "severity",
                super::playbooks::ConditionOperator::Equals,
                "critical",
            ))
            .with_action(RuleAction::Escalate {
                level: "critical".to_string(),
                recipients: vec!["security-team@example.com".to_string()],
            })
            .with_priority(RulePriority::Critical)
            .with_tag("vuln"),
        );

        self.register_template(
            RuleTemplate::new(
                "scan-failure-retry",
                "Retry scan on failure with different template",
                RuleCategory::ScanTrigger,
            )
            .with_condition(RuleCondition::new(
                RuleConditionType::ScanFailed,
                "error",
                super::playbooks::ConditionOperator::Contains,
                "timeout",
            ))
            .with_action(RuleAction::TriggerScan {
                target: "{{target}}".to_string(),
                template: "stealth".to_string(),
                ports: Some("1-1024".to_string()),
            })
            .with_priority(RulePriority::Medium)
            .with_cooldown(600)
            .with_tag("automation"),
        );
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

pub struct RuleBuilder {
    rule: ScanRule,
}

impl RuleBuilder {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            rule: ScanRule::new(name, description, RuleCategory::Custom),
        }
    }

    pub fn category(mut self, category: RuleCategory) -> Self {
        self.rule.category = category;
        self
    }

    pub fn priority(mut self, priority: RulePriority) -> Self {
        self.rule.priority = priority;
        self
    }

    pub fn condition(mut self, condition: RuleCondition) -> Self {
        self.rule.conditions.push(condition);
        self
    }

    pub fn logical_operator(mut self, op: LogicalOperator) -> Self {
        self.rule.logical_operator = op;
        self
    }

    pub fn action(mut self, action: RuleAction) -> Self {
        self.rule.actions.push(action);
        self
    }

    pub fn cooldown(mut self, secs: u64) -> Self {
        self.rule.cooldown_secs = secs;
        self
    }

    pub fn max_triggers(mut self, max: u32) -> Self {
        self.rule.max_triggers = Some(max);
        self
    }

    pub fn tag(mut self, tag: &str) -> Self {
        if !self.rule.tags.contains(&tag.to_string()) {
            self.rule.tags.push(tag.to_string());
        }
        self
    }

    pub fn build(self) -> ScanRule {
        self.rule
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::automation::playbooks::ConditionOperator;

    #[test]
    fn test_rule_condition_evaluation() {
        let mut context = HashMap::new();
        context.insert("port".to_string(), "22".to_string());
        context.insert("service".to_string(), "ssh".to_string());
        context.insert("risk_score".to_string(), "85".to_string());

        let eq_cond = RuleCondition::new(
            RuleConditionType::PortOpen,
            "port",
            ConditionOperator::Equals,
            "22",
        );
        assert!(eq_cond.evaluate(&context));

        let neq_cond = RuleCondition::new(
            RuleConditionType::PortOpen,
            "port",
            ConditionOperator::NotEquals,
            "80",
        );
        assert!(neq_cond.evaluate(&context));

        let contains_cond = RuleCondition::new(
            RuleConditionType::ServiceDetected,
            "service",
            ConditionOperator::Contains,
            "sh",
        );
        assert!(contains_cond.evaluate(&context));

        let gt_cond = RuleCondition::new(
            RuleConditionType::HighRiskScore,
            "risk_score",
            ConditionOperator::GreaterThan,
            "80",
        );
        assert!(gt_cond.evaluate(&context));

        let regex_cond = RuleCondition::new(
            RuleConditionType::ServiceDetected,
            "service",
            ConditionOperator::Regex,
            r"^s\w+",
        );
        assert!(regex_cond.evaluate(&context));
    }

    #[test]
    fn test_rule_condition_negate() {
        let context = HashMap::from([("port".to_string(), "22".to_string())]);

        let cond = RuleCondition::new(
            RuleConditionType::PortOpen,
            "port",
            ConditionOperator::Equals,
            "22",
        );
        assert!(cond.evaluate(&context));

        let negated = cond.with_negate();
        assert!(!negated.evaluate(&context));
    }

    #[test]
    fn test_rule_condition_missing_field() {
        let context = HashMap::new();

        let cond = RuleCondition::new(
            RuleConditionType::PortOpen,
            "port",
            ConditionOperator::Equals,
            "22",
        );
        assert!(!cond.evaluate(&context));

        let negated = RuleCondition::new(
            RuleConditionType::PortOpen,
            "port",
            ConditionOperator::Equals,
            "22",
        )
        .with_negate();
        assert!(negated.evaluate(&context));
    }

    #[test]
    fn test_scan_rule_creation() {
        let rule = ScanRule::new("ssh-alert", "Alert on SSH port", RuleCategory::Notification)
            .with_priority(RulePriority::High)
            .with_cooldown(300)
            .with_max_triggers(10)
            .with_tag("security")
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ))
            .with_action(RuleAction::SendNotification {
                channel: "slack".to_string(),
                message_template: "SSH open".to_string(),
                severity: "high".to_string(),
            });

        assert_eq!(rule.name, "ssh-alert");
        assert_eq!(rule.category, RuleCategory::Notification);
        assert_eq!(rule.priority, RulePriority::High);
        assert_eq!(rule.cooldown_secs, 300);
        assert_eq!(rule.max_triggers, Some(10));
        assert_eq!(rule.conditions.len(), 1);
        assert_eq!(rule.actions.len(), 1);
        assert!(rule.tags.contains(&"security".to_string()));
        assert!(rule.is_active());
    }

    #[test]
    fn test_scan_rule_evaluate_and_trigger() {
        let mut rule = ScanRule::new("test", "desc", RuleCategory::Notification).with_condition(
            RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ),
        );

        let context = HashMap::from([("port".to_string(), "22".to_string())]);
        assert!(rule.evaluate(&context));

        rule.trigger();
        assert_eq!(rule.trigger_count, 1);
        assert!(rule.last_triggered.is_some());
    }

    #[test]
    fn test_scan_rule_evaluate_and_logic() {
        let rule = ScanRule::new("test", "desc", RuleCategory::Notification)
            .with_logical_operator(LogicalOperator::And)
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ))
            .with_condition(RuleCondition::new(
                RuleConditionType::ServiceDetected,
                "service",
                ConditionOperator::Equals,
                "ssh",
            ));

        let both_match = HashMap::from([
            ("port".to_string(), "22".to_string()),
            ("service".to_string(), "ssh".to_string()),
        ]);
        assert!(rule.evaluate(&both_match));

        let one_match = HashMap::from([
            ("port".to_string(), "22".to_string()),
            ("service".to_string(), "http".to_string()),
        ]);
        assert!(!rule.evaluate(&one_match));
    }

    #[test]
    fn test_scan_rule_evaluate_or_logic() {
        let rule = ScanRule::new("test", "desc", RuleCategory::Notification)
            .with_logical_operator(LogicalOperator::Or)
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ))
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "443",
            ));

        let ctx_22 = HashMap::from([("port".to_string(), "22".to_string())]);
        assert!(rule.evaluate(&ctx_22));

        let ctx_443 = HashMap::from([("port".to_string(), "443".to_string())]);
        assert!(rule.evaluate(&ctx_443));

        let ctx_80 = HashMap::from([("port".to_string(), "80".to_string())]);
        assert!(!rule.evaluate(&ctx_80));
    }

    #[test]
    fn test_scan_rule_max_triggers() {
        let mut rule = ScanRule::new("test", "desc", RuleCategory::Notification)
            .with_max_triggers(2)
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ));

        let context = HashMap::from([("port".to_string(), "22".to_string())]);

        assert!(rule.evaluate(&context));
        rule.trigger();
        assert!(rule.evaluate(&context));
        rule.trigger();
        assert!(!rule.evaluate(&context)); // max reached
    }

    #[test]
    fn test_scan_rule_cooldown() {
        let mut rule = ScanRule::new("test", "desc", RuleCategory::Notification)
            .with_cooldown(3600)
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ));

        let context = HashMap::from([("port".to_string(), "22".to_string())]);

        assert!(rule.evaluate(&context));
        rule.trigger();
        assert!(!rule.evaluate(&context)); // cooldown active
    }

    #[test]
    fn test_scan_rule_inactive() {
        let mut rule = ScanRule::new("test", "desc", RuleCategory::Notification).with_condition(
            RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ),
        );

        let context = HashMap::from([("port".to_string(), "22".to_string())]);
        assert!(rule.evaluate(&context));

        rule.deactivate();
        assert!(!rule.evaluate(&context));

        rule.activate();
        assert!(rule.evaluate(&context));

        rule.disable();
        assert!(!rule.evaluate(&context));
    }

    #[test]
    fn test_scan_rule_empty_conditions() {
        let rule = ScanRule::new("test", "desc", RuleCategory::Notification);
        let context = HashMap::new();
        assert!(!rule.evaluate(&context)); // no conditions = no match
    }

    #[test]
    fn test_rule_status_display() {
        assert_eq!(RuleStatus::Active.to_string(), "active");
        assert_eq!(RuleStatus::Inactive.to_string(), "inactive");
        assert_eq!(RuleStatus::Disabled.to_string(), "disabled");
    }

    #[test]
    fn test_rule_category_display() {
        assert_eq!(RuleCategory::ScanTrigger.to_string(), "scan_trigger");
        assert_eq!(RuleCategory::Notification.to_string(), "notification");
        assert_eq!(RuleCategory::Filter.to_string(), "filter");
        assert_eq!(RuleCategory::Escalation.to_string(), "escalation");
        assert_eq!(RuleCategory::Custom.to_string(), "custom");
    }

    #[test]
    fn test_rule_priority_display_and_value() {
        assert_eq!(RulePriority::Low.to_string(), "low");
        assert_eq!(RulePriority::Low.value(), 1);
        assert_eq!(RulePriority::Medium.to_string(), "medium");
        assert_eq!(RulePriority::Medium.value(), 2);
        assert_eq!(RulePriority::High.to_string(), "high");
        assert_eq!(RulePriority::High.value(), 3);
        assert_eq!(RulePriority::Critical.to_string(), "critical");
        assert_eq!(RulePriority::Critical.value(), 4);
    }

    #[test]
    fn test_rule_condition_type_display() {
        assert_eq!(RuleConditionType::PortOpen.to_string(), "port_open");
        assert_eq!(
            RuleConditionType::ScanCompleted.to_string(),
            "scan_completed"
        );
        assert_eq!(
            RuleConditionType::Custom("my_cond".to_string()).to_string(),
            "my_cond"
        );
    }

    #[test]
    fn test_logical_operator_display() {
        assert_eq!(LogicalOperator::And.to_string(), "AND");
        assert_eq!(LogicalOperator::Or.to_string(), "OR");
    }

    #[test]
    fn test_rule_template_instantiate() {
        let tmpl = RuleTemplate::new("ssh-alert", "Alert on SSH", RuleCategory::Notification)
            .with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ))
            .with_action(RuleAction::SendNotification {
                channel: "slack".to_string(),
                message_template: "SSH open".to_string(),
                severity: "high".to_string(),
            })
            .with_priority(RulePriority::High)
            .with_cooldown(300)
            .with_tag("security");

        let rule = tmpl.instantiate("my-ssh-alert");
        assert_eq!(rule.name, "my-ssh-alert");
        assert_eq!(rule.category, RuleCategory::Notification);
        assert_eq!(rule.priority, RulePriority::High);
        assert_eq!(rule.cooldown_secs, 300);
        assert_eq!(rule.conditions.len(), 1);
        assert_eq!(rule.actions.len(), 1);
        assert!(rule.tags.contains(&"security".to_string()));
    }

    #[test]
    fn test_rule_engine_add_remove() {
        let mut engine = RuleEngine::new();
        let rule = ScanRule::new("test", "desc", RuleCategory::Custom);
        let id = rule.id.clone();

        engine.add_rule(rule);
        assert_eq!(engine.rule_count(), 1);
        assert!(engine.get_rule(&id).is_some());
        assert!(engine.get_rule("nonexistent").is_none());

        engine.remove_rule(&id);
        assert_eq!(engine.rule_count(), 0);
        assert!(!engine.remove_rule("nonexistent"));
    }

    #[test]
    fn test_rule_engine_active_rules() {
        let mut engine = RuleEngine::new();

        let mut r1 = ScanRule::new("active1", "desc", RuleCategory::Custom);
        r1.activate();
        engine.add_rule(r1);

        let mut r2 = ScanRule::new("inactive", "desc", RuleCategory::Custom);
        r2.deactivate();
        engine.add_rule(r2);

        let r3 = ScanRule::new("active2", "desc", RuleCategory::Custom);
        engine.add_rule(r3);

        assert_eq!(engine.active_rules().len(), 2);
    }

    #[test]
    fn test_rule_engine_evaluate() {
        let mut engine = RuleEngine::new();

        engine.add_rule(
            ScanRule::new("ssh-alert", "desc", RuleCategory::Notification)
                .with_condition(RuleCondition::new(
                    RuleConditionType::PortOpen,
                    "port",
                    ConditionOperator::Equals,
                    "22",
                ))
                .with_action(RuleAction::LogEvent {
                    level: "warn".to_string(),
                    message: "SSH open".to_string(),
                }),
        );

        engine.add_rule(
            ScanRule::new("http-alert", "desc", RuleCategory::Notification).with_condition(
                RuleCondition::new(
                    RuleConditionType::PortOpen,
                    "port",
                    ConditionOperator::Equals,
                    "80",
                ),
            ),
        );

        let context = HashMap::from([("port".to_string(), "22".to_string())]);
        let triggered = engine.evaluate(&context);
        assert_eq!(triggered.len(), 1);

        let rule = engine.get_rule(&triggered[0]).unwrap();
        assert_eq!(rule.name, "ssh-alert");
        assert_eq!(rule.trigger_count, 1);
        assert_eq!(engine.evaluation_log().len(), 2); // one matched, one not
    }

    #[test]
    fn test_rule_engine_defaults() {
        let engine = RuleEngine::with_defaults();
        assert!(engine.template_count() >= 3);
        assert!(engine.get_template("open-port-alert").is_some());
        assert!(engine.get_template("vuln-escalation").is_some());
        assert!(engine.get_template("scan-failure-retry").is_some());
    }

    #[test]
    fn test_rule_engine_create_from_template() {
        let mut engine = RuleEngine::with_defaults();
        let id = engine.create_from_template("open-port-alert", "My SSH Alert");
        assert!(id.is_some());
        assert_eq!(engine.rule_count(), 1);

        let rule = engine.get_rule(&id.unwrap()).unwrap();
        assert_eq!(rule.name, "My SSH Alert");
        assert_eq!(rule.conditions.len(), 1);
    }

    #[test]
    fn test_rule_builder() {
        let rule = RuleBuilder::new("builder-test", "Built rule")
            .category(RuleCategory::ScanTrigger)
            .priority(RulePriority::Critical)
            .condition(RuleCondition::new(
                RuleConditionType::VulnerabilityFound,
                "severity",
                ConditionOperator::Equals,
                "critical",
            ))
            .logical_operator(LogicalOperator::Or)
            .action(RuleAction::Escalate {
                level: "critical".to_string(),
                recipients: vec!["admin@example.com".to_string()],
            })
            .cooldown(600)
            .max_triggers(5)
            .tag("vuln")
            .build();

        assert_eq!(rule.name, "builder-test");
        assert_eq!(rule.category, RuleCategory::ScanTrigger);
        assert_eq!(rule.priority, RulePriority::Critical);
        assert_eq!(rule.logical_operator, LogicalOperator::Or);
        assert_eq!(rule.conditions.len(), 1);
        assert_eq!(rule.actions.len(), 1);
        assert_eq!(rule.cooldown_secs, 600);
        assert_eq!(rule.max_triggers, Some(5));
        assert!(rule.tags.contains(&"vuln".to_string()));
    }

    #[test]
    fn test_rule_serialization() {
        let rule = RuleBuilder::new("serde-test", "Serialization test")
            .category(RuleCategory::Notification)
            .priority(RulePriority::High)
            .condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            ))
            .action(RuleAction::LogEvent {
                level: "info".to_string(),
                message: "test".to_string(),
            })
            .tag("test")
            .build();

        let json = serde_json::to_string(&rule).unwrap();
        let loaded: ScanRule = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "serde-test");
        assert_eq!(loaded.category, RuleCategory::Notification);
        assert_eq!(loaded.priority, RulePriority::High);
        assert_eq!(loaded.conditions.len(), 1);
        assert_eq!(loaded.actions.len(), 1);
    }

    #[test]
    fn test_rule_engine_serialization() {
        let mut engine = RuleEngine::with_defaults();
        engine.add_rule(
            ScanRule::new("test", "desc", RuleCategory::Custom).with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            )),
        );

        let json = serde_json::to_string(&engine).unwrap();
        let loaded: RuleEngine = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(loaded.template_count(), engine.template_count());
    }

    #[test]
    fn test_rule_engine_clear_log() {
        let mut engine = RuleEngine::new();
        engine.add_rule(
            ScanRule::new("test", "desc", RuleCategory::Custom).with_condition(RuleCondition::new(
                RuleConditionType::PortOpen,
                "port",
                ConditionOperator::Equals,
                "22",
            )),
        );

        let context = HashMap::from([("port".to_string(), "22".to_string())]);
        engine.evaluate(&context);
        assert!(!engine.evaluation_log().is_empty());

        engine.clear_log();
        assert!(engine.evaluation_log().is_empty());
    }
}
