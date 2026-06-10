use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlaybookCategory {
    Recon,
    VulnAssessment,
    Compliance,
    Incident,
    Custom,
}

impl std::fmt::Display for PlaybookCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlaybookCategory::Recon => write!(f, "recon"),
            PlaybookCategory::VulnAssessment => write!(f, "vuln_assessment"),
            PlaybookCategory::Compliance => write!(f, "compliance"),
            PlaybookCategory::Incident => write!(f, "incident"),
            PlaybookCategory::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepStatus::Pending => write!(f, "pending"),
            StepStatus::Running => write!(f, "running"),
            StepStatus::Completed => write!(f, "completed"),
            StepStatus::Failed => write!(f, "failed"),
            StepStatus::Skipped => write!(f, "skipped"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
    Regex,
}

impl std::fmt::Display for ConditionOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConditionOperator::Equals => write!(f, "=="),
            ConditionOperator::NotEquals => write!(f, "!="),
            ConditionOperator::Contains => write!(f, "contains"),
            ConditionOperator::GreaterThan => write!(f, ">"),
            ConditionOperator::LessThan => write!(f, "<"),
            ConditionOperator::Regex => write!(f, "regex"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: String,
}

impl Condition {
    pub fn new(field: &str, operator: ConditionOperator, value: &str) -> Self {
        Self {
            field: field.to_string(),
            operator,
            value: value.to_string(),
        }
    }

    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        let actual = match context.get(&self.field) {
            Some(v) => v.as_str(),
            None => return false,
        };

        match self.operator {
            ConditionOperator::Equals => actual == self.value,
            ConditionOperator::NotEquals => actual != self.value,
            ConditionOperator::Contains => actual.contains(&self.value),
            ConditionOperator::GreaterThan => {
                let a: f64 = actual.parse().unwrap_or(0.0);
                let b: f64 = self.value.parse().unwrap_or(0.0);
                a > b
            }
            ConditionOperator::LessThan => {
                let a: f64 = actual.parse().unwrap_or(0.0);
                let b: f64 = self.value.parse().unwrap_or(0.0);
                a < b
            }
            ConditionOperator::Regex => regex::Regex::new(&self.value)
                .map(|re| re.is_match(actual))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub id: String,
    pub name: String,
    pub description: String,
    pub scan_type: String,
    pub target: String,
    pub ports: String,
    pub template: Option<String>,
    pub parameters: HashMap<String, String>,
    pub conditions: Vec<Condition>,
    pub on_success: Option<String>,
    pub on_failure: Option<String>,
    pub timeout_secs: Option<u64>,
    pub status: StepStatus,
    pub result: Option<String>,
}

impl PlaybookStep {
    pub fn new(name: &str, scan_type: &str, target: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            scan_type: scan_type.to_string(),
            target: target.to_string(),
            ports: "1-1024".to_string(),
            template: None,
            parameters: HashMap::new(),
            conditions: Vec::new(),
            on_success: None,
            on_failure: None,
            timeout_secs: None,
            status: StepStatus::Pending,
            result: None,
        }
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    pub fn with_ports(mut self, ports: &str) -> Self {
        self.ports = ports.to_string();
        self
    }

    pub fn with_template(mut self, template: &str) -> Self {
        self.template = Some(template.to_string());
        self
    }

    pub fn with_parameter(mut self, key: &str, value: &str) -> Self {
        self.parameters.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    pub fn with_on_success(mut self, step_id: &str) -> Self {
        self.on_success = Some(step_id.to_string());
        self
    }

    pub fn with_on_failure(mut self, step_id: &str) -> Self {
        self.on_failure = Some(step_id.to_string());
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    pub fn should_execute(&self, context: &HashMap<String, String>) -> bool {
        self.conditions.iter().all(|c| c.evaluate(context))
    }

    pub fn mark_running(&mut self) {
        self.status = StepStatus::Running;
    }

    pub fn mark_completed(&mut self, result: &str) {
        self.status = StepStatus::Completed;
        self.result = Some(result.to_string());
    }

    pub fn mark_failed(&mut self, error: &str) {
        self.status = StepStatus::Failed;
        self.result = Some(error.to_string());
    }

    pub fn mark_skipped(&mut self) {
        self.status = StepStatus::Skipped;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlaybookStatus {
    Draft,
    Ready,
    Running,
    Completed,
    Failed,
    Paused,
}

impl std::fmt::Display for PlaybookStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlaybookStatus::Draft => write!(f, "draft"),
            PlaybookStatus::Ready => write!(f, "ready"),
            PlaybookStatus::Running => write!(f, "running"),
            PlaybookStatus::Completed => write!(f, "completed"),
            PlaybookStatus::Failed => write!(f, "failed"),
            PlaybookStatus::Paused => write!(f, "paused"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: PlaybookCategory,
    pub version: String,
    pub author: String,
    pub steps: Vec<PlaybookStep>,
    pub variables: HashMap<String, String>,
    pub tags: Vec<String>,
    pub status: PlaybookStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Playbook {
    pub fn new(name: &str, description: &str, category: PlaybookCategory) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            category,
            version: "1.0.0".to_string(),
            author: String::new(),
            steps: Vec::new(),
            variables: HashMap::new(),
            tags: Vec::new(),
            status: PlaybookStatus::Draft,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.author = author.to_string();
        self
    }

    pub fn with_step(mut self, step: PlaybookStep) -> Self {
        self.steps.push(step);
        self
    }

    pub fn with_variable(mut self, key: &str, value: &str) -> Self {
        self.variables.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
        self
    }

    pub fn add_step(&mut self, step: PlaybookStep) {
        self.steps.push(step);
        self.updated_at = chrono::Utc::now();
    }

    pub fn remove_step(&mut self, step_id: &str) -> bool {
        if let Some(pos) = self.steps.iter().position(|s| s.id == step_id) {
            self.steps.remove(pos);
            self.updated_at = chrono::Utc::now();
            true
        } else {
            false
        }
    }

    pub fn get_step(&self, step_id: &str) -> Option<&PlaybookStep> {
        self.steps.iter().find(|s| s.id == step_id)
    }

    pub fn get_step_mut(&mut self, step_id: &str) -> Option<&mut PlaybookStep> {
        self.steps.iter_mut().find(|s| s.id == step_id)
    }

    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    pub fn completed_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.status == StepStatus::Completed)
            .count()
    }

    pub fn failed_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.status == StepStatus::Failed)
            .count()
    }

    pub fn pending_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.status == StepStatus::Pending)
            .count()
    }

    pub fn is_complete(&self) -> bool {
        self.steps.iter().all(|s| {
            matches!(
                s.status,
                StepStatus::Completed | StepStatus::Failed | StepStatus::Skipped
            )
        })
    }

    pub fn progress(&self) -> f64 {
        if self.steps.is_empty() {
            return 0.0;
        }
        let done = self.completed_steps()
            + self.failed_steps()
            + self
                .steps
                .iter()
                .filter(|s| s.status == StepStatus::Skipped)
                .count();
        done as f64 / self.steps.len() as f64
    }

    pub fn mark_ready(&mut self) {
        self.status = PlaybookStatus::Ready;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_running(&mut self) {
        self.status = PlaybookStatus::Running;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_completed(&mut self) {
        self.status = PlaybookStatus::Completed;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_failed(&mut self) {
        self.status = PlaybookStatus::Failed;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_paused(&mut self) {
        self.status = PlaybookStatus::Paused;
        self.updated_at = chrono::Utc::now();
    }

    pub fn resolve_variables(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (key, value) in &self.variables {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookTemplate {
    pub name: String,
    pub description: String,
    pub category: PlaybookCategory,
    pub tags: Vec<String>,
    pub step_templates: Vec<StepTemplate>,
    pub default_variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTemplate {
    pub name: String,
    pub description: String,
    pub scan_type: String,
    pub ports: String,
    pub template: Option<String>,
    pub parameters: HashMap<String, String>,
}

impl StepTemplate {
    pub fn new(name: &str, scan_type: &str, ports: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            scan_type: scan_type.to_string(),
            ports: ports.to_string(),
            template: None,
            parameters: HashMap::new(),
        }
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    pub fn with_template(mut self, template: &str) -> Self {
        self.template = Some(template.to_string());
        self
    }

    pub fn with_parameter(mut self, key: &str, value: &str) -> Self {
        self.parameters.insert(key.to_string(), value.to_string());
        self
    }

    pub fn instantiate(&self, target: &str) -> PlaybookStep {
        let mut step = PlaybookStep::new(&self.name, &self.scan_type, target)
            .with_description(&self.description)
            .with_ports(&self.ports);
        if let Some(tmpl) = &self.template {
            step = step.with_template(tmpl);
        }
        for (k, v) in &self.parameters {
            step = step.with_parameter(k, v);
        }
        step
    }
}

impl PlaybookTemplate {
    pub fn new(name: &str, description: &str, category: PlaybookCategory) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            category,
            tags: Vec::new(),
            step_templates: Vec::new(),
            default_variables: HashMap::new(),
        }
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
        self
    }

    pub fn with_step_template(mut self, step: StepTemplate) -> Self {
        self.step_templates.push(step);
        self
    }

    pub fn with_variable(mut self, key: &str, value: &str) -> Self {
        self.default_variables
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn instantiate(&self, name: &str, target: &str) -> Playbook {
        let mut playbook = Playbook::new(name, &self.description, self.category.clone())
            .with_tag(&self.tags.join(","));

        for (k, v) in &self.default_variables {
            playbook = playbook.with_variable(k, v);
        }

        for step_tmpl in &self.step_templates {
            playbook.add_step(step_tmpl.instantiate(target));
        }

        playbook.mark_ready();
        playbook
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookLibrary {
    playbooks: HashMap<String, Playbook>,
    templates: HashMap<String, PlaybookTemplate>,
}

impl PlaybookLibrary {
    pub fn new() -> Self {
        Self {
            playbooks: HashMap::new(),
            templates: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut lib = Self::new();
        lib.register_default_templates();
        lib
    }

    pub fn register_playbook(&mut self, playbook: Playbook) {
        self.playbooks.insert(playbook.id.clone(), playbook);
    }

    pub fn register_template(&mut self, template: PlaybookTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    pub fn get_playbook(&self, id: &str) -> Option<&Playbook> {
        self.playbooks.get(id)
    }

    pub fn get_playbook_mut(&mut self, id: &str) -> Option<&mut Playbook> {
        self.playbooks.get_mut(id)
    }

    pub fn get_template(&self, name: &str) -> Option<&PlaybookTemplate> {
        self.templates.get(name)
    }

    pub fn list_playbooks(&self) -> Vec<&Playbook> {
        self.playbooks.values().collect()
    }

    pub fn list_templates(&self) -> Vec<&PlaybookTemplate> {
        self.templates.values().collect()
    }

    pub fn playbook_count(&self) -> usize {
        self.playbooks.len()
    }

    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    pub fn remove_playbook(&mut self, id: &str) -> Option<Playbook> {
        self.playbooks.remove(id)
    }

    pub fn create_from_template(
        &mut self,
        template_name: &str,
        playbook_name: &str,
        target: &str,
    ) -> Option<String> {
        let template = self.templates.get(template_name)?.clone();
        let playbook = template.instantiate(playbook_name, target);
        let id = playbook.id.clone();
        self.playbooks.insert(id.clone(), playbook);
        Some(id)
    }

    fn register_default_templates(&mut self) {
        self.register_template(
            PlaybookTemplate::new(
                "network-recon",
                "Network reconnaissance playbook",
                PlaybookCategory::Recon,
            )
            .with_tag("recon")
            .with_tag("network")
            .with_step_template(
                StepTemplate::new("host-discovery", "connect", "top-100")
                    .with_description("Discover live hosts")
                    .with_template("quick"),
            )
            .with_step_template(
                StepTemplate::new("port-scan", "syn", "1-1024")
                    .with_description("Scan common ports on discovered hosts")
                    .with_template("quick-full"),
            )
            .with_step_template(
                StepTemplate::new("service-detection", "connect", "1-1024")
                    .with_description("Detect services on open ports")
                    .with_template("comprehensive"),
            )
            .with_variable("timing", "T3"),
        );

        self.register_template(
            PlaybookTemplate::new(
                "web-audit",
                "Web application audit playbook",
                PlaybookCategory::VulnAssessment,
            )
            .with_tag("web")
            .with_tag("audit")
            .with_step_template(
                StepTemplate::new("web-port-scan", "connect", "80,443,8080,8443")
                    .with_description("Scan web ports")
                    .with_template("comprehensive-web"),
            )
            .with_step_template(
                StepTemplate::new("service-enum", "connect", "80,443,8080,8443")
                    .with_description("Enumerate web services")
                    .with_template("comprehensive-web"),
            ),
        );

        self.register_template(
            PlaybookTemplate::new(
                "compliance-check",
                "Compliance scanning playbook",
                PlaybookCategory::Compliance,
            )
            .with_tag("compliance")
            .with_step_template(
                StepTemplate::new("full-port-scan", "syn", "1-65535")
                    .with_description("Scan all ports for compliance")
                    .with_template("comprehensive"),
            )
            .with_step_template(
                StepTemplate::new(
                    "db-service-scan",
                    "connect",
                    "1433,1521,3306,5432,6379,27017",
                )
                .with_description("Check database services")
                .with_template("comprehensive-db"),
            ),
        );
    }
}

impl Default for PlaybookLibrary {
    fn default() -> Self {
        Self::with_defaults()
    }
}

pub struct PlaybookBuilder {
    playbook: Playbook,
}

impl PlaybookBuilder {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            playbook: Playbook::new(name, description, PlaybookCategory::Custom),
        }
    }

    pub fn category(mut self, category: PlaybookCategory) -> Self {
        self.playbook.category = category;
        self
    }

    pub fn version(mut self, version: &str) -> Self {
        self.playbook.version = version.to_string();
        self
    }

    pub fn author(mut self, author: &str) -> Self {
        self.playbook.author = author.to_string();
        self
    }

    pub fn step(mut self, step: PlaybookStep) -> Self {
        self.playbook.steps.push(step);
        self
    }

    pub fn variable(mut self, key: &str, value: &str) -> Self {
        self.playbook
            .variables
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn tag(mut self, tag: &str) -> Self {
        if !self.playbook.tags.contains(&tag.to_string()) {
            self.playbook.tags.push(tag.to_string());
        }
        self
    }

    pub fn build(self) -> Playbook {
        self.playbook
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playbook_step_creation() {
        let step = PlaybookStep::new("port-scan", "syn", "192.168.1.0/24")
            .with_description("Scan local network")
            .with_ports("1-1024")
            .with_template("quick")
            .with_parameter("timing", "T4")
            .with_timeout(300);

        assert_eq!(step.name, "port-scan");
        assert_eq!(step.scan_type, "syn");
        assert_eq!(step.target, "192.168.1.0/24");
        assert_eq!(step.ports, "1-1024");
        assert_eq!(step.template.as_deref(), Some("quick"));
        assert_eq!(step.parameters.get("timing").unwrap(), "T4");
        assert_eq!(step.timeout_secs, Some(300));
        assert_eq!(step.status, StepStatus::Pending);
    }

    #[test]
    fn test_playbook_step_status_transitions() {
        let mut step = PlaybookStep::new("test", "connect", "10.0.0.1");
        assert_eq!(step.status, StepStatus::Pending);

        step.mark_running();
        assert_eq!(step.status, StepStatus::Running);

        step.mark_completed("5 open ports found");
        assert_eq!(step.status, StepStatus::Completed);
        assert_eq!(step.result.as_deref(), Some("5 open ports found"));

        let mut step2 = PlaybookStep::new("test2", "connect", "10.0.0.1");
        step2.mark_running();
        step2.mark_failed("timeout");
        assert_eq!(step2.status, StepStatus::Failed);
        assert_eq!(step2.result.as_deref(), Some("timeout"));

        let mut step3 = PlaybookStep::new("test3", "connect", "10.0.0.1");
        step3.mark_skipped();
        assert_eq!(step3.status, StepStatus::Skipped);
    }

    #[test]
    fn test_condition_evaluation() {
        let mut context = HashMap::new();
        context.insert("open_ports".to_string(), "5".to_string());
        context.insert("os".to_string(), "linux".to_string());

        let eq = Condition::new("os", ConditionOperator::Equals, "linux");
        assert!(eq.evaluate(&context));

        let neq = Condition::new("os", ConditionOperator::NotEquals, "windows");
        assert!(neq.evaluate(&context));

        let contains = Condition::new("os", ConditionOperator::Contains, "lin");
        assert!(contains.evaluate(&context));

        let gt = Condition::new("open_ports", ConditionOperator::GreaterThan, "3");
        assert!(gt.evaluate(&context));

        let lt = Condition::new("open_ports", ConditionOperator::LessThan, "10");
        assert!(lt.evaluate(&context));

        let regex = Condition::new("os", ConditionOperator::Regex, r"^lin\w+");
        assert!(regex.evaluate(&context));

        let missing = Condition::new("nonexistent", ConditionOperator::Equals, "val");
        assert!(!missing.evaluate(&context));
    }

    #[test]
    fn test_step_should_execute() {
        let mut context = HashMap::new();
        context.insert("skip_step".to_string(), "true".to_string());

        let step_no_cond = PlaybookStep::new("no-cond", "connect", "10.0.0.1");
        assert!(step_no_cond.should_execute(&context));

        let step_with_cond = PlaybookStep::new("with-cond", "connect", "10.0.0.1").with_condition(
            Condition::new("skip_step", ConditionOperator::Equals, "false"),
        );
        assert!(!step_with_cond.should_execute(&context));
    }

    #[test]
    fn test_playbook_creation() {
        let pb = Playbook::new("test-playbook", "A test playbook", PlaybookCategory::Recon)
            .with_version("2.0.0")
            .with_author("tester")
            .with_variable("target", "192.168.1.0/24")
            .with_tag("network")
            .with_tag("recon");

        assert_eq!(pb.name, "test-playbook");
        assert_eq!(pb.category, PlaybookCategory::Recon);
        assert_eq!(pb.version, "2.0.0");
        assert_eq!(pb.author, "tester");
        assert_eq!(pb.variables.get("target").unwrap(), "192.168.1.0/24");
        assert_eq!(pb.tags.len(), 2);
        assert_eq!(pb.status, PlaybookStatus::Draft);
    }

    #[test]
    fn test_playbook_add_remove_steps() {
        let mut pb = Playbook::new("test", "desc", PlaybookCategory::Custom);
        assert_eq!(pb.step_count(), 0);

        let s1 = PlaybookStep::new("step1", "connect", "10.0.0.1");
        let s1_id = s1.id.clone();
        pb.add_step(s1);

        let s2 = PlaybookStep::new("step2", "syn", "10.0.0.2");
        pb.add_step(s2);
        assert_eq!(pb.step_count(), 2);

        assert!(pb.get_step(&s1_id).is_some());
        assert!(pb.remove_step(&s1_id));
        assert_eq!(pb.step_count(), 1);
        assert!(!pb.remove_step("nonexistent"));
    }

    #[test]
    fn test_playbook_progress() {
        let mut pb = Playbook::new("test", "desc", PlaybookCategory::Custom);
        let mut s1 = PlaybookStep::new("s1", "connect", "10.0.0.1");
        let mut s2 = PlaybookStep::new("s2", "connect", "10.0.0.1");
        let s3 = PlaybookStep::new("s3", "connect", "10.0.0.1");

        s1.mark_completed("ok");
        s2.mark_failed("err");
        pb.add_step(s1);
        pb.add_step(s2);
        pb.add_step(s3);

        assert_eq!(pb.completed_steps(), 1);
        assert_eq!(pb.failed_steps(), 1);
        assert_eq!(pb.pending_steps(), 1);
        assert!(!pb.is_complete());
        assert!((pb.progress() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_playbook_is_complete() {
        let mut pb = Playbook::new("test", "desc", PlaybookCategory::Custom);
        let mut s1 = PlaybookStep::new("s1", "connect", "10.0.0.1");
        s1.mark_completed("ok");
        pb.add_step(s1);
        assert!(pb.is_complete());

        let mut s2 = PlaybookStep::new("s2", "connect", "10.0.0.1");
        s2.mark_running();
        pb.add_step(s2);
        assert!(!pb.is_complete());
    }

    #[test]
    fn test_playbook_status_transitions() {
        let mut pb = Playbook::new("test", "desc", PlaybookCategory::Custom);
        assert_eq!(pb.status, PlaybookStatus::Draft);

        pb.mark_ready();
        assert_eq!(pb.status, PlaybookStatus::Ready);

        pb.mark_running();
        assert_eq!(pb.status, PlaybookStatus::Running);

        pb.mark_paused();
        assert_eq!(pb.status, PlaybookStatus::Paused);

        pb.mark_running();
        pb.mark_completed();
        assert_eq!(pb.status, PlaybookStatus::Completed);
    }

    #[test]
    fn test_playbook_resolve_variables() {
        let pb = Playbook::new("test", "desc", PlaybookCategory::Custom)
            .with_variable("target", "192.168.1.1")
            .with_variable("ports", "80,443");

        let resolved = pb.resolve_variables("Scanning {{target}} on ports {{ports}}");
        assert_eq!(resolved, "Scanning 192.168.1.1 on ports 80,443");

        let no_vars = pb.resolve_variables("No variables here");
        assert_eq!(no_vars, "No variables here");
    }

    #[test]
    fn test_playbook_builder() {
        let pb = PlaybookBuilder::new("builder-test", "Built playbook")
            .category(PlaybookCategory::VulnAssessment)
            .version("3.0.0")
            .author("builder")
            .step(PlaybookStep::new("s1", "connect", "10.0.0.1"))
            .step(PlaybookStep::new("s2", "syn", "10.0.0.2"))
            .variable("key", "val")
            .tag("custom")
            .build();

        assert_eq!(pb.name, "builder-test");
        assert_eq!(pb.category, PlaybookCategory::VulnAssessment);
        assert_eq!(pb.version, "3.0.0");
        assert_eq!(pb.author, "builder");
        assert_eq!(pb.step_count(), 2);
        assert_eq!(pb.variables.get("key").unwrap(), "val");
        assert!(pb.tags.contains(&"custom".to_string()));
    }

    #[test]
    fn test_playbook_category_display() {
        assert_eq!(PlaybookCategory::Recon.to_string(), "recon");
        assert_eq!(
            PlaybookCategory::VulnAssessment.to_string(),
            "vuln_assessment"
        );
        assert_eq!(PlaybookCategory::Compliance.to_string(), "compliance");
        assert_eq!(PlaybookCategory::Incident.to_string(), "incident");
        assert_eq!(PlaybookCategory::Custom.to_string(), "custom");
    }

    #[test]
    fn test_step_status_display() {
        assert_eq!(StepStatus::Pending.to_string(), "pending");
        assert_eq!(StepStatus::Running.to_string(), "running");
        assert_eq!(StepStatus::Completed.to_string(), "completed");
        assert_eq!(StepStatus::Failed.to_string(), "failed");
        assert_eq!(StepStatus::Skipped.to_string(), "skipped");
    }

    #[test]
    fn test_condition_operator_display() {
        assert_eq!(ConditionOperator::Equals.to_string(), "==");
        assert_eq!(ConditionOperator::NotEquals.to_string(), "!=");
        assert_eq!(ConditionOperator::Contains.to_string(), "contains");
        assert_eq!(ConditionOperator::GreaterThan.to_string(), ">");
        assert_eq!(ConditionOperator::LessThan.to_string(), "<");
        assert_eq!(ConditionOperator::Regex.to_string(), "regex");
    }

    #[test]
    fn test_playbook_status_display() {
        assert_eq!(PlaybookStatus::Draft.to_string(), "draft");
        assert_eq!(PlaybookStatus::Ready.to_string(), "ready");
        assert_eq!(PlaybookStatus::Running.to_string(), "running");
        assert_eq!(PlaybookStatus::Completed.to_string(), "completed");
        assert_eq!(PlaybookStatus::Failed.to_string(), "failed");
        assert_eq!(PlaybookStatus::Paused.to_string(), "paused");
    }

    #[test]
    fn test_step_template_instantiate() {
        let tmpl = StepTemplate::new("port-scan", "syn", "1-1024")
            .with_description("Scan ports")
            .with_template("quick")
            .with_parameter("timing", "T4");

        let step = tmpl.instantiate("192.168.1.0/24");
        assert_eq!(step.name, "port-scan");
        assert_eq!(step.scan_type, "syn");
        assert_eq!(step.target, "192.168.1.0/24");
        assert_eq!(step.ports, "1-1024");
        assert_eq!(step.template.as_deref(), Some("quick"));
        assert_eq!(step.parameters.get("timing").unwrap(), "T4");
    }

    #[test]
    fn test_playbook_template_instantiate() {
        let tmpl = PlaybookTemplate::new("test-template", "A template", PlaybookCategory::Recon)
            .with_tag("test")
            .with_step_template(StepTemplate::new("s1", "connect", "80,443"))
            .with_step_template(StepTemplate::new("s2", "syn", "1-1024"))
            .with_variable("env", "production");

        let pb = tmpl.instantiate("my-playbook", "10.0.0.0/8");
        assert_eq!(pb.name, "my-playbook");
        assert_eq!(pb.category, PlaybookCategory::Recon);
        assert_eq!(pb.step_count(), 2);
        assert_eq!(pb.variables.get("env").unwrap(), "production");
        assert_eq!(pb.status, PlaybookStatus::Ready);
    }

    #[test]
    fn test_playbook_library_defaults() {
        let lib = PlaybookLibrary::with_defaults();
        assert!(lib.template_count() >= 3);
        assert!(lib.get_template("network-recon").is_some());
        assert!(lib.get_template("web-audit").is_some());
        assert!(lib.get_template("compliance-check").is_some());
    }

    #[test]
    fn test_playbook_library_register_and_get() {
        let mut lib = PlaybookLibrary::new();
        let pb = Playbook::new("test", "desc", PlaybookCategory::Custom);
        let id = pb.id.clone();

        lib.register_playbook(pb);
        assert_eq!(lib.playbook_count(), 1);
        assert!(lib.get_playbook(&id).is_some());
        assert!(lib.get_playbook("nonexistent").is_none());
    }

    #[test]
    fn test_playbook_library_create_from_template() {
        let mut lib = PlaybookLibrary::with_defaults();
        let id = lib.create_from_template("network-recon", "My Recon", "192.168.1.0/24");
        assert!(id.is_some());
        assert_eq!(lib.playbook_count(), 1);

        let pb = lib.get_playbook(&id.unwrap()).unwrap();
        assert_eq!(pb.name, "My Recon");
        assert!(pb.step_count() > 0);
    }

    #[test]
    fn test_playbook_library_remove() {
        let mut lib = PlaybookLibrary::new();
        let pb = Playbook::new("test", "desc", PlaybookCategory::Custom);
        let id = pb.id.clone();

        lib.register_playbook(pb);
        assert!(lib.remove_playbook(&id).is_some());
        assert_eq!(lib.playbook_count(), 0);
        assert!(lib.remove_playbook("nonexistent").is_none());
    }

    #[test]
    fn test_playbook_serialization() {
        let pb = PlaybookBuilder::new("serde-test", "Serialization test")
            .category(PlaybookCategory::Recon)
            .version("1.0.0")
            .step(PlaybookStep::new("s1", "connect", "10.0.0.1"))
            .variable("key", "val")
            .tag("test")
            .build();

        let json = serde_json::to_string(&pb).unwrap();
        let loaded: Playbook = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "serde-test");
        assert_eq!(loaded.category, PlaybookCategory::Recon);
        assert_eq!(loaded.step_count(), 1);
        assert_eq!(loaded.variables.get("key").unwrap(), "val");
    }

    #[test]
    fn test_playbook_library_serialization() {
        let lib = PlaybookLibrary::with_defaults();
        let json = serde_json::to_string(&lib).unwrap();
        let loaded: PlaybookLibrary = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.template_count(), lib.template_count());
    }

    #[test]
    fn test_condition_regex_invalid() {
        let context = HashMap::from([("key".to_string(), "value".to_string())]);
        let bad_regex = Condition::new("key", ConditionOperator::Regex, "[invalid");
        assert!(!bad_regex.evaluate(&context));
    }
}
