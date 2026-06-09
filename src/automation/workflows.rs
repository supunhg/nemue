use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStatus {
    Draft,
    Ready,
    Running,
    Completed,
    Failed,
    Paused,
    Cancelled,
}

impl std::fmt::Display for WorkflowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowStatus::Draft => write!(f, "draft"),
            WorkflowStatus::Ready => write!(f, "ready"),
            WorkflowStatus::Running => write!(f, "running"),
            WorkflowStatus::Completed => write!(f, "completed"),
            WorkflowStatus::Failed => write!(f, "failed"),
            WorkflowStatus::Paused => write!(f, "paused"),
            WorkflowStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepExecutionMode {
    Sequential,
    Parallel,
}

impl std::fmt::Display for StepExecutionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepExecutionMode::Sequential => write!(f, "sequential"),
            StepExecutionMode::Parallel => write!(f, "parallel"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStepStatus {
    Pending,
    WaitingForDeps,
    Running,
    Completed,
    Failed,
    Skipped,
    Cancelled,
}

impl std::fmt::Display for WorkflowStepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowStepStatus::Pending => write!(f, "pending"),
            WorkflowStepStatus::WaitingForDeps => write!(f, "waiting_for_deps"),
            WorkflowStepStatus::Running => write!(f, "running"),
            WorkflowStepStatus::Completed => write!(f, "completed"),
            WorkflowStepStatus::Failed => write!(f, "failed"),
            WorkflowStepStatus::Skipped => write!(f, "skipped"),
            WorkflowStepStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub description: String,
    pub action: WorkflowAction,
    pub dependencies: Vec<String>,
    pub execution_mode: StepExecutionMode,
    pub timeout_secs: Option<u64>,
    pub retry_count: u32,
    pub retry_delay_secs: u64,
    pub status: WorkflowStepStatus,
    pub output: Option<String>,
    pub attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowAction {
    Scan {
        target: String,
        ports: String,
        scan_type: String,
        template: Option<String>,
    },
    WaitForManual {
        prompt: String,
    },
    SetVariable {
        key: String,
        value: String,
    },
    Conditional {
        condition_key: String,
        condition_value: String,
        then_action: Box<WorkflowAction>,
        else_action: Option<Box<WorkflowAction>>,
    },
    Custom {
        action_type: String,
        parameters: HashMap<String, String>,
    },
}

impl WorkflowStep {
    pub fn new_scan(name: &str, target: &str, ports: &str, scan_type: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            action: WorkflowAction::Scan {
                target: target.to_string(),
                ports: ports.to_string(),
                scan_type: scan_type.to_string(),
                template: None,
            },
            dependencies: Vec::new(),
            execution_mode: StepExecutionMode::Sequential,
            timeout_secs: None,
            retry_count: 0,
            retry_delay_secs: 0,
            status: WorkflowStepStatus::Pending,
            output: None,
            attempts: 0,
        }
    }

    pub fn new_set_variable(name: &str, key: &str, value: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            action: WorkflowAction::SetVariable {
                key: key.to_string(),
                value: value.to_string(),
            },
            dependencies: Vec::new(),
            execution_mode: StepExecutionMode::Sequential,
            timeout_secs: None,
            retry_count: 0,
            retry_delay_secs: 0,
            status: WorkflowStepStatus::Pending,
            output: None,
            attempts: 0,
        }
    }

    pub fn new_wait_for_manual(name: &str, prompt: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: String::new(),
            action: WorkflowAction::WaitForManual {
                prompt: prompt.to_string(),
            },
            dependencies: Vec::new(),
            execution_mode: StepExecutionMode::Sequential,
            timeout_secs: None,
            retry_count: 0,
            retry_delay_secs: 0,
            status: WorkflowStepStatus::Pending,
            output: None,
            attempts: 0,
        }
    }

    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    pub fn with_dependency(mut self, step_id: &str) -> Self {
        self.dependencies.push(step_id.to_string());
        self
    }

    pub fn with_execution_mode(mut self, mode: StepExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    pub fn with_retry(mut self, count: u32, delay_secs: u64) -> Self {
        self.retry_count = count;
        self.retry_delay_secs = delay_secs;
        self
    }

    pub fn has_dependencies(&self) -> bool {
        !self.dependencies.is_empty()
    }

    pub fn is_ready(&self, completed_ids: &std::collections::HashSet<&str>) -> bool {
        self.status == WorkflowStepStatus::Pending
            && self.dependencies.iter().all(|dep| completed_ids.contains(dep.as_str()))
    }

    pub fn mark_waiting(&mut self) {
        self.status = WorkflowStepStatus::WaitingForDeps;
    }

    pub fn mark_running(&mut self) {
        self.status = WorkflowStepStatus::Running;
        self.attempts += 1;
    }

    pub fn mark_completed(&mut self, output: &str) {
        self.status = WorkflowStepStatus::Completed;
        self.output = Some(output.to_string());
    }

    pub fn mark_failed(&mut self, error: &str) {
        self.status = WorkflowStepStatus::Failed;
        self.output = Some(error.to_string());
    }

    pub fn mark_skipped(&mut self) {
        self.status = WorkflowStepStatus::Skipped;
    }

    pub fn mark_cancelled(&mut self) {
        self.status = WorkflowStepStatus::Cancelled;
    }

    pub fn can_retry(&self) -> bool {
        self.status == WorkflowStepStatus::Failed && self.attempts <= self.retry_count
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub steps: Vec<WorkflowStep>,
    pub variables: HashMap<String, String>,
    pub global_timeout_secs: Option<u64>,
    pub status: WorkflowStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Workflow {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            version: "1.0.0".to_string(),
            steps: Vec::new(),
            variables: HashMap::new(),
            global_timeout_secs: None,
            status: WorkflowStatus::Draft,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
        }
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    pub fn with_variable(mut self, key: &str, value: &str) -> Self {
        self.variables.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_global_timeout(mut self, secs: u64) -> Self {
        self.global_timeout_secs = Some(secs);
        self
    }

    pub fn add_step(&mut self, step: WorkflowStep) {
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

    pub fn get_step(&self, step_id: &str) -> Option<&WorkflowStep> {
        self.steps.iter().find(|s| s.id == step_id)
    }

    pub fn get_step_mut(&mut self, step_id: &str) -> Option<&mut WorkflowStep> {
        self.steps.iter_mut().find(|s| s.id == step_id)
    }

    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    pub fn completed_steps(&self) -> usize {
        self.steps.iter().filter(|s| s.status == WorkflowStepStatus::Completed).count()
    }

    pub fn failed_steps(&self) -> usize {
        self.steps.iter().filter(|s| s.status == WorkflowStepStatus::Failed).count()
    }

    pub fn pending_steps(&self) -> usize {
        self.steps.iter().filter(|s| s.status == WorkflowStepStatus::Pending).count()
    }

    pub fn running_steps(&self) -> usize {
        self.steps.iter().filter(|s| s.status == WorkflowStepStatus::Running).count()
    }

    pub fn is_complete(&self) -> bool {
        self.steps.iter().all(|s| {
            matches!(
                s.status,
                WorkflowStepStatus::Completed
                    | WorkflowStepStatus::Failed
                    | WorkflowStepStatus::Skipped
                    | WorkflowStepStatus::Cancelled
            )
        })
    }

    pub fn progress(&self) -> f64 {
        if self.steps.is_empty() {
            return 0.0;
        }
        let done = self.steps.iter().filter(|s| {
            matches!(
                s.status,
                WorkflowStepStatus::Completed
                    | WorkflowStepStatus::Failed
                    | WorkflowStepStatus::Skipped
                    | WorkflowStepStatus::Cancelled
            )
        }).count();
        done as f64 / self.steps.len() as f64
    }

    pub fn mark_ready(&mut self) {
        self.status = WorkflowStatus::Ready;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_running(&mut self) {
        self.status = WorkflowStatus::Running;
        self.started_at = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_completed(&mut self) {
        self.status = WorkflowStatus::Completed;
        self.completed_at = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_failed(&mut self) {
        self.status = WorkflowStatus::Failed;
        self.completed_at = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_paused(&mut self) {
        self.status = WorkflowStatus::Paused;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_cancelled(&mut self) {
        self.status = WorkflowStatus::Cancelled;
        self.completed_at = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }
}

pub struct WorkflowExecutionEngine {
    workflow: Workflow,
    execution_log: Vec<ExecutionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub step_id: String,
    pub step_name: String,
    pub event: String,
    pub details: Option<String>,
}

impl ExecutionLogEntry {
    pub fn new(step_id: &str, step_name: &str, event: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            step_id: step_id.to_string(),
            step_name: step_name.to_string(),
            event: event.to_string(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }
}

impl WorkflowExecutionEngine {
    pub fn new(workflow: Workflow) -> Self {
        Self {
            workflow,
            execution_log: Vec::new(),
        }
    }

    pub fn workflow(&self) -> &Workflow {
        &self.workflow
    }

    pub fn workflow_mut(&mut self) -> &mut Workflow {
        &mut self.workflow
    }

    pub fn execution_log(&self) -> &[ExecutionLogEntry] {
        &self.execution_log
    }

    pub fn ready_steps(&self) -> Vec<&WorkflowStep> {
        let completed_ids: std::collections::HashSet<&str> = self
            .workflow
            .steps
            .iter()
            .filter(|s| s.status == WorkflowStepStatus::Completed)
            .map(|s| s.id.as_str())
            .collect();

        self.workflow
            .steps
            .iter()
            .filter(|s| s.is_ready(&completed_ids))
            .collect()
    }

    pub fn mark_step_running(&mut self, step_id: &str) -> bool {
        if let Some(step) = self.workflow.get_step_mut(step_id) {
            step.mark_running();
            self.execution_log.push(
                ExecutionLogEntry::new(step_id, &step.name.clone(), "started"),
            );
            true
        } else {
            false
        }
    }

    pub fn mark_step_completed(&mut self, step_id: &str, output: &str) -> bool {
        if let Some(step) = self.workflow.get_step_mut(step_id) {
            step.mark_completed(output);
            self.execution_log.push(
                ExecutionLogEntry::new(step_id, &step.name.clone(), "completed")
                    .with_details(output),
            );
            self.check_workflow_completion();
            true
        } else {
            false
        }
    }

    pub fn mark_step_failed(&mut self, step_id: &str, error: &str) -> bool {
        if let Some(step) = self.workflow.get_step_mut(step_id) {
            step.mark_failed(error);
            self.execution_log.push(
                ExecutionLogEntry::new(step_id, &step.name.clone(), "failed")
                    .with_details(error),
            );
            if step.can_retry() {
                step.status = WorkflowStepStatus::Pending;
                self.execution_log.push(
                    ExecutionLogEntry::new(step_id, &step.name.clone(), "retry_scheduled"),
                );
            }
            self.check_workflow_completion();
            true
        } else {
            false
        }
    }

    pub fn mark_step_skipped(&mut self, step_id: &str) -> bool {
        if let Some(step) = self.workflow.get_step_mut(step_id) {
            step.mark_skipped();
            self.execution_log.push(
                ExecutionLogEntry::new(step_id, &step.name.clone(), "skipped"),
            );
            self.check_workflow_completion();
            true
        } else {
            false
        }
    }

    pub fn cancel(&mut self) {
        for step in &mut self.workflow.steps {
            if matches!(
                step.status,
                WorkflowStepStatus::Pending | WorkflowStepStatus::WaitingForDeps | WorkflowStepStatus::Running
            ) {
                step.mark_cancelled();
            }
        }
        self.workflow.mark_cancelled();
    }

    fn check_workflow_completion(&mut self) {
        if self.workflow.is_complete() {
            if self.workflow.failed_steps() > 0 {
                self.workflow.mark_failed();
            } else {
                self.workflow.mark_completed();
            }
        }
    }
}

pub struct WorkflowBuilder {
    workflow: Workflow,
}

impl WorkflowBuilder {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            workflow: Workflow::new(name, description),
        }
    }

    pub fn version(mut self, version: &str) -> Self {
        self.workflow.version = version.to_string();
        self
    }

    pub fn variable(mut self, key: &str, value: &str) -> Self {
        self.workflow.variables.insert(key.to_string(), value.to_string());
        self
    }

    pub fn global_timeout(mut self, secs: u64) -> Self {
        self.workflow.global_timeout_secs = Some(secs);
        self
    }

    pub fn step(mut self, step: WorkflowStep) -> Self {
        self.workflow.steps.push(step);
        self
    }

    pub fn build(self) -> Workflow {
        self.workflow
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowState {
    pub workflow_id: String,
    pub status: WorkflowStatus,
    pub step_states: HashMap<String, WorkflowStepStatus>,
    pub variables: HashMap<String, String>,
    pub current_step_index: usize,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl WorkflowState {
    pub fn from_workflow(workflow: &Workflow) -> Self {
        let step_states = workflow
            .steps
            .iter()
            .map(|s| (s.id.clone(), s.status.clone()))
            .collect();

        Self {
            workflow_id: workflow.id.clone(),
            status: workflow.status.clone(),
            step_states,
            variables: workflow.variables.clone(),
            current_step_index: 0,
            updated_at: chrono::Utc::now(),
        }
    }

    pub fn save_to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn load_from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_step_creation() {
        let step = WorkflowStep::new_scan("port-scan", "192.168.1.0/24", "1-1024", "syn")
            .with_description("Scan local network")
            .with_timeout(300)
            .with_retry(3, 10);

        assert_eq!(step.name, "port-scan");
        assert_eq!(step.dependencies.len(), 0);
        assert_eq!(step.execution_mode, StepExecutionMode::Sequential);
        assert_eq!(step.timeout_secs, Some(300));
        assert_eq!(step.retry_count, 3);
        assert_eq!(step.retry_delay_secs, 10);
        assert_eq!(step.status, WorkflowStepStatus::Pending);
    }

    #[test]
    fn test_workflow_step_set_variable() {
        let step = WorkflowStep::new_set_variable("set-env", "env", "production");
        match &step.action {
            WorkflowAction::SetVariable { key, value } => {
                assert_eq!(key, "env");
                assert_eq!(value, "production");
            }
            _ => panic!("Expected SetVariable action"),
        }
    }

    #[test]
    fn test_workflow_step_wait_for_manual() {
        let step = WorkflowStep::new_wait_for_manual("approval", "Please approve the scan");
        match &step.action {
            WorkflowAction::WaitForManual { prompt } => {
                assert_eq!(prompt, "Please approve the scan");
            }
            _ => panic!("Expected WaitForManual action"),
        }
    }

    #[test]
    fn test_workflow_step_dependencies() {
        let step = WorkflowStep::new_scan("dep-scan", "10.0.0.1", "80", "connect")
            .with_dependency("step-1")
            .with_dependency("step-2");

        assert!(step.has_dependencies());
        assert_eq!(step.dependencies.len(), 2);

        let no_dep = WorkflowStep::new_scan("no-dep", "10.0.0.1", "80", "connect");
        assert!(!no_dep.has_dependencies());
    }

    #[test]
    fn test_workflow_step_is_ready() {
        let step = WorkflowStep::new_scan("test", "10.0.0.1", "80", "connect")
            .with_dependency("dep1")
            .with_dependency("dep2");

        let mut completed = std::collections::HashSet::new();
        completed.insert("dep1");
        assert!(!step.is_ready(&completed));

        completed.insert("dep2");
        assert!(step.is_ready(&completed));

        let no_deps = WorkflowStep::new_scan("no-deps", "10.0.0.1", "80", "connect");
        assert!(no_deps.is_ready(&completed));
    }

    #[test]
    fn test_workflow_step_status_transitions() {
        let mut step = WorkflowStep::new_scan("test", "10.0.0.1", "80", "connect");
        assert_eq!(step.status, WorkflowStepStatus::Pending);

        step.mark_waiting();
        assert_eq!(step.status, WorkflowStepStatus::WaitingForDeps);

        step.mark_running();
        assert_eq!(step.status, WorkflowStepStatus::Running);
        assert_eq!(step.attempts, 1);

        step.mark_completed("5 open ports");
        assert_eq!(step.status, WorkflowStepStatus::Completed);
        assert_eq!(step.output.as_deref(), Some("5 open ports"));

        let mut step2 = WorkflowStep::new_scan("test2", "10.0.0.1", "80", "connect");
        step2.mark_running();
        step2.mark_failed("timeout");
        assert_eq!(step2.status, WorkflowStepStatus::Failed);
        assert_eq!(step2.output.as_deref(), Some("timeout"));

        let mut step3 = WorkflowStep::new_scan("test3", "10.0.0.1", "80", "connect");
        step3.mark_skipped();
        assert_eq!(step3.status, WorkflowStepStatus::Skipped);

        let mut step4 = WorkflowStep::new_scan("test4", "10.0.0.1", "80", "connect");
        step4.mark_cancelled();
        assert_eq!(step4.status, WorkflowStepStatus::Cancelled);
    }

    #[test]
    fn test_workflow_step_can_retry() {
        let mut step = WorkflowStep::new_scan("test", "10.0.0.1", "80", "connect")
            .with_retry(2, 5);

        step.mark_running();
        step.mark_failed("err");
        assert!(step.can_retry());

        step.mark_running();
        step.mark_failed("err");
        assert!(step.can_retry());

        step.mark_running();
        step.mark_failed("err");
        assert!(!step.can_retry());
    }

    #[test]
    fn test_workflow_creation() {
        let wf = Workflow::new("test-workflow", "A test workflow")
            .with_version("2.0.0")
            .with_variable("target", "192.168.1.0/24")
            .with_global_timeout(3600);

        assert_eq!(wf.name, "test-workflow");
        assert_eq!(wf.description, "A test workflow");
        assert_eq!(wf.version, "2.0.0");
        assert_eq!(wf.variables.get("target").unwrap(), "192.168.1.0/24");
        assert_eq!(wf.global_timeout_secs, Some(3600));
        assert_eq!(wf.status, WorkflowStatus::Draft);
    }

    #[test]
    fn test_workflow_add_remove_steps() {
        let mut wf = Workflow::new("test", "desc");
        assert_eq!(wf.step_count(), 0);

        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let s1_id = s1.id.clone();
        wf.add_step(s1);

        let s2 = WorkflowStep::new_scan("s2", "10.0.0.2", "443", "syn");
        wf.add_step(s2);
        assert_eq!(wf.step_count(), 2);

        assert!(wf.get_step(&s1_id).is_some());
        assert!(wf.remove_step(&s1_id));
        assert_eq!(wf.step_count(), 1);
        assert!(!wf.remove_step("nonexistent"));
    }

    #[test]
    fn test_workflow_progress() {
        let mut wf = Workflow::new("test", "desc");
        let mut s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let mut s2 = WorkflowStep::new_scan("s2", "10.0.0.1", "443", "connect");
        let s3 = WorkflowStep::new_scan("s3", "10.0.0.1", "8080", "connect");

        s1.mark_completed("ok");
        s2.mark_failed("err");
        wf.add_step(s1);
        wf.add_step(s2);
        wf.add_step(s3);

        assert_eq!(wf.completed_steps(), 1);
        assert_eq!(wf.failed_steps(), 1);
        assert_eq!(wf.pending_steps(), 1);
        assert!(!wf.is_complete());
        assert!((wf.progress() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_workflow_is_complete() {
        let mut wf = Workflow::new("test", "desc");
        let mut s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        s1.mark_completed("ok");
        wf.add_step(s1);
        assert!(wf.is_complete());

        let mut s2 = WorkflowStep::new_scan("s2", "10.0.0.1", "443", "connect");
        s2.mark_running();
        wf.add_step(s2);
        assert!(!wf.is_complete());
    }

    #[test]
    fn test_workflow_status_transitions() {
        let mut wf = Workflow::new("test", "desc");
        assert_eq!(wf.status, WorkflowStatus::Draft);

        wf.mark_ready();
        assert_eq!(wf.status, WorkflowStatus::Ready);

        wf.mark_running();
        assert_eq!(wf.status, WorkflowStatus::Running);
        assert!(wf.started_at.is_some());

        wf.mark_paused();
        assert_eq!(wf.status, WorkflowStatus::Paused);

        wf.mark_running();
        wf.mark_completed();
        assert_eq!(wf.status, WorkflowStatus::Completed);
        assert!(wf.completed_at.is_some());

        let mut wf2 = Workflow::new("test2", "desc");
        wf2.mark_running();
        wf2.mark_failed();
        assert_eq!(wf2.status, WorkflowStatus::Failed);
        assert!(wf2.completed_at.is_some());

        let mut wf3 = Workflow::new("test3", "desc");
        wf3.mark_running();
        wf3.mark_cancelled();
        assert_eq!(wf3.status, WorkflowStatus::Cancelled);
        assert!(wf3.completed_at.is_some());
    }

    #[test]
    fn test_execution_engine_ready_steps() {
        let mut wf = Workflow::new("test", "desc");
        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let s1_id = s1.id.clone();
        wf.add_step(s1);

        let s2 = WorkflowStep::new_scan("s2", "10.0.0.1", "443", "connect")
            .with_dependency(&s1_id);
        wf.add_step(s2);

        let s3 = WorkflowStep::new_scan("s3", "10.0.0.2", "80", "connect");
        wf.add_step(s3);

        let engine = WorkflowExecutionEngine::new(wf);
        let ready = engine.ready_steps();
        assert_eq!(ready.len(), 2); // s1 and s3 (no deps)
    }

    #[test]
    fn test_execution_engine_step_lifecycle() {
        let mut wf = Workflow::new("test", "desc");
        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let s1_id = s1.id.clone();
        wf.add_step(s1);

        let mut engine = WorkflowExecutionEngine::new(wf);
        assert!(engine.mark_step_running(&s1_id));
        assert!(engine.mark_step_completed(&s1_id, "3 open ports"));
        assert_eq!(engine.execution_log().len(), 2);
        assert!(engine.workflow().is_complete());
        assert_eq!(engine.workflow().status, WorkflowStatus::Completed);
    }

    #[test]
    fn test_execution_engine_step_failure() {
        let mut wf = Workflow::new("test", "desc");
        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let s1_id = s1.id.clone();
        wf.add_step(s1);

        let mut engine = WorkflowExecutionEngine::new(wf);
        engine.mark_step_running(&s1_id);
        engine.mark_step_failed(&s1_id, "connection refused");
        assert_eq!(engine.workflow().status, WorkflowStatus::Failed);
    }

    #[test]
    fn test_execution_engine_step_retry() {
        let mut wf = Workflow::new("test", "desc");
        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect")
            .with_retry(2, 5);
        let s1_id = s1.id.clone();
        wf.add_step(s1);

        let mut engine = WorkflowExecutionEngine::new(wf);
        engine.mark_step_running(&s1_id);
        engine.mark_step_failed(&s1_id, "timeout");

        // Step should be reset to Pending for retry
        let step = engine.workflow().get_step(&s1_id).unwrap();
        assert_eq!(step.status, WorkflowStepStatus::Pending);
        assert_eq!(engine.execution_log().len(), 3); // started, failed, retry_scheduled
    }

    #[test]
    fn test_execution_engine_cancel() {
        let mut wf = Workflow::new("test", "desc");
        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let s2 = WorkflowStep::new_scan("s2", "10.0.0.1", "443", "connect");
        wf.add_step(s1);
        wf.add_step(s2);

        let mut engine = WorkflowExecutionEngine::new(wf);
        engine.cancel();
        assert_eq!(engine.workflow().status, WorkflowStatus::Cancelled);
        for step in &engine.workflow().steps {
            assert_eq!(step.status, WorkflowStepStatus::Cancelled);
        }
    }

    #[test]
    fn test_execution_engine_nonexistent_step() {
        let wf = Workflow::new("test", "desc");
        let mut engine = WorkflowExecutionEngine::new(wf);
        assert!(!engine.mark_step_running("nonexistent"));
        assert!(!engine.mark_step_completed("nonexistent", "out"));
        assert!(!engine.mark_step_failed("nonexistent", "err"));
        assert!(!engine.mark_step_skipped("nonexistent"));
    }

    #[test]
    fn test_execution_engine_mark_skipped() {
        let mut wf = Workflow::new("test", "desc");
        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let s1_id = s1.id.clone();
        wf.add_step(s1);

        let mut engine = WorkflowExecutionEngine::new(wf);
        engine.mark_step_skipped(&s1_id);
        assert_eq!(engine.workflow().status, WorkflowStatus::Completed);
    }

    #[test]
    fn test_workflow_builder() {
        let wf = WorkflowBuilder::new("builder-test", "Built workflow")
            .version("2.0.0")
            .variable("target", "10.0.0.0/8")
            .global_timeout(7200)
            .step(WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect"))
            .step(WorkflowStep::new_scan("s2", "10.0.0.2", "443", "syn"))
            .build();

        assert_eq!(wf.name, "builder-test");
        assert_eq!(wf.version, "2.0.0");
        assert_eq!(wf.step_count(), 2);
        assert_eq!(wf.variables.get("target").unwrap(), "10.0.0.0/8");
        assert_eq!(wf.global_timeout_secs, Some(7200));
    }

    #[test]
    fn test_workflow_state_save_load() {
        let mut wf = Workflow::new("test", "desc");
        wf.add_step(WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect"));
        wf.add_step(WorkflowStep::new_scan("s2", "10.0.0.2", "443", "syn"));
        wf.mark_ready();

        let state = WorkflowState::from_workflow(&wf);
        let json = state.save_to_json().unwrap();
        let loaded = WorkflowState::load_from_json(&json).unwrap();

        assert_eq!(loaded.workflow_id, wf.id);
        assert_eq!(loaded.status, WorkflowStatus::Ready);
        assert_eq!(loaded.step_states.len(), 2);
    }

    #[test]
    fn test_workflow_status_display() {
        assert_eq!(WorkflowStatus::Draft.to_string(), "draft");
        assert_eq!(WorkflowStatus::Ready.to_string(), "ready");
        assert_eq!(WorkflowStatus::Running.to_string(), "running");
        assert_eq!(WorkflowStatus::Completed.to_string(), "completed");
        assert_eq!(WorkflowStatus::Failed.to_string(), "failed");
        assert_eq!(WorkflowStatus::Paused.to_string(), "paused");
        assert_eq!(WorkflowStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_step_execution_mode_display() {
        assert_eq!(StepExecutionMode::Sequential.to_string(), "sequential");
        assert_eq!(StepExecutionMode::Parallel.to_string(), "parallel");
    }

    #[test]
    fn test_workflow_step_status_display() {
        assert_eq!(WorkflowStepStatus::Pending.to_string(), "pending");
        assert_eq!(WorkflowStepStatus::WaitingForDeps.to_string(), "waiting_for_deps");
        assert_eq!(WorkflowStepStatus::Running.to_string(), "running");
        assert_eq!(WorkflowStepStatus::Completed.to_string(), "completed");
        assert_eq!(WorkflowStepStatus::Failed.to_string(), "failed");
        assert_eq!(WorkflowStepStatus::Skipped.to_string(), "skipped");
        assert_eq!(WorkflowStepStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_workflow_serialization() {
        let wf = WorkflowBuilder::new("serde-test", "Serialization test")
            .version("1.0.0")
            .step(WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect"))
            .variable("key", "val")
            .build();

        let json = serde_json::to_string(&wf).unwrap();
        let loaded: Workflow = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "serde-test");
        assert_eq!(loaded.step_count(), 1);
        assert_eq!(loaded.variables.get("key").unwrap(), "val");
    }

    #[test]
    fn test_execution_log_entry() {
        let entry = ExecutionLogEntry::new("step-1", "port-scan", "started")
            .with_details("scanning 10.0.0.1");

        assert_eq!(entry.step_id, "step-1");
        assert_eq!(entry.step_name, "port-scan");
        assert_eq!(entry.event, "started");
        assert_eq!(entry.details.as_deref(), Some("scanning 10.0.0.1"));
    }

    #[test]
    fn test_parallel_step_dependency_chain() {
        let mut wf = Workflow::new("test", "desc");
        let s1 = WorkflowStep::new_scan("s1", "10.0.0.1", "80", "connect");
        let s1_id = s1.id.clone();
        let s2 = WorkflowStep::new_scan("s2", "10.0.0.1", "443", "connect");
        let s2_id = s2.id.clone();
        let s3 = WorkflowStep::new_scan("s3", "10.0.0.1", "8080", "connect")
            .with_dependency(&s1_id)
            .with_dependency(&s2_id);

        wf.add_step(s1);
        wf.add_step(s2);
        wf.add_step(s3);

        let mut engine = WorkflowExecutionEngine::new(wf);

        // Initially s1 and s2 are ready (no deps)
        let ready = engine.ready_steps();
        assert_eq!(ready.len(), 2);

        // Complete s1 only
        engine.mark_step_running(&s1_id);
        engine.mark_step_completed(&s1_id, "ok");

        // s3 still waiting for s2
        let ready = engine.ready_steps();
        assert_eq!(ready.len(), 1); // only s2

        // Complete s2
        engine.mark_step_running(&s2_id);
        engine.mark_step_completed(&s2_id, "ok");

        // Now s3 is ready
        let ready = engine.ready_steps();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].name, "s3");
    }
}
