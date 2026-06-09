use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MacroStatus {
    Recording,
    Ready,
    Running,
    Completed,
    Failed,
}

impl std::fmt::Display for MacroStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MacroStatus::Recording => write!(f, "recording"),
            MacroStatus::Ready => write!(f, "ready"),
            MacroStatus::Running => write!(f, "running"),
            MacroStatus::Completed => write!(f, "completed"),
            MacroStatus::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroAction {
    pub action_type: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub parameters: HashMap<String, String>,
    pub delay_ms: u64,
    pub recorded_at: chrono::DateTime<chrono::Utc>,
}

impl MacroAction {
    pub fn new(action_type: &str, command: &str) -> Self {
        Self {
            action_type: action_type.to_string(),
            command: command.to_string(),
            arguments: Vec::new(),
            parameters: HashMap::new(),
            delay_ms: 0,
            recorded_at: chrono::Utc::now(),
        }
    }

    pub fn with_argument(mut self, arg: &str) -> Self {
        self.arguments.push(arg.to_string());
        self
    }

    pub fn with_arguments(mut self, args: Vec<String>) -> Self {
        self.arguments.extend(args);
        self
    }

    pub fn with_parameter(mut self, key: &str, value: &str) -> Self {
        self.parameters.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_delay(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    pub fn substitute_parameters(&self, vars: &HashMap<String, String>) -> MacroAction {
        let mut action = self.clone();
        for (key, value) in vars {
            action.command = action.command.replace(&format!("{{{{{}}}}}", key), value);
            for arg in &mut action.arguments {
                *arg = arg.replace(&format!("{{{{{}}}}}", key), value);
            }
        }
        action
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroParameter {
    pub name: String,
    pub description: String,
    pub default_value: Option<String>,
    pub required: bool,
    pub param_type: ParameterType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParameterType {
    String,
    Number,
    Boolean,
    Target,
    Port,
    ScanType,
}

impl std::fmt::Display for ParameterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterType::String => write!(f, "string"),
            ParameterType::Number => write!(f, "number"),
            ParameterType::Boolean => write!(f, "boolean"),
            ParameterType::Target => write!(f, "target"),
            ParameterType::Port => write!(f, "port"),
            ParameterType::ScanType => write!(f, "scan_type"),
        }
    }
}

impl MacroParameter {
    pub fn new(name: &str, description: &str, param_type: ParameterType) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            default_value: None,
            required: true,
            param_type,
        }
    }

    pub fn with_default(mut self, value: &str) -> Self {
        self.default_value = Some(value.to_string());
        self
    }

    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMacro {
    pub id: String,
    pub name: String,
    pub description: String,
    pub actions: Vec<MacroAction>,
    pub parameters: Vec<MacroParameter>,
    pub variables: HashMap<String, String>,
    pub status: MacroStatus,
    pub author: String,
    pub version: String,
    pub tags: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub execution_count: u32,
    pub last_executed: Option<chrono::DateTime<chrono::Utc>>,
}

impl ScanMacro {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            actions: Vec::new(),
            parameters: Vec::new(),
            variables: HashMap::new(),
            status: MacroStatus::Ready,
            author: String::new(),
            version: "1.0.0".to_string(),
            tags: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            execution_count: 0,
            last_executed: None,
        }
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.author = author.to_string();
        self
    }

    pub fn with_version(mut self, version: &str) -> Self {
        self.version = version.to_string();
        self
    }

    pub fn with_action(mut self, action: MacroAction) -> Self {
        self.actions.push(action);
        self
    }

    pub fn with_parameter(mut self, param: MacroParameter) -> Self {
        self.parameters.push(param);
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

    pub fn add_action(&mut self, action: MacroAction) {
        self.actions.push(action);
        self.updated_at = chrono::Utc::now();
    }

    pub fn remove_action(&mut self, index: usize) -> Option<MacroAction> {
        if index < self.actions.len() {
            self.updated_at = chrono::Utc::now();
            Some(self.actions.remove(index))
        } else {
            None
        }
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    pub fn start_recording(&mut self) {
        self.status = MacroStatus::Recording;
        self.actions.clear();
    }

    pub fn stop_recording(&mut self) {
        self.status = MacroStatus::Ready;
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_running(&mut self) {
        self.status = MacroStatus::Running;
    }

    pub fn mark_completed(&mut self) {
        self.status = MacroStatus::Completed;
        self.execution_count += 1;
        self.last_executed = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }

    pub fn mark_failed(&mut self) {
        self.status = MacroStatus::Failed;
        self.execution_count += 1;
        self.last_executed = Some(chrono::Utc::now());
        self.updated_at = chrono::Utc::now();
    }

    pub fn is_ready(&self) -> bool {
        self.status == MacroStatus::Ready && !self.actions.is_empty()
    }

    pub fn resolve_parameters(
        &self,
        provided: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, String> {
        let mut resolved = self.variables.clone();

        for param in &self.parameters {
            if let Some(value) = provided.get(&param.name) {
                resolved.insert(param.name.clone(), value.clone());
            } else if let Some(default) = &param.default_value {
                resolved.insert(param.name.clone(), default.clone());
            } else if param.required {
                return Err(format!("Missing required parameter: {}", param.name));
            }
        }

        Ok(resolved)
    }

    pub fn execute_with_params(
        &mut self,
        params: &HashMap<String, String>,
    ) -> Result<Vec<MacroAction>, String> {
        let resolved = self.resolve_parameters(params)?;
        self.mark_running();

        let resolved_actions: Vec<MacroAction> = self
            .actions
            .iter()
            .map(|a| a.substitute_parameters(&resolved))
            .collect();

        self.mark_completed();
        Ok(resolved_actions)
    }
}

pub struct MacroRecorder {
    macro_: ScanMacro,
    recording: bool,
}

impl MacroRecorder {
    pub fn new(name: &str, description: &str) -> Self {
        let mut m = ScanMacro::new(name, description);
        m.start_recording();
        Self {
            macro_: m,
            recording: true,
        }
    }

    pub fn record_action(&mut self, action: MacroAction) {
        if self.recording {
            self.macro_.add_action(action);
        }
    }

    pub fn record_scan(&mut self, target: &str, ports: &str, scan_type: &str) {
        self.record_action(
            MacroAction::new("scan", scan_type)
                .with_argument(target)
                .with_argument(ports),
        );
    }

    pub fn record_wait(&mut self, ms: u64) {
        self.record_action(MacroAction::new("wait", "delay").with_delay(ms));
    }

    pub fn record_set_variable(&mut self, key: &str, value: &str) {
        self.record_action(
            MacroAction::new("set_variable", key).with_parameter("value", value),
        );
    }

    pub fn finish(&mut self) -> ScanMacro {
        self.recording = false;
        self.macro_.stop_recording();
        self.macro_.clone()
    }

    pub fn is_recording(&self) -> bool {
        self.recording
    }

    pub fn action_count(&self) -> usize {
        self.macro_.action_count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroLibrary {
    macros: HashMap<String, ScanMacro>,
}

impl MacroLibrary {
    pub fn new() -> Self {
        Self {
            macros: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut lib = Self::new();
        lib.register_defaults();
        lib
    }

    pub fn register(&mut self, macro_: ScanMacro) -> String {
        let id = macro_.id.clone();
        self.macros.insert(id.clone(), macro_);
        id
    }

    pub fn get(&self, id: &str) -> Option<&ScanMacro> {
        self.macros.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut ScanMacro> {
        self.macros.get_mut(id)
    }

    pub fn get_by_name(&self, name: &str) -> Option<&ScanMacro> {
        self.macros.values().find(|m| m.name == name)
    }

    pub fn remove(&mut self, id: &str) -> Option<ScanMacro> {
        self.macros.remove(id)
    }

    pub fn list(&self) -> Vec<&ScanMacro> {
        self.macros.values().collect()
    }

    pub fn len(&self) -> usize {
        self.macros.len()
    }

    pub fn is_empty(&self) -> bool {
        self.macros.is_empty()
    }

    pub fn search_by_tag(&self, tag: &str) -> Vec<&ScanMacro> {
        self.macros
            .values()
            .filter(|m| m.tags.contains(&tag.to_string()))
            .collect()
    }

    pub fn export_macro(&self, id: &str) -> Option<String> {
        let macro_ = self.macros.get(id)?;
        serde_json::to_string_pretty(macro_).ok()
    }

    pub fn import_macro(&mut self, json: &str) -> Result<String, serde_json::Error> {
        let mut macro_: ScanMacro = serde_json::from_str(json)?;
        macro_.id = Uuid::new_v4().to_string();
        let id = macro_.id.clone();
        self.macros.insert(id.clone(), macro_);
        Ok(id)
    }

    fn register_defaults(&mut self) {
        self.register(
            ScanMacro::new("quick-network-scan", "Quick scan of a /24 network")
                .with_author("nemue")
                .with_tag("network")
                .with_tag("quick")
                .with_parameter(
                    MacroParameter::new("target", "Target network", ParameterType::Target)
                        .with_default("192.168.1.0/24"),
                )
                .with_parameter(
                    MacroParameter::new("ports", "Ports to scan", ParameterType::Port)
                        .with_default("top-100"),
                )
                .with_action(
                    MacroAction::new("scan", "connect")
                        .with_argument("{{target}}")
                        .with_argument("{{ports}}"),
                ),
        );

        self.register(
            ScanMacro::new("web-server-audit", "Audit web servers on common ports")
                .with_author("nemue")
                .with_tag("web")
                .with_tag("audit")
                .with_parameter(
                    MacroParameter::new("target", "Target host", ParameterType::Target),
                )
                .with_action(
                    MacroAction::new("scan", "connect")
                        .with_argument("{{target}}")
                        .with_argument("80,443,8080,8443"),
                )
                .with_action(
                    MacroAction::new("wait", "delay").with_delay(1000),
                )
                .with_action(
                    MacroAction::new("scan", "connect")
                        .with_argument("{{target}}")
                        .with_argument("8000,3000,5000,9000"),
                ),
        );

        self.register(
            ScanMacro::new("stealth-recon", "Stealthy reconnaissance scan")
                .with_author("nemue")
                .with_tag("stealth")
                .with_tag("recon")
                .with_parameter(
                    MacroParameter::new("target", "Target", ParameterType::Target),
                )
                .with_action(
                    MacroAction::new("scan", "syn")
                        .with_argument("{{target}}")
                        .with_argument("1-1024")
                        .with_parameter("timing", "T1"),
                ),
        );
    }
}

impl Default for MacroLibrary {
    fn default() -> Self {
        Self::with_defaults()
    }
}

pub struct MacroBuilder {
    macro_: ScanMacro,
}

impl MacroBuilder {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            macro_: ScanMacro::new(name, description),
        }
    }

    pub fn author(mut self, author: &str) -> Self {
        self.macro_.author = author.to_string();
        self
    }

    pub fn version(mut self, version: &str) -> Self {
        self.macro_.version = version.to_string();
        self
    }

    pub fn action(mut self, action: MacroAction) -> Self {
        self.macro_.actions.push(action);
        self
    }

    pub fn parameter(mut self, param: MacroParameter) -> Self {
        self.macro_.parameters.push(param);
        self
    }

    pub fn variable(mut self, key: &str, value: &str) -> Self {
        self.macro_.variables.insert(key.to_string(), value.to_string());
        self
    }

    pub fn tag(mut self, tag: &str) -> Self {
        if !self.macro_.tags.contains(&tag.to_string()) {
            self.macro_.tags.push(tag.to_string());
        }
        self
    }

    pub fn build(self) -> ScanMacro {
        self.macro_
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macro_action_creation() {
        let action = MacroAction::new("scan", "syn")
            .with_argument("192.168.1.0/24")
            .with_argument("1-1024")
            .with_parameter("timing", "T4")
            .with_delay(500);

        assert_eq!(action.action_type, "scan");
        assert_eq!(action.command, "syn");
        assert_eq!(action.arguments.len(), 2);
        assert_eq!(action.arguments[0], "192.168.1.0/24");
        assert_eq!(action.parameters.get("timing").unwrap(), "T4");
        assert_eq!(action.delay_ms, 500);
    }

    #[test]
    fn test_macro_action_substitute_parameters() {
        let action = MacroAction::new("scan", "connect")
            .with_argument("{{target}}")
            .with_argument("{{ports}}");

        let mut vars = HashMap::new();
        vars.insert("target".to_string(), "10.0.0.1".to_string());
        vars.insert("ports".to_string(), "80,443".to_string());

        let resolved = action.substitute_parameters(&vars);
        assert_eq!(resolved.arguments[0], "10.0.0.1");
        assert_eq!(resolved.arguments[1], "80,443");
    }

    #[test]
    fn test_macro_parameter_creation() {
        let param = MacroParameter::new("target", "Target host", ParameterType::Target)
            .with_default("192.168.1.1");

        assert_eq!(param.name, "target");
        assert_eq!(param.description, "Target host");
        assert_eq!(param.param_type, ParameterType::Target);
        assert_eq!(param.default_value.as_deref(), Some("192.168.1.1"));
        assert!(param.required);

        let optional_param = MacroParameter::new("verbose", "Verbose output", ParameterType::Boolean)
            .optional();
        assert!(!optional_param.required);
    }

    #[test]
    fn test_scan_macro_creation() {
        let macro_ = ScanMacro::new("test-macro", "A test macro")
            .with_author("tester")
            .with_version("2.0.0")
            .with_action(MacroAction::new("scan", "connect").with_argument("10.0.0.1"))
            .with_parameter(MacroParameter::new("target", "Target", ParameterType::Target))
            .with_variable("env", "test")
            .with_tag("network")
            .with_tag("test");

        assert_eq!(macro_.name, "test-macro");
        assert_eq!(macro_.description, "A test macro");
        assert_eq!(macro_.author, "tester");
        assert_eq!(macro_.version, "2.0.0");
        assert_eq!(macro_.action_count(), 1);
        assert_eq!(macro_.parameters.len(), 1);
        assert_eq!(macro_.variables.get("env").unwrap(), "test");
        assert_eq!(macro_.tags.len(), 2);
        assert_eq!(macro_.status, MacroStatus::Ready);
    }

    #[test]
    fn test_scan_macro_add_remove_actions() {
        let mut macro_ = ScanMacro::new("test", "desc");
        assert_eq!(macro_.action_count(), 0);

        macro_.add_action(MacroAction::new("scan", "connect"));
        macro_.add_action(MacroAction::new("scan", "syn"));
        assert_eq!(macro_.action_count(), 2);

        let removed = macro_.remove_action(0);
        assert!(removed.is_some());
        assert_eq!(macro_.action_count(), 1);
        assert!(macro_.remove_action(99).is_none());
    }

    #[test]
    fn test_scan_macro_status_transitions() {
        let mut macro_ = ScanMacro::new("test", "desc");
        assert_eq!(macro_.status, MacroStatus::Ready);

        macro_.start_recording();
        assert_eq!(macro_.status, MacroStatus::Recording);

        macro_.stop_recording();
        assert_eq!(macro_.status, MacroStatus::Ready);

        macro_.mark_running();
        assert_eq!(macro_.status, MacroStatus::Running);

        macro_.mark_completed();
        assert_eq!(macro_.status, MacroStatus::Completed);
        assert_eq!(macro_.execution_count, 1);
        assert!(macro_.last_executed.is_some());

        macro_.mark_running();
        macro_.mark_failed();
        assert_eq!(macro_.status, MacroStatus::Failed);
        assert_eq!(macro_.execution_count, 2);
    }

    #[test]
    fn test_scan_macro_is_ready() {
        let mut macro_ = ScanMacro::new("test", "desc");
        assert!(!macro_.is_ready()); // no actions

        macro_.add_action(MacroAction::new("scan", "connect"));
        assert!(macro_.is_ready());

        macro_.start_recording();
        assert!(!macro_.is_ready()); // recording status
    }

    #[test]
    fn test_scan_macro_resolve_parameters() {
        let macro_ = ScanMacro::new("test", "desc")
            .with_parameter(
                MacroParameter::new("target", "Target", ParameterType::Target)
                    .with_default("10.0.0.1"),
            )
            .with_parameter(
                MacroParameter::new("ports", "Ports", ParameterType::Port),
            )
            .with_variable("env", "production");

        // All provided
        let mut provided = HashMap::new();
        provided.insert("target".to_string(), "192.168.1.1".to_string());
        provided.insert("ports".to_string(), "80,443".to_string());
        let resolved = macro_.resolve_parameters(&provided).unwrap();
        assert_eq!(resolved.get("target").unwrap(), "192.168.1.1");
        assert_eq!(resolved.get("ports").unwrap(), "80,443");
        assert_eq!(resolved.get("env").unwrap(), "production");

        // Missing required
        let empty = HashMap::new();
        let result = macro_.resolve_parameters(&empty);
        assert!(result.is_err());

        // Using defaults
        let mut partial = HashMap::new();
        partial.insert("ports".to_string(), "22".to_string());
        let resolved = macro_.resolve_parameters(&partial).unwrap();
        assert_eq!(resolved.get("target").unwrap(), "10.0.0.1");
    }

    #[test]
    fn test_scan_macro_execute_with_params() {
        let mut macro_ = ScanMacro::new("test", "desc")
            .with_parameter(
                MacroParameter::new("target", "Target", ParameterType::Target),
            )
            .with_action(
                MacroAction::new("scan", "connect")
                    .with_argument("{{target}}")
                    .with_argument("80"),
            );

        let mut params = HashMap::new();
        params.insert("target".to_string(), "10.0.0.1".to_string());

        let actions = macro_.execute_with_params(&params).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].arguments[0], "10.0.0.1");
        assert_eq!(macro_.status, MacroStatus::Completed);
    }

    #[test]
    fn test_macro_recorder() {
        let mut recorder = MacroRecorder::new("test-macro", "Test recording");
        assert!(recorder.is_recording());
        assert_eq!(recorder.action_count(), 0);

        recorder.record_scan("192.168.1.0/24", "1-1024", "syn");
        recorder.record_wait(1000);
        recorder.record_set_variable("env", "test");
        assert_eq!(recorder.action_count(), 3);

        let macro_ = recorder.finish();
        assert!(!recorder.is_recording());
        assert_eq!(macro_.action_count(), 3);
        assert_eq!(macro_.status, MacroStatus::Ready);
    }

    #[test]
    fn test_macro_library_register_and_get() {
        let mut lib = MacroLibrary::new();
        assert!(lib.is_empty());

        let macro_ = ScanMacro::new("test", "desc");
        let id = macro_.id.clone();

        lib.register(macro_);
        assert_eq!(lib.len(), 1);
        assert!(lib.get(&id).is_some());
        assert!(lib.get("nonexistent").is_none());
        assert!(lib.get_by_name("test").is_some());
        assert!(lib.get_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_macro_library_remove() {
        let mut lib = MacroLibrary::new();
        let macro_ = ScanMacro::new("test", "desc");
        let id = macro_.id.clone();

        lib.register(macro_);
        assert!(lib.remove(&id).is_some());
        assert!(lib.is_empty());
        assert!(lib.remove("nonexistent").is_none());
    }

    #[test]
    fn test_macro_library_search_by_tag() {
        let mut lib = MacroLibrary::new();
        lib.register(ScanMacro::new("m1", "desc").with_tag("network"));
        lib.register(ScanMacro::new("m2", "desc").with_tag("web"));
        lib.register(ScanMacro::new("m3", "desc").with_tag("network").with_tag("quick"));

        let network = lib.search_by_tag("network");
        assert_eq!(network.len(), 2);

        let web = lib.search_by_tag("web");
        assert_eq!(web.len(), 1);

        let nonexistent = lib.search_by_tag("nonexistent");
        assert_eq!(nonexistent.len(), 0);
    }

    #[test]
    fn test_macro_library_defaults() {
        let lib = MacroLibrary::with_defaults();
        assert!(lib.len() >= 3);
        assert!(lib.get_by_name("quick-network-scan").is_some());
        assert!(lib.get_by_name("web-server-audit").is_some());
        assert!(lib.get_by_name("stealth-recon").is_some());
    }

    #[test]
    fn test_macro_library_export_import() {
        let mut lib = MacroLibrary::new();
        let macro_ = ScanMacro::new("export-test", "desc")
            .with_action(MacroAction::new("scan", "connect").with_argument("10.0.0.1"));
        let id = lib.register(macro_);

        let json = lib.export_macro(&id).unwrap();
        assert!(json.contains("export-test"));

        let imported_id = lib.import_macro(&json).unwrap();
        assert_ne!(imported_id, id); // new ID assigned
        let imported = lib.get(&imported_id).unwrap();
        assert_eq!(imported.action_count(), 1);
    }

    #[test]
    fn test_macro_library_import_invalid_json() {
        let mut lib = MacroLibrary::new();
        let result = lib.import_macro("not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn test_macro_status_display() {
        assert_eq!(MacroStatus::Recording.to_string(), "recording");
        assert_eq!(MacroStatus::Ready.to_string(), "ready");
        assert_eq!(MacroStatus::Running.to_string(), "running");
        assert_eq!(MacroStatus::Completed.to_string(), "completed");
        assert_eq!(MacroStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_parameter_type_display() {
        assert_eq!(ParameterType::String.to_string(), "string");
        assert_eq!(ParameterType::Number.to_string(), "number");
        assert_eq!(ParameterType::Boolean.to_string(), "boolean");
        assert_eq!(ParameterType::Target.to_string(), "target");
        assert_eq!(ParameterType::Port.to_string(), "port");
        assert_eq!(ParameterType::ScanType.to_string(), "scan_type");
    }

    #[test]
    fn test_macro_builder() {
        let macro_ = MacroBuilder::new("builder-test", "Built macro")
            .author("builder")
            .version("2.0.0")
            .action(MacroAction::new("scan", "connect").with_argument("10.0.0.1"))
            .action(MacroAction::new("wait", "delay").with_delay(500))
            .parameter(MacroParameter::new("target", "Target", ParameterType::Target))
            .variable("env", "test")
            .tag("custom")
            .build();

        assert_eq!(macro_.name, "builder-test");
        assert_eq!(macro_.author, "builder");
        assert_eq!(macro_.version, "2.0.0");
        assert_eq!(macro_.action_count(), 2);
        assert_eq!(macro_.parameters.len(), 1);
        assert_eq!(macro_.variables.get("env").unwrap(), "test");
        assert!(macro_.tags.contains(&"custom".to_string()));
    }

    #[test]
    fn test_macro_serialization() {
        let macro_ = MacroBuilder::new("serde-test", "Serialization test")
            .author("tester")
            .action(MacroAction::new("scan", "connect").with_argument("10.0.0.1"))
            .parameter(MacroParameter::new("target", "Target", ParameterType::Target))
            .tag("test")
            .build();

        let json = serde_json::to_string(&macro_).unwrap();
        let loaded: ScanMacro = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "serde-test");
        assert_eq!(loaded.author, "tester");
        assert_eq!(loaded.action_count(), 1);
        assert_eq!(loaded.parameters.len(), 1);
    }

    #[test]
    fn test_macro_library_serialization() {
        let lib = MacroLibrary::with_defaults();
        let json = serde_json::to_string(&lib).unwrap();
        let loaded: MacroLibrary = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.len(), lib.len());
    }

    #[test]
    fn test_macro_action_with_arguments_vec() {
        let action = MacroAction::new("scan", "connect")
            .with_arguments(vec!["10.0.0.1".to_string(), "80,443".to_string()]);
        assert_eq!(action.arguments.len(), 2);
    }

    #[test]
    fn test_macro_parameter_required_optional() {
        let required = MacroParameter::new("target", "Target", ParameterType::Target);
        assert!(required.required);

        let optional = MacroParameter::new("verbose", "Verbose", ParameterType::Boolean).optional();
        assert!(!optional.required);
    }
}
