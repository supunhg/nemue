use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::scanner::scan_types::ScanType;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TemplateCategory {
    Quick,
    Stealth,
    Comprehensive,
    Custom,
}

impl std::fmt::Display for TemplateCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateCategory::Quick => write!(f, "quick"),
            TemplateCategory::Stealth => write!(f, "stealth"),
            TemplateCategory::Comprehensive => write!(f, "comprehensive"),
            TemplateCategory::Custom => write!(f, "custom"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTemplate {
    pub name: String,
    pub description: String,
    pub category: TemplateCategory,
    pub scan_type: String,
    pub timing: String,
    pub ports: String,
    pub version_detect: bool,
    pub os_detect: bool,
    pub scripts: Vec<String>,
    pub extra_args: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl ScanTemplate {
    pub fn new(name: &str, description: &str, category: TemplateCategory) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            category,
            scan_type: "connect".to_string(),
            timing: "T3".to_string(),
            ports: "1-1024".to_string(),
            version_detect: false,
            os_detect: false,
            scripts: Vec::new(),
            extra_args: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_scan_type(mut self, scan_type: &str) -> Self {
        self.scan_type = scan_type.to_string();
        self
    }

    pub fn with_timing(mut self, timing: &str) -> Self {
        self.timing = timing.to_string();
        self
    }

    pub fn with_ports(mut self, ports: &str) -> Self {
        self.ports = ports.to_string();
        self
    }

    pub fn with_version_detect(mut self, enable: bool) -> Self {
        self.version_detect = enable;
        self
    }

    pub fn with_os_detect(mut self, enable: bool) -> Self {
        self.os_detect = enable;
        self
    }

    pub fn with_script(mut self, script: &str) -> Self {
        self.scripts.push(script.to_string());
        self
    }

    pub fn with_extra_arg(mut self, arg: &str) -> Self {
        self.extra_args.push(arg.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn scan_type_enum(&self) -> Option<ScanType> {
        ScanType::from_nmap_flag(&self.scan_type).or_else(|| {
            match self.scan_type.to_lowercase().as_str() {
                "connect" => Some(ScanType::Connect),
                "syn" => Some(ScanType::Syn),
                "udp" => Some(ScanType::Udp),
                _ => None,
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateLibrary {
    templates: HashMap<String, ScanTemplate>,
}

impl TemplateLibrary {
    pub fn new() -> Self {
        Self {
            templates: HashMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        let mut lib = Self::new();
        lib.register_defaults();
        lib
    }

    pub fn register(&mut self, template: ScanTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    pub fn get(&self, name: &str) -> Option<&ScanTemplate> {
        self.templates.get(name)
    }

    pub fn list(&self) -> Vec<&ScanTemplate> {
        self.templates.values().collect()
    }

    pub fn list_by_category(&self, category: &TemplateCategory) -> Vec<&ScanTemplate> {
        self.templates
            .values()
            .filter(|t| &t.category == category)
            .collect()
    }

    pub fn names(&self) -> Vec<&str> {
        self.templates.keys().map(|s| s.as_str()).collect()
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    pub fn remove(&mut self, name: &str) -> Option<ScanTemplate> {
        self.templates.remove(name)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.templates.contains_key(name)
    }

    fn register_defaults(&mut self) {
        self.register(
            ScanTemplate::new(
                "quick",
                "Fast scan of the most common 100 ports",
                TemplateCategory::Quick,
            )
            .with_scan_type("connect")
            .with_timing("T4")
            .with_ports("top-100"),
        );

        self.register(
            ScanTemplate::new(
                "quick-full",
                "Fast scan of top 1000 ports",
                TemplateCategory::Quick,
            )
            .with_scan_type("connect")
            .with_timing("T4")
            .with_ports("top-1000"),
        );

        self.register(
            ScanTemplate::new(
                "quick-all",
                "Fast scan of all 65535 ports",
                TemplateCategory::Quick,
            )
            .with_scan_type("syn")
            .with_timing("T5")
            .with_ports("1-65535"),
        );

        self.register(
            ScanTemplate::new(
                "stealth",
                "Slow SYN scan to avoid detection",
                TemplateCategory::Stealth,
            )
            .with_scan_type("syn")
            .with_timing("T1")
            .with_ports("1-1024")
            .with_extra_arg("--spoof-mac")
            .with_extra_arg("0"),
        );

        self.register(
            ScanTemplate::new(
                "stealth-fin",
                "FIN scan bypassing some firewalls",
                TemplateCategory::Stealth,
            )
            .with_scan_type("-sF")
            .with_timing("T2")
            .with_ports("1-1024"),
        );

        self.register(
            ScanTemplate::new(
                "stealth-null",
                "NULL scan for minimal fingerprint",
                TemplateCategory::Stealth,
            )
            .with_scan_type("-sN")
            .with_timing("T1")
            .with_ports("1-1024"),
        );

        self.register(
            ScanTemplate::new(
                "stealth-idle",
                "Idle scan using zombie host",
                TemplateCategory::Stealth,
            )
            .with_scan_type("syn")
            .with_timing("T1")
            .with_ports("1-1024")
            .with_extra_arg("-sI")
            .with_metadata("requires", "zombie-host"),
        );

        self.register(
            ScanTemplate::new(
                "comprehensive",
                "Full scan with version detection and scripts",
                TemplateCategory::Comprehensive,
            )
            .with_scan_type("syn")
            .with_timing("T3")
            .with_ports("1-65535")
            .with_version_detect(true)
            .with_os_detect(true)
            .with_script("default")
            .with_script("vuln"),
        );

        self.register(
            ScanTemplate::new(
                "comprehensive-web",
                "Web server scan with HTTP scripts",
                TemplateCategory::Comprehensive,
            )
            .with_scan_type("connect")
            .with_timing("T3")
            .with_ports("80,443,8080,8443,8000,3000,5000,9000")
            .with_version_detect(true)
            .with_script("http-enum")
            .with_script("http-title")
            .with_script("http-headers"),
        );

        self.register(
            ScanTemplate::new(
                "comprehensive-db",
                "Database service scan",
                TemplateCategory::Comprehensive,
            )
            .with_scan_type("connect")
            .with_timing("T3")
            .with_ports("1433,1521,3306,5432,6379,27017,9200,11211")
            .with_version_detect(true),
        );

        self.register(
            ScanTemplate::new(
                "comprehensive-mail",
                "Mail server scan",
                TemplateCategory::Comprehensive,
            )
            .with_scan_type("connect")
            .with_timing("T3")
            .with_ports("25,110,143,465,587,993,995")
            .with_version_detect(true)
            .with_script("smtp-enum-users"),
        );
    }
}

impl Default for TemplateLibrary {
    fn default() -> Self {
        Self::with_defaults()
    }
}

pub struct TemplateBuilder {
    template: ScanTemplate,
}

impl TemplateBuilder {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            template: ScanTemplate::new(name, description, TemplateCategory::Custom),
        }
    }

    pub fn scan_type(mut self, scan_type: &str) -> Self {
        self.template.scan_type = scan_type.to_string();
        self
    }

    pub fn timing(mut self, timing: &str) -> Self {
        self.template.timing = timing.to_string();
        self
    }

    pub fn ports(mut self, ports: &str) -> Self {
        self.template.ports = ports.to_string();
        self
    }

    pub fn version_detect(mut self, enable: bool) -> Self {
        self.template.version_detect = enable;
        self
    }

    pub fn os_detect(mut self, enable: bool) -> Self {
        self.template.os_detect = enable;
        self
    }

    pub fn script(mut self, script: &str) -> Self {
        self.template.scripts.push(script.to_string());
        self
    }

    pub fn extra_arg(mut self, arg: &str) -> Self {
        self.template.extra_args.push(arg.to_string());
        self
    }

    pub fn metadata(mut self, key: &str, value: &str) -> Self {
        self.template
            .metadata
            .insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> ScanTemplate {
        self.template
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_creation() {
        let tmpl = ScanTemplate::new("test", "A test template", TemplateCategory::Quick)
            .with_scan_type("syn")
            .with_timing("T4")
            .with_ports("top-100")
            .with_version_detect(true);

        assert_eq!(tmpl.name, "test");
        assert_eq!(tmpl.description, "A test template");
        assert_eq!(tmpl.category, TemplateCategory::Quick);
        assert_eq!(tmpl.scan_type, "syn");
        assert_eq!(tmpl.timing, "T4");
        assert_eq!(tmpl.ports, "top-100");
        assert!(tmpl.version_detect);
        assert!(!tmpl.os_detect);
    }

    #[test]
    fn test_template_builder() {
        let tmpl = TemplateBuilder::new("custom-web", "Custom web scan")
            .scan_type("connect")
            .timing("T3")
            .ports("80,443,8080")
            .version_detect(true)
            .script("http-title")
            .extra_arg("--open")
            .metadata("author", "tester")
            .build();

        assert_eq!(tmpl.name, "custom-web");
        assert_eq!(tmpl.category, TemplateCategory::Custom);
        assert_eq!(tmpl.ports, "80,443,8080");
        assert!(tmpl.version_detect);
        assert_eq!(tmpl.scripts, vec!["http-title"]);
        assert_eq!(tmpl.extra_args, vec!["--open"]);
        assert_eq!(tmpl.metadata.get("author").unwrap(), "tester");
    }

    #[test]
    fn test_template_scan_type_enum() {
        let tmpl = ScanTemplate::new("t", "d", TemplateCategory::Quick).with_scan_type("connect");
        assert_eq!(tmpl.scan_type_enum(), Some(ScanType::Connect));

        let tmpl_syn = ScanTemplate::new("t", "d", TemplateCategory::Quick).with_scan_type("syn");
        assert_eq!(tmpl_syn.scan_type_enum(), Some(ScanType::Syn));

        let tmpl_flag =
            ScanTemplate::new("t", "d", TemplateCategory::Stealth).with_scan_type("-sF");
        assert_eq!(tmpl_flag.scan_type_enum(), Some(ScanType::Fin));
    }

    #[test]
    fn test_template_library_defaults() {
        let lib = TemplateLibrary::with_defaults();
        assert!(lib.len() >= 10);
        assert!(lib.contains("quick"));
        assert!(lib.contains("stealth"));
        assert!(lib.contains("comprehensive"));
        assert!(lib.contains("quick-full"));
        assert!(lib.contains("quick-all"));
        assert!(lib.contains("stealth-fin"));
        assert!(lib.contains("stealth-null"));
        assert!(lib.contains("stealth-idle"));
        assert!(lib.contains("comprehensive-web"));
        assert!(lib.contains("comprehensive-db"));
        assert!(lib.contains("comprehensive-mail"));
    }

    #[test]
    fn test_template_library_get() {
        let lib = TemplateLibrary::with_defaults();
        let quick = lib.get("quick").unwrap();
        assert_eq!(quick.name, "quick");
        assert_eq!(quick.category, TemplateCategory::Quick);
        assert_eq!(quick.timing, "T4");
        assert!(lib.get("nonexistent").is_none());
    }

    #[test]
    fn test_template_library_list_by_category() {
        let lib = TemplateLibrary::with_defaults();
        let quick = lib.list_by_category(&TemplateCategory::Quick);
        assert!(!quick.is_empty());
        for tmpl in &quick {
            assert_eq!(tmpl.category, TemplateCategory::Quick);
        }

        let stealth = lib.list_by_category(&TemplateCategory::Stealth);
        assert!(!stealth.is_empty());
        for tmpl in &stealth {
            assert_eq!(tmpl.category, TemplateCategory::Stealth);
        }
    }

    #[test]
    fn test_template_library_register_remove() {
        let mut lib = TemplateLibrary::new();
        assert!(lib.is_empty());

        let tmpl = ScanTemplate::new("my-scan", "desc", TemplateCategory::Custom);
        lib.register(tmpl);
        assert_eq!(lib.len(), 1);
        assert!(lib.contains("my-scan"));

        let removed = lib.remove("my-scan");
        assert!(removed.is_some());
        assert!(lib.is_empty());
        assert!(lib.remove("nonexistent").is_none());
    }

    #[test]
    fn test_template_library_names() {
        let lib = TemplateLibrary::with_defaults();
        let names = lib.names();
        assert!(names.contains(&"quick"));
        assert!(names.contains(&"stealth"));
    }

    #[test]
    fn test_template_with_scripts() {
        let tmpl = ScanTemplate::new("t", "d", TemplateCategory::Comprehensive)
            .with_script("default")
            .with_script("vuln")
            .with_script("http-enum");

        assert_eq!(tmpl.scripts.len(), 3);
        assert_eq!(tmpl.scripts[0], "default");
        assert_eq!(tmpl.scripts[2], "http-enum");
    }

    #[test]
    fn test_template_with_metadata() {
        let tmpl = ScanTemplate::new("t", "d", TemplateCategory::Custom)
            .with_metadata("key1", "val1")
            .with_metadata("key2", "val2");

        assert_eq!(tmpl.metadata.get("key1").unwrap(), "val1");
        assert_eq!(tmpl.metadata.get("key2").unwrap(), "val2");
    }

    #[test]
    fn test_template_category_display() {
        assert_eq!(TemplateCategory::Quick.to_string(), "quick");
        assert_eq!(TemplateCategory::Stealth.to_string(), "stealth");
        assert_eq!(TemplateCategory::Comprehensive.to_string(), "comprehensive");
        assert_eq!(TemplateCategory::Custom.to_string(), "custom");
    }

    #[test]
    fn test_template_serialization_roundtrip() {
        let tmpl = TemplateBuilder::new("serde-test", "Serialization test")
            .scan_type("syn")
            .timing("T4")
            .ports("80,443")
            .version_detect(true)
            .script("default")
            .metadata("env", "test")
            .build();

        let json = serde_json::to_string(&tmpl).unwrap();
        let loaded: ScanTemplate = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "serde-test");
        assert_eq!(loaded.scan_type, "syn");
        assert_eq!(loaded.timing, "T4");
        assert_eq!(loaded.ports, "80,443");
        assert!(loaded.version_detect);
        assert_eq!(loaded.scripts, vec!["default"]);
        assert_eq!(loaded.metadata.get("env").unwrap(), "test");
    }

    #[test]
    fn test_template_library_serialization() {
        let lib = TemplateLibrary::with_defaults();
        let json = serde_json::to_string(&lib).unwrap();
        let loaded: TemplateLibrary = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.len(), lib.len());
        assert!(loaded.contains("quick"));
        assert!(loaded.contains("comprehensive"));
    }

    #[test]
    fn test_quick_templates_have_fast_timing() {
        let lib = TemplateLibrary::with_defaults();
        for tmpl in lib.list_by_category(&TemplateCategory::Quick) {
            assert!(
                tmpl.timing == "T4" || tmpl.timing == "T5",
                "Quick template '{}' should have fast timing, got {}",
                tmpl.name,
                tmpl.timing
            );
        }
    }

    #[test]
    fn test_stealth_templates_have_slow_timing() {
        let lib = TemplateLibrary::with_defaults();
        for tmpl in lib.list_by_category(&TemplateCategory::Stealth) {
            assert!(
                tmpl.timing == "T1" || tmpl.timing == "T2",
                "Stealth template '{}' should have slow timing, got {}",
                tmpl.name,
                tmpl.timing
            );
        }
    }

    #[test]
    fn test_comprehensive_templates_have_version_detect() {
        let lib = TemplateLibrary::with_defaults();
        for tmpl in lib.list_by_category(&TemplateCategory::Comprehensive) {
            assert!(
                tmpl.version_detect,
                "Comprehensive template '{}' should enable version detection",
                tmpl.name
            );
        }
    }
}
