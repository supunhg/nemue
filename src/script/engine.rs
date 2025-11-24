use anyhow::{anyhow, Result};
use mlua::{Lua, Table, Value};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub name: String,
    pub description: String,
    pub author: String,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub script_name: String,
    pub target: IpAddr,
    pub port: Option<u16>,
    pub output: String,
    pub vulnerability: Option<String>,
    pub severity: Option<String>, // low, medium, high, critical
}

pub struct ScriptEngine {
    lua: Lua,
}

impl ScriptEngine {
    pub fn new() -> Result<Self> {
        let lua = Lua::new();
        
        // Register custom functions for scripts
        Self::register_globals(&lua)?;
        
        Ok(Self { lua })
    }

    fn register_globals(lua: &Lua) -> Result<()> {
        let globals = lua.globals();
        
        // Create a table for Nemue-specific functions
        let nemue = lua.create_table()?;
        
        // Add version info
        nemue.set("version", "0.1.0")?;
        
        // Register logging functions
        let log_fn = lua.create_function(|_, msg: String| {
            println!("[Script] {}", msg);
            Ok(())
        })?;
        nemue.set("log", log_fn)?;
        
        globals.set("nemue", nemue)?;
        
        Ok(())
    }

    /// Load a script from a file
    pub fn load_script(&self, path: &Path) -> Result<()> {
        let script = std::fs::read_to_string(path)?;
        self.lua.load(&script).exec()?;
        Ok(())
    }

    /// Load a script from a string
    pub fn load_script_string(&self, script: &str) -> Result<()> {
        self.lua.load(script).exec()?;
        Ok(())
    }

    /// Get script metadata
    pub fn get_script_info(&self) -> Result<ScriptInfo> {
        let globals = self.lua.globals();
        
        let name = globals.get::<_, String>("name")
            .unwrap_or_else(|_| "Unknown".to_string());
        let description = globals.get::<_, String>("description")
            .unwrap_or_else(|_| "No description".to_string());
        let author = globals.get::<_, String>("author")
            .unwrap_or_else(|_| "Unknown".to_string());
        let categories = globals.get::<_, Vec<String>>("categories")
            .unwrap_or_else(|_| vec![]);
        
        Ok(ScriptInfo {
            name,
            description,
            author,
            categories,
        })
    }

    /// Execute the script's main action
    pub async fn execute(&self, target: IpAddr, port: Option<u16>) -> Result<ScriptResult> {
        let globals = self.lua.globals();
        
        // Get the action function
        let action: mlua::Function = globals.get("action")
            .map_err(|_| anyhow!("Script must define an 'action' function"))?;
        
        // Create arguments table
        let args = self.lua.create_table()?;
        args.set("target", target.to_string())?;
        if let Some(p) = port {
            args.set("port", p)?;
        }
        
        // Call the action function
        let result: Value = action.call(args)?;
        
        // Parse result
        let output = match result {
            Value::Table(t) => {
                let output = t.get::<_, String>("output")
                    .unwrap_or_else(|_| "No output".to_string());
                let vulnerability = t.get::<_, Option<String>>("vulnerability")
                    .unwrap_or(None);
                let severity = t.get::<_, Option<String>>("severity")
                    .unwrap_or(None);
                
                ScriptResult {
                    script_name: self.get_script_info()?.name,
                    target,
                    port,
                    output,
                    vulnerability,
                    severity,
                }
            }
            Value::String(s) => {
                ScriptResult {
                    script_name: self.get_script_info()?.name,
                    target,
                    port,
                    output: s.to_str()?.to_string(),
                    vulnerability: None,
                    severity: None,
                }
            }
            _ => {
                return Err(anyhow!("Script action must return a table or string"));
            }
        };
        
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_engine_creation() {
        let engine = ScriptEngine::new();
        assert!(engine.is_ok());
    }

    #[test]
    fn test_load_simple_script() {
        let engine = ScriptEngine::new().unwrap();
        let script = r#"
            name = "test-script"
            description = "A test script"
            author = "Nemue Team"
            categories = {"test"}
            
            function action(args)
                return {
                    output = "Test output",
                    vulnerability = nil,
                    severity = nil
                }
            end
        "#;
        
        let result = engine.load_script_string(script);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_script_info() {
        let engine = ScriptEngine::new().unwrap();
        let script = r#"
            name = "http-vuln-check"
            description = "Checks for HTTP vulnerabilities"
            author = "Nemue Team"
            categories = {"http", "vuln"}
            
            function action(args)
                return "OK"
            end
        "#;
        
        engine.load_script_string(script).unwrap();
        let info = engine.get_script_info().unwrap();
        
        assert_eq!(info.name, "http-vuln-check");
        assert_eq!(info.description, "Checks for HTTP vulnerabilities");
        assert_eq!(info.author, "Nemue Team");
        assert_eq!(info.categories, vec!["http", "vuln"]);
    }

    #[tokio::test]
    async fn test_execute_script() {
        let engine = ScriptEngine::new().unwrap();
        let script = r#"
            name = "port-test"
            description = "Tests a port"
            author = "Test"
            categories = {"test"}
            
            function action(args)
                return {
                    output = "Port " .. args.port .. " tested on " .. args.target,
                    vulnerability = nil,
                    severity = nil
                }
            end
        "#;
        
        engine.load_script_string(script).unwrap();
        let result = engine.execute("192.168.1.1".parse().unwrap(), Some(80)).await;
        
        assert!(result.is_ok());
        let script_result = result.unwrap();
        assert!(script_result.output.contains("192.168.1.1"));
        assert!(script_result.output.contains("80"));
    }

    #[tokio::test]
    async fn test_vulnerability_detection() {
        let engine = ScriptEngine::new().unwrap();
        let script = r#"
            name = "vuln-detector"
            description = "Detects vulnerabilities"
            author = "Test"
            categories = {"vuln"}
            
            function action(args)
                return {
                    output = "Vulnerability found!",
                    vulnerability = "CVE-2024-1234",
                    severity = "high"
                }
            end
        "#;
        
        engine.load_script_string(script).unwrap();
        let result = engine.execute("192.168.1.1".parse().unwrap(), Some(443)).await.unwrap();
        
        assert_eq!(result.vulnerability, Some("CVE-2024-1234".to_string()));
        assert_eq!(result.severity, Some("high".to_string()));
    }
}
