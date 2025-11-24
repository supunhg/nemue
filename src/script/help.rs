// Script Help Documentation Viewer
// Implements --script-help functionality

use anyhow::{anyhow, Result};
use std::path::Path;
use std::fs;

/// Script documentation
#[derive(Debug, Clone)]
pub struct ScriptHelp {
    pub name: String,
    pub description: String,
    pub author: String,
    pub categories: Vec<String>,
    pub usage: Option<String>,
    pub arguments: Vec<ScriptArgument>,
    pub examples: Vec<String>,
    pub output: Option<String>,
}

/// Script argument documentation
#[derive(Debug, Clone)]
pub struct ScriptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub default_value: Option<String>,
}

impl ScriptHelp {
    /// Parse help documentation from script file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow!("Failed to read script file: {}", e))?;

        Self::from_content(&content, path.as_ref().file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown"))
    }

    /// Parse help from script content
    pub fn from_content(content: &str, default_name: &str) -> Result<Self> {
        let mut name = default_name.to_string();
        let mut description = String::new();
        let mut author = String::new();
        let mut categories = Vec::new();
        let mut usage = None;
        let mut arguments = Vec::new();
        let mut examples = Vec::new();
        let mut output = None;

        // Parse Lua script for metadata and documentation
        for line in content.lines() {
            let line = line.trim();

            // Parse global assignments
            if line.starts_with("name") && line.contains('=') {
                name = Self::extract_string(line);
            } else if line.starts_with("description") && line.contains('=') {
                description = Self::extract_string(line);
            } else if line.starts_with("author") && line.contains('=') {
                author = Self::extract_string(line);
            } else if line.starts_with("categories") && line.contains('=') {
                categories = Self::extract_array(line);
            }

            // Parse documentation comments
            if line.starts_with("--@usage") {
                usage = Some(line.trim_start_matches("--@usage").trim().to_string());
            } else if line.starts_with("--@arg") {
                if let Some(arg) = Self::parse_arg_doc(line) {
                    arguments.push(arg);
                }
            } else if line.starts_with("--@example") {
                examples.push(line.trim_start_matches("--@example").trim().to_string());
            } else if line.starts_with("--@output") {
                output = Some(line.trim_start_matches("--@output").trim().to_string());
            }
        }

        Ok(Self {
            name,
            description,
            author,
            categories,
            usage,
            arguments,
            examples,
            output,
        })
    }

    /// Extract string from Lua assignment
    fn extract_string(line: &str) -> String {
        if let Some(eq_pos) = line.find('=') {
            line[eq_pos + 1..]
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string()
        } else {
            String::new()
        }
    }

    /// Extract array from Lua table
    fn extract_array(line: &str) -> Vec<String> {
        if let Some(start) = line.find('{') {
            if let Some(end) = line.find('}') {
                return line[start + 1..end]
                    .split(',')
                    .map(|s| s.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        Vec::new()
    }

    /// Parse argument documentation comment
    /// Format: --@arg name [required|optional] [default=value] Description
    fn parse_arg_doc(line: &str) -> Option<ScriptArgument> {
        let content = line.trim_start_matches("--@arg").trim();
        let parts: Vec<&str> = content.splitn(2, ' ').collect();
        
        if parts.is_empty() {
            return None;
        }

        let name = parts[0].to_string();
        let rest = if parts.len() > 1 { parts[1] } else { "" };

        let required = rest.contains("required");
        
        // Extract default value and remove it from description parsing
        let (default_value, description_text) = if let Some(start) = rest.find("default=") {
            let start = start + 8;
            let after_default = &rest[start..];
            
            // Find end of default value (whitespace or end of string)
            let end = after_default.find(|c: char| c.is_whitespace())
                .unwrap_or(after_default.len());
            
            let default = after_default[..end].to_string();
            let remaining = if end < after_default.len() {
                &after_default[end..]
            } else {
                ""
            };
            
            (Some(default), remaining.trim())
        } else {
            (None, rest)
        };

        // Extract description (everything after modifiers)
        let description = description_text
            .replace("required", "")
            .replace("optional", "")
            .trim()
            .to_string();

        Some(ScriptArgument {
            name,
            description,
            required,
            default_value,
        })
    }

    /// Display help to console
    pub fn display(&self) {
        println!("\n{}", "=".repeat(70));
        println!("Script: {}", self.name);
        println!("{}", "=".repeat(70));
        
        if !self.description.is_empty() {
            println!("\nDescription:");
            println!("  {}", self.description);
        }

        if !self.author.is_empty() {
            println!("\nAuthor: {}", self.author);
        }

        if !self.categories.is_empty() {
            println!("Categories: {}", self.categories.join(", "));
        }

        if let Some(ref usage) = self.usage {
            println!("\nUsage:");
            println!("  {}", usage);
        }

        if !self.arguments.is_empty() {
            println!("\nArguments:");
            for arg in &self.arguments {
                let req = if arg.required { "[required]" } else { "[optional]" };
                let default = if let Some(ref d) = arg.default_value {
                    format!(" (default: {})", d)
                } else {
                    String::new()
                };
                println!("  {}{} {} - {}", arg.name, default, req, arg.description);
            }
        }

        if !self.examples.is_empty() {
            println!("\nExamples:");
            for example in &self.examples {
                println!("  {}", example);
            }
        }

        if let Some(ref output_desc) = self.output {
            println!("\nOutput:");
            println!("  {}", output_desc);
        }

        println!("{}\n", "=".repeat(70));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_script() {
        let content = r#"
name = "test-script"
description = "A test script"
author = "Test Author"
categories = {"test", "demo"}

function action(args)
    return "OK"
end
"#;

        let help = ScriptHelp::from_content(content, "test").unwrap();
        assert_eq!(help.name, "test-script");
        assert_eq!(help.description, "A test script");
        assert_eq!(help.author, "Test Author");
        assert_eq!(help.categories, vec!["test", "demo"]);
    }

    #[test]
    fn test_parse_with_documentation() {
        let content = r#"
name = "http-check"
description = "Checks HTTP service"
author = "Nemue"
categories = {"http"}

--@usage nemue --script http-check --script-args url=http://example.com
--@arg url required The URL to check
--@arg timeout optional default=30 Request timeout in seconds
--@example nemue scan 192.168.1.1 --script http-check --script-args url=http://192.168.1.1
--@output Returns HTTP status code and headers

function action(args)
    return {output = "OK"}
end
"#;

        let help = ScriptHelp::from_content(content, "http-check").unwrap();
        assert_eq!(help.name, "http-check");
        assert!(help.usage.is_some());
        assert_eq!(help.arguments.len(), 2);
        assert_eq!(help.examples.len(), 1);
        assert!(help.output.is_some());

        // Check first argument
        let url_arg = &help.arguments[0];
        assert_eq!(url_arg.name, "url");
        assert!(url_arg.required);
        assert!(url_arg.default_value.is_none());

        // Check second argument
        let timeout_arg = &help.arguments[1];
        assert_eq!(timeout_arg.name, "timeout");
        assert!(!timeout_arg.required);
        assert_eq!(timeout_arg.default_value, Some("30".to_string()));
    }

    #[test]
    fn test_extract_string() {
        let result = ScriptHelp::extract_string(r#"name = "test""#);
        assert_eq!(result, "test");

        let result2 = ScriptHelp::extract_string("author = 'John Doe'");
        assert_eq!(result2, "John Doe");
    }

    #[test]
    fn test_extract_array() {
        let result = ScriptHelp::extract_array(r#"categories = {"a", "b", "c"}"#);
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_arg_doc_required() {
        let arg = ScriptHelp::parse_arg_doc("--@arg username required The username to use").unwrap();
        assert_eq!(arg.name, "username");
        assert!(arg.required);
        assert!(arg.default_value.is_none());
        assert_eq!(arg.description, "The username to use");
    }

    #[test]
    fn test_parse_arg_doc_optional_with_default() {
        let arg = ScriptHelp::parse_arg_doc("--@arg port optional default=80 The port number").unwrap();
        assert_eq!(arg.name, "port");
        assert!(!arg.required);
        assert_eq!(arg.default_value, Some("80".to_string()));
        // Description should have the text after all modifiers
        assert!(!arg.description.is_empty());
    }

    #[test]
    fn test_display_doesnt_panic() {
        let help = ScriptHelp {
            name: "test".to_string(),
            description: "Test script".to_string(),
            author: "Test".to_string(),
            categories: vec!["test".to_string()],
            usage: Some("nemue --script test".to_string()),
            arguments: vec![
                ScriptArgument {
                    name: "arg1".to_string(),
                    description: "First argument".to_string(),
                    required: true,
                    default_value: None,
                },
            ],
            examples: vec!["nemue --script test --script-args arg1=value".to_string()],
            output: Some("Returns test result".to_string()),
        };

        // Just ensure display doesn't panic
        help.display();
    }
}
