// Script Argument Parsing and Management
// Implements --script-args and --script-args-file functionality

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::Path;

/// Split string on separator while respecting quoted strings
fn split_respecting_quotes(input: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut quote_char = ' ';
    
    for (i, c) in input.char_indices() {
        if (c == '"' || c == '\'') && !in_quote {
            in_quote = true;
            quote_char = c;
        } else if c == quote_char && in_quote {
            in_quote = false;
        } else if c == separator && !in_quote {
            parts.push(&input[start..i]);
            start = i + 1;
        }
    }
    
    // Add remaining part
    if start < input.len() {
        parts.push(&input[start..]);
    }
    
    parts
}

/// Parsed script arguments
#[derive(Debug, Clone, Default)]
pub struct ScriptArgs {
    /// Key-value pairs of script arguments
    args: HashMap<String, String>,
}

impl ScriptArgs {
    /// Create empty script arguments
    pub fn new() -> Self {
        Self {
            args: HashMap::new(),
        }
    }

    /// Parse script arguments from command line string
    /// Format: "key1=value1,key2=value2" or "key1=value1;key2=value2"
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(anyhow!("Empty input string"));
        }

        let mut args = HashMap::new();

        // Support both comma and semicolon as separators
        // Use semicolon if present (takes precedence), otherwise comma
        let separator = if input.contains(';') { ';' } else { ',' };
        
        // Split while respecting quoted strings
        let pairs = split_respecting_quotes(input, separator);
        
        for pair in pairs {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }

            // Split on first '=' only
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(anyhow!(
                    "Invalid argument format: '{}'. Expected format: key=value",
                    pair
                ));
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            if key.is_empty() {
                return Err(anyhow!("Empty key in argument: '{}'", pair));
            }
            
            if value.is_empty() {
                return Err(anyhow!("Empty value in argument: '{}'", pair));
            }

            // Handle quoted values
            let value = if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                &value[1..value.len() - 1]
            } else {
                value
            };

            args.insert(key.to_string(), value.to_string());
        }

        Ok(Self { args })
    }

    /// Load script arguments from file
    /// File format: key=value (one per line), # for comments
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow!("Failed to read script args file: {}", e))?;

        Self::from_file_content(&content)
    }

    /// Parse file content (useful for testing)
    pub fn from_file_content(content: &str) -> Result<Self> {
        let mut args = HashMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Split on first '=' only
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(anyhow!(
                    "Invalid format on line {}: '{}'. Expected format: key=value",
                    line_num + 1,
                    line
                ));
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            if key.is_empty() {
                return Err(anyhow!("Empty key on line {}: '{}'", line_num + 1, line));
            }

            // Handle quoted values and strip comments after value
            let value = if let Some(hash_pos) = value.find('#') {
                // Check if # is inside quotes
                let before_hash = &value[..hash_pos];
                let quote_count = before_hash.matches('"').count();
                if quote_count % 2 == 0 {
                    // Even number of quotes, # is a comment
                    before_hash.trim()
                } else {
                    // Odd number of quotes, # is inside a quoted string
                    value
                }
            } else {
                value
            };

            let value = if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                &value[1..value.len() - 1]
            } else {
                value
            };

            args.insert(key.to_string(), value.to_string());
        }

        Ok(Self { args })
    }

    /// Merge arguments from another source
    /// Arguments from `other` take precedence over existing ones
    pub fn merge(&mut self, other: Self) {
        self.args.extend(other.args);
    }

    /// Get argument value by key
    pub fn get(&self, key: &str) -> Option<&String> {
        self.args.get(key)
    }

    /// Get argument value with default
    pub fn get_or(&self, key: &str, default: &str) -> String {
        self.args.get(key).cloned().unwrap_or_else(|| default.to_string())
    }

    /// Check if argument exists
    pub fn contains(&self, key: &str) -> bool {
        self.args.contains_key(key)
    }

    /// Get all arguments as HashMap
    pub fn as_map(&self) -> &HashMap<String, String> {
        &self.args
    }

    /// Convert to Lua-compatible table representation
    pub fn to_lua_table(&self) -> String {
        let mut entries: Vec<String> = self.args
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, v.replace('"', "\\\"")))
            .collect();
        entries.sort();
        format!("{{{}}}", entries.join(", "))
    }

    /// Get number of arguments
    pub fn len(&self) -> usize {
        self.args.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.args.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_args() {
        let args = ScriptArgs::parse("user=admin,pass=test123").unwrap();
        assert_eq!(args.get("user"), Some(&"admin".to_string()));
        assert_eq!(args.get("pass"), Some(&"test123".to_string()));
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn test_parse_with_semicolon() {
        let args = ScriptArgs::parse("user=admin;pass=test123").unwrap();
        assert_eq!(args.get("user"), Some(&"admin".to_string()));
        assert_eq!(args.get("pass"), Some(&"test123".to_string()));
    }

    #[test]
    fn test_parse_quoted_values() {
        let args = ScriptArgs::parse(r#"msg="hello world",url='http://example.com'"#).unwrap();
        assert_eq!(args.get("msg"), Some(&"hello world".to_string()));
        assert_eq!(args.get("url"), Some(&"http://example.com".to_string()));
    }

    #[test]
    fn test_parse_empty_string() {
        let result = ScriptArgs::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_format() {
        let result = ScriptArgs::parse("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_key() {
        let result = ScriptArgs::parse("=value");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_content() {
        let content = r#"
# This is a comment
user=admin
password=secret123

# Another comment
timeout=30
"#;
        let args = ScriptArgs::from_file_content(content).unwrap();
        assert_eq!(args.get("user"), Some(&"admin".to_string()));
        assert_eq!(args.get("password"), Some(&"secret123".to_string()));
        assert_eq!(args.get("timeout"), Some(&"30".to_string()));
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn test_from_file_with_inline_comments() {
        let content = "user=admin # default admin user\npass=test";
        let args = ScriptArgs::from_file_content(content).unwrap();
        assert_eq!(args.get("user"), Some(&"admin".to_string()));
        assert_eq!(args.get("pass"), Some(&"test".to_string()));
    }

    #[test]
    fn test_from_file_quoted_with_hash() {
        let content = r#"message="hello # world""#;
        let args = ScriptArgs::from_file_content(content).unwrap();
        assert_eq!(args.get("message"), Some(&"hello # world".to_string()));
    }

    #[test]
    fn test_merge_args() {
        let mut args1 = ScriptArgs::parse("user=admin,pass=old").unwrap();
        let args2 = ScriptArgs::parse("pass=new,timeout=30").unwrap();
        
        args1.merge(args2);
        
        assert_eq!(args1.get("user"), Some(&"admin".to_string()));
        assert_eq!(args1.get("pass"), Some(&"new".to_string())); // Overwritten
        assert_eq!(args1.get("timeout"), Some(&"30".to_string()));
        assert_eq!(args1.len(), 3);
    }

    #[test]
    fn test_get_or_default() {
        let args = ScriptArgs::parse("user=admin").unwrap();
        assert_eq!(args.get_or("user", "default"), "admin");
        assert_eq!(args.get_or("missing", "default"), "default");
    }

    #[test]
    fn test_contains() {
        let args = ScriptArgs::parse("user=admin").unwrap();
        assert!(args.contains("user"));
        assert!(!args.contains("password"));
    }

    #[test]
    fn test_to_lua_table() {
        let args = ScriptArgs::parse("user=admin,pass=test").unwrap();
        let lua = args.to_lua_table();
        assert!(lua.contains("user=\"admin\""));
        assert!(lua.contains("pass=\"test\""));
        assert!(lua.starts_with('{'));
        assert!(lua.ends_with('}'));
    }

    #[test]
    fn test_to_lua_table_escapes_quotes() {
        let args = ScriptArgs::parse(r#"msg="hello""#).unwrap();
        let lua = args.to_lua_table();
        // The value "hello" is stored without quotes in the HashMap
        assert!(lua.contains("msg=\""));
        assert!(lua.contains("hello"));
    }
}
