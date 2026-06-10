// Script Database Management
// Implements --script-updatedb functionality

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Script metadata stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptMetadata {
    pub name: String,
    pub path: PathBuf,
    pub description: String,
    pub author: String,
    pub categories: Vec<String>,
    pub last_modified: chrono::DateTime<chrono::Utc>,
}

/// Script database for managing available scripts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptDatabase {
    /// All available scripts indexed by name
    scripts: Vec<ScriptMetadata>,
    /// Last database update time
    last_updated: chrono::DateTime<chrono::Utc>,
}

impl ScriptDatabase {
    /// Create empty database
    pub fn new() -> Self {
        Self {
            scripts: Vec::new(),
            last_updated: chrono::Utc::now(),
        }
    }

    /// Load database from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| anyhow!("Failed to read script database: {}", e))?;

        let db: Self = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse script database: {}", e))?;

        Ok(db)
    }

    /// Save database to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize database: {}", e))?;

        fs::write(path.as_ref(), json).map_err(|e| anyhow!("Failed to write database: {}", e))?;

        Ok(())
    }

    /// Update database by scanning script directories
    pub fn update<P: AsRef<Path>>(&mut self, script_dir: P) -> Result<usize> {
        let script_dir = script_dir.as_ref();

        if !script_dir.exists() {
            return Err(anyhow!(
                "Script directory not found: {}",
                script_dir.display()
            ));
        }

        let mut new_scripts = Vec::new();
        let mut count = 0;

        // Recursively scan for .lua files
        self.scan_directory(script_dir, &mut new_scripts, &mut count)?;

        self.scripts = new_scripts;
        self.last_updated = chrono::Utc::now();

        Ok(count)
    }

    /// Recursively scan directory for script files
    fn scan_directory(
        &self,
        dir: &Path,
        scripts: &mut Vec<ScriptMetadata>,
        count: &mut usize,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                self.scan_directory(&path, scripts, count)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("lua") {
                if let Ok(metadata) = self.parse_script_file(&path) {
                    scripts.push(metadata);
                    *count += 1;
                }
            }
        }

        Ok(())
    }

    /// Parse script file to extract metadata
    fn parse_script_file(&self, path: &Path) -> Result<ScriptMetadata> {
        let content = fs::read_to_string(path)?;

        // Extract metadata from Lua comments and globals
        let mut name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut description = String::new();
        let mut author = String::new();
        let mut categories = Vec::new();

        // Simple parsing - look for Lua global assignments
        for line in content.lines() {
            let line = line.trim();

            if line.starts_with("name") && line.contains('=') {
                name = Self::extract_string_value(line);
            } else if line.starts_with("description") && line.contains('=') {
                description = Self::extract_string_value(line);
            } else if line.starts_with("author") && line.contains('=') {
                author = Self::extract_string_value(line);
            } else if line.starts_with("categories") && line.contains('=') {
                categories = Self::extract_array_value(line);
            }
        }

        let metadata = fs::metadata(path)?;
        let modified = metadata.modified()?;
        let last_modified = chrono::DateTime::from(modified);

        Ok(ScriptMetadata {
            name,
            path: path.to_path_buf(),
            description,
            author,
            categories,
            last_modified,
        })
    }

    /// Extract string value from Lua assignment (simple parser)
    fn extract_string_value(line: &str) -> String {
        if let Some(eq_pos) = line.find('=') {
            let value = line[eq_pos + 1..].trim();
            // Remove quotes
            value.trim_matches(|c| c == '"' || c == '\'').to_string()
        } else {
            String::new()
        }
    }

    /// Extract array values from Lua table assignment (simple parser)
    fn extract_array_value(line: &str) -> Vec<String> {
        if let Some(start) = line.find('{') {
            if let Some(end) = line.find('}') {
                let content = &line[start + 1..end];
                return content
                    .split(',')
                    .map(|s| s.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        Vec::new()
    }

    /// Find script by name
    pub fn find(&self, name: &str) -> Option<&ScriptMetadata> {
        self.scripts.iter().find(|s| s.name == name)
    }

    /// Get all scripts
    pub fn all(&self) -> &[ScriptMetadata] {
        &self.scripts
    }

    /// Get scripts by category
    pub fn by_category(&self, category: &str) -> Vec<&ScriptMetadata> {
        self.scripts
            .iter()
            .filter(|s| s.categories.iter().any(|c| c == category))
            .collect()
    }

    /// Get number of scripts
    pub fn count(&self) -> usize {
        self.scripts.len()
    }

    /// Get all categories
    pub fn categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .scripts
            .iter()
            .flat_map(|s| s.categories.clone())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }

    /// Get last update time
    pub fn last_updated(&self) -> chrono::DateTime<chrono::Utc> {
        self.last_updated
    }
}

impl Default for ScriptDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_database_creation() {
        let db = ScriptDatabase::new();
        assert_eq!(db.count(), 0);
    }

    #[test]
    fn test_extract_string_value() {
        let value = ScriptDatabase::extract_string_value(r#"name = "test-script""#);
        assert_eq!(value, "test-script");

        let value2 = ScriptDatabase::extract_string_value("author = 'John Doe'");
        assert_eq!(value2, "John Doe");
    }

    #[test]
    fn test_extract_array_value() {
        let values = ScriptDatabase::extract_array_value(r#"categories = {"http", "vuln"}"#);
        assert_eq!(values, vec!["http", "vuln"]);
    }

    #[test]
    fn test_parse_script_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let script_path = temp_dir.path().join("test.lua");

        let script_content = r#"
name = "http-vuln-check"
description = "Checks for HTTP vulnerabilities"
author = "Nemue Team"
categories = {"http", "vuln"}

function action(args)
    return "OK"
end
"#;

        let mut file = fs::File::create(&script_path)?;
        file.write_all(script_content.as_bytes())?;
        drop(file);

        let db = ScriptDatabase::new();
        let metadata = db.parse_script_file(&script_path)?;

        assert_eq!(metadata.name, "http-vuln-check");
        assert_eq!(metadata.description, "Checks for HTTP vulnerabilities");
        assert_eq!(metadata.author, "Nemue Team");
        assert_eq!(metadata.categories, vec!["http", "vuln"]);

        Ok(())
    }

    #[test]
    fn test_update_database() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Create test script
        let script_path = temp_dir.path().join("test.lua");
        let mut file = fs::File::create(&script_path)?;
        file.write_all(b"name = \"test\"\ndescription = \"Test script\"")?;
        drop(file);

        let mut db = ScriptDatabase::new();
        let count = db.update(temp_dir.path())?;

        assert_eq!(count, 1);
        assert_eq!(db.count(), 1);

        Ok(())
    }

    #[test]
    fn test_find_script() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let script_path = temp_dir.path().join("findme.lua");

        let mut file = fs::File::create(&script_path)?;
        file.write_all(b"name = \"findme\"\ndescription = \"Find this\"")?;
        drop(file);

        let mut db = ScriptDatabase::new();
        db.update(temp_dir.path())?;

        let found = db.find("findme");
        assert!(found.is_some());
        assert_eq!(found.unwrap().description, "Find this");

        let not_found = db.find("nonexistent");
        assert!(not_found.is_none());

        Ok(())
    }

    #[test]
    fn test_by_category() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Create two scripts with different categories
        let script1 = temp_dir.path().join("http-script.lua");
        let mut file = fs::File::create(&script1)?;
        file.write_all(b"name = \"http-script\"\ncategories = {\"http\"}")?;
        drop(file);

        let script2 = temp_dir.path().join("vuln-script.lua");
        let mut file = fs::File::create(&script2)?;
        file.write_all(b"name = \"vuln-script\"\ncategories = {\"vuln\"}")?;
        drop(file);

        let mut db = ScriptDatabase::new();
        db.update(temp_dir.path())?;

        let http_scripts = db.by_category("http");
        assert_eq!(http_scripts.len(), 1);
        assert_eq!(http_scripts[0].name, "http-script");

        let vuln_scripts = db.by_category("vuln");
        assert_eq!(vuln_scripts.len(), 1);

        Ok(())
    }

    #[test]
    fn test_save_and_load() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().join("scripts.db");

        let mut db = ScriptDatabase::new();
        db.scripts.push(ScriptMetadata {
            name: "test".to_string(),
            path: PathBuf::from("/tmp/test.lua"),
            description: "Test script".to_string(),
            author: "Test Author".to_string(),
            categories: vec!["test".to_string()],
            last_modified: chrono::Utc::now(),
        });

        db.save(&db_path)?;

        let loaded = ScriptDatabase::load(&db_path)?;
        assert_eq!(loaded.count(), 1);
        assert_eq!(loaded.all()[0].name, "test");

        Ok(())
    }
}
