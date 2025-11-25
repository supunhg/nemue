// Database backend for storing scan results
use serde::{Serialize, Deserialize};
use std::path::Path;
use tokio::fs;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub scan_id: String,
    pub timestamp: i64,
    pub target: String,
    pub status: ScanStatus,
    pub progress: f32,
    pub results_count: usize,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub scan_id: String,
    pub timestamp: i64,
    pub completed_targets: Vec<String>,
    pub pending_targets: Vec<String>,
    pub partial_results: String, // JSON blob
}

/// Simple file-based database for scan persistence
pub struct ScanDatabase {
    base_path: String,
}

impl ScanDatabase {
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        Self {
            base_path: base_path.as_ref().to_string_lossy().to_string(),
        }
    }

    pub async fn init(&self) -> Result<(), String> {
        fs::create_dir_all(&self.base_path)
            .await
            .map_err(|e| format!("Failed to create database directory: {}", e))
    }

    pub async fn save_scan(&self, record: &ScanRecord) -> Result<(), String> {
        let path = format!("{}/scan_{}.json", self.base_path, record.scan_id);
        let json = serde_json::to_string_pretty(record)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(&path, json)
            .await
            .map_err(|e| format!("Failed to write scan record: {}", e))
    }

    pub async fn load_scan(&self, scan_id: &str) -> Result<ScanRecord, String> {
        let path = format!("{}/scan_{}.json", self.base_path, scan_id);
        let data = fs::read_to_string(&path)
            .await
            .map_err(|e| format!("Failed to read scan record: {}", e))?;
        
        serde_json::from_str(&data)
            .map_err(|e| format!("Deserialization error: {}", e))
    }

    pub async fn save_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), String> {
        let path = format!("{}/checkpoint_{}.json", self.base_path, checkpoint.scan_id);
        let json = serde_json::to_string_pretty(checkpoint)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        fs::write(&path, json)
            .await
            .map_err(|e| format!("Failed to write checkpoint: {}", e))
    }

    pub async fn load_checkpoint(&self, scan_id: &str) -> Result<Checkpoint, String> {
        let path = format!("{}/checkpoint_{}.json", self.base_path, scan_id);
        let data = fs::read_to_string(&path)
            .await
            .map_err(|e| format!("Failed to read checkpoint: {}", e))?;
        
        serde_json::from_str(&data)
            .map_err(|e| format!("Deserialization error: {}", e))
    }

    pub async fn list_scans(&self) -> Result<Vec<ScanRecord>, String> {
        let mut scans = Vec::new();
        let mut entries = fs::read_dir(&self.base_path)
            .await
            .map_err(|e| format!("Failed to read directory: {}", e))?;

        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(filename) = entry.file_name().to_str() {
                if filename.starts_with("scan_") && filename.ends_with(".json") {
                    let data = fs::read_to_string(entry.path()).await.ok();
                    if let Some(json) = data {
                        if let Ok(record) = serde_json::from_str::<ScanRecord>(&json) {
                            scans.push(record);
                        }
                    }
                }
            }
        }

        Ok(scans)
    }

    pub async fn delete_scan(&self, scan_id: &str) -> Result<(), String> {
        let scan_path = format!("{}/scan_{}.json", self.base_path, scan_id);
        let checkpoint_path = format!("{}/checkpoint_{}.json", self.base_path, scan_id);
        
        let _ = fs::remove_file(&scan_path).await;
        let _ = fs::remove_file(&checkpoint_path).await;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_database_init() {
        let dir = tempdir().unwrap();
        let db = ScanDatabase::new(dir.path());
        assert!(db.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_save_and_load_scan() {
        let dir = tempdir().unwrap();
        let db = ScanDatabase::new(dir.path());
        db.init().await.unwrap();

        let record = ScanRecord {
            scan_id: "test123".to_string(),
            timestamp: 1234567890,
            target: "192.168.1.0/24".to_string(),
            status: ScanStatus::Completed,
            progress: 100.0,
            results_count: 42,
            metadata: HashMap::new(),
        };

        assert!(db.save_scan(&record).await.is_ok());
        let loaded = db.load_scan("test123").await.unwrap();
        assert_eq!(loaded.scan_id, "test123");
        assert_eq!(loaded.status, ScanStatus::Completed);
    }

    #[tokio::test]
    async fn test_checkpoint() {
        let dir = tempdir().unwrap();
        let db = ScanDatabase::new(dir.path());
        db.init().await.unwrap();

        let checkpoint = Checkpoint {
            scan_id: "test456".to_string(),
            timestamp: 9876543210,
            completed_targets: vec!["192.168.1.1".to_string()],
            pending_targets: vec!["192.168.1.2".to_string()],
            partial_results: "{}".to_string(),
        };

        assert!(db.save_checkpoint(&checkpoint).await.is_ok());
        let loaded = db.load_checkpoint("test456").await.unwrap();
        assert_eq!(loaded.scan_id, "test456");
        assert_eq!(loaded.completed_targets.len(), 1);
    }

    #[tokio::test]
    async fn test_list_scans() {
        let dir = tempdir().unwrap();
        let db = ScanDatabase::new(dir.path());
        db.init().await.unwrap();

        let record1 = ScanRecord {
            scan_id: "scan1".to_string(),
            timestamp: 111,
            target: "10.0.0.1".to_string(),
            status: ScanStatus::Running,
            progress: 50.0,
            results_count: 10,
            metadata: HashMap::new(),
        };

        let record2 = ScanRecord {
            scan_id: "scan2".to_string(),
            timestamp: 222,
            target: "10.0.0.2".to_string(),
            status: ScanStatus::Completed,
            progress: 100.0,
            results_count: 20,
            metadata: HashMap::new(),
        };

        db.save_scan(&record1).await.unwrap();
        db.save_scan(&record2).await.unwrap();

        let scans = db.list_scans().await.unwrap();
        assert_eq!(scans.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_scan() {
        let dir = tempdir().unwrap();
        let db = ScanDatabase::new(dir.path());
        db.init().await.unwrap();

        let record = ScanRecord {
            scan_id: "delete_me".to_string(),
            timestamp: 999,
            target: "1.1.1.1".to_string(),
            status: ScanStatus::Failed,
            progress: 25.0,
            results_count: 5,
            metadata: HashMap::new(),
        };

        db.save_scan(&record).await.unwrap();
        assert!(db.load_scan("delete_me").await.is_ok());
        
        db.delete_scan("delete_me").await.unwrap();
        assert!(db.load_scan("delete_me").await.is_err());
    }
}
