// Streaming results to disk for large scans
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use serde::Serialize;
use anyhow::{Result, Context};

pub struct StreamWriter {
    file: BufWriter<File>,
    format: OutputFormat,
    items_written: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    JsonLines,
    Csv,
    Tsv,
}

impl StreamWriter {
    pub async fn new(path: PathBuf, format: OutputFormat) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .context("Failed to open output file")?;

        let mut writer = Self {
            file: BufWriter::new(file),
            format,
            items_written: 0,
        };

        // Write CSV header if needed
        if matches!(format, OutputFormat::Csv | OutputFormat::Tsv) {
            writer.write_header().await?;
        }

        Ok(writer)
    }

    async fn write_header(&mut self) -> Result<()> {
        let delimiter = match self.format {
            OutputFormat::Csv => ",",
            OutputFormat::Tsv => "\t",
            _ => return Ok(()),
        };

        let header = format!(
            "timestamp{}target{}port{}state{}service{}version\n",
            delimiter, delimiter, delimiter, delimiter, delimiter
        );

        self.file.write_all(header.as_bytes()).await?;
        Ok(())
    }

    pub async fn write<T: Serialize>(&mut self, item: &T) -> Result<()> {
        match self.format {
            OutputFormat::JsonLines => {
                let json = serde_json::to_string(item)?;
                self.file.write_all(json.as_bytes()).await?;
                self.file.write_all(b"\n").await?;
            }
            OutputFormat::Csv | OutputFormat::Tsv => {
                let delimiter = match self.format {
                    OutputFormat::Csv => ",",
                    OutputFormat::Tsv => "\t",
                    _ => unreachable!(),
                };
                let json_value: serde_json::Value = serde_json::to_value(item)?;
                if let Some(obj) = json_value.as_object() {
                    let keys: Vec<&String> = obj.keys().collect();
                    let line: Vec<String> = keys.iter().map(|k| {
                        match obj.get(*k) {
                            Some(serde_json::Value::String(s)) => s.clone(),
                            Some(v) => v.to_string(),
                            None => String::new(),
                        }
                    }).collect();
                    self.file.write_all(line.join(delimiter).as_bytes()).await?;
                    self.file.write_all(b"\n").await?;
                } else {
                    let json = serde_json::to_string(item)?;
                    self.file.write_all(json.as_bytes()).await?;
                    self.file.write_all(b"\n").await?;
                }
            }
        }

        self.items_written += 1;

        // Flush periodically
        if self.items_written % 100 == 0 {
            self.file.flush().await?;
        }

        Ok(())
    }

    pub async fn write_batch<T: Serialize>(&mut self, items: &[T]) -> Result<()> {
        for item in items {
            self.write(item).await?;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.file.flush().await?;
        Ok(())
    }

    pub fn items_written(&self) -> u64 {
        self.items_written
    }
}

// BufWriter<File> implements Drop and will attempt to flush

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestRecord {
        id: u64,
        name: String,
    }

    #[tokio::test]
    async fn test_jsonlines_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let mut writer = StreamWriter::new(path.clone(), OutputFormat::JsonLines)
            .await
            .unwrap();

        let record = TestRecord {
            id: 1,
            name: "test".to_string(),
        };

        writer.write(&record).await.unwrap();
        writer.flush().await.unwrap();

        assert_eq!(writer.items_written(), 1);

        // Read and verify
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(content.contains("\"id\":1"));
        assert!(content.contains("\"name\":\"test\""));
    }

    #[tokio::test]
    async fn test_batch_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("batch.jsonl");

        let mut writer = StreamWriter::new(path.clone(), OutputFormat::JsonLines)
            .await
            .unwrap();

        let records = vec![
            TestRecord {
                id: 1,
                name: "first".to_string(),
            },
            TestRecord {
                id: 2,
                name: "second".to_string(),
            },
        ];

        writer.write_batch(&records).await.unwrap();
        writer.flush().await.unwrap();

        assert_eq!(writer.items_written(), 2);
    }

    #[tokio::test]
    async fn test_csv_format() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.csv");

        let mut writer = StreamWriter::new(path.clone(), OutputFormat::Csv)
            .await
            .unwrap();

        let record = TestRecord {
            id: 1,
            name: "test".to_string(),
        };

        writer.write(&record).await.unwrap();
        writer.flush().await.unwrap();

        // Read and verify header exists
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(content.starts_with("timestamp,target,port,state,service,version\n"));
    }

    #[tokio::test]
    async fn test_items_written_counter() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("counter.jsonl");

        let mut writer = StreamWriter::new(path, OutputFormat::JsonLines)
            .await
            .unwrap();

        for i in 0..10 {
            writer
                .write(&TestRecord {
                    id: i,
                    name: format!("item{}", i),
                })
                .await
                .unwrap();
        }

        assert_eq!(writer.items_written(), 10);
    }
}
