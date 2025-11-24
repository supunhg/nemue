// Cloud Storage Fuzzing - S3, Azure Blob, GCP bucket enumeration
// cloud_enum-style cloud storage discovery

use anyhow::Result;
use reqwest::{Client, StatusCode};
use std::time::Duration;
use tracing::{debug, info};
use serde::{Serialize, Deserialize};

/// Cloud storage provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudProvider {
    /// Amazon S3
    AwsS3,
    /// Azure Blob Storage
    AzureBlob,
    /// Google Cloud Storage
    GcpBucket,
    /// DigitalOcean Spaces
    DigitalOceanSpaces,
}

/// Cloud storage configuration
#[derive(Debug, Clone)]
pub struct CloudStorageConfig {
    /// Provider to enumerate
    pub provider: CloudProvider,
    /// AWS regions to check (for S3)
    pub aws_regions: Vec<String>,
    /// Check for public access
    pub check_public_access: bool,
    /// Check for bucket listing
    pub check_listing: bool,
    /// Try to download common files
    pub check_common_files: bool,
    /// Request timeout
    pub timeout_ms: u64,
}

impl Default for CloudStorageConfig {
    fn default() -> Self {
        Self {
            provider: CloudProvider::AwsS3,
            aws_regions: vec![
                "us-east-1".to_string(),
                "us-west-2".to_string(),
                "eu-west-1".to_string(),
                "ap-southeast-1".to_string(),
            ],
            check_public_access: true,
            check_listing: true,
            check_common_files: true,
            timeout_ms: 10000,
        }
    }
}

/// Cloud storage result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudStorageResult {
    /// Bucket/container name
    pub name: String,
    /// Provider
    pub provider: CloudProvider,
    /// Whether bucket exists
    pub exists: bool,
    /// Whether bucket is publicly accessible
    pub public_access: bool,
    /// Whether bucket listing is enabled
    pub listing_enabled: bool,
    /// Region (for S3)
    pub region: Option<String>,
    /// Found files (if listing enabled)
    pub files: Vec<String>,
}

/// Cloud storage fuzzer
pub struct CloudStorageFuzzer {
    config: CloudStorageConfig,
    client: Client,
}

impl CloudStorageFuzzer {
    /// Create a new cloud storage fuzzer
    pub fn new(config: CloudStorageConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;

        Ok(Self { config, client })
    }

    /// Enumerate cloud storage buckets
    pub async fn enumerate(&self, wordlist: Vec<String>) -> Result<Vec<CloudStorageResult>> {
        info!("Enumerating {} buckets for {:?}", wordlist.len(), self.config.provider);

        let mut results = Vec::new();

        for name in wordlist {
            let result = match self.config.provider {
                CloudProvider::AwsS3 => self.check_s3_bucket(&name).await?,
                CloudProvider::AzureBlob => self.check_azure_blob(&name).await?,
                CloudProvider::GcpBucket => self.check_gcp_bucket(&name).await?,
                CloudProvider::DigitalOceanSpaces => self.check_do_spaces(&name).await?,
            };

            if result.exists {
                results.push(result);
            }
        }

        info!("Found {} accessible buckets", results.len());
        Ok(results)
    }

    /// Check AWS S3 bucket
    async fn check_s3_bucket(&self, name: &str) -> Result<CloudStorageResult> {
        debug!("Checking S3 bucket: {}", name);

        let mut result = CloudStorageResult {
            name: name.to_string(),
            provider: CloudProvider::AwsS3,
            exists: false,
            public_access: false,
            listing_enabled: false,
            region: None,
            files: Vec::new(),
        };

        // Try standard S3 URL
        let url = format!("https://{}.s3.amazonaws.com", name);
        
        match self.client.head(&url).send().await {
            Ok(response) => {
                match response.status() {
                    StatusCode::OK | StatusCode::FORBIDDEN => {
                        result.exists = true;
                        result.public_access = response.status() == StatusCode::OK;

                        // Try to get region from headers
                        if let Some(region) = response.headers().get("x-amz-bucket-region") {
                            if let Ok(region_str) = region.to_str() {
                                result.region = Some(region_str.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => {
                // Try region-specific URLs
                for region in &self.config.aws_regions {
                    let regional_url = format!("https://{}.s3.{}.amazonaws.com", name, region);
                    
                    if let Ok(response) = self.client.head(&regional_url).send().await {
                        if response.status() == StatusCode::OK || response.status() == StatusCode::FORBIDDEN {
                            result.exists = true;
                            result.region = Some(region.clone());
                            result.public_access = response.status() == StatusCode::OK;
                            break;
                        }
                    }
                }
            }
        }

        // Check for listing if publicly accessible
        if result.public_access && self.config.check_listing {
            if let Ok(files) = self.list_s3_bucket(name, result.region.as_deref()).await {
                result.listing_enabled = !files.is_empty();
                result.files = files;
            }
        }

        // Check common files
        if result.exists && self.config.check_common_files {
            let region = result.region.clone();
            self.check_common_s3_files(name, region.as_deref(), &mut result).await?;
        }

        Ok(result)
    }

    /// List S3 bucket contents
    async fn list_s3_bucket(&self, name: &str, region: Option<&str>) -> Result<Vec<String>> {
        let url = if let Some(reg) = region {
            format!("https://{}.s3.{}.amazonaws.com/", name, reg)
        } else {
            format!("https://{}.s3.amazonaws.com/", name)
        };

        match self.client.get(&url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let body = response.text().await?;
                    Ok(self.parse_s3_listing(&body))
                } else {
                    Ok(Vec::new())
                }
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Parse S3 XML listing
    fn parse_s3_listing(&self, xml: &str) -> Vec<String> {
        let mut files = Vec::new();

        // Simple XML parsing to extract <Key> elements
        // In a real implementation, would use an XML parser
        for line in xml.lines() {
            if line.contains("<Key>") && line.contains("</Key>") {
                if let Some(start) = line.find("<Key>") {
                    if let Some(end) = line.find("</Key>") {
                        let key = &line[start + 5..end];
                        files.push(key.to_string());
                    }
                }
            }
        }

        files
    }

    /// Check for common sensitive files in S3
    async fn check_common_s3_files(&self, name: &str, region: Option<&str>, result: &mut CloudStorageResult) -> Result<()> {
        let common_files = vec![
            "backup.zip",
            "database.sql",
            "db.sql",
            ".env",
            "config.json",
            "secrets.json",
            "credentials.json",
            "aws.json",
        ];

        let base_url = if let Some(reg) = region {
            format!("https://{}.s3.{}.amazonaws.com", name, reg)
        } else {
            format!("https://{}.s3.amazonaws.com", name)
        };

        for file in common_files {
            let url = format!("{}/{}", base_url, file);
            
            if let Ok(response) = self.client.head(&url).send().await {
                if response.status().is_success() {
                    result.files.push(file.to_string());
                }
            }
        }

        Ok(())
    }

    /// Check Azure Blob storage
    async fn check_azure_blob(&self, name: &str) -> Result<CloudStorageResult> {
        debug!("Checking Azure Blob: {}", name);

        let mut result = CloudStorageResult {
            name: name.to_string(),
            provider: CloudProvider::AzureBlob,
            exists: false,
            public_access: false,
            listing_enabled: false,
            region: None,
            files: Vec::new(),
        };

        // Azure Blob URL format: https://{account}.blob.core.windows.net/{container}
        let url = format!("https://{}.blob.core.windows.net/", name);

        match self.client.head(&url).send().await {
            Ok(response) => {
                match response.status() {
                    StatusCode::OK => {
                        result.exists = true;
                        result.public_access = true;
                    }
                    StatusCode::FORBIDDEN => {
                        result.exists = true;
                        result.public_access = false;
                    }
                    _ => {}
                }
            }
            Err(_) => {}
        }

        Ok(result)
    }

    /// Check GCP bucket
    async fn check_gcp_bucket(&self, name: &str) -> Result<CloudStorageResult> {
        debug!("Checking GCP bucket: {}", name);

        let mut result = CloudStorageResult {
            name: name.to_string(),
            provider: CloudProvider::GcpBucket,
            exists: false,
            public_access: false,
            listing_enabled: false,
            region: None,
            files: Vec::new(),
        };

        // GCP Storage URL: https://storage.googleapis.com/{bucket}
        let url = format!("https://storage.googleapis.com/{}", name);

        match self.client.get(&url).send().await {
            Ok(response) => {
                match response.status() {
                    StatusCode::OK => {
                        result.exists = true;
                        result.public_access = true;

                        // Try to list contents
                        if self.config.check_listing {
                            let body = response.text().await?;
                            result.files = self.parse_gcp_listing(&body);
                            result.listing_enabled = !result.files.is_empty();
                        }
                    }
                    StatusCode::FORBIDDEN => {
                        result.exists = true;
                        result.public_access = false;
                    }
                    _ => {}
                }
            }
            Err(_) => {}
        }

        Ok(result)
    }

    /// Parse GCP bucket listing
    fn parse_gcp_listing(&self, xml: &str) -> Vec<String> {
        // Similar to S3, parse XML listing
        self.parse_s3_listing(xml)
    }

    /// Check DigitalOcean Spaces
    async fn check_do_spaces(&self, name: &str) -> Result<CloudStorageResult> {
        debug!("Checking DO Spaces: {}", name);

        let mut result = CloudStorageResult {
            name: name.to_string(),
            provider: CloudProvider::DigitalOceanSpaces,
            exists: false,
            public_access: false,
            listing_enabled: false,
            region: None,
            files: Vec::new(),
        };

        // DigitalOcean Spaces regions
        let regions = vec!["nyc3", "sfo3", "ams3", "sgp1"];

        for region in regions {
            let url = format!("https://{}.{}.digitaloceanspaces.com", name, region);
            
            if let Ok(response) = self.client.head(&url).send().await {
                if response.status() == StatusCode::OK || response.status() == StatusCode::FORBIDDEN {
                    result.exists = true;
                    result.region = Some(region.to_string());
                    result.public_access = response.status() == StatusCode::OK;
                    break;
                }
            }
        }

        Ok(result)
    }
}

/// Generate cloud bucket name variations
pub struct BucketNameGenerator;

impl BucketNameGenerator {
    /// Generate bucket name variations for a company/domain
    pub fn generate(base_name: &str) -> Vec<String> {
        let mut variations = Vec::new();

        // Clean base name
        let clean = base_name.to_lowercase()
            .replace(".", "-")
            .replace("_", "-");

        // Environment variations
        let envs = vec!["dev", "test", "stage", "staging", "prod", "production", 
                       "qa", "uat", "demo", "backup"];
        for env in envs {
            variations.push(format!("{}-{}", clean, env));
            variations.push(format!("{}{}", clean, env));
            variations.push(format!("{}-{}", env, clean));
        }

        // Type variations
        let types = vec!["backups", "backup", "logs", "assets", "media", "images", 
                        "files", "data", "uploads", "static", "public"];
        for typ in types {
            variations.push(format!("{}-{}", clean, typ));
            variations.push(format!("{}{}", clean, typ));
        }

        // Region variations
        let regions = vec!["us", "eu", "asia", "west", "east", "central"];
        for region in regions {
            variations.push(format!("{}-{}", clean, region));
            variations.push(format!("{}-{}", region, clean));
        }

        // Common patterns
        variations.push(format!("{}-bucket", clean));
        variations.push(format!("{}-storage", clean));
        variations.push(format!("backup-{}", clean));
        variations.push(format!("archive-{}", clean));

        variations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider() {
        assert_ne!(CloudProvider::AwsS3, CloudProvider::AzureBlob);
        assert_eq!(CloudProvider::AwsS3, CloudProvider::AwsS3);
    }

    #[test]
    fn test_cloud_storage_config_default() {
        let config = CloudStorageConfig::default();
        assert_eq!(config.provider, CloudProvider::AwsS3);
        assert_eq!(config.aws_regions.len(), 4);
        assert!(config.check_public_access);
    }

    #[test]
    fn test_bucket_name_generator() {
        let variations = BucketNameGenerator::generate("example.com");
        assert!(!variations.is_empty());
        assert!(variations.contains(&"example-com-dev".to_string()));
        assert!(variations.contains(&"example-com-backup".to_string()));
    }

    #[test]
    fn test_parse_s3_listing() {
        let config = CloudStorageConfig::default();
        let fuzzer = CloudStorageFuzzer::new(config).unwrap();

        let xml = r#"
            <ListBucketResult>
                <Contents>
                    <Key>file1.txt</Key>
                </Contents>
                <Contents>
                    <Key>file2.pdf</Key>
                </Contents>
            </ListBucketResult>
        "#;

        let files = fuzzer.parse_s3_listing(xml);
        assert_eq!(files.len(), 2);
        assert!(files.contains(&"file1.txt".to_string()));
        assert!(files.contains(&"file2.pdf".to_string()));
    }
}
