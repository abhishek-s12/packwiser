//! Cloud storage uploading client implementations for PackWiser.
//!
//! Provides URI routing and REST API client adapters to upload final packages to
//! AWS S3, Google Cloud Storage, Azure Blob Storage, and GitHub Releases.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use ureq;
use packwiser_core::{Uploader, UploadError};

/// Parsed metadata representing a targeted upload destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadDestination {
    /// AWS S3 target with bucket and object key
    S3 { bucket: String, key: String },
    /// Google Cloud Storage target with bucket and object key
    Gcs { bucket: String, key: String },
    /// Azure Blob storage with container and blob name
    Azure { container: String, blob: String },
    /// GitHub Release target with repository details and release tag
    GitHub { owner: String, repo: String, tag: String },
}

impl UploadDestination {
    /// Parses a target URI string into an `UploadDestination` variant.
    pub fn parse(uri: &str) -> Result<Self, UploadError> {
        let parsed = url::Url::parse(uri)
            .map_err(|e| UploadError::Network(format!("Failed to parse destination URI: {}", e)))?;

        let scheme = parsed.scheme();
        let host = parsed.host_str().ok_or_else(|| {
            UploadError::Network("Destination URI is missing host/bucket details".to_string())
        })?;
        let path = parsed.path().trim_start_matches('/');

        match scheme {
            "s3" => Ok(UploadDestination::S3 {
                bucket: host.to_string(),
                key: path.to_string(),
            }),
            "gcs" | "gs" => Ok(UploadDestination::Gcs {
                bucket: host.to_string(),
                key: path.to_string(),
            }),
            "azure" | "wasb" => Ok(UploadDestination::Azure {
                container: host.to_string(),
                blob: path.to_string(),
            }),
            "github" => {
                let parts: Vec<&str> = path.split('/').collect();
                if parts.len() < 3 {
                    return Err(UploadError::Network(
                        "GitHub URI format must match: github://host/owner/repo/tag".to_string(),
                    ));
                }
                Ok(UploadDestination::GitHub {
                    owner: host.to_string(),
                    repo: parts[0].to_string(),
                    tag: parts[1..].join("/"),
                })
            }
            _ => Err(UploadError::Network(format!("Unsupported upload scheme: {}", scheme))),
        }
    }
}

/// A dispatcher routing packages to designated cloud providers using the environment's configuration.
#[derive(Debug, Clone, Default)]
pub struct UniversalUploader {
    dry_run: bool,
}

impl UniversalUploader {
    /// Creates a new `UniversalUploader`.
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    fn upload_to_s3(&self, local_path: &Path, bucket: &str, key: &str) -> Result<(), UploadError> {
        let endpoint = std::env::var("AWS_ENDPOINT_URL")
            .unwrap_or_else(|_| format!("https://{}.s3.amazonaws.com", bucket));
        let url = format!("{}/{}", endpoint, key);

        if self.dry_run {
            return Ok(());
        }

        let access_key = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| {
            UploadError::Authentication("AWS_ACCESS_KEY_ID environment variable is missing".to_string())
        })?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| {
            UploadError::Authentication("AWS_SECRET_ACCESS_KEY environment variable is missing".to_string())
        })?;

        let mut file = File::open(local_path)
            .map_err(|e| UploadError::Network(format!("Failed to open payload: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| UploadError::Network(format!("Failed to read payload: {}", e)))?;

        // Perform HTTP PUT to upload the raw binary payload
        let response = ureq::put(&url)
            .set("Authorization", &format!("Bearer {}:{}", access_key, secret_key))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&buffer);

        match response {
            Ok(_) => Ok(()),
            Err(e) => Err(UploadError::Network(format!("S3 upload failed: {}", e))),
        }
    }

    fn upload_to_gcs(&self, local_path: &Path, bucket: &str, key: &str) -> Result<(), UploadError> {
        let url = format!("https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}", bucket, key);

        if self.dry_run {
            return Ok(());
        }

        let token = std::env::var("GCS_OAUTH_TOKEN").map_err(|_| {
            UploadError::Authentication("GCS_OAUTH_TOKEN authorization credential is missing".to_string())
        })?;

        let mut file = File::open(local_path)
            .map_err(|e| UploadError::Network(format!("Failed to open payload: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| UploadError::Network(format!("Failed to read payload: {}", e)))?;

        let response = ureq::post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&buffer);

        match response {
            Ok(_) => Ok(()),
            Err(e) => Err(UploadError::Network(format!("GCS upload failed: {}", e))),
        }
    }

    fn upload_to_azure(&self, local_path: &Path, container: &str, blob: &str) -> Result<(), UploadError> {
        if self.dry_run {
            return Ok(());
        }

        let account = std::env::var("AZURE_STORAGE_ACCOUNT").map_err(|_| {
            UploadError::Authentication("AZURE_STORAGE_ACCOUNT is missing".to_string())
        })?;
        let url = format!("https://{}.blob.core.windows.net/{}/{}", account, container, blob);

        let sas_token = std::env::var("AZURE_STORAGE_SAS_TOKEN").map_err(|_| {
            UploadError::Authentication("AZURE_STORAGE_SAS_TOKEN SAS credential is missing".to_string())
        })?;

        let mut file = File::open(local_path)
            .map_err(|e| UploadError::Network(format!("Failed to open payload: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| UploadError::Network(format!("Failed to read payload: {}", e)))?;

        let full_url = format!("{}?{}", url, sas_token);
        let response = ureq::put(&full_url)
            .set("x-ms-blob-type", "BlockBlob")
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&buffer);

        match response {
            Ok(_) => Ok(()),
            Err(e) => Err(UploadError::Network(format!("Azure blob upload failed: {}", e))),
        }
    }

    fn upload_to_github(&self, local_path: &Path, owner: &str, repo: &str, tag: &str) -> Result<(), UploadError> {
        let url = format!("https://uploads.github.com/repos/{}/{}/releases/tags/{}/assets", owner, repo, tag);

        if self.dry_run {
            return Ok(());
        }

        let token = std::env::var("GITHUB_TOKEN").map_err(|_| {
            UploadError::Authentication("GITHUB_TOKEN authorization credential is missing".to_string())
        })?;

        let mut file = File::open(local_path)
            .map_err(|e| UploadError::Network(format!("Failed to open payload: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| UploadError::Network(format!("Failed to read payload: {}", e)))?;

        let response = ureq::post(&url)
            .set("Authorization", &format!("token {}", token))
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&buffer);

        match response {
            Ok(_) => Ok(()),
            Err(e) => Err(UploadError::Network(format!("GitHub Release upload failed: {}", e))),
        }
    }
}

impl Uploader for UniversalUploader {
    fn upload(&self, local_path: &Path, target_uri: &str) -> Result<(), UploadError> {
        let destination = UploadDestination::parse(target_uri)?;

        match destination {
            UploadDestination::S3 { bucket, key } => self.upload_to_s3(local_path, &bucket, &key),
            UploadDestination::Gcs { bucket, key } => self.upload_to_gcs(local_path, &bucket, &key),
            UploadDestination::Azure { container, blob } => self.upload_to_azure(local_path, &container, &blob),
            UploadDestination::GitHub { owner, repo, tag } => self.upload_to_github(local_path, &owner, &repo, &tag),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destination_parsing() {
        let s3 = UploadDestination::parse("s3://my-bucket/releases/v1.tar.gz").unwrap();
        assert_eq!(
            s3,
            UploadDestination::S3 {
                bucket: "my-bucket".to_string(),
                key: "releases/v1.tar.gz".to_string()
            }
        );

        let gcs = UploadDestination::parse("gcs://google-bucket/packages/app.zip").unwrap();
        assert_eq!(
            gcs,
            UploadDestination::Gcs {
                bucket: "google-bucket".to_string(),
                key: "packages/app.zip".to_string()
            }
        );

        let azure = UploadDestination::parse("azure://mycontainer/blob-data.zst").unwrap();
        assert_eq!(
            azure,
            UploadDestination::Azure {
                container: "mycontainer".to_string(),
                blob: "blob-data.zst".to_string()
            }
        );

        let github = UploadDestination::parse("github://myorg/myrepo/v1.0.0/release").unwrap();
        assert_eq!(
            github,
            UploadDestination::GitHub {
                owner: "myorg".to_string(),
                repo: "myrepo".to_string(),
                tag: "v1.0.0/release".to_string()
            }
        );
    }

    #[test]
    fn test_dry_run_uploads() {
        let temp_dir = tempfile::tempdir().unwrap();
        let payload_path = temp_dir.path().join("payload.tar");
        std::fs::write(&payload_path, b"test-payload").unwrap();

        let uploader = UniversalUploader::new(true); // dry-run mode

        // Dry-run should succeed without credentials set
        assert!(uploader.upload(&payload_path, "s3://mock/obj").is_ok());
        assert!(uploader.upload(&payload_path, "gcs://mock/obj").is_ok());
        assert!(uploader.upload(&payload_path, "azure://mock/obj").is_ok());
        assert!(uploader.upload(&payload_path, "github://mock/repo/v1.0.0/release").is_ok());
    }
}
