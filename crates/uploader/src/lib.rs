//! Cloud storage uploading client implementations for PackWiser.
//!
//! Provides URI routing and REST API client adapters to upload final packages to
//! AWS S3, Google Cloud Storage, Azure Blob Storage, and GitHub Releases.

use packwiser_core::{UploadError, Uploader};
use sha2::Digest;
use std::fs::File;

use std::io::Read;
use std::path::Path;

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
    GitHub {
        owner: String,
        repo: String,
        tag: String,
    },
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
            _ => Err(UploadError::Network(format!(
                "Unsupported upload scheme: {}",
                scheme
            ))),
        }
    }
}

/// A dispatcher routing packages to designated cloud providers using the environment's configuration.
///
/// ### Provider Requirements
///
/// * **AWS S3 (`s3://...`):**
///   Requires `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to be set.
///   Optionally accepts `AWS_SESSION_TOKEN` (for temporary credentials) and `AWS_REGION`
///   (defaults to `us-east-1` if unset). Requests are authenticated using AWS Signature Version 4.
///   If a custom endpoint URL is needed, set `AWS_ENDPOINT_URL`.
///
/// * **Google Cloud Storage (`gcs://...` or `gs://...`):**
///   Requires `GCS_OAUTH_TOKEN` to be set to a valid OAuth2 access token.
///   Note: This tool does not perform the OAuth2 flow itself; the caller must supply an already-valid token.
///
/// * **Azure Blob Storage (`azure://...` or `wasb://...`):**
///   Requires `AZURE_STORAGE_ACCOUNT` and `AZURE_STORAGE_SAS_TOKEN` to be set.
///   Note: The SAS token can be supplied with or without a leading `?` character.
///
/// * **GitHub Releases (`github://...`):**
///   Requires `GITHUB_TOKEN` to be set with a valid token having permission to upload release assets.
#[derive(Debug, Clone, Default)]
pub struct UniversalUploader {
    dry_run: bool,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut ipad = [0x36; 64];
    let mut opad = [0x5c; 64];

    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hash = sha2::Sha256::digest(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut hasher = sha2::Sha256::new();
    hasher.update(ipad);
    hasher.update(message);
    let inner_hash = hasher.finalize();

    let mut hasher = sha2::Sha256::new();
    hasher.update(opad);
    hasher.update(inner_hash);
    hasher.finalize().into()
}

impl UniversalUploader {
    /// Creates a new `UniversalUploader`.
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    fn upload_to_s3(&self, local_path: &Path, bucket: &str, key: &str) -> Result<(), UploadError> {
        let endpoint = std::env::var("AWS_ENDPOINT_URL")
            .unwrap_or_else(|_| format!("https://{}.s3.amazonaws.com", bucket));
        let base_url = endpoint.trim_end_matches('/');
        let url = format!("{}/{}", base_url, key);

        if self.dry_run {
            return Ok(());
        }

        let access_key = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| {
            UploadError::Authentication(
                "AWS_ACCESS_KEY_ID environment variable is missing".to_string(),
            )
        })?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| {
            UploadError::Authentication(
                "AWS_SECRET_ACCESS_KEY environment variable is missing".to_string(),
            )
        })?;
        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let parsed_url = url::Url::parse(&url)
            .map_err(|e| UploadError::Network(format!("Failed to parse S3 URL: {}", e)))?;
        let host = parsed_url
            .host_str()
            .ok_or_else(|| UploadError::Network("S3 URL has no host name".to_string()))?;
        let host_header_val = match parsed_url.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host.to_string(),
        };

        // Canonical URI path must start with '/' and be percent-encoded (parsed_url.path() is already encoded)
        let canonical_uri = parsed_url.path();

        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let mut file = File::open(local_path)
            .map_err(|e| UploadError::Network(format!("Failed to open payload: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| UploadError::Network(format!("Failed to read payload: {}", e)))?;

        let payload_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&buffer);
            bytes_to_hex(&hasher.finalize())
        };

        let mut canonical_headers = format!(
            "host:{}\n\
             x-amz-content-sha256:{}\n\
             x-amz-date:{}\n",
            host_header_val, payload_hash, amz_date
        );
        let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();

        if let Some(ref token) = session_token {
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", token));
            signed_headers.push_str(";x-amz-security-token");
        }

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            "PUT",
            canonical_uri,
            "", // empty query string
            canonical_headers,
            signed_headers,
            payload_hash
        );

        let hashed_canonical_request = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(canonical_request.as_bytes());
            bytes_to_hex(&hasher.finalize())
        };

        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, "s3");
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            "AWS4-HMAC-SHA256", amz_date, credential_scope, hashed_canonical_request
        );

        // Derive signing key
        let k_date = hmac_sha256(
            format!("AWS4{}", secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, b"s3");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");

        // Calculate signature
        let signature = bytes_to_hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            access_key, credential_scope, signed_headers, signature
        );

        let mut request = ureq::put(&url)
            .set("host", &host_header_val)
            .set("x-amz-date", &amz_date)
            .set("x-amz-content-sha256", &payload_hash)
            .set("Authorization", &authorization)
            .set("Content-Type", "application/octet-stream");

        if let Some(ref token) = session_token {
            request = request.set("x-amz-security-token", token);
        }

        let response = request.send_bytes(&buffer);

        match response {
            Ok(_) => Ok(()),
            Err(e) => Err(UploadError::Network(format!("S3 upload failed: {}", e))),
        }
    }

    fn upload_to_gcs(&self, local_path: &Path, bucket: &str, key: &str) -> Result<(), UploadError> {
        let url = format!(
            "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            bucket, key
        );

        if self.dry_run {
            return Ok(());
        }

        let token = std::env::var("GCS_OAUTH_TOKEN").map_err(|_| {
            UploadError::Authentication(
                "GCS_OAUTH_TOKEN authorization credential is missing".to_string(),
            )
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

    fn upload_to_azure(
        &self,
        local_path: &Path,
        container: &str,
        blob: &str,
    ) -> Result<(), UploadError> {
        if self.dry_run {
            return Ok(());
        }

        let account = std::env::var("AZURE_STORAGE_ACCOUNT").map_err(|_| {
            UploadError::Authentication("AZURE_STORAGE_ACCOUNT is missing".to_string())
        })?;
        let url = format!(
            "https://{}.blob.core.windows.net/{}/{}",
            account, container, blob
        );

        let sas_token = std::env::var("AZURE_STORAGE_SAS_TOKEN").map_err(|_| {
            UploadError::Authentication(
                "AZURE_STORAGE_SAS_TOKEN SAS credential is missing".to_string(),
            )
        })?;

        let mut file = File::open(local_path)
            .map_err(|e| UploadError::Network(format!("Failed to open payload: {}", e)))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| UploadError::Network(format!("Failed to read payload: {}", e)))?;

        let clean_sas = sas_token.trim_start_matches('?');
        let full_url = format!("{}?{}", url, clean_sas);
        let response = ureq::put(&full_url)
            .set("x-ms-blob-type", "BlockBlob")
            .set("Content-Type", "application/octet-stream")
            .send_bytes(&buffer);

        match response {
            Ok(_) => Ok(()),
            Err(e) => Err(UploadError::Network(format!(
                "Azure blob upload failed: {}",
                e
            ))),
        }
    }

    fn upload_to_github(
        &self,
        local_path: &Path,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<(), UploadError> {
        let url = format!(
            "https://uploads.github.com/repos/{}/{}/releases/tags/{}/assets",
            owner, repo, tag
        );

        if self.dry_run {
            return Ok(());
        }

        let token = std::env::var("GITHUB_TOKEN").map_err(|_| {
            UploadError::Authentication(
                "GITHUB_TOKEN authorization credential is missing".to_string(),
            )
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
            Err(e) => Err(UploadError::Network(format!(
                "GitHub Release upload failed: {}",
                e
            ))),
        }
    }
}

impl Uploader for UniversalUploader {
    fn upload(&self, local_path: &Path, target_uri: &str) -> Result<(), UploadError> {
        let destination = UploadDestination::parse(target_uri)?;

        match destination {
            UploadDestination::S3 { bucket, key } => self.upload_to_s3(local_path, &bucket, &key),
            UploadDestination::Gcs { bucket, key } => self.upload_to_gcs(local_path, &bucket, &key),
            UploadDestination::Azure { container, blob } => {
                self.upload_to_azure(local_path, &container, &blob)
            }
            UploadDestination::GitHub { owner, repo, tag } => {
                self.upload_to_github(local_path, &owner, &repo, &tag)
            }
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
        assert!(
            uploader
                .upload(&payload_path, "github://mock/repo/v1.0.0/release")
                .is_ok()
        );
    }

    #[test]
    fn test_aws_sigv4_key_derivation() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let date = "20150830";
        let region = "us-east-1";
        let service = "iam";

        let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");

        let k_signing_hex = bytes_to_hex(&k_signing);
        assert_eq!(
            k_signing_hex,
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }
}
