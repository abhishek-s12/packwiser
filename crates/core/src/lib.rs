//! PackWiser Core Domain Library
//!
//! Exposes key traits, structures, and unified error types
//! that define the PackWiser domain model and drive clean dependencies.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// Represents the classification of a software project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectType {
    /// Rust cargo project
    Rust,
    /// Python poetry project
    PythonPoetry,
    /// Python standard pip project
    PythonPip,
    /// Node.js npm project
    NodeNpm,
    /// Node.js pnpm project
    NodePnpm,
    /// Node.js yarn project
    NodeYarn,
    /// Node.js bun project
    NodeBun,
    /// Go language project
    Go,
    /// Java maven project
    JavaMaven,
    /// Java gradle project
    JavaGradle,
    /// Flutter app project
    Flutter,
    /// Unknown/Generic project type
    Generic,
}

/// Metadata about a single file in the packaging pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path of the file from the workspace root
    pub relative_path: PathBuf,
    /// Absolute path of the file on the host filesystem
    pub absolute_path: PathBuf,
    /// Total file size in bytes
    pub size: u64,
    /// True if the entry points to a symbolic link
    pub is_symlink: bool,
    /// File type string (e.g. extension or mime classification)
    pub file_type: String,
}

/// Severity classification for security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Low severity, informational or minor risk
    Low,
    /// Medium severity, possible credential exposure
    Medium,
    /// High severity, confirmed credential exposure
    High,
    /// Critical severity, high-impact private keys or database access
    Critical,
}

/// Represents a detected secret leak within a file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretLeak {
    /// Relative path of the file containing the leak
    pub file_path: PathBuf,
    /// Line number where the secret was found (1-indexed)
    pub line_number: usize,
    /// Friendly name of the detection rule matched
    pub rule_name: String,
    /// Level of severity for this credential leak
    pub severity: Severity,
    /// Hashed value or masked version of the leak to avoid raw leakage
    pub masked_value: String,
}

/// Final packaged metadata configuration saved as `manifest.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Name of the packaged project
    pub project_name: String,
    /// Version of the package
    pub version: String,
    /// Associated git commit hash if available
    pub git_commit: Option<String>,
    /// Associated git branch name if available
    pub git_branch: Option<String>,
    /// ISO 8601 formatting of the build timestamp
    pub timestamp: String,
    /// Primary language classification detected
    pub language: String,
    /// Package quality score (0-100)
    pub score: u8,
    /// Hash verification table mapping format names to hexadecimal digests
    pub checksums: HashMap<String, String>,
    /// List of file entries successfully included in the archive
    pub files: Vec<PathBuf>,
    /// List of directories included
    pub directories: Vec<PathBuf>,
    /// List of files skipped due to ignore configurations
    pub excluded_files: Vec<PathBuf>,
    /// List of secret warnings generated during build execution
    pub secrets: Vec<SecretLeak>,
    /// Computed compression ratio of the final output package
    pub compression_ratio: f64,
    /// Target operating system where package was created
    pub os: String,
}

/// Unified error enum for Scanner operations.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// I/O error reading the targeted files
    #[error("I/O error during scanning: {0}")]
    Io(#[from] std::io::Error),

    /// Regular expression failure during scan execution
    #[error("Regex execution failure: {0}")]
    Regex(#[from] regex::Error),

    /// General custom scan failure wrapper
    #[error("Scan failure: {0}")]
    Custom(String),
}

/// Unified error enum for Compressor operations.
#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    /// I/O error during read/write of stream blocks
    #[error("I/O error during archiving: {0}")]
    Io(#[from] std::io::Error),

    /// Formatting or encoder specific failure
    #[error("Archiver encoding failure: {0}")]
    Encoding(String),

    /// Path conversion failure
    #[error("Invalid path component in input: {0}")]
    InvalidPath(String),
}

/// Unified error enum for Signer operations.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// Key serialization or syntax failure
    #[error("Invalid signature key formatting: {0}")]
    InvalidKey(String),

    /// Hashing or signing execution failure
    #[error("Signing calculation failure: {0}")]
    Calculation(String),
}

/// Unified error enum for Uploader operations.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// Network connection or protocol timeout
    #[error("Network connection error: {0}")]
    Network(String),

    /// Authentication credential rejection
    #[error("Authentication failed: {0}")]
    Authentication(String),
}

/// Unified package orchestrator pipeline error.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// Core scanner failure bubbling up
    #[error("Scanning error occurred: {0}")]
    Scan(#[from] ScanError),

    /// Compression failure bubbling up
    #[error("Compression error occurred: {0}")]
    Compression(#[from] CompressionError),

    /// Signature failure bubbling up
    #[error("Signature error occurred: {0}")]
    Signature(#[from] SignatureError),

    /// Upload failure bubbling up
    #[error("Upload error occurred: {0}")]
    Upload(#[from] UploadError),

    /// SBOM failure bubbling up
    #[error("SBOM error occurred: {0}")]
    Sbom(#[from] SbomError),

    /// License scanning failure bubbling up
    #[error("License scanning error occurred: {0}")]
    License(#[from] LicenseError),

    /// Plugin system failure bubbling up
    #[error("Plugin error occurred: {0}")]
    Plugin(#[from] PluginError),

    /// Configuration engine failure bubbling up
    #[error("Configuration error occurred: {0}")]
    Config(#[from] ConfigError),

    /// Smart project stack detection failure bubbling up
    #[error("Detection error occurred: {0}")]
    Detection(#[from] DetectionError),

    /// Report compilation failure bubbling up
    #[error("Report generation error occurred: {0}")]
    Report(#[from] ReportError),

    /// Policy check violation triggering abort
    #[error("Policy compliance check failed: {0}")]
    PolicyViolation(String),
}

/// Unified error type for report generator failures.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// IO formatting write issue
    #[error("Failed to write report output contents: {0}")]
    Write(String),
}

/// Detailed data structure representing scanner results needed to format reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportInput {
    /// Unique name of the project
    pub project_name: String,
    /// Resolved semantic version
    pub version: String,
    /// Total count of scanned files
    pub total_files_scanned: usize,
    /// Total count of excluded files
    pub total_files_ignored: usize,
    /// Final compressed package archive size in bytes
    pub archive_size_bytes: u64,
    /// Final archive compression ratio (e.g. 2.45)
    pub compression_ratio: f32,
    /// Unified packaging quality score (0 - 100)
    pub quality_score: u8,
    /// Array of detected secret identifiers (masked for safety)
    pub secrets_detected: Vec<String>,
    /// System warning notifications
    pub warnings: Vec<String>,
    /// Actionable optimization updates
    pub recommendations: Vec<String>,
}

/// Trait defining report compiler capabilities.
pub trait ReportGenerator {
    /// Formats findings as a clean GitHub-Flavored Markdown report.
    fn generate_markdown(&self, input: &ReportInput) -> Result<String, ReportError>;
    /// Compiles findings into an interactive dashboard HTML page.
    fn generate_html(&self, input: &ReportInput) -> Result<String, ReportError>;
    /// Formats findings into standard SARIF static analysis security format.
    fn generate_sarif(&self, input: &ReportInput) -> Result<String, ReportError>;
}

/// Unified error type for project stack auto-detection issues.
#[derive(Debug, thiserror::Error)]
pub enum DetectionError {
    /// Read error loading manifest file from workspace
    #[error("Failed to read directory/file: {0}")]
    Read(String),

    /// Parse error deserializing manifest files
    #[error("Failed to parse manifest: {0}")]
    Parse(String),
}

/// Represents a specific technology stack or framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProjectStack {
    Rust,
    Go,
    Node,
    React,
    NextJs,
    Nuxt,
    Angular,
    Vue,
    Python,
    Django,
    FastApi,
    Java,
    Kotlin,
    SpringBoot,
    DotNet,
    Flutter,
    Swift,
    Android,
    Ios,
    Unity,
    Unreal,
    CMake,
    Monorepo,
    Generic,
}

/// The result returned on successful workspace auto-detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// Array of detected stacks/frameworks
    pub stacks: Vec<ProjectStack>,
    /// Array of recommended ignore patterns
    pub recommended_ignores: Vec<String>,
}

/// Trait defining project detection operations.
pub trait ProjectDetector {
    /// Scans the target workspace root to autodetect its technology stacks.
    fn detect(&self, workspace_root: &Path) -> Result<DetectionResult, DetectionError>;
}

/// Unified error type for configuration loader failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Read error loading config file
    #[error("Failed to read configuration file: {0}")]
    Read(String),

    /// Parse error deserializing config (toml/json)
    #[error("Failed to parse configuration TOML contents: {0}")]
    Parse(String),

    /// Profile lookup failure
    #[error("Requested profile {0} is not defined in configuration")]
    ProfileNotFound(String),
}

/// Represents a single configuration profile's settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigProfile {
    /// Target compression file format (e.g. "zip", "tar.gz")
    pub compression_format: Option<String>,
    /// Minimum allowed policy quality score
    pub min_quality_score: Option<u8>,
    /// Disallow secret leaks
    pub no_secrets: Option<bool>,
    /// Require digital signature
    pub require_signature: Option<bool>,
    /// Remote target uploader URI
    pub upload_target: Option<String>,
}

/// Represents the complete loaded config manifest containing profiles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackWiserConfig {
    /// Map of profiles (e.g. "release", "ci", "backup", "distribution")
    pub profiles: HashMap<String, ConfigProfile>,
}

/// Trait defining config loader routing and resolution.
pub trait ConfigLoader {
    /// Loads combined configurations from Global -> User -> Workspace locations.
    fn load_config(&self, workspace_root: &Path) -> Result<PackWiserConfig, ConfigError>;
}

/// Unified error type for plugin system failures.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// Read error loading plugin manifest
    #[error("Failed to read plugin directory/file: {0}")]
    Read(String),

    /// Parse error deserializing plugin manifest (toml/json)
    #[error("Failed to parse plugin manifest: {0}")]
    Parse(String),

    /// Execution failure running a plugin shell script or hook
    #[error("Plugin hook command execution failed: {0}")]
    Execution(String),
}

/// Represents a custom language registration from a plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomLanguage {
    /// Identifier name (e.g. "my-lang")
    pub name: String,
    /// Associated file extension list (e.g. ["xyz"])
    pub extensions: Vec<String>,
}

/// Represents a custom secret leakage detection rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustomSecretRule {
    /// Name identifier of the custom rule
    pub name: String,
    /// Regular expression pattern matching targets
    pub regex: String,
    /// Minimum Shannon entropy threshold to check (optional)
    pub entropy_threshold: Option<f32>,
}

/// Represents a custom compressor hook contributing command execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomCompressorHook {
    /// Supported archive format suffix (e.g. "xyz")
    pub format: String,
    /// Absolute or relative command string executing compression, receiving inputs.
    pub command: String,
}

/// Represents a custom remote upload provider hook.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomUploaderHook {
    /// Scheme format identifier matching (e.g. "myscheme")
    pub scheme: String,
    /// Command string executing upload, passing archive and target parameters.
    pub command: String,
}

/// Represents the complete loaded plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    /// Unique name identifying the plugin
    pub name: String,
    /// Version constraints
    pub version: String,
    /// Languages contributed by this plugin
    pub languages: Vec<CustomLanguage>,
    /// Secret scanner rules contributed by this plugin
    pub secret_rules: Vec<CustomSecretRule>,
    /// Compression format handlers
    pub compressors: Vec<CustomCompressorHook>,
    /// Custom upload handlers
    pub uploaders: Vec<CustomUploaderHook>,
}

/// Trait defining plugin registry loader.
pub trait PluginEngine {
    /// Scans the target directory, loading and validating all plugin manifests.
    fn load_plugins(&self, plugins_dir: &Path) -> Result<Vec<PluginManifest>, PluginError>;
}

/// Unified error type for license scanning issues.
#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    /// Read error loading source file for header scanning
    #[error("Failed to read source file for license scanning: {0}")]
    Read(String),

    /// Custom error type
    #[error("License scanner failure: {0}")]
    Scan(String),
}

/// Represents a specific license check result for a single file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LicenseFinding {
    /// Relative path to target file
    pub file_path: PathBuf,
    /// Matching license code (e.g. MIT, Apache-2.0)
    pub license_type: String,
    /// Confidence probability (0.0 to 1.0)
    pub confidence: f32,
}

/// Represents the comprehensive project license compliance report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LicenseReport {
    /// Aggregated general project license suggestion
    pub project_license: String,
    /// Detailed file level license finding list
    pub findings: Vec<LicenseFinding>,
}

/// Trait defining license scanning operations.
pub trait LicenseScanner {
    /// Scans the workspace files to resolve compliance findings and reports.
    fn scan_licenses(&self, files: &[FileEntry]) -> Result<LicenseReport, LicenseError>;
}

/// Unified error type for SBOM generation issues.
#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    /// Read error loading manifest file from workspace
    #[error("Failed to read dependency descriptor: {0}")]
    Read(String),
    
    /// Parse error deserializing manifest files (json/toml)
    #[error("Failed to parse dependency contents: {0}")]
    Parse(String),

    /// Formatting error generating CycloneDX or SPDX structures
    #[error("Format serialization failed: {0}")]
    Serialization(String),
}

/// Represents a software package dependency scanned from the workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    /// Name of dependency
    pub name: String,
    /// Exact target version constraint
    pub version: String,
    /// Package URL identifier if available
    pub purl: Option<String>,
}

/// Supported compliance output formats for SBOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SbomFormat {
    /// CycloneDX JSON format
    CycloneDX,
    /// SPDX JSON format
    Spdx,
}

/// Trait defining dependency scanning and SBOM file generation.
pub trait SbomGenerator {
    /// Scans the workspace directory to detect package manifest dependencies.
    fn detect_dependencies(&self, workspace_root: &Path) -> Result<Vec<Dependency>, SbomError>;
    /// Serializes extracted dependency information into requested format text.
    fn generate_sbom(&self, dependencies: &[Dependency], format: SbomFormat) -> Result<String, SbomError>;
}

/// Trait defining the engine interface to evaluate file ignore exclusions.
pub trait PathMatcher {
    /// Evaluates if the targeted path should be excluded based on configured rules.
    fn is_ignored(&self, path: &Path) -> bool;
}

/// Trait defining the client interface to scan file contents for potential secret leaks.
pub trait SecretScanner {
    /// Analyzes a targeted path returning the lists of found credentials.
    fn scan_file(&self, path: &Path) -> Result<Vec<SecretLeak>, ScanError>;
}

/// Trait defining the streaming archival interface.
pub trait Compressor {
    /// Compresses a collection of file entries into a generic write stream.
    ///
    /// The progress function callback accepts the total accumulated bytes processed.
    fn compress(
        &self,
        files: &[FileEntry],
        output: &mut dyn Write,
        progress: Box<dyn Fn(u64) + Send>,
    ) -> Result<u64, CompressionError>;
}

impl<T: ?Sized + Compressor> Compressor for Box<T> {
    fn compress(
        &self,
        files: &[FileEntry],
        output: &mut dyn Write,
        progress: Box<dyn Fn(u64) + Send>,
    ) -> Result<u64, CompressionError> {
        (**self).compress(files, output, progress)
    }
}

/// Trait defining digital signing operations.
pub trait Signer {
    /// Calculates signature over bytes using private key.
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, SignatureError>;
    /// Verifies digital signature over bytes using public key.
    fn verify(&self, data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, SignatureError>;
}

/// Trait defining remote target upload operations.
pub trait Uploader {
    /// Uploads local file payload directly to target URI.
    fn upload(&self, local_path: &Path, target_uri: &str) -> Result<(), UploadError>;
}

/// Trait defining the engine to evaluate package quality score.
pub trait QualityEvaluator {
    /// Computes the rating score (0-100) of the package.
    fn evaluate(&self, manifest: &PackageManifest) -> u8;
}

/// Trait defining policy enforcement.
pub trait PolicyEnforcer {
    /// Enforces validation check constraints over manifest and packaging stats.
    fn enforce(
        &self,
        manifest: &PackageManifest,
        archive_size: u64,
        is_signed: bool,
    ) -> Result<(), Vec<String>>;
}

/// Trait defining hash generation.
pub trait Hasher {
    /// Computes checksums mapping for the target reader.
    fn calculate(&self, reader: &mut dyn Read) -> Result<HashMap<String, String>, std::io::Error>;
}

/// Configuration options to execute the packaging pipeline.
#[derive(Debug, Clone)]
pub struct PipelineOptions {
    /// Name of the project
    pub project_name: String,
    /// Target package version
    pub version: String,
    /// Destination archive file path
    pub output_archive: PathBuf,
    /// Custom path for signing public/private keys
    pub private_key: Option<Vec<u8>>,
    /// Target cloud upload destination URI
    pub upload_uri: Option<String>,
    /// Language classification
    pub language: String,
}

/// The result returned on successful pipeline packaging execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    /// Generated manifest description
    pub manifest: PackageManifest,
    /// Total byte size of final archive
    pub archive_size: u64,
    /// Hashed signature bytes if signed
    pub signature: Option<Vec<u8>>,
}

/// Cohesive pipeline runner orchestration that executes the packaging steps.
pub struct PackagingPipeline<M, S, C, G, U, Q, P, H> {
    matcher: M,
    scanner: S,
    compressor: C,
    signer: G,
    uploader: U,
    quality: Q,
    policy: P,
    hasher: H,
}

impl<M, S, C, G, U, Q, P, H> PackagingPipeline<M, S, C, G, U, Q, P, H>
where
    M: PathMatcher,
    S: SecretScanner,
    C: Compressor,
    G: Signer,
    U: Uploader,
    Q: QualityEvaluator,
    P: PolicyEnforcer,
    H: Hasher,
{
    /// Creates a new `PackagingPipeline` wiring all core traits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        matcher: M,
        scanner: S,
        compressor: C,
        signer: G,
        uploader: U,
        quality: Q,
        policy: P,
        hasher: H,
    ) -> Self {
        Self {
            matcher,
            scanner,
            compressor,
            signer,
            uploader,
            quality,
            policy,
            hasher,
        }
    }

    /// Runs the complete packaging orchestrator.
    pub fn run(
        &self,
        _workspace_root: &Path,
        files: &[FileEntry],
        excluded_files: &[PathBuf],
        opts: PipelineOptions,
    ) -> Result<PipelineResult, PipelineError> {
        // 1. Scan for secrets in the list of files
        let mut secrets = Vec::new();
        for file in files {
            if !self.matcher.is_ignored(&file.absolute_path) {
                let mut file_secrets = self.scanner.scan_file(&file.absolute_path)?;
                secrets.append(&mut file_secrets);
            }
        }

        // 2. Perform compression into output archive path
        let output_file = File::create(&opts.output_archive)
            .map_err(|e| CompressionError::Io(e))?;
        let mut writer = std::io::BufWriter::new(output_file);
        
        let _ = self.compressor.compress(
            files,
            &mut writer,
            Box::new(|_| {}),
        )?;
        writer.flush().map_err(|e| CompressionError::Io(e))?;

        // 3. Compute checksums of the output file
        let mut check_file = File::open(&opts.output_archive)
            .map_err(|e| CompressionError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Failed to reopen archive: {:?}", e)
            )))?;
        let checksums = self.hasher.calculate(&mut check_file)
            .map_err(|e| CompressionError::Io(e))?;

        let archive_size = opts.output_archive.metadata()
            .map_err(|e| CompressionError::Io(e))?
            .len();

        // 4. Generate draft manifest
        let timestamp = chrono::Utc::now().to_rfc3339();
        let os = std::env::consts::OS.to_string();

        let mut manifest = PackageManifest {
            project_name: opts.project_name,
            version: opts.version,
            git_commit: None, // Will be populated by caller/manifest handler if git is resolved
            git_branch: None,
            timestamp,
            language: opts.language,
            score: 0,
            checksums,
            files: files.iter().map(|f| f.relative_path.clone()).collect(),
            directories: Vec::new(),
            excluded_files: excluded_files.to_vec(),
            secrets,
            compression_ratio: 1.0, // Simplification
            os,
        };

        // 5. Evaluate quality score
        let score = self.quality.evaluate(&manifest);
        manifest.score = score;

        // 6. Check signature requirements
        let is_signed = opts.private_key.is_some();
        
        // 7. Enforce policy check rules
        if let Err(violations) = self.policy.enforce(&manifest, archive_size, is_signed) {
            // Delete output archive to prevent releasing uncompliant builds
            let _ = std::fs::remove_file(&opts.output_archive);
            return Err(PipelineError::PolicyViolation(violations.join("; ")));
        }

        // 8. Sign the archive if private key is supplied
        let signature = if let Some(ref key) = opts.private_key {
            // Read archive bytes to sign
            let mut archive_file = File::open(&opts.output_archive)
                .map_err(|e| CompressionError::Io(e))?;
            let mut archive_bytes = Vec::new();
            archive_file.read_to_end(&mut archive_bytes)
                .map_err(|e| CompressionError::Io(e))?;

            let sig = self.signer.sign(&archive_bytes, key)?;
            
            // Save signature file
            let sig_path = opts.output_archive.with_extension(format!(
                "{}.sig",
                opts.output_archive.extension().and_then(|e| e.to_str()).unwrap_or("")
            ));
            let mut sig_file = File::create(sig_path).map_err(|e| CompressionError::Io(e))?;
            sig_file.write_all(&sig).map_err(|e| CompressionError::Io(e))?;
            sig_file.flush().map_err(|e| CompressionError::Io(e))?;

            Some(sig)
        } else {
            None
        };

        // 9. Upload package if target URI is configured
        if let Some(ref uri) = opts.upload_uri {
            self.uploader.upload(&opts.output_archive, uri)?;
        }

        Ok(PipelineResult {
            manifest,
            archive_size,
            signature,
        })
    }
}

