//! PackWiser CLI executable.
//!
//! Parses command line args and executes high-level packaging and scanning workflows.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use packwiser_compressor::{
    TarCompressor, TarGzCompressor, TarXzCompressor, TarZstCompressor, ZipCompressor,
};
use packwiser_core::{
    FileEntry, Hasher, PathMatcher, PipelineOptions, PolicyEnforcer, QualityEvaluator,
    SecretScanner, Signer,
};
use packwiser_ignore::IgnoreMatcher;
use packwiser_scanner::CredentialScanner;
use packwiser_signature::{self, Ed25519Signer};
use packwiser_uploader::UniversalUploader;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "packwiser",
    author = "PackWiser Maintainers",
    version = "0.1.0",
    about = "Secure. Intelligent. Reproducible Project Packaging.",
    long_about = "PackWiser combines code packaging, secret analysis, reproducibility scores, and signing verification into a unified toolchain."
)]
struct Cli {
    /// Output logs and findings in raw JSON format
    #[arg(long, global = true)]
    json: bool,

    /// Output verbose diagnostics for pipeline tracing
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Suppress status reports and write only errors
    #[arg(long, short, global = true)]
    quiet: bool,

    /// Simulate execution without writing final archive files
    #[arg(long, global = true)]
    dry_run: bool,

    /// Colorization choice for terminal output decoration
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto, global = true)]
    color: ColorChoice,

    /// Custom target output destination path for packaging
    #[arg(long, short, global = true)]
    output: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Copy, PartialEq, Eq, Debug)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate ignore files, check for secret leaks, and archive project
    Package {
        /// Target folder to package
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Path to a private key file for digital signing
        #[arg(long, help = "Optional path to a 32-byte raw Ed25519 private key file")]
        key_file: Option<PathBuf>,

        /// Target upload destination URI
        #[arg(long, help = "Optional cloud upload URI (e.g. s3://bucket/key)")]
        upload: Option<String>,
    },

    /// Run full vulnerability, credential, and secret leakage analysis
    Scan {
        /// Target folder to inspect
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Validate the digital signature, manifest files, and checksum hashes of an archive
    Verify {
        /// Path pointing to the target archive file
        archive_path: PathBuf,

        /// Path to a public key file for signature verification
        #[arg(long, help = "Path to a 32-byte raw Ed25519 public key file")]
        key_file: PathBuf,
    },
}

// Wrapper structures to bridge local crate functionalities with the core injection traits

struct HasherWrapper;
impl Hasher for HasherWrapper {
    fn calculate(&self, reader: &mut dyn Read) -> Result<HashMap<String, String>, std::io::Error> {
        let res = packwiser_checksum::calculate_checksums(reader)?;
        let mut map = HashMap::new();
        map.insert("sha256".to_string(), res.sha256);
        map.insert("sha512".to_string(), res.sha512);
        map.insert("blake3".to_string(), res.blake3);
        map.insert("crc32".to_string(), res.crc32);
        Ok(map)
    }
}

struct QualityEvaluatorWrapper;
impl QualityEvaluator for QualityEvaluatorWrapper {
    fn evaluate(&self, manifest: &packwiser_core::PackageManifest) -> u8 {
        packwiser_quality::calculate_quality_score(manifest)
    }
}

struct PolicyEnforcerWrapper {
    policy: packwiser_policy::PolicyConfig,
}
impl PolicyEnforcer for PolicyEnforcerWrapper {
    fn enforce(
        &self,
        manifest: &packwiser_core::PackageManifest,
        archive_size: u64,
        is_signed: bool,
    ) -> Result<(), Vec<String>> {
        packwiser_policy::validate_policy(manifest, archive_size, is_signed, &self.policy)
    }
}

fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Package {
            path,
            key_file,
            upload,
        } => {
            let canonical_root = fs::canonicalize(&path)
                .with_context(|| format!("Failed to canonicalize target path: {:?}", path))?;

            if !args.quiet && !args.json {
                println!("Evaluating workspace at: {:?}", canonical_root);
            }

            // 1. Gather all files and excluded entries
            let matcher = IgnoreMatcher::new(&canonical_root, &[]);
            let mut files = Vec::new();
            let mut excluded_files = Vec::new();
            collect_workspace_entries(
                &canonical_root,
                &canonical_root,
                &matcher,
                &mut files,
                &mut excluded_files,
            )?;

            // 2. Identify the language heuristics
            let language = detect_primary_language(&files);

            // 3. Determine output archive format and path
            let output_archive = args
                .output
                .clone()
                .unwrap_or_else(|| PathBuf::from("packwiser_archive.zip"));

            // 4. Instantiating compressor based on file extension
            let ext = output_archive
                .to_str()
                .unwrap_or("")
                .split('.')
                .collect::<Vec<&str>>();

            let is_tar_gz = ext.contains(&"tar") && ext.contains(&"gz");
            let is_tar_xz = ext.contains(&"tar") && ext.contains(&"xz");
            let is_tar_zst = ext.contains(&"tar") && ext.contains(&"zst");

            let compressor_box: Box<dyn packwiser_core::Compressor> = if is_tar_gz {
                Box::new(TarGzCompressor::default())
            } else if is_tar_xz {
                Box::new(TarXzCompressor::default())
            } else if is_tar_zst {
                Box::new(TarZstCompressor::default())
            } else if ext.contains(&"tar") {
                Box::new(TarCompressor)
            } else {
                Box::new(ZipCompressor::default())
            };

            // 5. Load policy constraints if present
            let policy_path = Path::new("policy.toml");
            let policy = packwiser_policy::load_policy(policy_path).unwrap_or_default();

            // 6. Load private key if configured
            let private_key = if let Some(ref path) = key_file {
                let mut f = File::open(path)
                    .with_context(|| format!("Failed to open signing key file {:?}", path))?;
                let mut buffer = Vec::new();
                f.read_to_end(&mut buffer)?;
                Some(buffer)
            } else {
                None
            };

            // 7. Initialize and trigger the unified PackagingPipeline orchestrator
            let scanner = CredentialScanner::new();
            let signer = Ed25519Signer;
            let uploader = UniversalUploader::new(args.dry_run);

            let pipeline = packwiser_core::PackagingPipeline::new(
                matcher,
                scanner,
                compressor_box,
                signer,
                uploader,
                QualityEvaluatorWrapper,
                PolicyEnforcerWrapper { policy },
                HasherWrapper,
            );

            let project_name = canonical_root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("project")
                .to_string();

            let pipeline_opts = PipelineOptions {
                project_name,
                version: "0.1.0".to_string(), // Default version
                output_archive: output_archive.clone(),
                private_key,
                upload_uri: upload,
                language,
            };

            let res = pipeline
                .run(&canonical_root, &files, &excluded_files, pipeline_opts)
                .context("Pipeline execution failed")?;

            // 8. Populate git metadata programmatically and save manifest.json
            let mut final_manifest = res.manifest;
            let (commit, branch) = packwiser_manifest::resolve_git_metadata(&canonical_root);
            final_manifest.git_commit = commit;
            final_manifest.git_branch = branch;

            let manifest_path = Path::new("manifest.json");
            packwiser_manifest::save_manifest(&final_manifest, manifest_path)
                .context("Failed to save manifest file")?;

            // 9. Report results
            if args.json {
                let output = serde_json::json!({
                    "manifest": final_manifest,
                    "archive_size": res.archive_size,
                    "signed": res.signature.is_some(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else if !args.quiet {
                println!("Packaging completed successfully!");
                println!(
                    "  Archive:          {:?} ({} bytes)",
                    output_archive, res.archive_size
                );
                println!("  Manifest:         {:?}", manifest_path);
                println!("  Quality Score:    {}/100", final_manifest.score);
                if final_manifest.git_commit.is_some() {
                    println!(
                        "  Reproducibility:  Git commit {} on branch {}",
                        final_manifest
                            .git_commit
                            .as_ref()
                            .unwrap_or(&"".to_string()),
                        final_manifest
                            .git_branch
                            .as_ref()
                            .unwrap_or(&"".to_string())
                    );
                }
                if res.signature.is_some() {
                    println!("  Signature:        {:?}.sig saved", output_archive);
                }
            }
        }
        Commands::Scan { path } => {
            let path = fs::canonicalize(&path)
                .with_context(|| format!("Failed to canonicalize target path: {:?}", path))?;

            if !args.quiet && !args.json {
                println!(
                    "Starting credentials and secret detection scan on {:?}",
                    path
                );
            }

            let matcher = IgnoreMatcher::new(&path, &[]);
            let scanner = CredentialScanner::new();

            let mut leaks = Vec::new();
            let mut files = Vec::new();
            let mut excluded_files = Vec::new();
            collect_workspace_entries(&path, &path, &matcher, &mut files, &mut excluded_files)?;

            for file in &files {
                let mut found = scanner.scan_file(&file.absolute_path)?;
                leaks.append(&mut found);
            }

            if args.json {
                let output = serde_json::json!({
                    "scanned_files": files.len(),
                    "secrets": leaks,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else if !args.quiet {
                println!("Scan completed successfully.");
                println!(
                    "Scanned {} files. Found {} potential leaks.",
                    files.len(),
                    leaks.len()
                );
                for leak in &leaks {
                    println!(
                        "  - [{:?}] File: {:?} (Line: {}) | Rule: {} | Masked: {}",
                        leak.severity,
                        leak.file_path,
                        leak.line_number,
                        leak.rule_name,
                        leak.masked_value
                    );
                }
            }
        }
        Commands::Verify {
            archive_path,
            key_file,
        } => {
            if !args.quiet {
                println!("Verifying digital signature of: {:?}", archive_path);
            }

            // Read archive bytes
            let mut f = File::open(&archive_path)
                .with_context(|| format!("Failed to open archive file: {:?}", archive_path))?;
            let mut archive_bytes = Vec::new();
            f.read_to_end(&mut archive_bytes)?;

            // Read signature bytes
            let sig_path = archive_path.with_extension(format!(
                "{}.sig",
                archive_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
            ));
            let mut sig_file = File::open(&sig_path)
                .with_context(|| format!("Failed to open signature file: {:?}", sig_path))?;
            let mut sig_bytes = Vec::new();
            sig_file.read_to_end(&mut sig_bytes)?;

            // Read public key
            let mut pub_key_file = File::open(&key_file)
                .with_context(|| format!("Failed to open public key file: {:?}", key_file))?;
            let mut pub_key_bytes = Vec::new();
            pub_key_file.read_to_end(&mut pub_key_bytes)?;

            let signer = Ed25519Signer;
            let verified = signer
                .verify(&archive_bytes, &sig_bytes, &pub_key_bytes)
                .context("Verification execution failed")?;

            if verified {
                if !args.quiet {
                    println!(
                        "Signature matches public key! Package integrity and authenticity VERIFIED."
                    );
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Authenticity check failed: digital signature does not match public key"
                ));
            }
        }
    }

    Ok(())
}

/// Helper method to recursively count and collect workspace elements.
fn collect_workspace_entries(
    root: &Path,
    current: &Path,
    matcher: &IgnoreMatcher,
    files: &mut Vec<FileEntry>,
    excluded: &mut Vec<PathBuf>,
) -> Result<()> {
    if matcher.is_ignored(current) {
        let rel = current.strip_prefix(root).unwrap_or(current).to_path_buf();
        excluded.push(rel);
        return Ok(());
    }

    if current.is_dir() {
        for entry in fs::read_dir(current)
            .with_context(|| format!("Failed to read directory {:?}", current))?
        {
            let entry = entry?;
            let path = entry.path();
            if matcher.is_ignored(&path) {
                let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                excluded.push(rel);
            } else if path.is_dir() {
                collect_workspace_entries(root, &path, matcher, files, excluded)?;
            } else {
                let size = path.metadata()?.len();
                let is_symlink = path.is_symlink();
                let file_type = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_string();
                let relative_path = path.strip_prefix(root).unwrap_or(&path).to_path_buf();

                files.push(FileEntry {
                    relative_path,
                    absolute_path: path,
                    size,
                    is_symlink,
                    file_type,
                });
            }
        }
    } else {
        let size = current.metadata()?.len();
        let is_symlink = current.is_symlink();
        let file_type = current
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        let relative_path = current.strip_prefix(root).unwrap_or(current).to_path_buf();

        files.push(FileEntry {
            relative_path,
            absolute_path: current.to_path_buf(),
            size,
            is_symlink,
            file_type,
        });
    }

    Ok(())
}

/// Detects the primary language of the files in the workspace.
fn detect_primary_language(files: &[FileEntry]) -> String {
    let mut counts = HashMap::new();
    for file in files {
        if !file.file_type.is_empty() {
            *counts.entry(file.file_type.clone()).or_insert(0) += 1;
        }
    }

    let mut primary = "Generic";
    let mut max = 0;
    for (ext, count) in &counts {
        if *count > max {
            max = *count;
            primary = match ext.as_str() {
                "rs" => "Rust",
                "py" => "Python",
                "js" | "ts" => "JavaScript",
                "go" => "Go",
                "java" | "kt" => "Java/Kotlin",
                _ => primary,
            };
        }
    }

    primary.to_string()
}
