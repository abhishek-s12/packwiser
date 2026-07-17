//! Dynamic plugin registry and script execution hook adapter for PackWiser.
//!
//! Enforces decoupling by letting users declare custom languages, regex secret rules,
//! and command hooks that delegate compression and uploading to subprocesses.

use packwiser_core::{PluginEngine, PluginError, PluginManifest};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default implementation of the `PluginEngine` trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPluginEngine;

impl DefaultPluginEngine {
    /// Creates a new `DefaultPluginEngine`.
    pub fn new() -> Self {
        Self
    }

    /// Helper to execute a custom compressor hook command via subprocess.
    ///
    /// Receives a list of input file paths and the output archive path, replaces
    /// `{input}` and `{output}` placeholders, and runs the command.
    pub fn execute_compressor(
        &self,
        program: &str,
        args: &[String],
        allow_shell: bool,
        input_files: &[PathBuf],
        output_archive: &Path,
    ) -> Result<(), PluginError> {
        let expanded_args = expand_compressor_args(args, input_files, output_archive);

        if allow_shell {
            let cmd_string = format!("{} {}", program, expanded_args.join(" "));
            execute_shell_command(&cmd_string)
        } else {
            let status = Command::new(program)
                .args(&expanded_args)
                .status()
                .map_err(|e| {
                    PluginError::Execution(format!("Failed to execute compressor command: {}", e))
                })?;
            if status.success() {
                Ok(())
            } else {
                Err(PluginError::Execution(format!(
                    "Compressor command returned non-zero exit status: {:?}",
                    status.code()
                )))
            }
        }
    }

    /// Helper to execute a custom uploader hook command.
    ///
    /// Replaces `{archive}` and `{uri}` parameters, and executes the command subprocess.
    pub fn execute_uploader(
        &self,
        program: &str,
        args: &[String],
        allow_shell: bool,
        archive_path: &Path,
        target_uri: &str,
    ) -> Result<(), PluginError> {
        let expanded_args = expand_uploader_args(args, archive_path, target_uri);

        if allow_shell {
            let cmd_string = format!("{} {}", program, expanded_args.join(" "));
            execute_shell_command(&cmd_string)
        } else {
            let status = Command::new(program)
                .args(&expanded_args)
                .status()
                .map_err(|e| {
                    PluginError::Execution(format!("Failed to execute uploader command: {}", e))
                })?;
            if status.success() {
                Ok(())
            } else {
                Err(PluginError::Execution(format!(
                    "Uploader command returned non-zero exit status: {:?}",
                    status.code()
                )))
            }
        }
    }
}

fn expand_compressor_args(
    args: &[String],
    input_files: &[PathBuf],
    output_archive: &Path,
) -> Vec<String> {
    let mut expanded = Vec::new();
    let output_str = output_archive.to_string_lossy().into_owned();

    for arg in args {
        if arg == "{input}" {
            for file in input_files {
                expanded.push(file.to_string_lossy().into_owned());
            }
        } else {
            let replaced = arg
                .replace(
                    "{input}",
                    &input_files
                        .iter()
                        .map(|p| p.to_string_lossy().into_owned())
                        .collect::<Vec<String>>()
                        .join(" "),
                )
                .replace("{output}", &output_str);
            expanded.push(replaced);
        }
    }
    expanded
}

fn expand_uploader_args(args: &[String], archive_path: &Path, target_uri: &str) -> Vec<String> {
    let archive_str = archive_path.to_string_lossy().into_owned();
    args.iter()
        .map(|arg| {
            arg.replace("{archive}", &archive_str)
                .replace("{uri}", target_uri)
        })
        .collect()
}

impl PluginEngine for DefaultPluginEngine {
    fn load_plugins(&self, plugins_dir: &Path) -> Result<Vec<PluginManifest>, PluginError> {
        if !plugins_dir.exists() || !plugins_dir.is_dir() {
            return Ok(Vec::new());
        }

        let mut plugins = Vec::new();

        for entry in fs::read_dir(plugins_dir)
            .map_err(|e| PluginError::Read(format!("Failed to read plugins directory: {}", e)))?
        {
            let entry = entry.map_err(|e| {
                PluginError::Read(format!("Failed to access plugin directory entry: {}", e))
            })?;
            let path = entry.path();
            if path.is_dir() {
                let manifest_path = path.join("plugin.toml");
                if manifest_path.exists() {
                    let content = fs::read_to_string(&manifest_path).map_err(|e| {
                        PluginError::Read(format!(
                            "Failed to read plugin manifest {:?}: {}",
                            manifest_path, e
                        ))
                    })?;
                    let manifest: PluginManifest = toml::from_str(&content).map_err(|e| {
                        PluginError::Parse(format!(
                            "Failed to parse plugin manifest {:?}: {}",
                            manifest_path, e
                        ))
                    })?;
                    plugins.push(manifest);
                }
            }
        }

        Ok(plugins)
    }
}

/// Runs a command string inside the platform's default shell environment.
fn execute_shell_command(cmd_string: &str) -> Result<(), PluginError> {
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = Command::new("powershell");
        c.arg("-Command").arg(cmd_string);
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut command = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmd_string);
        c
    };

    let status = command
        .status()
        .map_err(|e| PluginError::Execution(format!("Failed to spawn shell subprocess: {}", e)))?;

    if status.success() {
        Ok(())
    } else {
        Err(PluginError::Execution(format!(
            "Subprocess command returned non-zero exit status: {:?}",
            status.code()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_parse_plugin_manifest() {
        let content = r#"
name = "my-plugin"
version = "1.0.0"
allow_shell = true

[[languages]]
name = "MyCustomLang"
extensions = ["xyz", "abc"]

[[secret_rules]]
name = "CustomToken"
regex = "xyz-[0-9a-f]{32}"
entropy_threshold = 5.2

[[compressors]]
format = "xyz"
command = "zip"
args = ["-r", "{output}", "{input}"]

[[uploaders]]
scheme = "myscheme"
command = "curl"
args = ["-T", "{archive}", "{uri}"]
"#;

        let manifest: PluginManifest = toml::from_str(content).unwrap();
        assert_eq!(manifest.name, "my-plugin");
        assert!(manifest.allow_shell);
        assert_eq!(manifest.languages.len(), 1);
        assert_eq!(manifest.languages[0].name, "MyCustomLang");
        assert_eq!(manifest.languages[0].extensions, vec!["xyz", "abc"]);
        assert_eq!(manifest.secret_rules[0].name, "CustomToken");
        assert_eq!(manifest.compressors[0].format, "xyz");
        assert_eq!(manifest.compressors[0].command, "zip");
        assert_eq!(
            manifest.compressors[0].args,
            vec![
                "-r".to_string(),
                "{output}".to_string(),
                "{input}".to_string()
            ]
        );
        assert_eq!(manifest.uploaders[0].scheme, "myscheme");
        assert_eq!(manifest.uploaders[0].command, "curl");
        assert_eq!(
            manifest.uploaders[0].args,
            vec![
                "-T".to_string(),
                "{archive}".to_string(),
                "{uri}".to_string()
            ]
        );
    }

    #[test]
    fn test_load_plugins_from_directory() {
        let temp_dir = tempdir().unwrap();
        let plugin_sub_dir = temp_dir.path().join("my-cool-plugin");
        fs::create_dir(&plugin_sub_dir).unwrap();

        let toml_content = r#"
name = "my-cool-plugin"
version = "2.1.0"
languages = []
secret_rules = []
compressors = []
uploaders = []
"#;
        fs::write(plugin_sub_dir.join("plugin.toml"), toml_content).unwrap();

        let engine = DefaultPluginEngine::new();
        let plugins = engine.load_plugins(temp_dir.path()).unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "my-cool-plugin");
        assert_eq!(plugins[0].version, "2.1.0");
        assert!(!plugins[0].allow_shell); // defaults to false
    }

    #[test]
    fn test_execute_shell_echo_command() {
        let engine = DefaultPluginEngine::new();
        let command_string = "echo 'Executing packwiser task'";
        assert!(execute_shell_command(command_string).is_ok());

        // Placeholders replacement
        let archive = Path::new("test.zip");
        assert!(
            engine
                .execute_uploader(
                    "echo",
                    &[
                        "{archive}".to_string(),
                        "to".to_string(),
                        "{uri}".to_string()
                    ],
                    true,
                    archive,
                    "s3://mybucket"
                )
                .is_ok()
        );

        // Subprocess (no-shell) execution test using cargo --version (which is a standalone binary)
        assert!(
            engine
                .execute_uploader(
                    "cargo",
                    &[
                        "--version".to_string(),
                        "{archive}".to_string(),
                        "{uri}".to_string()
                    ],
                    false,
                    archive,
                    "s3://mybucket"
                )
                .is_ok()
        );
    }
}
