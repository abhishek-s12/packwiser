//! SBOM (Software Bill of Materials) scanner and compliance report generator.
//!
//! Provides workspace package manifest parsing and standard formatting to CycloneDX and SPDX.

use packwiser_core::{Dependency, SbomError, SbomFormat, SbomGenerator};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use toml::Value;

/// Default implementation of the `SbomGenerator` trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultSbomGenerator;

impl DefaultSbomGenerator {
    /// Creates a new `DefaultSbomGenerator`.
    pub fn new() -> Self {
        Self
    }

    fn parse_cargo_toml(&self, path: &Path) -> Result<Vec<Dependency>, SbomError> {
        let content = fs::read_to_string(path)
            .map_err(|e| SbomError::Read(format!("Failed to read Cargo.toml: {}", e)))?;

        let parsed: Value = toml::from_str(&content)
            .map_err(|e| SbomError::Parse(format!("Failed to parse Cargo.toml: {}", e)))?;

        let mut deps = Vec::new();

        // Check for dependencies, dev-dependencies, build-dependencies
        let dep_keys = ["dependencies", "dev-dependencies", "build-dependencies"];
        for key in &dep_keys {
            if let Some(table) = parsed.get(*key).and_then(|v| v.as_table()) {
                for (name, val) in table {
                    let version = match val {
                        Value::String(s) => s.clone(),
                        Value::Table(t) => {
                            if let Some(Value::String(ver)) = t.get("version") {
                                ver.clone()
                            } else if t.contains_key("workspace") {
                                "workspace".to_string()
                            } else if t.contains_key("path") {
                                "local-path".to_string()
                            } else {
                                "unknown".to_string()
                            }
                        }
                        _ => "unknown".to_string(),
                    };

                    let purl = Some(format!("pkg:cargo/{}@{}", name, version));
                    deps.push(Dependency {
                        name: name.clone(),
                        version,
                        purl,
                    });
                }
            }
        }

        // Also check workspace dependencies
        if let Some(workspace) = parsed.get("workspace").and_then(|w| w.as_table())
            && let Some(table) = workspace.get("dependencies").and_then(|d| d.as_table())
        {
            for (name, val) in table {
                let version = match val {
                    Value::String(s) => s.clone(),
                    Value::Table(t) => {
                        if let Some(Value::String(ver)) = t.get("version") {
                            ver.clone()
                        } else {
                            "workspace-spec".to_string()
                        }
                    }
                    _ => "workspace-spec".to_string(),
                };
                let purl = Some(format!("pkg:cargo/{}@{}", name, version));
                deps.push(Dependency {
                    name: name.clone(),
                    version,
                    purl,
                });
            }
        }

        Ok(deps)
    }

    fn parse_package_json(&self, path: &Path) -> Result<Vec<Dependency>, SbomError> {
        let content = fs::read_to_string(path)
            .map_err(|e| SbomError::Read(format!("Failed to read package.json: {}", e)))?;

        let parsed: JsonValue = serde_json::from_str(&content)
            .map_err(|e| SbomError::Parse(format!("Failed to parse package.json: {}", e)))?;

        let mut deps = Vec::new();
        let dep_keys = ["dependencies", "devDependencies"];

        for key in &dep_keys {
            if let Some(obj) = parsed.get(*key).and_then(|v| v.as_object()) {
                for (name, val) in obj {
                    if let Some(version) = val.as_str() {
                        let purl = Some(format!("pkg:npm/{}@{}", name, version));
                        deps.push(Dependency {
                            name: name.clone(),
                            version: version.to_string(),
                            purl,
                        });
                    }
                }
            }
        }

        Ok(deps)
    }

    fn parse_requirements_txt(&self, path: &Path) -> Result<Vec<Dependency>, SbomError> {
        let content = fs::read_to_string(path)
            .map_err(|e| SbomError::Read(format!("Failed to read requirements.txt: {}", e)))?;

        let mut deps = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Split by operators like ==, >=, <=, >, <, ~=
            let operators = ["==", ">=", "<=", "~=", ">", "<"];
            let mut split_res = None;

            for op in &operators {
                if let Some(idx) = line.find(op) {
                    let name = line[..idx].trim().to_string();
                    let version = line[idx + op.len()..].trim().to_string();
                    split_res = Some((name, version));
                    break;
                }
            }

            if let Some((name, version)) = split_res {
                let purl = Some(format!("pkg:pypi/{}@{}", name, version));
                deps.push(Dependency {
                    name,
                    version,
                    purl,
                });
            } else {
                // Versionless requirement
                let name = line.to_string();
                let purl = Some(format!("pkg:pypi/{}@latest", name));
                deps.push(Dependency {
                    name,
                    version: "latest".to_string(),
                    purl,
                });
            }
        }

        Ok(deps)
    }
}

impl SbomGenerator for DefaultSbomGenerator {
    fn detect_dependencies(&self, workspace_root: &Path) -> Result<Vec<Dependency>, SbomError> {
        let mut all_deps = Vec::new();
        let mut checked = HashMap::new();

        // 1. Scan for Cargo.toml
        let cargo_path = workspace_root.join("Cargo.toml");
        if cargo_path.exists()
            && let Ok(mut deps) = self.parse_cargo_toml(&cargo_path)
        {
            for dep in deps.drain(..) {
                checked.insert(format!("cargo-{}", dep.name), dep);
            }
        }

        // 2. Scan for package.json
        let npm_path = workspace_root.join("package.json");
        if npm_path.exists()
            && let Ok(mut deps) = self.parse_package_json(&npm_path)
        {
            for dep in deps.drain(..) {
                checked.insert(format!("npm-{}", dep.name), dep);
            }
        }

        // 3. Scan for requirements.txt
        let py_path = workspace_root.join("requirements.txt");
        if py_path.exists()
            && let Ok(mut deps) = self.parse_requirements_txt(&py_path)
        {
            for dep in deps.drain(..) {
                checked.insert(format!("pypi-{}", dep.name), dep);
            }
        }

        for (_, dep) in checked {
            all_deps.push(dep);
        }

        all_deps.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all_deps)
    }

    fn generate_sbom(
        &self,
        dependencies: &[Dependency],
        format: SbomFormat,
    ) -> Result<String, SbomError> {
        let timestamp = chrono::Utc::now().to_rfc3339();

        match format {
            SbomFormat::CycloneDX => {
                let components: Vec<serde_json::Value> = dependencies
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "type": "library",
                            "name": d.name,
                            "version": d.version,
                            "purl": d.purl,
                        })
                    })
                    .collect();

                let cyclonedx = serde_json::json!({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
                    "version": 1,
                    "metadata": {
                        "timestamp": timestamp,
                        "tools": [
                            {
                                "vendor": "PackWiser",
                                "name": "PackWiser-SBOM",
                                "version": "0.1.0"
                            }
                        ]
                    },
                    "components": components
                });

                serde_json::to_string_pretty(&cyclonedx)
                    .map_err(|e| SbomError::Serialization(e.to_string()))
            }
            SbomFormat::Spdx => {
                let packages: Vec<serde_json::Value> = dependencies
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "name": d.name,
                            "SPDXID": format!("SPDXRef-Package-{}", d.name.replace(['_', '.'], "-")),
                            "versionInfo": d.version,
                            "downloadLocation": "NOASSERTION",
                            "filesAnalyzed": false,
                            "externalRefs": [
                                {
                                    "referenceCategory": "PACKAGE-MANAGER",
                                    "referenceType": "purl",
                                    "referenceLocator": d.purl.as_ref().unwrap_or(&"".to_string())
                                }
                            ]
                        })
                    })
                    .collect();

                let spdx = serde_json::json!({
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "SPDXID": "SPDXRef-DOCUMENT",
                    "name": "PackWiser-SBOM",
                    "documentNamespace": "https://packwiser.io/spdx/00000000-0000-0000-0000-000000000000",
                    "creationInfo": {
                        "created": timestamp,
                        "creators": [
                            "Tool: PackWiser-0.1.0"
                        ]
                    },
                    "packages": packages
                });

                serde_json::to_string_pretty(&spdx)
                    .map_err(|e| SbomError::Serialization(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_requirements_txt_parser() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("requirements.txt");
        let content = "\
# Requirements
requests==2.31.0
numpy>=1.24
gunicorn
";
        fs::write(&file_path, content).unwrap();

        let generator = DefaultSbomGenerator;
        let deps = generator.parse_requirements_txt(&file_path).unwrap();

        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.31.0");
        assert_eq!(deps[0].purl, Some("pkg:pypi/requests@2.31.0".to_string()));

        assert_eq!(deps[1].name, "numpy");
        assert_eq!(deps[1].version, "1.24");

        assert_eq!(deps[2].name, "gunicorn");
        assert_eq!(deps[2].version, "latest");
    }

    #[test]
    fn test_package_json_parser() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("package.json");
        let content = r#"{
            "name": "test-project",
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "4.17.21"
            },
            "devDependencies": {
                "typescript": "^5.0.0"
            }
        }"#;
        fs::write(&file_path, content).unwrap();

        let generator = DefaultSbomGenerator;
        let deps = generator.parse_package_json(&file_path).unwrap();

        assert_eq!(deps.len(), 3);

        let express = deps.iter().find(|d| d.name == "express").unwrap();
        assert_eq!(express.version, "^4.18.2");
        assert_eq!(express.purl, Some("pkg:npm/express@^4.18.2".to_string()));

        let ts = deps.iter().find(|d| d.name == "typescript").unwrap();
        assert_eq!(ts.version, "^5.0.0");
    }

    #[test]
    fn test_cargo_toml_parser() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("Cargo.toml");
        let content = r#"[package]
name = "my-rust-pkg"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.30", features = ["full"] }
"#;
        fs::write(&file_path, content).unwrap();

        let generator = DefaultSbomGenerator;
        let deps = generator.parse_cargo_toml(&file_path).unwrap();

        assert_eq!(deps.len(), 2);
        let serde = deps.iter().find(|d| d.name == "serde").unwrap();
        assert_eq!(serde.version, "1.0");

        let tokio = deps.iter().find(|d| d.name == "tokio").unwrap();
        assert_eq!(tokio.version, "1.30");
    }

    #[test]
    fn test_generate_sbom_formats() {
        let generator = DefaultSbomGenerator;
        let deps = vec![Dependency {
            name: "anyhow".to_string(),
            version: "1.0".to_string(),
            purl: Some("pkg:cargo/anyhow@1.0".to_string()),
        }];

        let cyclonedx_str = generator
            .generate_sbom(&deps, SbomFormat::CycloneDX)
            .unwrap();
        let cyclonedx_json: serde_json::Value = serde_json::from_str(&cyclonedx_str).unwrap();
        assert_eq!(cyclonedx_json["bomFormat"], "CycloneDX");
        assert_eq!(cyclonedx_json["components"][0]["name"], "anyhow");

        let spdx_str = generator.generate_sbom(&deps, SbomFormat::Spdx).unwrap();
        let spdx_json: serde_json::Value = serde_json::from_str(&spdx_str).unwrap();
        assert_eq!(spdx_json["spdxVersion"], "SPDX-2.3");
        assert_eq!(spdx_json["packages"][0]["name"], "anyhow");
    }
}
