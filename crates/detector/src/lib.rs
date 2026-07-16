//! Smart project stack and technology framework auto-detector for PackWiser.
//!
//! Scans workspaces recursively (filtering nested folders) to detect 20+ languages
//! and frameworks, returning recommended exclusions to prevent archiving dependencies and cache files.

use packwiser_core::{DetectionError, DetectionResult, ProjectDetector, ProjectStack};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Default implementation of the `ProjectDetector` trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicProjectDetector;

impl HeuristicProjectDetector {
    /// Creates a new `HeuristicProjectDetector`.
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Deserialize)]
struct DummyPackageJson {
    #[serde(default)]
    dependencies: std::collections::HashMap<String, String>,
    #[serde(default)]
    #[serde(rename = "devDependencies")]
    dev_dependencies: std::collections::HashMap<String, String>,
}

impl ProjectDetector for HeuristicProjectDetector {
    fn detect(&self, workspace_root: &Path) -> Result<DetectionResult, DetectionError> {
        let mut stacks = HashSet::new();
        let mut recommended_ignores = HashSet::new();

        if !workspace_root.exists() || !workspace_root.is_dir() {
            return Ok(DetectionResult {
                stacks: vec![ProjectStack::Generic],
                recommended_ignores: Vec::new(),
            });
        }

        // Recursively walk directory structure up to depth 3 to find indicator manifests.
        // Skips typical VCS and heavy dependency folders for performance.
        let mut paths_to_check = vec![(workspace_root.to_path_buf(), 0)];
        let mut manifest_counts = 0;

        while let Some((dir, depth)) = paths_to_check.pop() {
            if depth > 3 {
                continue;
            }

            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = path.file_name().unwrap_or_default().to_string_lossy();

                // Skip known dependency and version control directories
                if path.is_dir() {
                    let name_str = file_name.as_ref();
                    if name_str == ".git"
                        || name_str == "node_modules"
                        || name_str == "target"
                        || name_str == "Library"
                        || name_str == "Intermediate"
                    {
                        continue;
                    }
                    paths_to_check.push((path.clone(), depth + 1));

                    // Unity directory match check
                    if name_str == "Assets" && dir.join("ProjectSettings").exists() {
                        stacks.insert(ProjectStack::Unity);
                        recommended_ignores.insert("/Library".to_string());
                        recommended_ignores.insert("/Temp".to_string());
                        recommended_ignores.insert("/Obj".to_string());
                        recommended_ignores.insert("/Logs".to_string());
                        recommended_ignores.insert("/Build".to_string());
                    }
                    continue;
                }

                // File indicator heuristics
                let name_str = file_name.as_ref();

                if name_str == "Cargo.toml" {
                    stacks.insert(ProjectStack::Rust);
                    recommended_ignores.insert("/target".to_string());
                    manifest_counts += 1;
                } else if name_str == "go.mod" {
                    stacks.insert(ProjectStack::Go);
                    manifest_counts += 1;
                } else if name_str == "CMakeLists.txt" {
                    stacks.insert(ProjectStack::CMake);
                    recommended_ignores.insert("/build".to_string());
                    recommended_ignores.insert("CMakeFiles/".to_string());
                } else if name_str == "package.json" {
                    stacks.insert(ProjectStack::Node);
                    recommended_ignores.insert("/node_modules".to_string());
                    recommended_ignores.insert("/dist".to_string());
                    manifest_counts += 1;

                    // Parse package dependencies for web frameworks
                    if let Ok(content) = fs::read_to_string(&path)
                        && let Ok(pkg) = serde_json::from_str::<DummyPackageJson>(&content) {
                            let has_dep = |name: &str| {
                                pkg.dependencies.contains_key(name)
                                    || pkg.dev_dependencies.contains_key(name)
                            };
                            if has_dep("next") {
                                stacks.insert(ProjectStack::NextJs);
                                recommended_ignores.insert("/.next".to_string());
                            }
                            if has_dep("react") {
                                stacks.insert(ProjectStack::React);
                            }
                            if has_dep("vue") {
                                stacks.insert(ProjectStack::Vue);
                            }
                            if has_dep("nuxt") {
                                stacks.insert(ProjectStack::Nuxt);
                                recommended_ignores.insert("/.nuxt".to_string());
                            }
                            if has_dep("@angular/core") {
                                stacks.insert(ProjectStack::Angular);
                                recommended_ignores.insert("/.cache".to_string());
                            }
                        }
                } else if name_str == "requirements.txt"
                    || name_str == "pyproject.toml"
                    || name_str == "poetry.lock"
                    || name_str == "Pipfile"
                {
                    stacks.insert(ProjectStack::Python);
                    recommended_ignores.insert("**/__pycache__".to_string());
                    recommended_ignores.insert("**/*.pyc".to_string());
                    recommended_ignores.insert("/.venv".to_string());
                    recommended_ignores.insert("/venv".to_string());
                    manifest_counts += 1;

                    // Parse python metadata for web framework dependencies
                    if let Ok(content) = fs::read_to_string(&path) {
                        let lower = content.to_lowercase();
                        if lower.contains("django") || dir.join("manage.py").exists() {
                            stacks.insert(ProjectStack::Django);
                        }
                        if lower.contains("fastapi") {
                            stacks.insert(ProjectStack::FastApi);
                        }
                    }
                } else if name_str == "pom.xml"
                    || name_str == "build.gradle"
                    || name_str == "build.gradle.kts"
                {
                    stacks.insert(ProjectStack::Java);
                    recommended_ignores.insert("/build".to_string());
                    recommended_ignores.insert("/.gradle".to_string());
                    recommended_ignores.insert("**/target".to_string());
                    manifest_counts += 1;

                    if name_str.ends_with(".gradle.kts")
                        || (name_str == "build.gradle"
                            && path.extension().is_some_and(|ext| ext == "gradle"))
                    {
                        stacks.insert(ProjectStack::Kotlin);
                    }

                    if let Ok(content) = fs::read_to_string(&path)
                        && content.contains("spring-boot") {
                            stacks.insert(ProjectStack::SpringBoot);
                        }
                } else if path
                    .extension()
                    .is_some_and(|ext| ext == "csproj" || ext == "sln")
                {
                    stacks.insert(ProjectStack::DotNet);
                    recommended_ignores.insert("/bin".to_string());
                    recommended_ignores.insert("/obj".to_string());
                    manifest_counts += 1;
                } else if name_str == "pubspec.yaml" {
                    if let Ok(content) = fs::read_to_string(&path)
                        && content.contains("flutter:") {
                            stacks.insert(ProjectStack::Flutter);
                            recommended_ignores.insert("/.dart_tool".to_string());
                            recommended_ignores.insert("/build".to_string());
                            manifest_counts += 1;
                        }
                } else if name_str == "Package.swift"
                    || path
                        .extension()
                        .is_some_and(|ext| ext == "xcodeproj" || ext == "xcworkspace")
                {
                    stacks.insert(ProjectStack::Swift);
                    stacks.insert(ProjectStack::Ios);
                    recommended_ignores.insert("/build".to_string());
                    manifest_counts += 1;
                } else if name_str == "AndroidManifest.xml" {
                    stacks.insert(ProjectStack::Android);
                    recommended_ignores.insert("/build".to_string());
                    manifest_counts += 1;
                } else if path.extension().is_some_and(|ext| ext == "uproject") {
                    stacks.insert(ProjectStack::Unreal);
                    recommended_ignores.insert("/Binaries".to_string());
                    recommended_ignores.insert("/Build".to_string());
                    recommended_ignores.insert("/Intermediate".to_string());
                    recommended_ignores.insert("/Saved".to_string());
                    manifest_counts += 1;
                }
            }
        }

        // Monorepo check: multiple stack manifests nested in the tree structure
        if manifest_counts > 1 {
            stacks.insert(ProjectStack::Monorepo);
        }

        if stacks.is_empty() {
            stacks.insert(ProjectStack::Generic);
        }

        let mut final_stacks: Vec<ProjectStack> = stacks.into_iter().collect();
        // Sort stacks to guarantee stable order in results
        final_stacks.sort_by_key(|s| format!("{:?}", s));

        let mut final_ignores: Vec<String> = recommended_ignores.into_iter().collect();
        final_ignores.sort();

        Ok(DetectionResult {
            stacks: final_stacks,
            recommended_ignores: final_ignores,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_detect_rust_project() {
        let temp_dir = tempdir().unwrap();
        fs::write(temp_dir.path().join("Cargo.toml"), "[package]").unwrap();

        let detector = HeuristicProjectDetector::new();
        let result = detector.detect(temp_dir.path()).unwrap();

        assert_eq!(result.stacks, vec![ProjectStack::Rust]);
        assert_eq!(result.recommended_ignores, vec!["/target".to_string()]);
    }

    #[test]
    fn test_detect_node_nextjs_project() {
        let temp_dir = tempdir().unwrap();
        let pkg_content = r#"{
            "dependencies": {
                "react": "^18.2.0",
                "next": "^14.0.0"
            }
        }"#;
        fs::write(temp_dir.path().join("package.json"), pkg_content).unwrap();

        let detector = HeuristicProjectDetector::new();
        let result = detector.detect(temp_dir.path()).unwrap();

        assert!(result.stacks.contains(&ProjectStack::Node));
        assert!(result.stacks.contains(&ProjectStack::React));
        assert!(result.stacks.contains(&ProjectStack::NextJs));
        assert!(result.recommended_ignores.contains(&"/.next".to_string()));
        assert!(
            result
                .recommended_ignores
                .contains(&"/node_modules".to_string())
        );
    }

    #[test]
    fn test_detect_python_fastapi() {
        let temp_dir = tempdir().unwrap();
        fs::write(
            temp_dir.path().join("requirements.txt"),
            "fastapi==0.100.0\nuvicorn",
        )
        .unwrap();

        let detector = HeuristicProjectDetector::new();
        let result = detector.detect(temp_dir.path()).unwrap();

        assert!(result.stacks.contains(&ProjectStack::Python));
        assert!(result.stacks.contains(&ProjectStack::FastApi));
        assert!(
            result
                .recommended_ignores
                .contains(&"**/__pycache__".to_string())
        );
    }

    #[test]
    fn test_detect_unity_project() {
        let temp_dir = tempdir().unwrap();
        fs::create_dir(temp_dir.path().join("Assets")).unwrap();
        fs::create_dir(temp_dir.path().join("ProjectSettings")).unwrap();

        let detector = HeuristicProjectDetector::new();
        let result = detector.detect(temp_dir.path()).unwrap();

        assert!(result.stacks.contains(&ProjectStack::Unity));
        assert!(result.recommended_ignores.contains(&"/Library".to_string()));
    }
}
