//! License scanning and compliance auditing engine for PackWiser.
//!
//! Exposes heuristics to detect standard software licenses (MIT, Apache, BSD, GPL, LGPL, AGPL, MPL)
//! from source comments and standalone license descriptors.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use regex::Regex;
use packwiser_core::{FileEntry, LicenseFinding, LicenseReport, LicenseScanner, LicenseError};

/// Concrete license compliance scanner implementation.
pub struct HeuristicLicenseScanner {
    spdx_regex: Regex,
    mit_regexes: Vec<Regex>,
    apache_regexes: Vec<Regex>,
    bsd_regexes: Vec<Regex>,
    gpl_regexes: Vec<Regex>,
    lgpl_regexes: Vec<Regex>,
    agpl_regexes: Vec<Regex>,
    mpl_regexes: Vec<Regex>,
}

impl HeuristicLicenseScanner {
    /// Creates a new `HeuristicLicenseScanner` compiling regular expressions.
    pub fn new() -> Self {
        Self {
            spdx_regex: Regex::new(r"(?i)SPDX-License-Identifier:\s*([a-zA-Z0-9\.\-]+)").unwrap(),
            mit_regexes: vec![
                Regex::new(r"(?i)mit\s+license").unwrap(),
                Regex::new(r"(?i)permission\s+is\s+hereby\s+granted.*free\s+of\s+charge").unwrap(),
            ],
            apache_regexes: vec![
                Regex::new(r"(?i)apache\s+license\s*,\s*version\s*2\.0").unwrap(),
                Regex::new(r"(?i)http://www\.apache\.org/licenses/LICENSE-2\.0").unwrap(),
            ],
            bsd_regexes: vec![
                Regex::new(r"(?i)redistribution\s+and\s+use\s+in\s+source\s+and\s+binary\s+forms").unwrap(),
                Regex::new(r"(?i)bsd\s+2-clause").unwrap(),
                Regex::new(r"(?i)bsd\s+3-clause").unwrap(),
            ],
            gpl_regexes: vec![
                Regex::new(r"(?i)gnu\s+general\s+public\s+license").unwrap(),
                Regex::new(r"(?i)gpl\s*v?[23]").unwrap(),
            ],
            lgpl_regexes: vec![
                Regex::new(r"(?i)gnu\s+lesser\s+general\s+public\s+license").unwrap(),
                Regex::new(r"(?i)lgpl\s*v?[23]").unwrap(),
            ],
            agpl_regexes: vec![
                Regex::new(r"(?i)gnu\s+affero\s+general\s+public\s+license").unwrap(),
                Regex::new(r"(?i)agpl\s*v?3").unwrap(),
            ],
            mpl_regexes: vec![
                Regex::new(r"(?i)mozilla\s+public\s+license").unwrap(),
                Regex::new(r"(?i)mpl\s*v?2").unwrap(),
            ],
        }
    }

    /// Evaluates license type of a raw text slice.
    ///
    /// Returns `(license_type, confidence)` if a match is determined.
    pub fn detect_license(&self, text: &str) -> Option<(String, f32)> {
        // 1. Direct SPDX identifier match (highest confidence)
        if let Some(captures) = self.spdx_regex.captures(text) {
            if let Some(m) = captures.get(1) {
                let license = m.as_str().trim();
                // Map common inputs to clean keys
                let mapped = match license.to_uppercase().as_str() {
                    "MIT" => "MIT",
                    "APACHE-2.0" | "APACHE2" => "Apache-2.0",
                    "BSD-3-CLAUSE" => "BSD-3-Clause",
                    "BSD-2-CLAUSE" => "BSD-2-Clause",
                    "GPL-3.0" | "GPLV3" => "GPL-3.0",
                    "GPL-2.0" | "GPLV2" => "GPL-2.0",
                    "LGPL-3.0" | "LGPLV3" => "LGPL-3.0",
                    "LGPL-2.1" | "LGPLV2.1" => "LGPL-2.1",
                    "AGPL-3.0" | "AGPLV3" => "AGPL-3.0",
                    "MPL-2.0" | "MPLV2" => "MPL-2.0",
                    _ => license,
                };
                return Some((mapped.to_string(), 1.0));
            }
        }

        // 2. Exact block header matching
        if self.mit_regexes[1].is_match(text) {
            return Some(("MIT".to_string(), 0.95));
        }
        if self.apache_regexes[1].is_match(text) {
            return Some(("Apache-2.0".to_string(), 0.95));
        }

        // 3. Keyword / description matching
        if self.mit_regexes[0].is_match(text) {
            return Some(("MIT".to_string(), 0.8));
        }
        if self.apache_regexes[0].is_match(text) {
            return Some(("Apache-2.0".to_string(), 0.8));
        }
        if self.bsd_regexes[0].is_match(text) {
            // Default to 3-Clause if generic BSD redistribution is found
            if self.bsd_regexes[1].is_match(text) {
                return Some(("BSD-2-Clause".to_string(), 0.85));
            }
            return Some(("BSD-3-Clause".to_string(), 0.8));
        }
        if self.agpl_regexes[0].is_match(text) || self.agpl_regexes[1].is_match(text) {
            return Some(("AGPL-3.0".to_string(), 0.8));
        }
        if self.lgpl_regexes[0].is_match(text) || self.lgpl_regexes[1].is_match(text) {
            return Some(("LGPL-3.0".to_string(), 0.75));
        }
        if self.gpl_regexes[0].is_match(text) || self.gpl_regexes[1].is_match(text) {
            return Some(("GPL-3.0".to_string(), 0.75));
        }
        if self.mpl_regexes[0].is_match(text) || self.mpl_regexes[1].is_match(text) {
            return Some(("MPL-2.0".to_string(), 0.8));
        }

        None
    }
}

impl Default for HeuristicLicenseScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseScanner for HeuristicLicenseScanner {
    fn scan_licenses(&self, files: &[FileEntry]) -> Result<LicenseReport, LicenseError> {
        let mut findings = Vec::new();
        let mut root_license = None;
        let mut license_counts = std::collections::HashMap::new();

        for file in files {
            // Skip large or binary files (> 1MB)
            if file.size > 1_048_576 {
                continue;
            }

            let file_name = file.relative_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            
            let is_root_license_file = file.relative_path.parent() == Some(Path::new(""))
                && (file_name.to_ascii_uppercase().starts_with("LICENSE")
                    || file_name.to_ascii_uppercase().starts_with("COPYING"));

            let mut f = File::open(&file.absolute_path)
                .map_err(|e| LicenseError::Read(format!("Failed to open file {:?}: {}", file.absolute_path, e)))?;
            
            // Read first 8KB (headers or root license contents are small)
            let mut buf = vec![0; 8192];
            let read_bytes = f.read(&mut buf)
                .map_err(|e| LicenseError::Read(format!("Failed to read file {:?}: {}", file.absolute_path, e)))?;
            buf.truncate(read_bytes);

            let text = String::from_utf8_lossy(&buf);
            if let Some((license, confidence)) = self.detect_license(&text) {
                findings.push(LicenseFinding {
                    file_path: file.relative_path.clone(),
                    license_type: license.clone(),
                    confidence,
                });

                *license_counts.entry(license.clone()).or_insert(0) += 1;

                if is_root_license_file {
                    root_license = Some(license);
                }
            }
        }

        // Aggregate project license
        let project_license = if let Some(root_lic) = root_license {
            root_lic
        } else {
            // Heuristic fallback: the most frequent license found
            license_counts.into_iter()
                .max_by_key(|&(_, count)| count)
                .map(|(lic, _)| lic)
                .unwrap_or_else(|| "Unknown".to_string())
        };

        Ok(LicenseReport {
            project_license,
            findings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_detect_license_spdx() {
        let scanner = HeuristicLicenseScanner::new();
        
        let mit_header = "// SPDX-License-Identifier: MIT\nfn main() {}";
        let (lic, conf) = scanner.detect_license(mit_header).unwrap();
        assert_eq!(lic, "MIT");
        assert_eq!(conf, 1.0);

        let apache_header = "/* SPDX-License-Identifier: Apache-2.0 */";
        let (lic, conf) = scanner.detect_license(apache_header).unwrap();
        assert_eq!(lic, "Apache-2.0");
        assert_eq!(conf, 1.0);
    }

    #[test]
    fn test_detect_license_keywords() {
        let scanner = HeuristicLicenseScanner::new();
        
        let mit_text = "Permission is hereby granted, free of charge, to any person obtaining a copy...";
        let (lic, conf) = scanner.detect_license(mit_text).unwrap();
        assert_eq!(lic, "MIT");
        assert_eq!(conf, 0.95);

        let mpl_text = "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.";
        let (lic, conf) = scanner.detect_license(mpl_text).unwrap();
        assert_eq!(lic, "MPL-2.0");
        assert_eq!(conf, 0.8);
    }

    #[test]
    fn test_scan_license_findings() {
        let temp_dir = tempdir().unwrap();
        
        let file1 = temp_dir.path().join("lib.rs");
        fs::write(&file1, "// SPDX-License-Identifier: MIT\n").unwrap();

        let file2 = temp_dir.path().join("LICENSE");
        fs::write(&file2, "Apache License, Version 2.0").unwrap();

        let scanner = HeuristicLicenseScanner::new();
        let files = vec![
            FileEntry {
                relative_path: PathBuf::from("lib.rs"),
                absolute_path: file1,
                size: 30,
                is_symlink: false,
                file_type: "rs".to_string(),
            },
            FileEntry {
                relative_path: PathBuf::from("LICENSE"),
                absolute_path: file2,
                size: 27,
                is_symlink: false,
                file_type: "".to_string(),
            },
        ];

        let report = scanner.scan_licenses(&files).unwrap();
        // Since LICENSE is in root and contains Apache, project_license is Apache-2.0
        assert_eq!(report.project_license, "Apache-2.0");
        assert_eq!(report.findings.len(), 2);
    }
}
