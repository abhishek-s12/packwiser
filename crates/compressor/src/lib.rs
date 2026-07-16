//! Archive and compression formats implementation for PackWiser.
//!
//! Exposes streaming compressor adapters for ZIP, Tar, Tar.Gz, Tar.Xz, and Tar.Zst.

use packwiser_core::{CompressionError, Compressor, FileEntry};
use std::fs::File;
use std::io::{Read, Write};

/// Supported archive formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// Standard ZIP format
    Zip,
    /// Uncompressed Tar archive
    Tar,
    /// Gzip-compressed Tar archive
    TarGz,
    /// Xz-compressed Tar archive
    TarXz,
    /// Zstandard-compressed Tar archive
    TarZst,
}

/// Compressor for standard ZIP archives.
#[derive(Debug, Clone)]
pub struct ZipCompressor {
    level: zip::CompressionMethod,
}

impl ZipCompressor {
    /// Creates a new `ZipCompressor` using standard Deflate compression.
    pub fn new() -> Self {
        Self {
            level: zip::CompressionMethod::Deflated,
        }
    }
}

impl Default for ZipCompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Compressor for ZipCompressor {
    fn compress(
        &self,
        files: &[FileEntry],
        output: &mut dyn Write,
        progress: Box<dyn Fn(u64) + Send>,
    ) -> Result<u64, CompressionError> {
        let mut temp_file = tempfile::tempfile()?;
        let mut zip = zip::ZipWriter::new(&mut temp_file);
        let mut total_written = 0;

        // Use standard zip::write::SimpleFileOptions in modern zip releases (or fallback to FileOptions)
        let options = zip::write::FileOptions::<()>::default().compression_method(self.level);

        for file in files {
            let mut f = File::open(&file.absolute_path)?;
            let name_str = file.relative_path.to_str().ok_or_else(|| {
                CompressionError::InvalidPath(format!(
                    "Invalid path name: {:?}",
                    file.relative_path
                ))
            })?;

            zip.start_file(name_str, options)
                .map_err(|e| CompressionError::Encoding(e.to_string()))?;

            let mut buffer = vec![0u8; 128 * 1024]; // 128KB buffer
            loop {
                let n = f.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                zip.write_all(&buffer[..n])?;
                total_written += n as u64;
                progress(total_written);
            }
        }

        zip.finish()
            .map_err(|e| CompressionError::Encoding(e.to_string()))?;

        // Rewind the tempfile and stream it to the final output
        use std::io::Seek;
        temp_file.rewind()?;
        std::io::copy(&mut temp_file, output)?;

        Ok(total_written)
    }
}

/// Compressor for uncompressed Tar archives.
#[derive(Debug, Clone)]
pub struct TarCompressor;

impl Compressor for TarCompressor {
    fn compress(
        &self,
        files: &[FileEntry],
        output: &mut dyn Write,
        progress: Box<dyn Fn(u64) + Send>,
    ) -> Result<u64, CompressionError> {
        let mut archive = tar::Builder::new(output);
        let mut total_written = 0;

        for file in files {
            let mut f = File::open(&file.absolute_path)?;
            let name_str = file.relative_path.to_str().ok_or_else(|| {
                CompressionError::InvalidPath(format!(
                    "Invalid path name: {:?}",
                    file.relative_path
                ))
            })?;

            let mut header = tar::Header::new_gnu();
            header.set_size(file.size);
            header.set_mode(0o644);

            archive.append_data(&mut header, name_str, &mut f)?;
            total_written += file.size;
            progress(total_written);
        }

        archive.finish()?;
        Ok(total_written)
    }
}

/// Compressor for Gzip-compressed Tar archives (`tar.gz`).
#[derive(Debug, Clone)]
pub struct TarGzCompressor {
    level: u32,
}

impl TarGzCompressor {
    /// Creates a new `TarGzCompressor` with specified compression level (0-9).
    pub fn new(level: u32) -> Self {
        Self { level }
    }
}

impl Default for TarGzCompressor {
    fn default() -> Self {
        Self::new(6)
    }
}

impl Compressor for TarGzCompressor {
    fn compress(
        &self,
        files: &[FileEntry],
        output: &mut dyn Write,
        progress: Box<dyn Fn(u64) + Send>,
    ) -> Result<u64, CompressionError> {
        let encoder = flate2::write::GzEncoder::new(output, flate2::Compression::new(self.level));
        let mut archive = tar::Builder::new(encoder);
        let mut total_written = 0;

        for file in files {
            let mut f = File::open(&file.absolute_path)?;
            let name_str = file.relative_path.to_str().ok_or_else(|| {
                CompressionError::InvalidPath(format!(
                    "Invalid path name: {:?}",
                    file.relative_path
                ))
            })?;

            let mut header = tar::Header::new_gnu();
            header.set_size(file.size);
            header.set_mode(0o644);

            archive.append_data(&mut header, name_str, &mut f)?;
            total_written += file.size;
            progress(total_written);
        }

        let encoder = archive.into_inner()?;
        encoder.finish()?;
        Ok(total_written)
    }
}

/// Compressor for Xz-compressed Tar archives (`tar.xz`).
#[derive(Debug, Clone)]
pub struct TarXzCompressor {
    level: u32,
}

impl TarXzCompressor {
    /// Creates a new `TarXzCompressor` with specified compression level (0-9).
    pub fn new(level: u32) -> Self {
        Self { level }
    }
}

impl Default for TarXzCompressor {
    fn default() -> Self {
        Self::new(6)
    }
}

impl Compressor for TarXzCompressor {
    fn compress(
        &self,
        files: &[FileEntry],
        output: &mut dyn Write,
        progress: Box<dyn Fn(u64) + Send>,
    ) -> Result<u64, CompressionError> {
        let encoder = xz2::write::XzEncoder::new(output, self.level);
        let mut archive = tar::Builder::new(encoder);
        let mut total_written = 0;

        for file in files {
            let mut f = File::open(&file.absolute_path)?;
            let name_str = file.relative_path.to_str().ok_or_else(|| {
                CompressionError::InvalidPath(format!(
                    "Invalid path name: {:?}",
                    file.relative_path
                ))
            })?;

            let mut header = tar::Header::new_gnu();
            header.set_size(file.size);
            header.set_mode(0o644);

            archive.append_data(&mut header, name_str, &mut f)?;
            total_written += file.size;
            progress(total_written);
        }

        let encoder = archive.into_inner()?;
        encoder.finish()?;
        Ok(total_written)
    }
}

/// Compressor for Zstandard-compressed Tar archives (`tar.zst`).
#[derive(Debug, Clone)]
pub struct TarZstCompressor {
    level: i32,
}

impl TarZstCompressor {
    /// Creates a new `TarZstCompressor` with specified compression level (-7 to 22).
    pub fn new(level: i32) -> Self {
        Self { level }
    }
}

impl Default for TarZstCompressor {
    fn default() -> Self {
        Self::new(3)
    }
}

impl Compressor for TarZstCompressor {
    fn compress(
        &self,
        files: &[FileEntry],
        output: &mut dyn Write,
        progress: Box<dyn Fn(u64) + Send>,
    ) -> Result<u64, CompressionError> {
        let encoder = zstd::stream::write::Encoder::new(output, self.level)?;
        let mut archive = tar::Builder::new(encoder);
        let mut total_written = 0;

        for file in files {
            let mut f = File::open(&file.absolute_path)?;
            let name_str = file.relative_path.to_str().ok_or_else(|| {
                CompressionError::InvalidPath(format!(
                    "Invalid path name: {:?}",
                    file.relative_path
                ))
            })?;

            let mut header = tar::Header::new_gnu();
            header.set_size(file.size);
            header.set_mode(0o644);

            archive.append_data(&mut header, name_str, &mut f)?;
            total_written += file.size;
            progress(total_written);
        }

        let encoder = archive.into_inner()?;
        encoder.finish()?;
        Ok(total_written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    fn make_test_files(temp_dir: &Path) -> Vec<FileEntry> {
        let file1_path = temp_dir.join("a.txt");
        let file2_path = temp_dir.join("b.txt");

        let mut f1 = File::create(&file1_path).unwrap();
        f1.write_all(b"Hello world from file A").unwrap();

        let mut f2 = File::create(&file2_path).unwrap();
        f2.write_all(b"Hello world from file B indeed!").unwrap();

        vec![
            FileEntry {
                relative_path: PathBuf::from("a.txt"),
                absolute_path: file1_path,
                size: 23,
                is_symlink: false,
                file_type: "text".to_string(),
            },
            FileEntry {
                relative_path: PathBuf::from("b.txt"),
                absolute_path: file2_path,
                size: 31,
                is_symlink: false,
                file_type: "text".to_string(),
            },
        ]
    }

    #[test]
    fn test_zip_compression() {
        let temp_dir = tempfile::tempdir().unwrap();
        let files = make_test_files(temp_dir.path());

        let out_path = temp_dir.path().join("output.zip");
        let mut out_file = File::create(&out_path).unwrap();

        let compressor = ZipCompressor::default();
        let bytes = compressor
            .compress(&files, &mut out_file, Box::new(|_| {}))
            .unwrap();

        assert!(bytes > 0);
        assert!(out_path.exists());
        assert!(out_path.metadata().unwrap().len() > 0);
    }

    #[test]
    fn test_tar_compression() {
        let temp_dir = tempfile::tempdir().unwrap();
        let files = make_test_files(temp_dir.path());

        let out_path = temp_dir.path().join("output.tar");
        let mut out_file = File::create(&out_path).unwrap();

        let compressor = TarCompressor;
        let bytes = compressor
            .compress(&files, &mut out_file, Box::new(|_| {}))
            .unwrap();

        assert_eq!(bytes, 54);
        assert!(out_path.exists());
    }

    #[test]
    fn test_targz_compression() {
        let temp_dir = tempfile::tempdir().unwrap();
        let files = make_test_files(temp_dir.path());

        let out_path = temp_dir.path().join("output.tar.gz");
        let mut out_file = File::create(&out_path).unwrap();

        let compressor = TarGzCompressor::default();
        let bytes = compressor
            .compress(&files, &mut out_file, Box::new(|_| {}))
            .unwrap();

        assert_eq!(bytes, 54);
        assert!(out_path.exists());
    }

    #[test]
    fn test_tarxz_compression() {
        let temp_dir = tempfile::tempdir().unwrap();
        let files = make_test_files(temp_dir.path());

        let out_path = temp_dir.path().join("output.tar.xz");
        let mut out_file = File::create(&out_path).unwrap();

        let compressor = TarXzCompressor::default();
        let bytes = compressor
            .compress(&files, &mut out_file, Box::new(|_| {}))
            .unwrap();

        assert_eq!(bytes, 54);
        assert!(out_path.exists());
    }

    #[test]
    fn test_tarzst_compression() {
        let temp_dir = tempfile::tempdir().unwrap();
        let files = make_test_files(temp_dir.path());

        let out_path = temp_dir.path().join("output.tar.zst");
        let mut out_file = File::create(&out_path).unwrap();

        let compressor = TarZstCompressor::default();
        let bytes = compressor
            .compress(&files, &mut out_file, Box::new(|_| {}))
            .unwrap();

        assert_eq!(bytes, 54);
        assert!(out_path.exists());
    }
}
