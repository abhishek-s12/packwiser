//! Checksum calculation and validation engine for PackWiser.
//!
//! Provides streaming calculations for SHA-256, SHA-512, BLAKE3, and CRC32.

use crc32fast::Hasher as CrcHasher;
use sha2::{Digest, Sha256, Sha512};
use std::io::{self, Read};

/// Aggregated checksum results for a file or stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumResult {
    /// SHA-256 hex digest
    pub sha256: String,
    /// SHA-512 hex digest
    pub sha512: String,
    /// BLAKE3 hex digest
    pub blake3: String,
    /// CRC32 hex digest
    pub crc32: String,
}

/// Helper function to format raw bytes as a hexadecimal string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Calculates all supported checksums for a stream in a single read pass.
pub fn calculate_checksums<R: Read>(mut reader: R) -> io::Result<ChecksumResult> {
    let mut sha256_hasher = Sha256::new();
    let mut sha512_hasher = Sha512::new();
    let mut blake3_hasher = blake3::Hasher::new();
    let mut crc32_hasher = CrcHasher::new();

    let mut buffer = [0u8; 128 * 1024]; // 128KB buffer
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let data = &buffer[..n];
        sha256_hasher.update(data);
        sha512_hasher.update(data);
        blake3_hasher.update(data);
        crc32_hasher.update(data);
    }

    let sha256_result = sha256_hasher.finalize();
    let sha512_result = sha512_hasher.finalize();
    let blake3_result = blake3_hasher.finalize();
    let crc32_result = crc32_hasher.finalize();

    Ok(ChecksumResult {
        sha256: bytes_to_hex(&sha256_result),
        sha512: bytes_to_hex(&sha512_result),
        blake3: blake3_result.to_hex().to_string(),
        crc32: format!("{:08x}", crc32_result),
    })
}

/// Verifies if a computed hash matches an expected hash string (case-insensitive).
pub fn verify_checksum(computed: &str, expected: &str) -> bool {
    computed.eq_ignore_ascii_case(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string_checksums() {
        let data = b"";
        let res = calculate_checksums(&data[..]).unwrap();

        // Standard empty digests
        assert_eq!(
            res.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            res.sha512,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            res.blake3,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(res.crc32, "00000000");
    }

    #[test]
    fn test_hello_checksums() {
        let data = b"hello";
        let res = calculate_checksums(&data[..]).unwrap();

        // Standard digests for "hello"
        assert_eq!(
            res.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(res.crc32, "3610a686");
    }

    #[test]
    fn test_verify() {
        assert!(verify_checksum("ABCDEF", "abcdef"));
        assert!(!verify_checksum("ABCDEF", "abcdeg"));
    }
}
