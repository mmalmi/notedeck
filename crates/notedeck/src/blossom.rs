use crate::Error;

/// Detects if a URL follows the blossom protocol pattern: /<sha256>[.ext]
///
/// Blossom URLs have the form:
/// - https://example.com/<64-char-hex-sha256>
/// - https://example.com/<64-char-hex-sha256>.jpg
///
/// Returns Some(sha256_hex) if detected, None otherwise
#[profiling::function]
pub fn extract_blossom_sha256(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    let path = url.path();

    // Remove leading slash
    let path = path.strip_prefix('/').unwrap_or(path);

    // Get the filename component (last segment)
    let filename = path.split('/').last()?;

    // Strip extension if present
    let hash_part = filename.split('.').next()?;

    // Verify it's exactly 64 hex characters (SHA256)
    if hash_part.len() == 64 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(hash_part.to_lowercase())
    } else {
        None
    }
}

/// Verifies that data matches the expected SHA256 hash
#[profiling::function]
pub fn verify_sha256(data: &[u8], expected_hash: &str) -> Result<(), Error> {
    use sha2::Digest;

    let actual_hash = sha2::Sha256::digest(data);
    let actual_hex = hex::encode(actual_hash);

    if actual_hex.eq_ignore_ascii_case(expected_hash) {
        Ok(())
    } else {
        Err(Error::Generic(format!(
            "SHA256 mismatch: expected {}, got {}",
            expected_hash, actual_hex
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_blossom_sha256_basic() {
        let url = "https://cdn.example.com/a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd";
        assert_eq!(
            extract_blossom_sha256(url),
            Some("a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd".to_string())
        );
    }

    #[test]
    fn test_extract_blossom_sha256_with_extension() {
        let url = "https://cdn.example.com/a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd.jpg";
        assert_eq!(
            extract_blossom_sha256(url),
            Some("a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd".to_string())
        );
    }

    #[test]
    fn test_extract_blossom_sha256_nested_path() {
        let url = "https://cdn.example.com/blobs/a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd.png";
        assert_eq!(
            extract_blossom_sha256(url),
            Some("a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd".to_string())
        );
    }

    #[test]
    fn test_extract_blossom_sha256_uppercase() {
        let url = "https://cdn.example.com/A1B2C3D4E5F6789012345678901234567890123456789012345678901234ABCD";
        assert_eq!(
            extract_blossom_sha256(url),
            Some("a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd".to_string())
        );
    }

    #[test]
    fn test_extract_blossom_sha256_too_short() {
        let url = "https://cdn.example.com/a1b2c3d4";
        assert_eq!(extract_blossom_sha256(url), None);
    }

    #[test]
    fn test_extract_blossom_sha256_too_long() {
        let url = "https://cdn.example.com/a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd00";
        assert_eq!(extract_blossom_sha256(url), None);
    }

    #[test]
    fn test_extract_blossom_sha256_non_hex() {
        let url = "https://cdn.example.com/g1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd";
        assert_eq!(extract_blossom_sha256(url), None);
    }

    #[test]
    fn test_extract_blossom_sha256_regular_url() {
        let url = "https://example.com/images/photo.jpg";
        assert_eq!(extract_blossom_sha256(url), None);
    }

    #[test]
    fn test_verify_sha256_success() {
        let data = b"hello world";
        let hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_sha256(data, hash).is_ok());
    }

    #[test]
    fn test_verify_sha256_uppercase() {
        let data = b"hello world";
        let hash = "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
        assert!(verify_sha256(data, hash).is_ok());
    }

    #[test]
    fn test_verify_sha256_mismatch() {
        let data = b"hello world";
        let wrong_hash = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd";
        assert!(verify_sha256(data, wrong_hash).is_err());
    }
}
