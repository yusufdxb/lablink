//! OpenSSH `SHA256:` fingerprints, computed exactly as `ssh-keygen -l` does:
//! unpadded standard base64 of SHA-256 over the decoded public-key blob.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

/// Errors decoding a public-key blob.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyBlobError {
    #[error("public key is not valid base64")]
    Base64,
    #[error("public key blob is truncated")]
    Truncated,
    #[error("public key blob declares type '{inner}' but was labelled '{outer}'")]
    TypeMismatch { outer: String, inner: String },
}

/// Fingerprint of a base64 public-key blob, checking that the blob's embedded
/// key type matches `key_type`.
pub fn fingerprint_of_blob(key_type: &str, blob_b64: &str) -> Result<String, KeyBlobError> {
    let blob = STANDARD
        .decode(blob_b64.trim())
        .map_err(|_| KeyBlobError::Base64)?;
    if blob.len() < 4 {
        return Err(KeyBlobError::Truncated);
    }
    let n = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let inner = blob.get(4..4 + n).ok_or(KeyBlobError::Truncated)?;
    let inner = String::from_utf8_lossy(inner).to_string();
    if inner != key_type {
        return Err(KeyBlobError::TypeMismatch {
            outer: key_type.to_string(),
            inner,
        });
    }
    let digest = Sha256::digest(&blob);
    Ok(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real ed25519 public key; fingerprint cross-checked with
    // `ssh-keygen -lf` (see tests/fixtures note in docs/PERFORMANCE.md is not
    // needed: the integration test `keygen_agrees` recomputes it live).
    pub const ED25519_BLOB: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

    #[test]
    fn computes_fingerprint_shape() {
        let fp = fingerprint_of_blob("ssh-ed25519", ED25519_BLOB).unwrap();
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), 7 + 43);
        assert!(lablink_core::config::valid_fingerprint(&fp));
    }

    #[test]
    fn rejects_type_confusion_and_garbage() {
        assert!(matches!(
            fingerprint_of_blob("ssh-rsa", ED25519_BLOB),
            Err(KeyBlobError::TypeMismatch { .. })
        ));
        assert_eq!(
            fingerprint_of_blob("ssh-ed25519", "!!!"),
            Err(KeyBlobError::Base64)
        );
        assert_eq!(
            fingerprint_of_blob("ssh-ed25519", "AAAA"),
            Err(KeyBlobError::Truncated)
        );
    }
}
