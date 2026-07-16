//! Cryptographic package signing and signature verification for PackWiser.
//!
//! Implements Ed25519-based signing and verification for package integrity and authenticity.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use packwiser_core::{SignatureError, Signer};
use rand::rngs::OsRng;

/// Concrete implementor of the `Signer` trait using the Ed25519 algorithm.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519Signer;

impl Signer for Ed25519Signer {
    fn sign(&self, data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, SignatureError> {
        let key_arr: [u8; 32] = private_key.try_into().map_err(|_| {
            SignatureError::InvalidKey("Ed25519 private key must be exactly 32 bytes".to_string())
        })?;

        let signing_key = SigningKey::from_bytes(&key_arr);
        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, SignatureError> {
        let pub_key_arr: [u8; 32] = public_key.try_into().map_err(|_| {
            SignatureError::InvalidKey("Ed25519 public key must be exactly 32 bytes".to_string())
        })?;

        let verifying_key = VerifyingKey::from_bytes(&pub_key_arr)
            .map_err(|e| SignatureError::InvalidKey(format!("Invalid public key bytes: {}", e)))?;

        let sig_arr: [u8; 64] = signature.try_into().map_err(|_| {
            SignatureError::Calculation("Ed25519 signature must be exactly 64 bytes".to_string())
        })?;

        let signature = Signature::from_bytes(&sig_arr);

        Ok(verifying_key.verify(data, &signature).is_ok())
    }
}

/// Generates a cryptographically secure, fresh Ed25519 keypair.
///
/// Returns a tuple of `(private_key_bytes, public_key_bytes)` where each is a 32-byte vector.
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (priv_key, pub_key) = generate_keypair();
        assert_eq!(priv_key.len(), 32);
        assert_eq!(pub_key.len(), 32);
        // Ensure private key matches public key verification
        let verifying_key = VerifyingKey::from_bytes(&pub_key.clone().try_into().unwrap()).unwrap();
        let signing_key = SigningKey::from_bytes(&priv_key.try_into().unwrap());
        assert_eq!(verifying_key, signing_key.verifying_key());
    }

    #[test]
    fn test_sign_and_verify_success() {
        let (priv_key, pub_key) = generate_keypair();
        let payload = b"PackWiser target release payload metadata contents";

        let signer = Ed25519Signer;
        let sig = signer.sign(payload, &priv_key).unwrap();
        assert_eq!(sig.len(), 64);

        let verified = signer.verify(payload, &sig, &pub_key).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_verify_fails_with_altered_payload() {
        let (priv_key, pub_key) = generate_keypair();
        let payload = b"Original uncorrupted message bytes";

        let signer = Ed25519Signer;
        let sig = signer.sign(payload, &priv_key).unwrap();

        let altered_payload = b"Original uncorrupted Message bytes"; // capital M
        let verified = signer.verify(altered_payload, &sig, &pub_key).unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_verify_fails_with_corrupt_signature() {
        let (priv_key, pub_key) = generate_keypair();
        let payload = b"Original message";

        let signer = Ed25519Signer;
        let mut sig = signer.sign(payload, &priv_key).unwrap();

        // Corrupt signature bytes
        sig[10] ^= 0xFF;

        let verified = signer.verify(payload, &sig, &pub_key).unwrap();
        assert!(!verified);
    }
}
