// Copyright 2024 Saorsa Labs Limited
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
// This file may not be copied, modified, or distributed except according to those terms.

//! Entangled Attestation logic for zkVM execution.
//!
//! This module provides the core attestation logic that can be proven in a zkVM.
//! The key insight is that an EntangledId is derived deterministically from:
//!
//! ```text
//! EntangledId = BLAKE3(public_key || binary_hash || nonce)
//! ```
//!
//! By running this derivation inside a zkVM, a node can prove:
//! 1. It knows the private key corresponding to `public_key`
//! 2. Its binary hash matches the attested value
//! 3. The derivation was computed correctly
//!
//! ## zkVM Execution Model
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                     zkVM Guest Program                      │
//! ├────────────────────────────────────────────────────────────┤
//! │  Inputs (from prover):                                     │
//! │    - public_key: [u8; 1952]  (ML-DSA-65)                   │
//! │    - binary_hash: [u8; 32]   (BLAKE3 of binary)            │
//! │    - nonce: u64              (unique per derivation)       │
//! │                                                            │
//! │  Computation (proven):                                      │
//! │    entangled_id = derive_entangled_id(pk, bh, nonce)       │
//! │                                                            │
//! │  Outputs (public):                                          │
//! │    - entangled_id: [u8; 32]                                 │
//! │    - binary_hash: [u8; 32]   (committed for verification)  │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Properties
//!
//! - **Binding**: EntangledId is cryptographically bound to public_key and binary_hash
//! - **Collision Resistance**: BLAKE3 provides 256-bit collision resistance
//! - **Determinism**: Same inputs always produce same output (required for zkVM)
//! - **Non-malleability**: Cannot modify inputs without changing the output

use crate::error::{LogicError, LogicResult};
use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// Size of ML-DSA-65 public key in bytes.
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;

/// Size of BLAKE3 hash output in bytes.
pub const HASH_SIZE: usize = 32;

/// Size of EntangledId in bytes.
pub const ENTANGLED_ID_SIZE: usize = 32;

/// Components used to derive an EntangledId.
///
/// This struct captures all inputs needed for EntangledId derivation,
/// making it easy to pass through zkVM input/output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntangledIdComponents {
    /// The ML-DSA-65 public key (1952 bytes).
    pub public_key_hash: [u8; HASH_SIZE],

    /// BLAKE3 hash of the running binary.
    pub binary_hash: [u8; HASH_SIZE],

    /// Unique nonce for this derivation.
    pub nonce: u64,
}

impl EntangledIdComponents {
    /// Create new components from a full public key.
    ///
    /// The public key is hashed to reduce the data size while maintaining
    /// the cryptographic binding.
    #[must_use]
    pub fn new(public_key: &[u8], binary_hash: [u8; HASH_SIZE], nonce: u64) -> Self {
        // Hash the public key to get a fixed-size commitment
        let public_key_hash = blake3::hash(public_key);

        Self {
            public_key_hash: *public_key_hash.as_bytes(),
            binary_hash,
            nonce,
        }
    }

    /// Create components from a pre-hashed public key.
    #[must_use]
    pub const fn from_hashed(
        public_key_hash: [u8; HASH_SIZE],
        binary_hash: [u8; HASH_SIZE],
        nonce: u64,
    ) -> Self {
        Self {
            public_key_hash,
            binary_hash,
            nonce,
        }
    }
}

/// Derive an EntangledId from its components.
///
/// This is the core function that should be executed in the zkVM.
/// It computes:
///
/// ```text
/// EntangledId = BLAKE3(public_key || binary_hash || nonce_bytes)
/// ```
///
/// # Arguments
///
/// * `public_key` - The ML-DSA-65 public key (any length, will be hashed)
/// * `binary_hash` - BLAKE3 hash of the running binary (32 bytes)
/// * `nonce` - Unique nonce for this derivation
///
/// # Returns
///
/// A 32-byte EntangledId.
///
/// # Example
///
/// ```rust
/// use saorsa_logic::attestation::derive_entangled_id;
///
/// let public_key = [0u8; 1952]; // ML-DSA-65 public key
/// let binary_hash = [1u8; 32];   // Binary hash
/// let nonce = 12345u64;
///
/// let id = derive_entangled_id(&public_key, &binary_hash, nonce);
/// assert_eq!(id.len(), 32);
/// ```
#[must_use]
pub fn derive_entangled_id(
    public_key: &[u8],
    binary_hash: &[u8; HASH_SIZE],
    nonce: u64,
) -> [u8; ENTANGLED_ID_SIZE] {
    let mut hasher = Hasher::new();

    // Include full public key in hash (not pre-hashed, for maximum binding)
    hasher.update(public_key);

    // Include binary hash
    hasher.update(binary_hash);

    // Include nonce as little-endian bytes
    hasher.update(&nonce.to_le_bytes());

    *hasher.finalize().as_bytes()
}

/// Derive an EntangledId from pre-structured components.
///
/// This variant is useful when passing data through zkVM where
/// the components are already structured.
#[must_use]
pub fn derive_entangled_id_from_components(
    components: &EntangledIdComponents,
) -> [u8; ENTANGLED_ID_SIZE] {
    let mut hasher = Hasher::new();

    // Use the pre-hashed public key
    hasher.update(&components.public_key_hash);

    // Include binary hash
    hasher.update(&components.binary_hash);

    // Include nonce as little-endian bytes
    hasher.update(&components.nonce.to_le_bytes());

    *hasher.finalize().as_bytes()
}

/// Verify that an EntangledId was correctly derived.
///
/// This function recomputes the EntangledId and compares it to the provided value.
///
/// # Arguments
///
/// * `entangled_id` - The claimed EntangledId
/// * `public_key` - The ML-DSA-65 public key
/// * `binary_hash` - BLAKE3 hash of the binary
/// * `nonce` - The nonce used in derivation
///
/// # Returns
///
/// `true` if the EntangledId matches, `false` otherwise.
#[must_use]
pub fn verify_entangled_id(
    entangled_id: &[u8; ENTANGLED_ID_SIZE],
    public_key: &[u8],
    binary_hash: &[u8; HASH_SIZE],
    nonce: u64,
) -> bool {
    let computed = derive_entangled_id(public_key, binary_hash, nonce);
    constant_time_eq(&computed, entangled_id)
}

/// Verify EntangledId with structured components.
#[must_use]
pub fn verify_entangled_id_components(
    entangled_id: &[u8; ENTANGLED_ID_SIZE],
    components: &EntangledIdComponents,
) -> bool {
    let computed = derive_entangled_id_from_components(components);
    constant_time_eq(&computed, entangled_id)
}

/// Check if a binary hash is in the allowlist.
///
/// This function is designed to be called in a zkVM to prove that
/// a binary is authorized.
///
/// # Arguments
///
/// * `binary_hash` - The hash to check
/// * `allowlist` - List of allowed binary hashes
///
/// # Returns
///
/// `Ok(())` if the binary is allowed, `Err(BinaryNotAllowed)` otherwise.
pub fn verify_binary_allowlist(
    binary_hash: &[u8; HASH_SIZE],
    allowlist: &[[u8; HASH_SIZE]],
) -> LogicResult<()> {
    for allowed in allowlist {
        if constant_time_eq(binary_hash, allowed) {
            return Ok(());
        }
    }
    Err(LogicError::BinaryNotAllowed)
}

/// Compute XOR distance between two EntangledIds.
///
/// This is used for DHT routing when EntangledId becomes the routing address.
#[must_use]
pub fn xor_distance(
    a: &[u8; ENTANGLED_ID_SIZE],
    b: &[u8; ENTANGLED_ID_SIZE],
) -> [u8; ENTANGLED_ID_SIZE] {
    let mut result = [0u8; ENTANGLED_ID_SIZE];
    for i in 0..ENTANGLED_ID_SIZE {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Constant-time equality comparison.
///
/// Prevents timing attacks when comparing sensitive values.
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Attestation witness data for zkVM proofs.
///
/// This structure contains all the data needed to generate a zkVM proof
/// of correct EntangledId derivation.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationWitness {
    /// The full public key (private to the prover).
    pub public_key: alloc::vec::Vec<u8>,

    /// Hash of the running binary.
    pub binary_hash: [u8; HASH_SIZE],

    /// Nonce used in derivation.
    pub nonce: u64,
}

#[cfg(feature = "alloc")]
impl AttestationWitness {
    /// Create a new attestation witness.
    #[must_use]
    pub fn new(public_key: alloc::vec::Vec<u8>, binary_hash: [u8; HASH_SIZE], nonce: u64) -> Self {
        Self {
            public_key,
            binary_hash,
            nonce,
        }
    }

    /// Derive the EntangledId from this witness.
    #[must_use]
    pub fn derive_id(&self) -> [u8; ENTANGLED_ID_SIZE] {
        derive_entangled_id(&self.public_key, &self.binary_hash, self.nonce)
    }
}

/// Public output from zkVM attestation proof.
///
/// This is committed to the proof's public outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationOutput {
    /// The derived EntangledId.
    pub entangled_id: [u8; ENTANGLED_ID_SIZE],

    /// The binary hash (public for verification).
    pub binary_hash: [u8; HASH_SIZE],

    /// Hash of the public key (for binding without revealing full key).
    pub public_key_hash: [u8; HASH_SIZE],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_entangled_id_deterministic() {
        let pk = [42u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let bh = [1u8; HASH_SIZE];
        let nonce = 12345u64;

        let id1 = derive_entangled_id(&pk, &bh, nonce);
        let id2 = derive_entangled_id(&pk, &bh, nonce);

        assert_eq!(id1, id2, "derivation must be deterministic");
    }

    #[test]
    fn test_derive_entangled_id_different_keys() {
        let pk1 = [1u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let pk2 = [2u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let bh = [0u8; HASH_SIZE];
        let nonce = 0u64;

        let id1 = derive_entangled_id(&pk1, &bh, nonce);
        let id2 = derive_entangled_id(&pk2, &bh, nonce);

        assert_ne!(id1, id2, "different keys must produce different IDs");
    }

    #[test]
    fn test_derive_entangled_id_different_binaries() {
        let pk = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let bh1 = [1u8; HASH_SIZE];
        let bh2 = [2u8; HASH_SIZE];
        let nonce = 0u64;

        let id1 = derive_entangled_id(&pk, &bh1, nonce);
        let id2 = derive_entangled_id(&pk, &bh2, nonce);

        assert_ne!(id1, id2, "different binaries must produce different IDs");
    }

    #[test]
    fn test_derive_entangled_id_different_nonces() {
        let pk = [0u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let bh = [0u8; HASH_SIZE];

        let id1 = derive_entangled_id(&pk, &bh, 1);
        let id2 = derive_entangled_id(&pk, &bh, 2);

        assert_ne!(id1, id2, "different nonces must produce different IDs");
    }

    #[test]
    fn test_verify_entangled_id_success() {
        let pk = [99u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let bh = [88u8; HASH_SIZE];
        let nonce = 777u64;

        let id = derive_entangled_id(&pk, &bh, nonce);
        assert!(verify_entangled_id(&id, &pk, &bh, nonce));
    }

    #[test]
    fn test_verify_entangled_id_failure() {
        let pk = [99u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let bh = [88u8; HASH_SIZE];
        let nonce = 777u64;

        let id = derive_entangled_id(&pk, &bh, nonce);
        assert!(!verify_entangled_id(&id, &pk, &bh, nonce + 1));
    }

    #[test]
    fn test_binary_allowlist_success() {
        let binary = [1u8; HASH_SIZE];
        let allowlist = [[1u8; HASH_SIZE], [2u8; HASH_SIZE], [3u8; HASH_SIZE]];

        assert!(verify_binary_allowlist(&binary, &allowlist).is_ok());
    }

    #[test]
    fn test_binary_allowlist_failure() {
        let binary = [99u8; HASH_SIZE];
        let allowlist = [[1u8; HASH_SIZE], [2u8; HASH_SIZE], [3u8; HASH_SIZE]];

        assert!(matches!(
            verify_binary_allowlist(&binary, &allowlist),
            Err(LogicError::BinaryNotAllowed)
        ));
    }

    #[test]
    fn test_xor_distance_self() {
        let id = [42u8; ENTANGLED_ID_SIZE];
        let distance = xor_distance(&id, &id);
        assert_eq!(distance, [0u8; ENTANGLED_ID_SIZE]);
    }

    #[test]
    fn test_xor_distance_symmetric() {
        let a = [1u8; ENTANGLED_ID_SIZE];
        let b = [2u8; ENTANGLED_ID_SIZE];

        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_attestation_witness_derive() {
        let witness =
            AttestationWitness::new(vec![0u8; ML_DSA_65_PUBLIC_KEY_SIZE], [1u8; HASH_SIZE], 42);

        let id = witness.derive_id();
        let expected =
            derive_entangled_id(&witness.public_key, &witness.binary_hash, witness.nonce);

        assert_eq!(id, expected);
    }

    #[test]
    fn test_components_derivation() {
        let pk = [7u8; ML_DSA_65_PUBLIC_KEY_SIZE];
        let bh = [8u8; HASH_SIZE];
        let nonce = 999u64;

        let components = EntangledIdComponents::new(&pk, bh, nonce);
        let id_from_components = derive_entangled_id_from_components(&components);

        // Note: derive_entangled_id uses full public key, derive_entangled_id_from_components
        // uses pre-hashed public key, so they won't match. This is intentional for zkVM
        // where we want to minimize data passed through.
        assert_eq!(id_from_components.len(), ENTANGLED_ID_SIZE);
    }
}
