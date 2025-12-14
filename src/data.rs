// Copyright 2024 Saorsa Labs Limited
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
// This file may not be copied, modified, or distributed except according to those terms.

//! Data verification primitives for zkVM execution.
//!
//! This module provides content-addressing and verification functions that
//! can be proven in a zkVM. These are fundamental to Saorsa's storage system.
//!
//! ## Content Addressing
//!
//! All data in Saorsa is content-addressed using BLAKE3. The address of
//! data is its hash:
//!
//! ```text
//! address = BLAKE3(data)
//! ```
//!
//! This enables:
//! - **Deduplication**: Same content has same address
//! - **Integrity**: Address proves content hasn't been modified
//! - **Verifiability**: Anyone can verify content matches address
//!
//! ## zkVM Usage
//!
//! In zkVM, we prove that stored data matches its claimed address:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                    zkVM Guest Program                       │
//! ├────────────────────────────────────────────────────────────┤
//! │  Inputs (from prover):                                     │
//! │    - data: Vec<u8>        (the actual content)             │
//! │    - claimed_hash: [u8;32] (the claimed address)           │
//! │                                                            │
//! │  Computation (proven):                                      │
//! │    computed_hash = BLAKE3(data)                            │
//! │    assert!(computed_hash == claimed_hash)                  │
//! │                                                            │
//! │  Outputs (public):                                          │
//! │    - verified: bool                                         │
//! │    - data_hash: [u8; 32]                                    │
//! └────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{LogicError, LogicResult};
use blake3::Hasher;

/// Size of content hash in bytes.
pub const CONTENT_HASH_SIZE: usize = 32;

/// Compute the content hash (address) of data.
///
/// This is the fundamental content-addressing function in Saorsa.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 32-byte BLAKE3 hash.
///
/// # Example
///
/// ```rust
/// use saorsa_logic::data::compute_content_hash;
///
/// let data = b"Hello, Saorsa!";
/// let hash = compute_content_hash(data);
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn compute_content_hash(data: &[u8]) -> [u8; CONTENT_HASH_SIZE] {
    *blake3::hash(data).as_bytes()
}

/// Verify that data matches its claimed hash.
///
/// # Arguments
///
/// * `data` - The data to verify
/// * `claimed_hash` - The expected hash
///
/// # Returns
///
/// `Ok(())` if the hash matches, `Err(HashMismatch)` otherwise.
///
/// # Example
///
/// ```rust
/// use saorsa_logic::data::{compute_content_hash, verify_content_hash};
///
/// let data = b"Hello, Saorsa!";
/// let hash = compute_content_hash(data);
/// assert!(verify_content_hash(data, &hash).is_ok());
/// ```
pub fn verify_content_hash(data: &[u8], claimed_hash: &[u8; CONTENT_HASH_SIZE]) -> LogicResult<()> {
    let computed = compute_content_hash(data);
    if constant_time_eq(&computed, claimed_hash) {
        Ok(())
    } else {
        Err(LogicError::HashMismatch)
    }
}

/// Compute a keyed hash for data authentication.
///
/// Used for creating authenticated data structures where the key
/// provides domain separation.
///
/// # Arguments
///
/// * `key` - Domain separation key
/// * `data` - Data to hash
///
/// # Returns
///
/// A 32-byte keyed hash.
#[must_use]
pub fn compute_keyed_hash(key: &[u8], data: &[u8]) -> [u8; CONTENT_HASH_SIZE] {
    let mut hasher = Hasher::new_keyed(&derive_blake3_key(key));
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Derive a BLAKE3 key from arbitrary-length input.
///
/// BLAKE3 keyed mode requires exactly 32 bytes. This function
/// hashes the input to produce a valid key.
fn derive_blake3_key(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

/// Verify a keyed hash.
pub fn verify_keyed_hash(
    key: &[u8],
    data: &[u8],
    claimed_hash: &[u8; CONTENT_HASH_SIZE],
) -> LogicResult<()> {
    let computed = compute_keyed_hash(key, data);
    if constant_time_eq(&computed, claimed_hash) {
        Ok(())
    } else {
        Err(LogicError::HashMismatch)
    }
}

/// Chunk data into fixed-size pieces and compute their hashes.
///
/// This is used for chunked storage where large data is split
/// into smaller pieces.
///
/// # Arguments
///
/// * `data` - Data to chunk
/// * `chunk_size` - Size of each chunk (last chunk may be smaller)
///
/// # Returns
///
/// A vector of (chunk_hash, chunk_data) pairs.
#[cfg(feature = "alloc")]
#[must_use]
pub fn chunk_and_hash(
    data: &[u8],
    chunk_size: usize,
) -> alloc::vec::Vec<([u8; CONTENT_HASH_SIZE], alloc::vec::Vec<u8>)> {
    let mut result = alloc::vec::Vec::new();

    for chunk in data.chunks(chunk_size) {
        let hash = compute_content_hash(chunk);
        result.push((hash, chunk.to_vec()));
    }

    result
}

/// Compute a content hash with prefix for domain separation.
///
/// Useful for preventing hash collision attacks across different
/// data types in the system.
///
/// # Arguments
///
/// * `prefix` - Domain prefix (e.g., "chunk", "manifest", "key")
/// * `data` - Data to hash
#[must_use]
pub fn compute_prefixed_hash(prefix: &[u8], data: &[u8]) -> [u8; CONTENT_HASH_SIZE] {
    let mut hasher = Hasher::new();
    hasher.update(prefix);
    hasher.update(&[0u8]); // null separator
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Storage operation types for zkVM verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StorageOp {
    /// Store new data
    Store = 0,
    /// Retrieve existing data
    Retrieve = 1,
    /// Delete data
    Delete = 2,
    /// Replicate data to another node
    Replicate = 3,
}

/// Witness data for storage operation proofs.
///
/// Contains all information needed to verify a storage operation in zkVM.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct StorageWitness {
    /// Type of operation
    pub op: StorageOp,
    /// Content hash (address)
    pub content_hash: [u8; CONTENT_HASH_SIZE],
    /// The actual data (for Store/Retrieve)
    pub data: Option<alloc::vec::Vec<u8>>,
    /// Node that performed the operation
    pub node_id: [u8; 32],
    /// Timestamp of operation
    pub timestamp: u64,
}

#[cfg(feature = "alloc")]
impl StorageWitness {
    /// Verify that the data matches the content hash.
    pub fn verify_content(&self) -> LogicResult<()> {
        match &self.data {
            Some(data) => verify_content_hash(data, &self.content_hash),
            None => Ok(()), // No data to verify (e.g., delete operation)
        }
    }
}

/// Constant-time equality comparison.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_content_hash_deterministic() {
        let data = b"test data for hashing";
        let hash1 = compute_content_hash(data);
        let hash2 = compute_content_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_content_hash_different_data() {
        let data1 = b"first data";
        let data2 = b"second data";
        let hash1 = compute_content_hash(data1);
        let hash2 = compute_content_hash(data2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_content_hash_success() {
        let data = b"verify me";
        let hash = compute_content_hash(data);
        assert!(verify_content_hash(data, &hash).is_ok());
    }

    #[test]
    fn test_verify_content_hash_failure() {
        let data = b"verify me";
        let wrong_hash = [0u8; CONTENT_HASH_SIZE];
        assert!(matches!(
            verify_content_hash(data, &wrong_hash),
            Err(LogicError::HashMismatch)
        ));
    }

    #[test]
    fn test_keyed_hash_different_keys() {
        let data = b"same data";
        let key1 = b"key1";
        let key2 = b"key2";

        let hash1 = compute_keyed_hash(key1, data);
        let hash2 = compute_keyed_hash(key2, data);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_keyed_hash_verification() {
        let key = b"my-key";
        let data = b"my-data";

        let hash = compute_keyed_hash(key, data);
        assert!(verify_keyed_hash(key, data, &hash).is_ok());
    }

    #[test]
    fn test_prefixed_hash_domain_separation() {
        let data = b"same data";

        let hash1 = compute_prefixed_hash(b"chunk", data);
        let hash2 = compute_prefixed_hash(b"manifest", data);

        assert_ne!(
            hash1, hash2,
            "different prefixes should produce different hashes"
        );
    }

    #[test]
    fn test_empty_data() {
        let empty: &[u8] = &[];
        let hash = compute_content_hash(empty);
        assert!(verify_content_hash(empty, &hash).is_ok());
    }

    #[test]
    fn test_large_data() {
        let large_data = vec![42u8; 1024 * 1024]; // 1 MB
        let hash = compute_content_hash(&large_data);
        assert!(verify_content_hash(&large_data, &hash).is_ok());
    }
}
