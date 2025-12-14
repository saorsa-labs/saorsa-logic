// Copyright 2024 Saorsa Labs Limited
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
// This file may not be copied, modified, or distributed except according to those terms.

//! Merkle tree primitives for zkVM proofs.
//!
//! This module provides Merkle tree construction and proof verification
//! that can be executed in a zkVM. Merkle trees enable:
//!
//! - **Efficient Verification**: Prove membership with O(log n) data
//! - **Data Integrity**: Root hash commits to all leaves
//! - **Incremental Updates**: Update single leaves efficiently
//!
//! ## Structure
//!
//! ```text
//!              [Root Hash]
//!             /           \
//!       [Hash 01]       [Hash 23]
//!       /      \        /      \
//!   [Hash 0] [Hash 1] [Hash 2] [Hash 3]
//!      |        |        |        |
//!   [Leaf0] [Leaf1]  [Leaf2]  [Leaf3]
//! ```
//!
//! ## zkVM Usage
//!
//! Merkle proofs are ideal for zkVM because verification is:
//! - Deterministic
//! - Low complexity (O(log n) hash operations)
//! - Memory efficient
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                    zkVM Guest Program                       │
//! ├────────────────────────────────────────────────────────────┤
//! │  Inputs (from prover):                                     │
//! │    - leaf: [u8; 32]          (the data being proven)       │
//! │    - proof: Vec<[u8; 32]>    (sibling hashes)              │
//! │    - path: Vec<bool>         (left/right path)             │
//! │    - root: [u8; 32]          (expected root)               │
//! │                                                            │
//! │  Computation (proven):                                      │
//! │    computed_root = verify_proof(leaf, proof, path)         │
//! │    assert!(computed_root == root)                          │
//! │                                                            │
//! │  Outputs (public):                                          │
//! │    - valid: bool                                            │
//! └────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{LogicError, LogicResult};
use blake3::Hasher;

/// Size of Merkle hash in bytes.
pub const MERKLE_HASH_SIZE: usize = 32;

/// Hash two nodes together to form parent.
///
/// Uses domain separation to prevent second preimage attacks:
/// `parent = BLAKE3(0x01 || left || right)`
#[must_use]
pub fn hash_nodes(
    left: &[u8; MERKLE_HASH_SIZE],
    right: &[u8; MERKLE_HASH_SIZE],
) -> [u8; MERKLE_HASH_SIZE] {
    let mut hasher = Hasher::new();
    hasher.update(&[0x01]); // Internal node prefix
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Hash a leaf node.
///
/// Uses domain separation: `leaf_hash = BLAKE3(0x00 || data)`
#[must_use]
pub fn hash_leaf(data: &[u8]) -> [u8; MERKLE_HASH_SIZE] {
    let mut hasher = Hasher::new();
    hasher.update(&[0x00]); // Leaf prefix
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// A Merkle proof for a single leaf.
///
/// Contains the sibling hashes and path needed to verify
/// that a leaf is included in a tree with a given root.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    /// Sibling hashes from leaf to root.
    pub siblings: alloc::vec::Vec<[u8; MERKLE_HASH_SIZE]>,
    /// Path from leaf to root (true = right, false = left).
    pub path: alloc::vec::Vec<bool>,
}

#[cfg(feature = "alloc")]
impl MerkleProof {
    /// Create a new Merkle proof.
    #[must_use]
    pub fn new(
        siblings: alloc::vec::Vec<[u8; MERKLE_HASH_SIZE]>,
        path: alloc::vec::Vec<bool>,
    ) -> Self {
        Self { siblings, path }
    }

    /// Verify this proof against a leaf and root.
    pub fn verify(
        &self,
        leaf_hash: &[u8; MERKLE_HASH_SIZE],
        root: &[u8; MERKLE_HASH_SIZE],
    ) -> LogicResult<()> {
        verify_merkle_proof(leaf_hash, &self.siblings, &self.path, root)
    }

    /// Compute the root from this proof and leaf.
    #[must_use]
    pub fn compute_root(&self, leaf_hash: &[u8; MERKLE_HASH_SIZE]) -> [u8; MERKLE_HASH_SIZE] {
        compute_root_from_proof(leaf_hash, &self.siblings, &self.path)
    }
}

/// Verify a Merkle proof.
///
/// # Arguments
///
/// * `leaf_hash` - Hash of the leaf being proven
/// * `siblings` - Sibling hashes from leaf to root
/// * `path` - Path bits (true = leaf is on right, false = leaf is on left)
/// * `expected_root` - Expected root hash
///
/// # Returns
///
/// `Ok(())` if proof is valid, `Err(MerkleProofInvalid)` otherwise.
pub fn verify_merkle_proof(
    leaf_hash: &[u8; MERKLE_HASH_SIZE],
    siblings: &[[u8; MERKLE_HASH_SIZE]],
    path: &[bool],
    expected_root: &[u8; MERKLE_HASH_SIZE],
) -> LogicResult<()> {
    if siblings.len() != path.len() {
        return Err(LogicError::MerkleProofInvalid);
    }

    let computed_root = compute_root_from_proof(leaf_hash, siblings, path);

    if constant_time_eq(&computed_root, expected_root) {
        Ok(())
    } else {
        Err(LogicError::MerkleProofInvalid)
    }
}

/// Compute root hash from a proof and leaf.
///
/// This is the core computation that would be proven in a zkVM.
#[must_use]
pub fn compute_root_from_proof(
    leaf_hash: &[u8; MERKLE_HASH_SIZE],
    siblings: &[[u8; MERKLE_HASH_SIZE]],
    path: &[bool],
) -> [u8; MERKLE_HASH_SIZE] {
    let mut current = *leaf_hash;

    for (sibling, is_right) in siblings.iter().zip(path.iter()) {
        current = if *is_right {
            // Current node is on the right
            hash_nodes(sibling, &current)
        } else {
            // Current node is on the left
            hash_nodes(&current, sibling)
        };
    }

    current
}

/// Build a Merkle tree from leaves and return the root.
///
/// # Arguments
///
/// * `leaves` - Leaf hashes (must be a power of 2, or will be padded)
///
/// # Returns
///
/// The root hash of the tree.
#[cfg(feature = "alloc")]
#[must_use]
pub fn build_tree_root(leaves: &[[u8; MERKLE_HASH_SIZE]]) -> [u8; MERKLE_HASH_SIZE] {
    if leaves.is_empty() {
        return [0u8; MERKLE_HASH_SIZE];
    }

    if leaves.len() == 1 {
        return leaves[0];
    }

    // Pad to power of 2 if needed
    let mut padded = alloc::vec::Vec::from(leaves);
    while !padded.len().is_power_of_two() {
        padded.push([0u8; MERKLE_HASH_SIZE]);
    }

    let mut current_level = padded;

    while current_level.len() > 1 {
        let mut next_level = alloc::vec::Vec::with_capacity(current_level.len() / 2);

        for pair in current_level.chunks(2) {
            next_level.push(hash_nodes(&pair[0], &pair[1]));
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Generate a Merkle proof for a leaf at a given index.
///
/// # Arguments
///
/// * `leaves` - All leaf hashes
/// * `index` - Index of the leaf to prove
///
/// # Returns
///
/// A Merkle proof for the leaf at the given index.
#[cfg(feature = "alloc")]
#[must_use]
pub fn generate_proof(leaves: &[[u8; MERKLE_HASH_SIZE]], index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }

    // Pad to power of 2
    let mut padded = alloc::vec::Vec::from(leaves);
    while !padded.len().is_power_of_two() {
        padded.push([0u8; MERKLE_HASH_SIZE]);
    }

    let mut siblings = alloc::vec::Vec::new();
    let mut path = alloc::vec::Vec::new();
    let mut current_index = index;
    let mut current_level = padded;

    while current_level.len() > 1 {
        let is_right = current_index % 2 == 1;
        let sibling_index = if is_right {
            current_index - 1
        } else {
            current_index + 1
        };

        siblings.push(current_level[sibling_index]);
        path.push(is_right);

        // Build next level
        let mut next_level = alloc::vec::Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            next_level.push(hash_nodes(&pair[0], &pair[1]));
        }

        current_index /= 2;
        current_level = next_level;
    }

    Some(MerkleProof::new(siblings, path))
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
    fn test_hash_leaf_deterministic() {
        let data = b"leaf data";
        let hash1 = hash_leaf(data);
        let hash2 = hash_leaf(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_nodes_deterministic() {
        let left = [1u8; MERKLE_HASH_SIZE];
        let right = [2u8; MERKLE_HASH_SIZE];

        let parent1 = hash_nodes(&left, &right);
        let parent2 = hash_nodes(&left, &right);
        assert_eq!(parent1, parent2);
    }

    #[test]
    fn test_hash_nodes_order_matters() {
        let a = [1u8; MERKLE_HASH_SIZE];
        let b = [2u8; MERKLE_HASH_SIZE];

        let ab = hash_nodes(&a, &b);
        let ba = hash_nodes(&b, &a);
        assert_ne!(ab, ba);
    }

    #[test]
    fn test_leaf_vs_internal_domain_separation() {
        let data = [1u8; MERKLE_HASH_SIZE];

        // Leaf hash of data
        let leaf = hash_leaf(&data);

        // Internal node hash of data (as if two zero children)
        let internal = hash_nodes(&data, &[0u8; MERKLE_HASH_SIZE]);

        // These should be different due to domain separation
        assert_ne!(leaf, internal);
    }

    #[test]
    fn test_build_tree_single_leaf() {
        let leaves = [hash_leaf(b"only leaf")];
        let root = build_tree_root(&leaves);
        assert_eq!(root, leaves[0]);
    }

    #[test]
    fn test_build_tree_two_leaves() {
        let leaf0 = hash_leaf(b"leaf 0");
        let leaf1 = hash_leaf(b"leaf 1");
        let leaves = [leaf0, leaf1];

        let root = build_tree_root(&leaves);
        let expected = hash_nodes(&leaf0, &leaf1);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_build_tree_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| hash_leaf(&[i as u8])).collect();

        let root = build_tree_root(&leaves);

        // Manual computation
        let h01 = hash_nodes(&leaves[0], &leaves[1]);
        let h23 = hash_nodes(&leaves[2], &leaves[3]);
        let expected = hash_nodes(&h01, &h23);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_generate_and_verify_proof() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| hash_leaf(&[i as u8])).collect();

        let root = build_tree_root(&leaves);

        // Generate and verify proof for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = generate_proof(&leaves, i).expect("proof should exist");
            assert!(
                proof.verify(leaf, &root).is_ok(),
                "proof for leaf {i} should be valid"
            );
        }
    }

    #[test]
    fn test_proof_invalid_root() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| hash_leaf(&[i as u8])).collect();

        let proof = generate_proof(&leaves, 0).expect("proof should exist");
        let wrong_root = [0u8; MERKLE_HASH_SIZE];

        assert!(matches!(
            proof.verify(&leaves[0], &wrong_root),
            Err(LogicError::MerkleProofInvalid)
        ));
    }

    #[test]
    fn test_proof_invalid_leaf() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| hash_leaf(&[i as u8])).collect();

        let root = build_tree_root(&leaves);
        let proof = generate_proof(&leaves, 0).expect("proof should exist");
        let wrong_leaf = [99u8; MERKLE_HASH_SIZE];

        assert!(matches!(
            proof.verify(&wrong_leaf, &root),
            Err(LogicError::MerkleProofInvalid)
        ));
    }

    #[test]
    fn test_compute_root_from_proof() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| hash_leaf(&[i as u8])).collect();

        let root = build_tree_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = generate_proof(&leaves, i).expect("proof should exist");
            let computed_root = proof.compute_root(leaf);
            assert_eq!(
                computed_root, root,
                "computed root should match for leaf {i}"
            );
        }
    }

    #[test]
    fn test_empty_leaves() {
        let leaves: &[[u8; 32]] = &[];
        let root = build_tree_root(leaves);
        assert_eq!(root, [0u8; MERKLE_HASH_SIZE]);
    }

    #[test]
    fn test_generate_proof_out_of_bounds() {
        let leaves = [hash_leaf(b"single")];
        assert!(generate_proof(&leaves, 1).is_none());
    }
}
