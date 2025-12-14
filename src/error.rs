// Copyright 2024 Saorsa Labs Limited
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
// This file may not be copied, modified, or distributed except according to those terms.

//! Error types for `saorsa-logic`.
//!
//! Designed to be `no_std` compatible while providing useful error information.

use core::fmt;

/// Result type for `saorsa-logic` operations.
pub type LogicResult<T> = Result<T, LogicError>;

/// Errors that can occur in `saorsa-logic`.
///
/// This enum is designed to be compact and `no_std` compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicError {
    /// Invalid input length for an operation.
    InvalidLength {
        /// What was being validated
        field: &'static str,
        /// Expected length
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Hash verification failed.
    HashMismatch,

    /// Signature verification failed.
    SignatureInvalid,

    /// Merkle proof verification failed.
    MerkleProofInvalid,

    /// `EntangledId` verification failed.
    EntangledIdMismatch,

    /// Binary hash not in allowlist.
    BinaryNotAllowed,

    /// Timestamp validation failed (e.g., sunset expired).
    TimestampInvalid,

    /// Nonce validation failed.
    NonceInvalid,

    /// Public key format is invalid.
    PublicKeyInvalid,
}

impl fmt::Display for LogicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid length for {field}: expected {expected}, got {actual}"
                )
            }
            Self::HashMismatch => write!(f, "hash verification failed"),
            Self::SignatureInvalid => write!(f, "signature verification failed"),
            Self::MerkleProofInvalid => write!(f, "merkle proof verification failed"),
            Self::EntangledIdMismatch => write!(f, "entangled ID verification failed"),
            Self::BinaryNotAllowed => write!(f, "binary hash not in allowlist"),
            Self::TimestampInvalid => write!(f, "timestamp validation failed"),
            Self::NonceInvalid => write!(f, "nonce validation failed"),
            Self::PublicKeyInvalid => write!(f, "public key format is invalid"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LogicError {}
