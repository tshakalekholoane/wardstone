//! Validate cryptographic primitives against the levels of security
//! mentioned in the paper Key Lengths, Arjen K. Lenstra, The Handbook
//! of Information Security, 06/2004.
//!
//! # Safety
//!
//! This module contains functions that use raw pointers as arguments
//! for reading and writing data. However, this is only for the C API
//! that is exposed to interact with safe Rust equivalents. The C API is
//! essentially a wrapper around the Rust function to maintain
//! consistency with existing conventions.
//!
//! Checks against null dereferences are made in which the function will
//! return `-1` if the argument is required.

use std::ffi::c_int;
use std::result;

use crate::primitives::hash::Hash;
use crate::primitives::symmetric::Symmetric;

#[derive(PartialEq, Eq, Debug)]
pub enum ValidationError {
  SecurityLevelTooLow,
}

type Result<T> = result::Result<T, ValidationError>;

const BASE_YEAR: u16 = 1982;
const BASE_SECURITY: u16 = 56;

fn calculate_year(security: u16) -> Result<u16> {
  if security < BASE_SECURITY {
    return Err(ValidationError::SecurityLevelTooLow);
  }
  Ok(BASE_YEAR + (((security + (security << 1)) - 168) >> 1))
}

/// Validates a hash function according to page 14 of the paper.
pub fn validate_hash(hash: &Hash, expiry: u16) -> Result<bool> {
  let security = hash.n >> 1;
  calculate_year(security).map(|year| year >= expiry)
}

/// Validates a symmetric key primitive according to pages 11-12 of the
/// paper.
pub fn validate_symmetric(symmetric: &Symmetric, expiry: u16) -> Result<bool> {
  calculate_year(symmetric.security).map(|year| year >= expiry)
}

/// Validates a hash function according to page 14 of the paper.
///
/// # Safety
///
/// See [module documentation](crate::standards::lenstra) for comment on
/// safety.
#[no_mangle]
pub unsafe extern "C" fn lenstra_validate_hash(hash: *const Hash, expiry: u16) -> c_int {
  if let Some(hash_ref) = unsafe { hash.as_ref() } {
    validate_hash(hash_ref, expiry).map_or(-1, |is_compliant| is_compliant as c_int)
  } else {
    -1
  }
}

/// Validates a symmetric key primitive according to pages 11-12 of the
/// paper.
///
/// # Safety
///
/// See [module documentation](crate::standards::lenstra) for comment on
/// safety.
#[no_mangle]
pub unsafe extern "C" fn lenstra_validate_symmetric(
  symmetric: *const Symmetric,
  expiry: u16,
) -> c_int {
  if let Some(symmetric_ref) = unsafe { symmetric.as_ref() } {
    validate_symmetric(symmetric_ref, expiry).map_or(-1, |is_compliant| is_compliant as c_int)
  } else {
    -1
  }
}
