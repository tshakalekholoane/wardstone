use std::ffi::c_int;
use std::result;

use crate::primitives::hash::Hash;
use crate::primitives::symmetric::Symmetric;

#[derive(Debug)]
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

pub fn validate_hash(hash: &Hash, expiry: u16) -> Result<bool> {
  let security = hash.digest_len >> 1;
  calculate_year(security).map(|year| year >= expiry)
}

pub fn validate_symmetric(symmetric: &Symmetric, expiry: u16) -> Result<bool> {
  calculate_year(symmetric.security).map(|year| year >= expiry)
}

#[no_mangle]
pub unsafe extern "C" fn lenstra_validate_hash(hash: *const Hash, expiry: u16) -> c_int {
  if let Some(hash_ref) = unsafe { hash.as_ref() } {
    validate_hash(hash_ref, expiry).map_or(-1, |is_compliant| is_compliant as c_int)
  } else {
    -1
  }
}

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
