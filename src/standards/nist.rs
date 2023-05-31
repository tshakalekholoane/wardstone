use std::ffi::c_int;

use crate::primitives::hash::Hash;
use crate::primitives::symmetric::Symmetric;

const CUTOFF_YEAR: u16 = 2023;

pub fn validate_hash(hash: &Hash) -> bool {
  let security = hash.0 >> 1;
  match security {
    ..=111 => false,
    112.. => true,
  }
}

pub fn validate_symmetric(symmetric: &Symmetric, expiry: u16) -> bool {
  let security = symmetric.0;
  match security {
    ..=80 => false,
    112 if expiry < CUTOFF_YEAR => true,
    128.. => true,
    _ => false,
  }
}

#[no_mangle]
pub unsafe extern "C" fn nist_validate_hash(hash: *const Hash) -> c_int {
  if let Some(hash_ref) = unsafe { hash.as_ref() } {
    validate_hash(hash_ref) as c_int
  } else {
    -1
  }
}

#[no_mangle]
pub unsafe extern "C" fn nist_validate_symmetric(
  symmetric: *const Symmetric,
  expiry: u16,
) -> c_int {
  if let Some(symmetric_ref) = unsafe { symmetric.as_ref() } {
    validate_symmetric(symmetric_ref, expiry) as c_int
  } else {
    -1
  }
}
