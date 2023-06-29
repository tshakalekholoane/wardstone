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

use std::collections::HashSet;
use std::ffi::c_int;

use lazy_static::lazy_static;

use crate::context::Context;
use crate::primitives::hash::*;
use crate::primitives::symmetric::*;
use crate::standards;

#[derive(PartialEq, Eq, Debug)]
pub enum ValidationError {
  SecurityLevelTooLow,
}

const BASE_YEAR: u16 = 1982;
const BASE_SECURITY: u16 = 56;

lazy_static! {
  static ref SPECIFIED_HASH: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(RIPEMD160.id);
    s.insert(SHA1.id);
    s.insert(SHA256.id);
    s.insert(SHA384.id);
    s.insert(SHA512.id);
    s
  };
  static ref SPECIFIED_SYMMETRIC: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(AES128.id);
    s.insert(AES192.id);
    s.insert(AES256.id);
    s.insert(DES.id);
    s.insert(DESX.id);
    s.insert(IDEA.id);
    s.insert(TDEA2.id);
    s.insert(TDEA3.id);
    s
  };
}

// Calculates the security according to the formula on page 7. If the
// year is less than the BASE_YEAR, a ValidationError is returned.
fn calculate_security(year: u16) -> Result<u16, ValidationError> {
  if year < BASE_YEAR {
    Err(ValidationError::SecurityLevelTooLow)
  } else {
    let mut a = (year - BASE_YEAR) << 1;
    a /= 3;
    a += BASE_SECURITY;
    Ok(a)
  }
}

/// Validates a hash function according to pages 12-14 of the paper.
///
/// Unlike other functions in this module, there is no distinction in
/// security based on the application. As such this module does not have
/// a corresponding `validate_hash_based` function. All hash function
/// and hash based application are assessed by this single function.
///
/// If the hash function is not compliant then `Err` will contain the
/// recommended primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `Ok` will also hold the recommended primitive with
/// the desired security level.
///
/// **Note:** An alternative might be suggested for a compliant hash
/// function with a similar security level in which a switch to the
/// recommended primitive would likely be unwarranted. For example, when
/// evaluating compliance for the `SHA3-256`, a recommendation to use
/// `SHA256` will be made but switching to this as a result is likely
/// unnecessary.
///
/// # Example
///
/// The following illustrates a call to validate a non-compliant hash
/// function.
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::hash::{SHA1, SHA256};
/// use wardstone::standards::lenstra;
///
/// let ctx = Context::default();
/// assert_eq!(lenstra::validate_hash(&ctx, &SHA1), Err(SHA256));
/// ```
pub fn validate_hash(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let implied_security = ctx.security().max(hash.collision_resistance());
    let recommendation = match implied_security {
      // SHA1 and RIPEMD-160 offer less security than their digest
      // length so they are omitted even though they might cover the
      // range ..=80.
      ..=128 => SHA256,
      129..=192 => SHA384,
      193.. => SHA512,
    };
    calculate_security(ctx.year()).map_or(Err(recommendation), |minimum_security| {
      if implied_security < minimum_security {
        Err(recommendation)
      } else {
        Ok(recommendation)
      }
    })
  } else {
    Err(SHA256)
  }
}

/// Validates a symmetric key primitive according to pages 9-12 of the
/// paper.
///
/// If the key is not compliant then `Err` will contain the recommended
/// primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `Ok` will also hold the recommended primitive with the
/// desired security level.
///
/// # Example
///
/// The following illustrates a call to validate a compliant key.
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::symmetric::TDEA3;
/// use wardstone::standards::lenstra;
///
/// let ctx = Context::default();
/// assert_eq!(lenstra::validate_symmetric(&ctx, &TDEA3), Ok(TDEA3));
/// ```
pub fn validate_symmetric(ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric> {
  if SPECIFIED_SYMMETRIC.contains(&key.id) {
    let implied_security = ctx.security().max(key.security);
    let recommendation = match implied_security {
      ..=95 => TDEA2,
      96..=112 => TDEA3,
      113..=120 => DESX,
      121..=128 => AES128,
      129..=192 => AES192,
      193.. => AES256,
    };
    calculate_security(ctx.year()).map_or(Err(recommendation), |minimum_security| {
      if implied_security < minimum_security {
        Err(recommendation)
      } else {
        Ok(recommendation)
      }
    })
  } else {
    Err(AES128)
  }
}

/// Validates a hash function according to page 14 of the paper.
///
/// If the hash function is not compliant then
/// `struct ws_hash* alternative` will point to the recommended
/// primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `struct ws_hash*` will also point to the recommended
/// primitive with the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// **Note:** that this means an alternative might be suggested for a
/// compliant hash functions with a similar security level in which a
/// switch to the recommended primitive would likely be unwarranted. For
/// example, when evaluating compliance for the `SHA3-256`, a
/// recommendation to use `SHA256` will be made but this likely
/// unnecessary.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_lenstra_validate_hash(
  ctx: *const Context,
  hash: *const Hash,
  alternative: *mut Hash,
) -> c_int {
  standards::c_call(validate_hash, ctx, hash, alternative)
}

/// Validates a symmetric key primitive according to pages 9-12 of the
/// paper.
///
/// If the key is not compliant then `struct ws_symmetric* alternative`
/// will point to the recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `struct ws_symmetric*` will also point to the recommended
/// primitive with the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_lenstra_validate_symmetric(
  ctx: *const Context,
  key: *const Symmetric,
  alternative: *mut Symmetric,
) -> c_int {
  standards::c_call(validate_symmetric, ctx, key, alternative)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::test_case;

  test_case!(blake_224, validate_hash, &BLAKE_224, Err(SHA256));
  test_case!(blake_256, validate_hash, &BLAKE_256, Err(SHA256));
  test_case!(blake_384, validate_hash, &BLAKE_384, Err(SHA256));
  test_case!(blake_512, validate_hash, &BLAKE_512, Err(SHA256));
  test_case!(blake2b_256, validate_hash, &BLAKE2b_256, Err(SHA256));
  test_case!(blake2b_384, validate_hash, &BLAKE2b_384, Err(SHA256));
  test_case!(blake2b_512, validate_hash, &BLAKE2b_512, Err(SHA256));
  test_case!(blake2s_256, validate_hash, &BLAKE2s_256, Err(SHA256));
  test_case!(md4, validate_hash, &MD4, Err(SHA256));
  test_case!(md5, validate_hash, &MD5, Err(SHA256));
  test_case!(ripemd160, validate_hash, &RIPEMD160, Err(SHA256));
  test_case!(sha1, validate_hash, &SHA1, Err(SHA256));
  test_case!(sha224, validate_hash, &SHA224, Err(SHA256));
  test_case!(sha256, validate_hash, &SHA256, Ok(SHA256));
  test_case!(sha384, validate_hash, &SHA384, Ok(SHA384));
  test_case!(sha3_224, validate_hash, &SHA3_224, Err(SHA256));
  test_case!(sha3_256, validate_hash, &SHA3_256, Err(SHA256));
  test_case!(sha3_384, validate_hash, &SHA3_384, Err(SHA256));
  test_case!(sha3_512, validate_hash, &SHA3_512, Err(SHA256));
  test_case!(sha512, validate_hash, &SHA512, Ok(SHA512));
  test_case!(sha512_224, validate_hash, &SHA512_224, Err(SHA256));
  test_case!(sha512_256, validate_hash, &SHA512_256, Err(SHA256));
  test_case!(shake128, validate_hash, &SHAKE128, Err(SHA256));
  test_case!(shake256, validate_hash, &SHAKE256, Err(SHA256));
  test_case!(whirlpool, validate_hash, &WHIRLPOOL, Err(SHA256));

  test_case!(aes128, validate_symmetric, &AES128, Ok(AES128));
  test_case!(aes192, validate_symmetric, &AES192, Ok(AES192));
  test_case!(aes256, validate_symmetric, &AES256, Ok(AES256));
  test_case!(camellia128, validate_symmetric, &Camellia128, Err(AES128));
  test_case!(camellia192, validate_symmetric, &Camellia192, Err(AES128));
  test_case!(camellia256, validate_symmetric, &Camellia256, Err(AES128));
  test_case!(des, validate_symmetric, &DES, Err(TDEA2));
  test_case!(desx, validate_symmetric, &DESX, Ok(DESX));
  test_case!(idea, validate_symmetric, &IDEA, Ok(AES128));
  test_case!(serpent128, validate_symmetric, &Serpent128, Err(AES128));
  test_case!(serpent192, validate_symmetric, &Serpent192, Err(AES128));
  test_case!(serpent256, validate_symmetric, &Serpent256, Err(AES128));
  test_case!(three_key_tdea, validate_symmetric, &TDEA3, Ok(TDEA3));
  test_case!(two_key_tdea, validate_symmetric, &TDEA2, Ok(TDEA2));
}
