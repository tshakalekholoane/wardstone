//! Validate cryptographic primitives against the [NIST Special
//! Publication 800-57 Part 1 Revision 5 standard].
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
//!
//! [NIST Special Publication 800-57 Part 1 Revision 5 standard]: https://doi.org/10.6028/NIST.SP.800-57pt1r5

use std::collections::HashSet;
use std::ffi::c_int;

use lazy_static::lazy_static;

use crate::primitives::hash::{
  Hash, SHA1, SHA224, SHA256, SHA384, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA512, SHA512_224,
  SHA512_256, SHAKE128, SHAKE256,
};
use crate::primitives::symmetric::{Symmetric, AES128};

const CUTOFF_YEAR: u16 = 2023;

lazy_static! {
  static ref CUSTOM_HASH_FUNCTIONS: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(SHAKE128.id);
    s.insert(SHAKE256.id);
    s
  };
  static ref SPECIFIED_HASH_FUNCTIONS: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(SHA1.id);
    s.insert(SHA224.id);
    s.insert(SHA256.id);
    s.insert(SHA384.id);
    s.insert(SHA3_224.id);
    s.insert(SHA3_256.id);
    s.insert(SHA3_384.id);
    s.insert(SHA3_512.id);
    s.insert(SHA512.id);
    s.insert(SHA512_224.id);
    s.insert(SHA512_256.id);
    s.insert(SHAKE128.id);
    s.insert(SHAKE256.id);
    s
  };
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications involving digital
/// signatures and others that require collision resistance.
///
/// If the hash function is not compliant then `Err` will contain the
/// recommended primitive that one should use instead.
///
/// **Caution:** The default recommendation is SHA256. While this is
/// safe for most use cases, it is generally not recommended for hashing
/// secrets given its lack of resistance against length extension
/// attacks.
///
/// # Example
///
/// The following illustrates a call to validate a non-compliant hash
/// function.
///
/// ```
/// use crate::primitives::hash::{SHA1, SHA256};
///
/// assert_eq!(validate_hash(&SHA1), Err(SHA256));
/// ```
pub fn validate_hash(hash: &Hash) -> Result<(), Hash> {
  if SPECIFIED_HASH_FUNCTIONS.contains(&hash.id) {
    let security = if CUSTOM_HASH_FUNCTIONS.contains(&hash.id) {
      hash.n
    } else {
      hash.n >> 1
    };
    match security {
      ..=111 => Err(SHA256),
      112.. => Ok(()),
    }
  } else {
    Err(SHA256)
  }
}

/// Validates a symmetric key primitive according to pages 54-55 of the
/// standard.
///
/// If the key is not compliant then `Err` will contain the recommended
/// primitive that one should use instead.
///
/// # Example
///
/// The following illustrates a call to validate a three-key Triple DES
/// key which is deprecated through the year 2023.
///
/// ```
/// use crate::primitives::symmetric::{AES128, TDEA3};
///
/// const CUTOFF_YEAR: u16 = 2023;
///
/// assert_eq!(validate_symmetric(&TDEA3, CUTOFF_YEAR), Ok(()));
/// assert_eq!(validate_symmetric(&TDEA3, CUTOFF_YEAR + 1), Err(AES128));
/// ```
pub fn validate_symmetric(key: &Symmetric, expiry: u16) -> Result<(), Symmetric> {
  match key.security {
    112 if expiry <= CUTOFF_YEAR => Ok(()),
    ..=127 => Err(AES128),
    128.. => Ok(()),
  }
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications involving digital
/// signatures and others that require collision resistance.
///
/// If the hash function is not compliant then
/// `struct ws_hash* alternative` will contain the recommended primitive
/// that one should use instead.
///
/// **Caution:** The default recommendation is SHA256. While this is
/// safe for most use cases, it is generally not recommended for hashing
/// secrets given its lack of resistance against length extension
/// attacks.
///
/// # Safety
///
/// See [module documentation](crate::standards::nist) for comment on
/// safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_hash(hash: *const Hash, alternative: *mut Hash) -> c_int {
  unsafe {
    hash
      .as_ref()
      .map_or(-1, |hash_ref| match validate_hash(hash_ref) {
        Ok(_) => 1,
        Err(recommendation) => {
          if !alternative.is_null() {
            *alternative = recommendation;
          }
          0
        },
      })
  }
}

/// Validates a symmetric key primitive according to pages 54-55 of the
/// standard.
///
/// If the key is not compliant then `struct ws_symmetric* alternative`
/// will contain the recommended primitive that one should use instead.
///
/// The function returns 1 if the key is compliant, 0 if it is not, and
/// -1 if an error occurs as a result of a missing or invalid argument.
///
/// # Safety
///
/// See [module documentation](crate::standards::nist) for comment on
/// safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_symmetric(
  key: *const Symmetric,
  expiry: u16,
  alternative: *mut Symmetric,
) -> c_int {
  unsafe {
    key
      .as_ref()
      .map_or(-1, |key_ref| match validate_symmetric(key_ref, expiry) {
        Ok(_) => 1,
        Err(recommendation) => {
          if !alternative.is_null() {
            *alternative = recommendation;
          }
          0
        },
      })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::primitives::hash::*;
  use crate::primitives::symmetric::*;

  macro_rules! test_hash {
    ($name:ident, $input:expr, $want:expr) => {
      #[test]
      fn $name() {
        assert_eq!(validate_hash($input), $want);
      }
    };
  }

  macro_rules! test_symmetric {
    ($name:ident, $input_a:expr, $input_b:expr, $want:expr) => {
      #[test]
      fn $name() {
        assert_eq!(validate_symmetric($input_a, $input_b), $want);
      }
    };
  }

  test_hash!(blake2b_256, &BLAKE2b_256, Err(SHA256));
  test_hash!(blake2b_384, &BLAKE2b_384, Err(SHA256));
  test_hash!(blake2b_512, &BLAKE2b_512, Err(SHA256));
  test_hash!(blake2s_256, &BLAKE2s_256, Err(SHA256));
  test_hash!(md4, &MD4, Err(SHA256));
  test_hash!(md5, &MD5, Err(SHA256));
  test_hash!(ripemd160, &RIPEMD160, Err(SHA256));
  test_hash!(sha1, &SHA1, Err(SHA256));
  test_hash!(sha224, &SHA224, Ok(()));
  test_hash!(sha256, &SHA256, Ok(()));
  test_hash!(sha384, &SHA384, Ok(()));
  test_hash!(sha3_224, &SHA3_224, Ok(()));
  test_hash!(sha3_256, &SHA3_256, Ok(()));
  test_hash!(sha3_384, &SHA3_384, Ok(()));
  test_hash!(sha3_512, &SHA3_512, Ok(()));
  test_hash!(sha512, &SHA512, Ok(()));
  test_hash!(sha512_224, &SHA512_224, Ok(()));
  test_hash!(sha512_256, &SHA512_256, Ok(()));
  test_hash!(shake128, &SHAKE128, Ok(()));
  test_hash!(shake256, &SHAKE256, Ok(()));

  test_symmetric!(two_key_tdea, &TDEA2, CUTOFF_YEAR, Err(AES128));
  test_symmetric!(three_key_tdea_pre, &TDEA3, CUTOFF_YEAR, Ok(()));
  test_symmetric!(three_key_tdea_post, &TDEA3, CUTOFF_YEAR + 1, Err(AES128));
  test_symmetric!(aes128, &AES128, CUTOFF_YEAR, Ok(()));
  test_symmetric!(aes192, &AES192, CUTOFF_YEAR, Ok(()));
  test_symmetric!(aes256, &AES256, CUTOFF_YEAR, Ok(()));
}
