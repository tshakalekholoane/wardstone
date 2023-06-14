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

use crate::context::Context;
use crate::primitives::hash::{
  Hash, SHA1, SHA224, SHA256, SHA384, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA512, SHA512_224,
  SHA512_256,
};
use crate::primitives::symmetric::{Symmetric, AES128};

const CUTOFF_YEAR: u16 = 2031;

lazy_static! {
  static ref SPECIFIED_HASH: HashSet<u16> = {
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
    s
  };
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications that require
/// collision resistance such as digital signatures.
///
/// For applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation use [`validate_hash_based`](crate::standards::nist::validate_hash_based).
///
/// If the hash function is not compliant then `Err` will contain the
/// recommended primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `Ok` will also hold the recommended primitive with
/// the desired security level.
///
/// **Note:** that this means an alternative might be suggested for a
/// compliant hash functions with a similar security level in which a
/// switch to the recommended primitive would likely be unwarranted. For
/// example, when evaluating compliance for the `SHA3-256`, a
/// recommendation to use `SHA256` will be made but switching to this as
/// a result is likely unnecessary.
///
/// **Caution:** The default recommendation is from the SHA2 family.
/// While this is safe for most use cases, it is generally not
/// recommended for hashing secrets given its lack of resistance against
/// length extension attacks.
///
/// # Example
///
/// The following illustrates a call to validate a non-compliant hash
/// function.
///
/// ```
/// use crate::context::Context;
/// use crate::primitives::hash::{SHA1, SHA224};
///
/// let ctx = Context::default();
/// assert_eq!(validate_hash(&ctx, &SHA1), Err(SHA224));
pub fn validate_hash(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let security = ctx.security().max(hash.collision_resistance());
    match security {
      ..=111 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(SHA256)
        } else {
          Err(SHA224)
        }
      },
      112 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(SHA256)
        } else {
          Ok(SHA224)
        }
      },
      113..=128 => Ok(SHA256),
      129..=192 => Ok(SHA384),
      193.. => Ok(SHA512),
    }
  } else {
    Err(SHA256)
  }
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications that primarily
/// require pre-image resistance such as message authentication codes
/// (MACs), key derivation functions (KDFs), and random bit generation.
///
/// For applications that require collision resistance such digital
/// signatures use [`validate_hash`](crate::standards::nist::validate_hash).
///
/// If the hash function is not compliant then `Err` will contain the
/// recommended primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `Ok` will also hold the recommended primitive with
/// the desired security level.
///
/// **Note:** that this means an alternative might be suggested for a
/// compliant hash functions with a similar security level in which a
/// switch to the recommended primitive would likely be unwarranted. For
/// example, when evaluating compliance for the `SHA3-256`, a
/// recommendation to use `SHA256` will be made but switching to this as
/// a result is likely unnecessary.
///
/// **Caution:** The default recommendation is from the SHA2 family.
/// While this is safe for most use cases, it is generally not
/// recommended for hashing secrets given its lack of resistance against
/// length extension attacks.
///
/// # Example
///
/// The following illustrates a call to validate a non-compliant hash
/// function.
///
/// ```
/// use crate::context::Context;
/// use crate::primitives::hash::{SHA1, SHA224};
///
/// let ctx = Context::default();
/// assert_eq!(validate_hash_based(&ctx, &SHA1), Err(SHA224));
pub fn validate_hash_based(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let security = ctx.security().max(hash.pre_image_resistance());
    match security {
      ..=111 => Err(SHA224),
      112..=127 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(SHA224)
        } else {
          Ok(SHA224)
        }
      },
      128..=224 => Ok(SHA224),
      225..=256 => Ok(SHA256),
      257..=394 => Ok(SHA384),
      395.. => Ok(SHA512),
    }
  } else {
    Err(SHA224)
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

// This function abstracts a call to a Rust function `f` and returns a
// result following C error handling conventions.
unsafe fn c_call<T>(
  f: fn(&Context, &T) -> Result<T, T>,
  ctx: *const Context,
  hash: *const T,
  alternative: *mut T,
) -> c_int {
  if ctx.is_null() || hash.is_null() {
    return -1;
  }

  let (recommendation, ok) = match f(ctx.as_ref().unwrap(), hash.as_ref().unwrap()) {
    Ok(recommendation) => (recommendation, true),
    Err(recommendation) => (recommendation, false),
  };

  if !alternative.is_null() {
    *alternative = recommendation;
  }

  ok as c_int
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications that require
/// collision resistance such as digital signatures.
///
/// For applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation use `ws_validate_hash_based`.
///
/// If the hash function is not compliant then `struct ws_hash* alternative`
/// will contain the recommended primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `struct ws_hash*` will also hold the recommended
/// primitive with the desired security level.
///
/// **Note:** that this means an alternative might be suggested for a
/// compliant hash functions with a similar security level in which a
/// switch to the recommended primitive would likely be unwarranted. For
/// example, when evaluating compliance for the `SHA3-256`, a
/// recommendation to use `SHA256` will be made but this likely
/// unnecessary.
///
/// **Caution:** The default recommendation is from the SHA2 family.
/// While this is safe for most use cases, it is generally not
/// recommended for hashing secrets given its lack of resistance against
/// length extension attacks.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_hash(
  ctx: *const Context,
  hash: *const Hash,
  alternative: *mut Hash,
) -> c_int {
  c_call(validate_hash, ctx, hash, alternative)
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications that primarily
/// require pre-image resistance such as message authentication codes
/// (MACs), key derivation functions (KDFs), and random bit generation.
///
/// For applications that require collision resistance such digital
/// signatures use `ws_nist_validate_hash`.
///
/// If the hash function is not compliant then
/// `struct ws_hash* alternative` will contain the recommended primitive
/// that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `struct ws_hash*` will also hold the recommended
/// primitive with the desired security level.
///
/// **Note:** that this means an alternative might be suggested for a
/// compliant hash functions with a similar security level in which a
/// switch to the recommended primitive would likely be unwarranted. For
/// example, when evaluating compliance for the `SHA3-256`, a
/// recommendation to use `SHA256` will be made but this likely
/// unnecessary.
///
/// **Caution:** The default recommendation is from the SHA2 family.
/// While this is safe for most use cases, it is generally not
/// recommended for hashing secrets given its lack of resistance against
/// length extension attacks.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_hash_based(
  ctx: *const Context,
  hash: *const Hash,
  alternative: *mut Hash,
) -> c_int {
  c_call(validate_hash_based, ctx, hash, alternative)
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
/// See module documentation for comment on safety.
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
        assert_eq!(validate_hash(&Context::default(), $input), $want);
      }
    };
  }

  macro_rules! test_hash_based {
    ($name:ident, $input:expr, $want:expr) => {
      #[test]
      fn $name() {
        assert_eq!(validate_hash_based(&Context::default(), $input), $want);
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

  test_hash!(blake2b_256_collision_resistance, &BLAKE2b_256, Err(SHA256));
  test_hash!(blake2b_384_collision_resistance, &BLAKE2b_384, Err(SHA256));
  test_hash!(blake2b_512_collision_resistance, &BLAKE2b_512, Err(SHA256));
  test_hash!(blake2s_256_collision_resistance, &BLAKE2s_256, Err(SHA256));
  test_hash!(md4_collision_resistance, &MD4, Err(SHA256));
  test_hash!(md5_collision_resistance, &MD5, Err(SHA256));
  test_hash!(ripemd160_collision_resistance, &RIPEMD160, Err(SHA256));
  test_hash!(sha1_collision_resistance, &SHA1, Err(SHA224));
  test_hash!(sha224_collision_resistance, &SHA224, Ok(SHA224));
  test_hash!(sha256_collision_resistance, &SHA256, Ok(SHA256));
  test_hash!(sha384_collision_resistance, &SHA384, Ok(SHA384));
  test_hash!(sha3_224_collision_resistance, &SHA3_224, Ok(SHA224));
  test_hash!(sha3_256_collision_resistance, &SHA3_256, Ok(SHA256));
  test_hash!(sha3_384_collision_resistance, &SHA3_384, Ok(SHA384));
  test_hash!(sha3_512_collision_resistance, &SHA3_512, Ok(SHA512));
  test_hash!(sha512_collision_resistance, &SHA512, Ok(SHA512));
  test_hash!(sha512_224_collision_resistance, &SHA512_224, Ok(SHA224));
  test_hash!(sha512_256_collision_resistance, &SHA512_256, Ok(SHA256));
  test_hash!(shake128_collision_resistance, &SHAKE128, Err(SHA256));
  test_hash!(shake256_collision_resistance, &SHAKE256, Err(SHA256));
  test_hash_based!(blake2b_256_pre_image_resistance, &BLAKE2b_256, Err(SHA224));
  test_hash_based!(blake2b_384_pre_image_resistance, &BLAKE2b_384, Err(SHA224));
  test_hash_based!(blake2b_512_pre_image_resistance, &BLAKE2b_512, Err(SHA224));
  test_hash_based!(blake2s_256_pre_image_resistance, &BLAKE2s_256, Err(SHA224));
  test_hash_based!(md4_pre_image_resistance, &MD4, Err(SHA224));
  test_hash_based!(md5_pre_image_resistance, &MD5, Err(SHA224));
  test_hash_based!(ripemd160_pre_image_resistance, &RIPEMD160, Err(SHA224));
  test_hash_based!(sha1_pre_image_resistance, &SHA1, Err(SHA224));
  test_hash_based!(sha224_pre_image_resistance, &SHA224, Ok(SHA224));
  test_hash_based!(sha256_pre_image_resistance, &SHA256, Ok(SHA256));
  test_hash_based!(sha384_pre_image_resistance, &SHA384, Ok(SHA384));
  test_hash_based!(sha3_224_pre_image_resistance, &SHA3_224, Ok(SHA224));
  test_hash_based!(sha3_256_pre_image_resistance, &SHA3_256, Ok(SHA256));
  test_hash_based!(sha3_384_pre_image_resistance, &SHA3_384, Ok(SHA384));
  test_hash_based!(sha3_512_pre_image_resistance, &SHA3_512, Ok(SHA512));
  test_hash_based!(sha512_pre_image_resistance, &SHA512, Ok(SHA512));
  test_hash_based!(sha512_224_pre_image_resistance, &SHA512_224, Ok(SHA224));
  test_hash_based!(sha512_256_pre_image_resistance, &SHA512_256, Ok(SHA256));
  test_hash_based!(shake128_pre_image_resistance, &SHAKE128, Err(SHA224));
  test_hash_based!(shake256_pre_image_resistance, &SHAKE256, Err(SHA224));
  test_symmetric!(two_key_tdea, &TDEA2, CUTOFF_YEAR, Err(AES128));
  test_symmetric!(three_key_tdea_pre, &TDEA3, CUTOFF_YEAR, Ok(()));
  test_symmetric!(three_key_tdea_post, &TDEA3, CUTOFF_YEAR + 1, Err(AES128));
  test_symmetric!(aes128, &AES128, CUTOFF_YEAR, Ok(()));
  test_symmetric!(aes192, &AES192, CUTOFF_YEAR, Ok(()));
  test_symmetric!(aes256, &AES256, CUTOFF_YEAR, Ok(()));
}
