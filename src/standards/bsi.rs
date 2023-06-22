//! Validate cryptographic primitives against the [BSI TR-02102-1
//! Cryptographic Mechanisms: Recommendations and Key Lengths] technical
//! guide.
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
//! [BSI TR-02102-1 Cryptographic Mechanisms: Recommendations and Key Lengths]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html

use std::collections::HashSet;
use std::ffi::c_int;

use lazy_static::lazy_static;

use crate::primitives::hash::*;
use crate::primitives::symmetric::*;
use crate::standards;
use crate::standards::Context;

lazy_static! {
  static ref SPECIFIED_HASH: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(SHA256.id);
    s.insert(SHA384.id);
    s.insert(SHA3_256.id);
    s.insert(SHA3_384.id);
    s.insert(SHA3_512.id);
    s.insert(SHA512.id);
    s.insert(SHA512_256.id);
    s
  };
  static ref SPECIFIED_SYMMETRIC: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(AES128.id);
    s.insert(AES192.id);
    s.insert(AES256.id);
    s
  };
}

/// Validates a hash function according to page 41 of the guide. The
/// reference is made with regards to applications that require
/// collision resistance such as digital signatures.
///
/// For applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation use [`validate_hash_based`](crate::standards::bsi::validate_hash_based).
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
/// use wardstone::standards::bsi;
///
/// let ctx = Context::default();
/// assert_eq!(bsi::validate_hash(&ctx, &SHA1), Err(SHA256));
/// ```
pub fn validate_hash(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let security = ctx.security().max(hash.collision_resistance());
    match security {
      ..=119 => Err(SHA256),
      120..=128 => Ok(SHA256),
      129..=192 => Ok(SHA384),
      193.. => Ok(SHA512),
    }
  } else {
    Err(SHA256)
  }
}

/// Validates a hash function. The reference is made with regards to
/// applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation.
///
/// For applications that require collision resistance such digital
/// signatures use [`validate_hash`](crate::standards::bsi::validate_hash).
///
/// If the hash function is not compliant then `Err` will contain the
/// recommended primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `Ok` will also hold the recommended primitive with
/// the desired security level.
///
/// **Note:** For an HMAC the minimum security required is ≥ 128 (see
/// p. 45) but the minimum digest length for a hash function that can be
/// used with this primitive is 256 (see p. 41). This means any
/// recommendation from this function will be likely too conservative.
///
/// An alternative might also be suggested for a compliant hash
/// functions with a similar security level in which a switch to the
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
/// use wardstone::standards::bsi;
///
/// let ctx = Context::default();
/// let hmac_sha1 = SHA1;
/// let hmac_sha256 = SHA256;
/// assert_eq!(bsi::validate_hash_based(&ctx, &hmac_sha1), Err(hmac_sha256));
/// ```
pub fn validate_hash_based(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let security = ctx.security().max(hash.pre_image_resistance());
    match security {
      ..=127 => Err(SHA256),
      128..=256 => Ok(SHA256),
      257..=384 => Ok(SHA384),
      385.. => Ok(SHA512),
    }
  } else {
    Err(SHA256)
  }
}

/// Validates a symmetric key primitive according to page 24 of the
/// guide.
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
/// The following illustrates a call to validate a three-key Triple DES
/// key (which is not recommended by the guide).
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::symmetric::{AES128, TDEA3};
/// use wardstone::standards::bsi;
///
/// let ctx = Context::default();
/// assert_eq!(bsi::validate_symmetric(&ctx, &TDEA3), Err(AES128));
/// ```
pub fn validate_symmetric(ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric> {
  // "The present version of this Technical Guideline does not recommend
  // any other block ciphers besides AES" (2023, p. 24).
  if SPECIFIED_SYMMETRIC.contains(&key.id) {
    let security = ctx.security().max(key.security);
    match security {
      ..=119 => Err(AES128),
      120..=128 => Ok(AES128),
      129..=192 => Ok(AES192),
      193.. => Ok(AES256),
    }
  } else {
    Err(AES128)
  }
}

/// Validates a hash function according to page 41 of the guide. The
/// reference is made with regards to applications that require
/// collision resistance such as digital signatures.
///
/// For applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation use `ws_bsi_validate_hash_based`.
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
/// **Caution:** Unlike the NIST standard, the guide does not make a
/// distinction between security requirements based on usage. For
/// example, collision resistance generally requires twice more the
/// security that one would want if they only cared about pre-image
/// resistance. As a result, this module does not have a corresponding
/// `validate_hash_based` function and the recommendation returned may
/// be overly conservative.
///
/// **Note:** An alternative might be suggested for a compliant hash
/// function with a similar security level in which a switch to the
/// recommended primitive would likely be unwarranted. For example, when
/// evaluating compliance for the `SHA3-256`, a recommendation to use
/// `SHA256` will be made but switching to this as a result is likely
/// unnecessary.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_bsi_validate_hash(
  ctx: *const Context,
  hash: *const Hash,
  alternative: *mut Hash,
) -> c_int {
  standards::c_call(validate_hash, ctx, hash, alternative)
}

/// Validates a hash function. The reference is made with regards to
/// applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation.
///
/// For applications that require collision resistance such digital
/// signatures use `ws_bsi_validate_hash`.
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
/// **Note:** For an HMAC the minimum security required is ≥ 128 (see
/// p. 45) but the minimum digest length for a hash function that can be
/// used with this primitive is 256 (see p. 41). This means any
/// recommendation from this function will be likely too conservative.
///
/// An alternative might also be suggested for a compliant hash
/// functions with a similar security level in which a switch to the
/// recommended primitive would likely be unwarranted. For example, when
/// evaluating compliance for the `SHA3-256`, a recommendation to use
/// `SHA256` will be made but switching to this as a result is likely
/// unnecessary.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_bsi_validate_hash_based(
  ctx: *const Context,
  hash: *const Hash,
  alternative: *mut Hash,
) -> c_int {
  standards::c_call(validate_hash_based, ctx, hash, alternative)
}

/// Validates a symmetric key primitive according to pages 24 of the
/// guide.
///
/// If the key is not compliant then `struct ws_symmetric* alternative`
/// will point to the recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `struct ws_symmetric*` will also point to the recommended
/// primitive with the desired security level.
///
/// The function returns `1` if the key is compliant, `0` if it is not,
/// and `-1` if an error occurs as a result of a missing or invalid
/// argument.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_bsi_validate_symmetric(
  ctx: *const Context,
  key: *const Symmetric,
  alternative: *mut Symmetric,
) -> c_int {
  standards::c_call(validate_symmetric, ctx, key, alternative)
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
  use super::*;
  use crate::test_case;

  test_case!(blake2b_256_collision_resistance, validate_hash, &BLAKE2b_256, Err(SHA256));
  test_case!(blake2b_384_collision_resistance, validate_hash, &BLAKE2b_384, Err(SHA256));
  test_case!(blake2b_512_collision_resistance, validate_hash, &BLAKE2b_512, Err(SHA256));
  test_case!(blake2s_256_collision_resistance, validate_hash, &BLAKE2s_256, Err(SHA256));
  test_case!(md4_collision_resistance, validate_hash, &MD4, Err(SHA256));
  test_case!(md5_collision_resistance, validate_hash, &MD5, Err(SHA256));
  test_case!(ripemd160_collision_resistance, validate_hash, &RIPEMD160, Err(SHA256));
  test_case!(sha1_collision_resistance, validate_hash, &SHA1, Err(SHA256));
  test_case!(sha224_collision_resistance, validate_hash, &SHA224, Err(SHA256));
  test_case!(sha256_collision_resistance, validate_hash, &SHA256, Ok(SHA256));
  test_case!(sha384_collision_resistance, validate_hash, &SHA384, Ok(SHA384));
  test_case!(sha3_224_collision_resistance, validate_hash, &SHA3_224, Err(SHA256));
  test_case!(sha3_256_collision_resistance, validate_hash, &SHA3_256, Ok(SHA256));
  test_case!(sha3_384_collision_resistance, validate_hash, &SHA3_384, Ok(SHA384));
  test_case!(sha3_512_collision_resistance, validate_hash, &SHA3_512, Ok(SHA512));
  test_case!(sha512_collision_resistance, validate_hash, &SHA512, Ok(SHA512));
  test_case!(sha512_224_collision_resistance, validate_hash, &SHA512_224, Err(SHA256));
  test_case!(sha512_256_collision_resistance, validate_hash, &SHA512_256, Ok(SHA256));
  test_case!(shake128_collision_resistance, validate_hash, &SHAKE128, Err(SHA256));
  test_case!(shake256_collision_resistance, validate_hash, &SHAKE256, Err(SHA256));

  test_case!(blake2b_256_pre_image_resistance, validate_hash_based, &BLAKE2b_256, Err(SHA256));
  test_case!(blake2b_384_pre_image_resistance, validate_hash_based, &BLAKE2b_384, Err(SHA256));
  test_case!(blake2b_512_pre_image_resistance, validate_hash_based, &BLAKE2b_512, Err(SHA256));
  test_case!(blake2s_256_pre_image_resistance, validate_hash_based, &BLAKE2s_256, Err(SHA256));
  test_case!(md4_pre_image_resistance, validate_hash_based, &MD4, Err(SHA256));
  test_case!(md5_pre_image_resistance, validate_hash_based, &MD5, Err(SHA256));
  test_case!(ripemd160_pre_image_resistance, validate_hash_based, &RIPEMD160, Err(SHA256));
  test_case!(sha1_pre_image_resistance, validate_hash_based, &SHA1, Err(SHA256));
  test_case!(sha224_pre_image_resistance, validate_hash_based, &SHA224, Err(SHA256));
  test_case!(sha256_pre_image_resistance, validate_hash_based, &SHA256, Ok(SHA256));
  test_case!(sha384_pre_image_resistance, validate_hash_based, &SHA384, Ok(SHA384));
  test_case!(sha3_224_pre_image_resistance, validate_hash_based, &SHA3_224, Err(SHA256));
  test_case!(sha3_256_pre_image_resistance, validate_hash_based, &SHA3_256, Ok(SHA256));
  test_case!(sha3_384_pre_image_resistance, validate_hash_based, &SHA3_384, Ok(SHA384));
  test_case!(sha3_512_pre_image_resistance, validate_hash_based, &SHA3_512, Ok(SHA512));
  test_case!(sha512_pre_image_resistance, validate_hash_based, &SHA512, Ok(SHA512));
  test_case!(sha512_224_pre_image_resistance, validate_hash_based, &SHA512_224, Err(SHA256));
  test_case!(sha512_256_pre_image_resistance, validate_hash_based, &SHA512_256, Ok(SHA256));
  test_case!(shake128_pre_image_resistance, validate_hash_based, &SHAKE128, Err(SHA256));
  test_case!(shake256_pre_image_resistance, validate_hash_based, &SHAKE256, Err(SHA256));

  test_case!(two_key_tdea, validate_symmetric, &TDEA2, Err(AES128));
  test_case!(three_key_tdea, validate_symmetric, &TDEA3, Err(AES128));
  test_case!(aes128, validate_symmetric, &AES128, Ok(AES128));
  test_case!(aes192, validate_symmetric, &AES192, Ok(AES192));
  test_case!(aes256, validate_symmetric, &AES256, Ok(AES256));
}
