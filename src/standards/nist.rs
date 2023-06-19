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
use crate::primitives::ecc::*;
use crate::primitives::ffc::*;
use crate::primitives::hash::*;
use crate::primitives::ifc::*;
use crate::primitives::symmetric::*;

const CUTOFF_YEAR: u16 = 2031; // See p. 59.
const CUTOFF_YEAR_3TDEA: u16 = 2023; // See footnote on p. 54.
const CUTOFF_YEAR_DSA: u16 = 2023; // See FIPS-186-5 p. 16.

lazy_static! {
  static ref SPECIFIED_EC: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(P224.id);
    s.insert(P256.id);
    s.insert(P384.id);
    s.insert(P521.id);
    s.insert(W25519.id);
    s.insert(W448.id);
    s.insert(Curve25519.id);
    s.insert(Curve448.id);
    s.insert(Edwards25519.id);
    s.insert(Edwards448.id);
    s.insert(E448.id);
    s.insert(brainpoolP224r1.id);
    s.insert(brainpoolP256r1.id);
    s.insert(brainpoolP320r1.id);
    s.insert(brainpoolP384r1.id);
    s.insert(brainpoolP512r1.id);
    s.insert(secp256k1.id);
    s
  };
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
  static ref SPECIFIED_SYMMETRIC: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(TDEA2.id);
    s.insert(TDEA3.id);
    s.insert(AES128.id);
    s.insert(AES192.id);
    s.insert(AES256.id);
    s
  };
}

/// Validates a finite field cryptography primitive.
///
/// Examples include the DSA and key establishment algorithms such as
/// Diffie-Hellman and MQV which can also be implemented as such,
/// according to page 54-55 of the standard.
///
/// A newer revision of FIPS-186, FIPS-186-5 no longer approves the DSA.
///
/// If the key is not compliant then `Err` will contain the recommended
/// key sizes L and N that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `Ok` will also hold the recommended key sizes L and N with
/// the desired security level.
///
/// **Note:** The standard specifies the choices for the pair l and n
/// and so primitives that do not strictly conform to this will be
/// deemed non-compliant. This restricts the choice of security
/// specified in the `Context` to the values 160, 224, 256, 384, and
/// 512.
///
/// # Example
///
/// The following illustrates a call to validate a compliant key.
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::ffc::FFC_2048_224;
/// use wardstone::standards::nist;
///
/// let ctx = Context::default();
/// let dsa_2048 = FFC_2048_224;
/// assert_eq!(nist::validate_ffc(&ctx, &dsa_2048), Ok(FFC_2048_224));
/// ```
pub fn validate_ffc(ctx: &Context, key: &Ffc) -> Result<Ffc, Ffc> {
  // TODO: Does this also apply to other key agreement use cases?
  if ctx.year() > CUTOFF_YEAR_DSA {
    return Err(NOT_SUPPORTED);
  }

  // Use the public key size n as a proxy for security.
  let mut aux = *key;
  aux.n = ctx.security().max(key.n);

  match aux {
    Ffc { l: 1024, n: 160 } => {
      if ctx.year() > CUTOFF_YEAR {
        Err(FFC_3072_256)
      } else {
        Err(FFC_2048_224)
      }
    },
    Ffc {
      l: 2048,
      n: 224 | 256,
    } => {
      if ctx.year() > CUTOFF_YEAR {
        Err(FFC_3072_256)
      } else {
        Ok(FFC_2048_224)
      }
    },
    Ffc { l: 3072, n: 256 } => Ok(FFC_3072_256),
    Ffc { l: 7680, n: 384 } => Ok(FFC_7680_384),
    Ffc { l: 15360, n: 512 } => Ok(FFC_15360_512),
    _ => Err(NOT_SUPPORTED),
  }
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size according
/// to page 54-55 of the standard.
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
/// use wardstone::primitives::ecc::P224;
/// use wardstone::standards::nist;
///
/// let ctx = Context::default();
/// assert_eq!(nist::validate_ecc(&ctx, &P224), Ok(P224));
/// ```
pub fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
  if SPECIFIED_EC.contains(&key.id) {
    let security = ctx.security().max(key.f >> 1);
    match security {
      ..=111 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(P256)
        } else {
          Err(P224)
        }
      },
      112 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(P256)
        } else {
          Ok(P224)
        }
      },
      113..=128 => Ok(P256),
      129..=192 => Ok(P384),
      193.. => Ok(P521),
    }
  } else {
    Err(P256)
  }
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications that require
/// collision resistance such as digital signatures.
///
/// For applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation use
/// [`validate_hash_based`](crate::standards::nist::validate_hash_based).
///
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
/// use wardstone::context::Context;
/// use wardstone::primitives::hash::{SHA1, SHA224};
/// use wardstone::standards::nist;
///
/// let ctx = Context::default();
/// assert_eq!(nist::validate_hash(&ctx, &SHA1), Err(SHA224));
/// ```
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
/// signatures use
/// [`validate_hash`](crate::standards::nist::validate_hash).
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
/// use wardstone::context::Context;
/// use wardstone::primitives::hash::{SHA1, SHA224};
/// use wardstone::standards::nist;
///
/// let ctx = Context::default();
/// assert_eq!(nist::validate_hash_based(&ctx, &SHA1), Err(SHA224));
/// ```
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

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size according to page 54-55 of the standard.
///
/// If the key is not compliant then `Err` will contain the recommended
/// key size that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `Ok` will also hold the recommended key size with the desired
/// security level.
///
/// **Note:** Unlike other functions in this module, this will return a
/// generic structure that specifies minimum private and public key
/// sizes.
///
/// # Example
///
/// The following illustrates a call to validate a compliant key.
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::ifc::IFC_2048;
/// use wardstone::standards::nist;
///
/// let ctx = Context::default();
/// assert_eq!(nist::validate_ifc(&ctx, &IFC_2048), Ok(IFC_2048));
/// ```
pub fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<Ifc, Ifc> {
  let security = ctx.security().max(*key.security().start());
  match security {
    ..=111 => {
      if ctx.year() > CUTOFF_YEAR {
        Err(IFC_3072)
      } else {
        Err(IFC_2048)
      }
    },
    112..=127 => {
      if ctx.year() > CUTOFF_YEAR {
        Err(IFC_3072)
      } else {
        Ok(IFC_2048)
      }
    },
    128..=191 => Ok(IFC_3072),
    192..=255 => Ok(IFC_7680),
    256.. => Ok(IFC_15360),
  }
}

/// Validates a symmetric key primitive according to pages 54-55 of the
/// standard.
///
/// If the key is not compliant then `Err` will contain the recommended
/// primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `Ok` will also hold the recommended primitive with
/// the desired security level.
///
/// # Example
///
/// The following illustrates a call to validate a three-key Triple DES
/// key (which is deprecated through the year 2023).
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::symmetric::{AES128, TDEA3};
/// use wardstone::standards::nist;
///
/// let ctx = Context::default();
/// assert_eq!(nist::validate_symmetric(&ctx, &TDEA3), Ok(AES128));
/// ```
pub fn validate_symmetric(ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric> {
  if SPECIFIED_SYMMETRIC.contains(&key.id) {
    let security = ctx.security().max(key.security);
    match security {
      ..=111 => Err(AES128),
      112 => {
        // See SP 800-131Ar2 p. 7.
        let cutoff = if key.id == TDEA3.id {
          CUTOFF_YEAR_3TDEA
        } else {
          CUTOFF_YEAR
        };
        if ctx.year() > cutoff {
          Err(AES128)
        } else {
          Ok(AES128)
        }
      },
      113..=128 => Ok(AES128),
      129..=192 => Ok(AES192),
      193.. => Ok(AES256),
    }
  } else {
    Err(AES128)
  }
}

// This function abstracts a call to a Rust function `f` and returns a
// result following C error handling conventions.
unsafe fn c_call<T>(
  f: fn(&Context, &T) -> Result<T, T>,
  ctx: *const Context,
  primitive: *const T,
  alternative: *mut T,
) -> c_int {
  if ctx.is_null() || primitive.is_null() {
    return -1;
  }

  let (recommendation, is_compliant) = match f(ctx.as_ref().unwrap(), primitive.as_ref().unwrap()) {
    Ok(recommendation) => (recommendation, true),
    Err(recommendation) => (recommendation, false),
  };

  if !alternative.is_null() {
    *alternative = recommendation;
  }

  is_compliant as c_int
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size according
/// to page 54-55 of the standard.
///
/// If the key is not compliant then `ws_ecc*` will contain the
/// recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `ws_ecc*` will also hold the recommended primitive with the
/// desired security level.
///
/// The function returns 1 if the key is compliant, 0 if it is not, and
/// -1 if an error occurs as a result of a missing or invalid argument.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_ecc(
  ctx: *const Context,
  key: *const Ecc,
  alternative: *mut Ecc,
) -> c_int {
  c_call(validate_ecc, ctx, key, alternative)
}

/// Validates a finite field cryptography primitive function examples
/// which include DSA and key establishment algorithms such as
/// Diffie-Hellman and MQV according to page 54-55 of the standard.
///
/// If the key is not compliant then `struct ws_ffc*` will point to the
/// recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `struct ws_ffc` will also point to the recommended primitive
/// with the desired security level.
///
/// The function returns 1 if the key is compliant, 0 if it is not, and
/// -1 if an error occurs as a result of a missing or invalid argument.
///
/// **Note:** Unlike other functions in this module, this will return a
/// generic structure that specifies minimum private and public key
/// sizes.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_ffc(
  ctx: *const Context,
  key: *const Ffc,
  alternative: *mut Ffc,
) -> c_int {
  c_call(validate_ffc, ctx, key, alternative)
}

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size according to page 54-55 of the standard.
///
/// If the key is not compliant then `ws_ifc*` will point to the
/// recommended key size that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `ws_ifc*` will also point to the recommended key size with
/// the desired security level.
///
/// The function returns 1 if the key is compliant, 0 if it is not, and
/// -1 if an error occurs as a result of a missing or invalid argument.
///
/// **Note:** Unlike other functions in this module, this will return a
/// generic structure that specifies minimum private and public key
/// sizes.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_ifc(
  ctx: *const Context,
  key: *const Ifc,
  alternative: *mut Ifc,
) -> c_int {
  c_call(validate_ifc, ctx, key, alternative)
}

/// Validates a hash function according to page 56 of the standard. The
/// reference is made with regards to applications that require
/// collision resistance such as digital signatures.
///
/// For applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation use `ws_validate_hash_based`.
///
/// If the hash function is not compliant then `struct ws_hash*
/// alternative` will point to the recommended key sizes L and N that
/// one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `struct ws_hash*` will also point to the recommended
/// key sizes L and N with the desired security level.
///
/// The function returns 1 if the hash function is compliant, 0 if it is
/// not, and -1 if an error occurs as a result of a missing or invalid
/// argument.
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
/// `struct ws_hash* alternative` will point to the recommended
/// primitive that one should use instead.
///
/// If the hash function is compliant but the context specifies a higher
/// security level, `struct ws_hash*` will also point to the recommended
/// primitive with the desired security level.
///
/// The function returns 1 if the hash function is compliant, 0 if it is
/// not, and -1 if an error occurs as a result of a missing or invalid
/// argument.
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
/// will point to the recommended primitive that one should use instead.
///
/// If the symmetric key is compliant but the context specifies a higher
/// security level, `struct ws_symmetric*` will also point to the
/// recommended primitive with the desired security level.
///
/// The function returns 1 if the key is compliant, 0 if it is not, and
/// -1 if an error occurs as a result of a missing or invalid argument.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_nist_validate_symmetric(
  ctx: *const Context,
  key: *const Symmetric,
  alternative: *mut Symmetric,
) -> c_int {
  c_call(validate_symmetric, ctx, key, alternative)
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
  use super::*;

  macro_rules! test_case {
    ($name:ident, $func:ident, $input:expr, $want:expr) => {
      #[test]
      fn $name() {
        let ctx = Context::default();
        assert_eq!($func(&ctx, $input), $want);
      }
    };
  }

  test_case!(p224, validate_ecc, &P224, Ok(P224));
  test_case!(p256, validate_ecc, &P256, Ok(P256));
  test_case!(p384, validate_ecc, &P384, Ok(P384));
  test_case!(p521, validate_ecc, &P521, Ok(P521));
  test_case!(w25519, validate_ecc, &W25519, Ok(P256));
  test_case!(w448, validate_ecc, &W448, Ok(P521));
  test_case!(curve25519, validate_ecc, &Curve25519, Ok(P256));
  test_case!(curve488, validate_ecc, &Curve448, Ok(P521));
  test_case!(edwards25519, validate_ecc, &Edwards25519, Ok(P256));
  test_case!(edwards448, validate_ecc, &Edwards448, Ok(P521));
  test_case!(e448, validate_ecc, &E448, Ok(P521));
  test_case!(brainpoolp224r1, validate_ecc, &brainpoolP224r1, Ok(P224));
  test_case!(brainpoolp256r1, validate_ecc, &brainpoolP256r1, Ok(P256));
  test_case!(brainpoolp320r1, validate_ecc, &brainpoolP320r1, Ok(P384));
  test_case!(brainpoolp384r1, validate_ecc, &brainpoolP384r1, Ok(P384));
  test_case!(brainpoolp512r1, validate_ecc, &brainpoolP512r1, Ok(P521));
  test_case!(secp256k1_, validate_ecc, &secp256k1, Ok(P256));

  test_case!(ffc_1024_160, validate_ffc, &FFC_1024_160, Err(FFC_2048_224));
  test_case!(ffc_2048_224, validate_ffc, &FFC_2048_224, Ok(FFC_2048_224));
  test_case!(ffc_3072_256, validate_ffc, &FFC_3072_256, Ok(FFC_3072_256));
  test_case!(ffc_7680_384, validate_ffc, &FFC_7680_384, Ok(FFC_7680_384));
  test_case!(ffc_15360_512, validate_ffc, &FFC_15360_512, Ok(FFC_15360_512));

  test_case!(ifc_1024, validate_ifc, &IFC_1024, Err(IFC_2048));
  test_case!(ifc_2048, validate_ifc, &IFC_2048, Ok(IFC_2048));
  test_case!(ifc_3072, validate_ifc, &IFC_3072, Ok(IFC_3072));
  test_case!(ifc_7680, validate_ifc, &IFC_7680, Ok(IFC_7680));
  test_case!(ifc_15360, validate_ifc, &IFC_15360, Ok(IFC_15360));

  test_case!(blake2b_256_collision_resistance, validate_hash, &BLAKE2b_256, Err(SHA256));
  test_case!(blake2b_384_collision_resistance, validate_hash, &BLAKE2b_384, Err(SHA256));
  test_case!(blake2b_512_collision_resistance, validate_hash, &BLAKE2b_512, Err(SHA256));
  test_case!(blake2s_256_collision_resistance, validate_hash, &BLAKE2s_256, Err(SHA256));
  test_case!(md4_collision_resistance, validate_hash, &MD4, Err(SHA256));
  test_case!(md5_collision_resistance, validate_hash, &MD5, Err(SHA256));
  test_case!(ripemd160_collision_resistance, validate_hash, &RIPEMD160, Err(SHA256));
  test_case!(sha1_collision_resistance, validate_hash, &SHA1, Err(SHA224));
  test_case!(sha224_collision_resistance, validate_hash, &SHA224, Ok(SHA224));
  test_case!(sha256_collision_resistance, validate_hash, &SHA256, Ok(SHA256));
  test_case!(sha384_collision_resistance, validate_hash, &SHA384, Ok(SHA384));
  test_case!(sha3_224_collision_resistance, validate_hash, &SHA3_224, Ok(SHA224));
  test_case!(sha3_256_collision_resistance, validate_hash, &SHA3_256, Ok(SHA256));
  test_case!(sha3_384_collision_resistance, validate_hash, &SHA3_384, Ok(SHA384));
  test_case!(sha3_512_collision_resistance, validate_hash, &SHA3_512, Ok(SHA512));
  test_case!(sha512_collision_resistance, validate_hash, &SHA512, Ok(SHA512));
  test_case!(sha512_224_collision_resistance, validate_hash, &SHA512_224, Ok(SHA224));
  test_case!(sha512_256_collision_resistance, validate_hash, &SHA512_256, Ok(SHA256));
  test_case!(shake128_collision_resistance, validate_hash, &SHAKE128, Err(SHA256));
  test_case!(shake256_collision_resistance, validate_hash, &SHAKE256, Err(SHA256));

  test_case!(blake2b_256_pre_image_resistance, validate_hash_based, &BLAKE2b_256, Err(SHA224));
  test_case!(blake2b_384_pre_image_resistance, validate_hash_based, &BLAKE2b_384, Err(SHA224));
  test_case!(blake2b_512_pre_image_resistance, validate_hash_based, &BLAKE2b_512, Err(SHA224));
  test_case!(blake2s_256_pre_image_resistance, validate_hash_based, &BLAKE2s_256, Err(SHA224));
  test_case!(md4_pre_image_resistance, validate_hash_based, &MD4, Err(SHA224));
  test_case!(md5_pre_image_resistance, validate_hash_based, &MD5, Err(SHA224));
  test_case!(ripemd160_pre_image_resistance, validate_hash_based, &RIPEMD160, Err(SHA224));
  test_case!(sha1_pre_image_resistance, validate_hash_based, &SHA1, Err(SHA224));
  test_case!(sha224_pre_image_resistance, validate_hash_based, &SHA224, Ok(SHA224));
  test_case!(sha256_pre_image_resistance, validate_hash_based, &SHA256, Ok(SHA256));
  test_case!(sha384_pre_image_resistance, validate_hash_based, &SHA384, Ok(SHA384));
  test_case!(sha3_224_pre_image_resistance, validate_hash_based, &SHA3_224, Ok(SHA224));
  test_case!(sha3_256_pre_image_resistance, validate_hash_based, &SHA3_256, Ok(SHA256));
  test_case!(sha3_384_pre_image_resistance, validate_hash_based, &SHA3_384, Ok(SHA384));
  test_case!(sha3_512_pre_image_resistance, validate_hash_based, &SHA3_512, Ok(SHA512));
  test_case!(sha512_pre_image_resistance, validate_hash_based, &SHA512, Ok(SHA512));
  test_case!(sha512_224_pre_image_resistance, validate_hash_based, &SHA512_224, Ok(SHA224));
  test_case!(sha512_256_pre_image_resistance, validate_hash_based, &SHA512_256, Ok(SHA256));
  test_case!(shake128_pre_image_resistance, validate_hash_based, &SHAKE128, Err(SHA224));
  test_case!(shake256_pre_image_resistance, validate_hash_based, &SHAKE256, Err(SHA224));

  test_case!(two_key_tdea, validate_symmetric, &TDEA2, Err(AES128));
  test_case!(three_key_tdea, validate_symmetric, &TDEA3, Ok(AES128));
  test_case!(aes128, validate_symmetric, &AES128, Ok(AES128));
  test_case!(aes192, validate_symmetric, &AES192, Ok(AES192));
  test_case!(aes256, validate_symmetric, &AES256, Ok(AES256));
}
