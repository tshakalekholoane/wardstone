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
use crate::primitives::ecc::*;
use crate::primitives::ffc::*;
use crate::primitives::hash::*;
use crate::primitives::ifc::*;
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
    let mut lambda = (year - BASE_YEAR) << 1;
    lambda /= 3;
    lambda += BASE_SECURITY;
    Ok(lambda)
  }
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size.
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
/// use wardstone::primitives::ecc::{brainpoolP256r1, ECC_256};
/// use wardstone::standards::lenstra;
///
/// let ctx = Context::default();
/// assert_eq!(lenstra::validate_ecc(&ctx, &brainpoolP256r1), Ok(ECC_256));
/// ```
pub fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
  let implied_security = ctx.security().max(key.security());
  let recommendation = match implied_security {
    ..=111 => ECC_NOT_SUPPORTED,
    112 => ECC_224,
    113..=128 => ECC_256,
    129..=192 => ECC_384,
    193.. => ECC_512,
  };
  // Because group orders are generally chosen as powers of 2,
  // log(#<g>, base = 4) gives the lambda value of half the exponent.
  // For example, DSA has #<g> = 2 ** 160 which implies lambda = 80.
  calculate_security(ctx.year()).map_or(Err(recommendation), |min_security| {
    if implied_security < min_security {
      Err(recommendation)
    } else {
      Ok(recommendation)
    }
  })
}

/// Validates a finite field cryptography primitive.
///
/// Examples include the DSA and key establishment algorithms such as
/// Diffie-Hellman and MQV which can also be implemented as such.
///
/// If the key is not compliant then `Err` will contain the recommended
/// key sizes L and N that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `Ok` will also hold the recommended key sizes L and N with
/// the desired security level.
///
/// # Example
///
/// The following illustrates a call to validate a compliant key.
///
/// ```
/// use wardstone::context::Context;
/// use wardstone::primitives::ffc::FFC_2048_256;
/// use wardstone::standards::lenstra;
///
/// let ctx = Context::default();
/// let dsa_2048 = FFC_2048_256;
/// assert_eq!(lenstra::validate_ffc(&ctx, &dsa_2048), Ok(dsa_2048));
/// ```
pub fn validate_ffc(ctx: &Context, key: &Ffc) -> Result<Ffc, Ffc> {
  // HACK: Use the private key as a proxy for security.
  let (implied_year, implied_security) = match key.l {
    ..=1023 => (u16::MIN, u16::MIN),
    1024 => (2006, 72),
    1025..=1280 => (2014, 78),
    1281..=1536 => (2020, 82),
    1537..=2048 => (2030, 88),
    2049..=3072 => (2046, 99),
    3073..=4096 => (2060, 108),
    4097.. /* =8192 */ => (2100, 135),
  };

  // XXX: The table above might yield overly conservative
  // recommendations.
  let year = implied_year.max(ctx.year());
  let (security_range, recommendation) = match year {
    ..=2006 => (0..=72, FFC_1024_160),
    2007..=2014 => (73..=78, FFC_2048_224),
    2015..=2020 => (79..=82, FFC_2048_224),
    2021..=2030 => (83..=88, FFC_2048_256),
    2031..=2046 => (89..=99, FFC_3072_256),
    2047..=2060 => (100..=108, FFC_7680_384),
    2061.. /* =2100 */ => (109..=135 /* technically u16::MAX */, FFC_15360_512),
  };

  let security = ctx.security().max(implied_security);
  if !security_range.contains(&security) {
    Err(recommendation)
  } else {
    Ok(recommendation)
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

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm based on pages 17-25.
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
/// use wardstone::standards::lenstra;
///
/// let ctx = Context::default();
/// let rsa_2048 = IFC_2048;
/// assert_eq!(lenstra::validate_ifc(&ctx, &rsa_2048), Ok(rsa_2048));
/// ```
pub fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<Ifc, Ifc> {
  // Per Table 4 on page 25.
  let (implied_year, implied_security) = match key.k {
    ..=1023 => (u16::MIN, u16::MIN),
    1024 => (2006, 72),
    1025..=1280 => (2014, 78),
    1281..=1536 => (2020, 82),
    1537..=2048 => (2030, 88),
    2049..=3072 => (2046, 99),
    3073..=4096 => (2060, 108),
    4097.. /* =8192 */ => (2100, 135),
  };

  let year = implied_year.max(ctx.year());
  let (security_range, recommendation) = match year {
    ..=2006 => (0..=72, IFC_1024),
    2007..=2014 => (73..=78, IFC_1280),
    2015..=2020 => (79..=82, IFC_1536),
    2021..=2030 => (83..=88, IFC_2048),
    2031..=2046 => (89..=99, IFC_3072),
    2047..=2060 => (100..=108, IFC_4096),
    2061.. /* =2100 */ => (109..=135 /* technically u16::MAX */, IFC_8192),
  };

  let security = ctx.security().max(implied_security);
  if !security_range.contains(&security) {
    Err(recommendation)
  } else {
    Ok(recommendation)
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
    calculate_security(ctx.year()).map_or(Err(recommendation), |min_security| {
      if implied_security < min_security {
        Err(recommendation)
      } else {
        Ok(recommendation)
      }
    })
  } else {
    Err(AES128)
  }
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size.
///
/// If the key is not compliant then `ws_ecc*` will contain the
/// recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `ws_ecc*` will also hold the recommended primitive with the
/// desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_lenstra_validate_ecc(
  ctx: *const Context,
  key: *const Ecc,
  alternative: *mut Ecc,
) -> c_int {
  standards::c_call(validate_ecc, ctx, key, alternative)
}

/// Validates a finite field cryptography primitive function examples
/// which include DSA and key establishment algorithms such as
/// Diffie-Hellman and MQV.
///
/// If the key is not compliant then `struct ws_ffc*` will point to the
/// recommended primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `struct ws_ffc` will also point to the recommended primitive
/// with the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
///
/// **Note:** Unlike other functions in this module, this will return a
/// generic structure that specifies minimum private and public key
/// sizes.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_lenstra_validate_ffc(
  ctx: *const Context,
  key: *const Ffc,
  alternative: *mut Ffc,
) -> c_int {
  standards::c_call(validate_ffc, ctx, key, alternative)
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

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm based on pages 17-25.
///
/// If the key is not compliant then `ws_ifc*` will point to the
/// recommended key size that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `ws_ifc*` will also point to the recommended key size with
/// the desired security level.
///
/// The function returns `1` if the hash function is compliant, `0` if
/// it is not, and `-1` if an error occurs as a result of a missing or
/// invalid argument.
//
/// **Note:** Unlike other functions in this module, this will return a
/// generic structure that specifies minimum private and public key
/// sizes.
///
/// # Safety
///
/// See module documentation for comment on safety.
#[no_mangle]
pub unsafe extern "C" fn ws_lenstra_validate_ifc(
  ctx: *const Context,
  key: *const Ifc,
  alternative: *mut Ifc,
) -> c_int {
  standards::c_call(validate_ifc, ctx, key, alternative)
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
#[rustfmt::skip]
mod tests {
  use super::*;
  use crate::test_case;

  test_case!(p224, validate_ecc, &P224, Ok(ECC_224));
  test_case!(p256, validate_ecc, &P256, Ok(ECC_256));
  test_case!(p384, validate_ecc, &P384, Ok(ECC_384));
  test_case!(p521, validate_ecc, &P521, Ok(ECC_512));
  test_case!(w25519, validate_ecc, &W25519, Ok(ECC_256));
  test_case!(w448, validate_ecc, &W448, Ok(ECC_512));
  test_case!(curve25519, validate_ecc, &Curve25519, Ok(ECC_256));
  test_case!(curve488, validate_ecc, &Curve448, Ok(ECC_512));
  test_case!(edwards25519, validate_ecc, &Edwards25519, Ok(ECC_256));
  test_case!(edwards448, validate_ecc, &Edwards448, Ok(ECC_512));
  test_case!(e448, validate_ecc, &E448, Ok(ECC_512));
  test_case!(brainpoolp224r1, validate_ecc, &brainpoolP224r1, Ok(ECC_224));
  test_case!(brainpoolp256r1, validate_ecc, &brainpoolP256r1, Ok(ECC_256));
  test_case!(brainpoolp320r1, validate_ecc, &brainpoolP320r1, Ok(ECC_384));
  test_case!(brainpoolp384r1, validate_ecc, &brainpoolP384r1, Ok(ECC_384));
  test_case!(brainpoolp512r1, validate_ecc, &brainpoolP512r1, Ok(ECC_512));
  test_case!(secp256k1_, validate_ecc, &secp256k1, Ok(ECC_256));

  test_case!(ffc_1024_160, validate_ffc, &FFC_1024_160, Err(FFC_2048_256));
  test_case!(ffc_2048_224, validate_ffc, &FFC_2048_256, Ok(FFC_2048_256));
  test_case!(ffc_3072_256, validate_ffc, &FFC_3072_256, Ok(FFC_3072_256));
  test_case!(ffc_7680_384, validate_ffc, &FFC_7680_384, Ok(FFC_15360_512));
  test_case!(ffc_15360_512, validate_ffc, &FFC_15360_512, Ok(FFC_15360_512));

  test_case!(ifc_1024, validate_ifc, &IFC_1024, Err(IFC_2048));
  test_case!(ifc_1280, validate_ifc, &IFC_1280, Err(IFC_2048));
  test_case!(ifc_1536, validate_ifc, &IFC_1536, Err(IFC_2048));
  test_case!(ifc_2048, validate_ifc, &IFC_2048, Ok(IFC_2048));
  test_case!(ifc_3072, validate_ifc, &IFC_3072, Ok(IFC_3072));
  test_case!(ifc_4096, validate_ifc, &IFC_4096, Ok(IFC_4096));
  test_case!(ifc_7680, validate_ifc, &IFC_7680, Ok(IFC_8192));
  test_case!(ifc_8192, validate_ifc, &IFC_8192, Ok(IFC_8192));
  test_case!(ifc_15360, validate_ifc, &IFC_15360, Ok(IFC_8192));

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
