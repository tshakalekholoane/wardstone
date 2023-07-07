//! Validate cryptographic primitives against the Commercial National
//! Security Algorithm Suites, [CNSA 1.0] and [CNSA 2.0].
//!
//! [CNSA 1.0]: https://media.defense.gov/2021/Sep/27/2002862527/-1/-1/0/CNSS%20WORKSHEET.PDF
//! [CNSA 2.0]: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
use std::collections::HashSet;

use crate::context::Context;
use crate::primitives::ecc::*;
use crate::primitives::ffc::*;
use crate::primitives::hash::*;
use crate::primitives::ifc::*;
use crate::primitives::symmetric::*;

// Exclusive use of CNSA 2.0 by this date.
const CUTOFF_YEAR: u16 = 2030;

lazy_static! {
  static ref SPECIFIED_HASH: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(SHA384.id);
    s.insert(SHA512.id);
    s
  };
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment.
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
/// The following illustrates a call to validate a non-compliant key.
///
/// ```
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::ecc::{P256, P384};
/// use wardstone_core::standards::cnsa;
///
/// let ctx = Context::default();
/// assert_eq!(cnsa::validate_ecc(&ctx, &P256), Err(P384));
/// ```
pub fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
  if ctx.year() > CUTOFF_YEAR {
    return Err(ECC_NOT_SUPPORTED);
  }

  if *key == P384 {
    Ok(P384)
  } else {
    Err(P384)
  }
}

/// Validates a finite field cryptography primitive.
///
/// Examples include the DSA and key establishment algorithms such as
/// Diffie-Hellman and MQV which can also be implemented as such.
///
/// This primitive is not supported by either version of the CNSA
/// guidance.
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
/// The following illustrates a call to validate a non-compliant key.
///
/// ```
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::ffc::{FFC_7680_384, FFC_NOT_SUPPORTED};
/// use wardstone_core::standards::cnsa;
///
/// let ctx = Context::default();
/// let dsa_7680 = FFC_7680_384;
/// assert_eq!(cnsa::validate_ffc(&ctx, &dsa_7680), Err(FFC_NOT_SUPPORTED));
/// ```
pub fn validate_ffc(_ctx: &Context, _key: &Ffc) -> Result<Ffc, Ffc> {
  Err(FFC_NOT_SUPPORTED)
}

/// Validates a hash function.
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
/// # Example
///
/// The following illustrates a call to validate a non-compliant hash
/// function.
///
/// ```
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::hash::{SHA1, SHA384};
/// use wardstone_core::standards::cnsa;
///
/// let ctx = Context::default();
/// assert_eq!(cnsa::validate_hash(&ctx, &SHA1), Err(SHA384));
/// ```
pub fn validate_hash(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let security = ctx.security().max(hash.collision_resistance());
    match security {
      ..=191 => Err(SHA384),
      192..=255 => Ok(SHA384),
      256.. => Ok(SHA512),
    }
  } else {
    Err(SHA384)
  }
}

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm.
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
/// The following illustrates a call to validate a non-compliant key.
///
/// ```
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::ifc::{IFC_2048, IFC_3072};
/// use wardstone_core::standards::cnsa;
///
/// let ctx = Context::default();
/// let rsa_2048 = IFC_2048;
/// let rsa_3072 = IFC_3072;
/// assert_eq!(cnsa::validate_ifc(&ctx, &rsa_2048), Err(rsa_3072));
/// ```
pub fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<Ifc, Ifc> {
  if ctx.year() > CUTOFF_YEAR {
    return Err(IFC_NOT_SUPPORTED);
  }

  let security = ctx.security().max(*key.security().start());
  match security {
    ..=127 => Err(IFC_3072),
    128..=191 => Ok(IFC_3072),
    192..=255 => Ok(IFC_7680),
    256.. => Ok(IFC_15360),
  }
}

/// Validates a symmetric key primitive.
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
/// The following illustrates a call to validate a non-compliant key.
///
/// ```
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::symmetric::{AES256, TDEA3};
/// use wardstone_core::standards::cnsa;
///
/// let ctx = Context::default();
/// assert_eq!(cnsa::validate_symmetric(&ctx, &TDEA3), Err(AES256));
/// ```
pub fn validate_symmetric(_ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric> {
  if *key != AES256 {
    Err(AES256)
  } else {
    Ok(AES256)
  }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
  use super::*;
  use crate::test_case;

  test_case!(p224, validate_ecc, &P224, Err(P384));
  test_case!(p256, validate_ecc, &P256, Err(P384));
  test_case!(p384, validate_ecc, &P384, Ok(P384));
  test_case!(p521, validate_ecc, &P521, Err(P384));
  test_case!(w25519, validate_ecc, &W25519, Err(P384));
  test_case!(w448, validate_ecc, &W448, Err(P384));
  test_case!(curve25519, validate_ecc, &CURVE25519, Err(P384));
  test_case!(curve488, validate_ecc, &CURVE448, Err(P384));
  test_case!(edwards25519, validate_ecc, &EDWARDS25519, Err(P384));
  test_case!(edwards448, validate_ecc, &EDWARDS448, Err(P384));
  test_case!(e448, validate_ecc, &E448, Err(P384));
  test_case!(brainpoolp224r1, validate_ecc, &BRAINPOOLP224R1, Err(P384));
  test_case!(brainpoolp256r1, validate_ecc, &BRAINPOOLP256R1, Err(P384));
  test_case!(brainpoolp320r1, validate_ecc, &BRAINPOOLP320R1, Err(P384));
  test_case!(brainpoolp384r1, validate_ecc, &BRAINPOOLP384R1, Err(P384));
  test_case!(brainpoolp512r1, validate_ecc, &BRAINPOOLP512R1, Err(P384));
  test_case!(secp256k1, validate_ecc, &SECP256K1, Err(P384));

  test_case!(blake2b_256, validate_hash, &BLAKE2B_256, Err(SHA384));
  test_case!(blake2b_384, validate_hash, &BLAKE2B_384, Err(SHA384));
  test_case!(blake2b_512, validate_hash, &BLAKE2B_512, Err(SHA384));
  test_case!(blake2s_256, validate_hash, &BLAKE2S_256, Err(SHA384));
  test_case!(md4, validate_hash, &MD4, Err(SHA384));
  test_case!(md5, validate_hash, &MD5, Err(SHA384));
  test_case!(ripemd160, validate_hash, &RIPEMD160, Err(SHA384));
  test_case!(sha1, validate_hash, &SHA1, Err(SHA384));
  test_case!(sha224, validate_hash, &SHA224, Err(SHA384));
  test_case!(sha256, validate_hash, &SHA256, Err(SHA384));
  test_case!(sha384, validate_hash, &SHA384, Ok(SHA384));
  test_case!(sha3_224, validate_hash, &SHA3_224, Err(SHA384));
  test_case!(sha3_256, validate_hash, &SHA3_256, Err(SHA384));
  test_case!(sha3_384, validate_hash, &SHA3_384, Err(SHA384));
  test_case!(sha3_512, validate_hash, &SHA3_512, Err(SHA384));
  test_case!(sha512, validate_hash, &SHA512, Ok(SHA512));
  test_case!(sha512_224, validate_hash, &SHA512_224, Err(SHA384));
  test_case!(sha512_256, validate_hash, &SHA512_256, Err(SHA384));
  test_case!(shake128, validate_hash, &SHAKE128, Err(SHA384));
  test_case!(shake256, validate_hash, &SHAKE256, Err(SHA384));

  test_case!(ffc_1024_160, validate_ffc, &FFC_1024_160, Err(FFC_NOT_SUPPORTED));
  test_case!(ffc_2048_224, validate_ffc, &FFC_2048_224, Err(FFC_NOT_SUPPORTED));
  test_case!(ffc_3072_256, validate_ffc, &FFC_3072_256, Err(FFC_NOT_SUPPORTED));
  test_case!(ffc_7680_384, validate_ffc, &FFC_7680_384, Err(FFC_NOT_SUPPORTED));
  test_case!(ffc_15360_512, validate_ffc, &FFC_15360_512, Err(FFC_NOT_SUPPORTED));

  test_case!(ifc_1024, validate_ifc, &IFC_1024, Err(IFC_3072));
  test_case!(ifc_2048, validate_ifc, &IFC_2048, Err(IFC_3072));
  test_case!(ifc_3072, validate_ifc, &IFC_3072, Ok(IFC_3072));
  test_case!(ifc_7680, validate_ifc, &IFC_7680, Ok(IFC_7680));
  test_case!(ifc_15360, validate_ifc, &IFC_15360, Ok(IFC_15360));

  test_case!(two_key_tdea, validate_symmetric, &TDEA2, Err(AES256));
  test_case!(three_key_tdea, validate_symmetric, &TDEA3, Err(AES256));
  test_case!(aes128, validate_symmetric, &AES128, Err(AES256));
  test_case!(aes192, validate_symmetric, &AES192, Err(AES256));
  test_case!(aes256, validate_symmetric, &AES256, Ok(AES256));
}
