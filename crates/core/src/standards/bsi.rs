//! Validate cryptographic primitives against the [BSI TR-02102-1
//! Cryptographic Mechanisms: Recommendations and Key Lengths] technical
//! guide.
//!
//! [BSI TR-02102-1 Cryptographic Mechanisms: Recommendations and Key Lengths]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html
use std::collections::HashSet;

use crate::context::Context;
use crate::ecc::Ecc;
use crate::ffc::Ffc;
use crate::hash::Hash;
use crate::ifc::Ifc;
use crate::primitive::Primitive;
use crate::primitives::ecc::*;
use crate::primitives::ffc::*;
use crate::primitives::hash::*;
use crate::primitives::ifc::*;
use crate::primitives::symmetric::*;
use crate::symmetric::Symmetric;

const CUTOFF_YEAR_RSA: u16 = 2023; // See p. 17.

lazy_static! {
  static ref SPECIFIED_EC: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(BRAINPOOLP256R1.id);
    s.insert(BRAINPOOLP320R1.id);
    s.insert(BRAINPOOLP384R1.id);
    s.insert(BRAINPOOLP512R1.id);
    s
  };
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
  // "The present version of this Technical Guideline does not recommend
  // any other block ciphers besides AES" (2023, p. 24).
  static ref SPECIFIED_SYMMETRIC: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(AES128.id);
    s.insert(AES192.id);
    s.insert(AES256.id);
    s
  };
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
/// **Note:** While the guide allows for elliptic curve system
/// parameters "that are provided by a trustworthy authority"
/// (see p. 73), this function conservatively deems any curve that is
/// not explicitly stated as non-compliant. This means only the
/// Brainpool curves are considered compliant.
///
/// # Example
///
/// The following illustrates a call to validate a compliant key.
///
/// ```
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::ecc::BRAINPOOLP256R1;
/// use wardstone_core::standards::bsi;
///
/// let ctx = Context::default();
/// assert_eq!(
///   bsi::validate_ecc(&ctx, &BRAINPOOLP256R1),
///   Ok(BRAINPOOLP256R1)
/// );
/// ```
pub fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
  if SPECIFIED_EC.contains(&key.id) {
    let security = ctx.security().max(key.security());
    match security {
      ..=124 => Err(BRAINPOOLP256R1),
      125..=128 => Ok(BRAINPOOLP256R1),
      129..=160 => Ok(BRAINPOOLP320R1),
      161..=192 => Ok(BRAINPOOLP384R1),
      193.. => Ok(BRAINPOOLP512R1),
    }
  } else {
    Err(BRAINPOOLP256R1)
  }
}

/// Validates a finite field cryptography primitive.
///
/// Examples include the DSA and key establishment algorithms such as
/// Diffie-Hellman.
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
/// use wardstone_core::primitives::ffc::{FFC_2048_224, FFC_3072_256};
/// use wardstone_core::standards::bsi;
///
/// let ctx = Context::default();
/// let dsa_2048 = FFC_2048_224;
/// let dsa_3072 = FFC_3072_256;
/// assert_eq!(bsi::validate_ffc(&ctx, &dsa_2048), Err(dsa_3072));
/// ```
pub fn validate_ffc(ctx: &Context, key: &Ffc) -> Result<Ffc, Ffc> {
  let security = ctx.security().max(key.security());
  match security {
    // Page 48 says q > 2²⁵⁰.
    ..=124 => Err(FFC_3072_256),
    125..=128 => Ok(FFC_3072_256),
    129..=192 => Ok(FFC_7680_384),
    193.. => Ok(FFC_15360_512),
  }
}

/// Validates a hash function according to page 41 of the guide. The
/// reference is made with regards to applications that require
/// collision resistance such as digital signatures.
///
/// For applications that primarily require pre-image resistance such as
/// message authentication codes (MACs), key derivation functions
/// (KDFs), and random bit generation use
/// [`validate_hash_based`](crate::standards::bsi::validate_hash_based).
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
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::hash::{SHA1, SHA256};
/// use wardstone_core::standards::bsi;
///
/// let ctx = Context::default();
/// assert_eq!(bsi::validate_hash(&ctx, &SHA1), Err(SHA256));
/// ```
pub fn validate_hash(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let security = ctx.security().max(hash.security());
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
/// signatures use
/// [`validate_hash`](crate::standards::bsi::validate_hash).
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
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::hash::{SHA1, SHA256};
/// use wardstone_core::standards::bsi;
///
/// let ctx = Context::default();
/// let hmac_sha1 = SHA1;
/// let hmac_sha256 = SHA256;
/// assert_eq!(bsi::validate_hash_based(&ctx, &hmac_sha1), Err(hmac_sha256));
/// ```
pub fn validate_hash_based(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let pre_image_resistance = hash.security() << 1;
    let security = ctx.security().max(pre_image_resistance);
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
/// The following illustrates a call to validate a compliant key.
///
/// ```
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::ifc::IFC_2048;
/// use wardstone_core::standards::bsi;
///
/// let ctx = Context::default();
/// let rsa_2048 = IFC_2048;
/// assert_eq!(bsi::validate_ifc(&ctx, &rsa_2048), Ok(rsa_2048));
/// ```
pub fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<Ifc, Ifc> {
  let security = ctx.security().max(key.security());
  match security {
    ..=111 => {
      if ctx.year() > CUTOFF_YEAR_RSA {
        Err(IFC_3072)
      } else {
        Err(IFC_2048)
      }
    },
    112..=127 => {
      if ctx.year() > CUTOFF_YEAR_RSA {
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
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::symmetric::{AES128, TDEA3};
/// use wardstone_core::standards::bsi;
///
/// let ctx = Context::default();
/// assert_eq!(bsi::validate_symmetric(&ctx, &TDEA3), Err(AES128));
/// ```
pub fn validate_symmetric(ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric> {
  if SPECIFIED_SYMMETRIC.contains(&key.id) {
    let security = ctx.security().max(key.security());
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

#[cfg(test)]
#[rustfmt::skip]
mod tests {
  use super::*;
  use crate::test_case;

  test_case!(p224, validate_ecc, &P224, Err(BRAINPOOLP256R1));
  test_case!(p256, validate_ecc, &P256, Err(BRAINPOOLP256R1));
  test_case!(p384, validate_ecc, &P384, Err(BRAINPOOLP256R1));
  test_case!(p521, validate_ecc, &P521, Err(BRAINPOOLP256R1));
  test_case!(w25519, validate_ecc, &W25519, Err(BRAINPOOLP256R1));
  test_case!(w448, validate_ecc, &W448, Err(BRAINPOOLP256R1));
  test_case!(curve25519, validate_ecc, &CURVE25519, Err(BRAINPOOLP256R1));
  test_case!(curve488, validate_ecc, &CURVE448, Err(BRAINPOOLP256R1));
  test_case!(edwards25519, validate_ecc, &EDWARDS25519, Err(BRAINPOOLP256R1));
  test_case!(edwards448, validate_ecc, &EDWARDS448, Err(BRAINPOOLP256R1));
  test_case!(e448, validate_ecc, &E448, Err(BRAINPOOLP256R1));
  test_case!(brainpoolp224r1, validate_ecc, &BRAINPOOLP224R1, Err(BRAINPOOLP256R1));
  test_case!(brainpoolp256r1, validate_ecc, &BRAINPOOLP256R1, Ok(BRAINPOOLP256R1));
  test_case!(brainpoolp320r1, validate_ecc, &BRAINPOOLP320R1, Ok(BRAINPOOLP320R1));
  test_case!(brainpoolp384r1, validate_ecc, &BRAINPOOLP384R1, Ok(BRAINPOOLP384R1));
  test_case!(brainpoolp512r1, validate_ecc, &BRAINPOOLP512R1, Ok(BRAINPOOLP512R1));
  test_case!(secp256k1, validate_ecc, &SECP256K1, Err(BRAINPOOLP256R1));

  test_case!(ffc_1024_160, validate_ffc, &FFC_1024_160, Err(FFC_3072_256));
  test_case!(ffc_2048_224, validate_ffc, &FFC_2048_224, Err(FFC_3072_256));
  test_case!(ffc_3072_256, validate_ffc, &FFC_3072_256, Ok(FFC_3072_256));
  test_case!(ffc_7680_384, validate_ffc, &FFC_7680_384, Ok(FFC_7680_384));
  test_case!(ffc_15360_512, validate_ffc, &FFC_15360_512, Ok(FFC_15360_512));

  test_case!(ifc_1024, validate_ifc, &IFC_1024, Err(IFC_2048));
  test_case!(ifc_2048, validate_ifc, &IFC_2048, Ok(IFC_2048));
  test_case!(ifc_3072, validate_ifc, &IFC_3072, Ok(IFC_3072));
  test_case!(ifc_7680, validate_ifc, &IFC_7680, Ok(IFC_7680));
  test_case!(ifc_15360, validate_ifc, &IFC_15360, Ok(IFC_15360));

  test_case!(blake2b_256_collision_resistance, validate_hash, &BLAKE2B_256, Err(SHA256));
  test_case!(blake2b_384_collision_resistance, validate_hash, &BLAKE2B_384, Err(SHA256));
  test_case!(blake2b_512_collision_resistance, validate_hash, &BLAKE2B_512, Err(SHA256));
  test_case!(blake2s_256_collision_resistance, validate_hash, &BLAKE2S_256, Err(SHA256));
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

  test_case!(blake2b_256_pre_image_resistance, validate_hash_based, &BLAKE2B_256, Err(SHA256));
  test_case!(blake2b_384_pre_image_resistance, validate_hash_based, &BLAKE2B_384, Err(SHA256));
  test_case!(blake2b_512_pre_image_resistance, validate_hash_based, &BLAKE2B_512, Err(SHA256));
  test_case!(blake2s_256_pre_image_resistance, validate_hash_based, &BLAKE2S_256, Err(SHA256));
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
