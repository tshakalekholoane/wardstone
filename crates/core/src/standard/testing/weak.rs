//! A mock standard with a minimum security requirement of at least
//! 64-bits.
//!
//! **Caution:** This might return recommendations for primitives that
//! are considered unsafe when used in some applications such as MD5 and
//! SHA1. For secure applications use any of the other standards defined
//! in this crate.

use crate::context::Context;
use crate::primitive::ecc::*;
use crate::primitive::ffc::*;
use crate::primitive::hash::*;
use crate::primitive::ifc::*;
use crate::primitive::symmetric::*;
use crate::primitive::Primitive;
use crate::standard::Standard;

/// [`Standard`](crate::standard::Standard) implementation of a mock
/// standard that is intended to be relatively weak compared to all the
/// other standards defined in this crate.
pub struct Weak;

impl Standard for Weak {
  /// Validate an elliptic curve cryptography primitive used for digital
  /// signatures and key establishment.
  ///
  /// If the key is not compliant then `Err` will contain the
  /// recommended primitive that one should use instead.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended primitive
  /// with the desired security level.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::ecc::ED25519;
  /// use wardstone_core::standard::testing::weak::Weak;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Weak::validate_ecc(ctx, ED25519), Ok(ED25519));
  /// ```
  fn validate_ecc(ctx: Context, key: Ecc) -> Result<Ecc, Ecc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=63 => Err(P224),
      64..=112 => Ok(P224),
      113..=128 => Ok(ED25519),
      129..=160 => Ok(BRAINPOOLP320R1),
      161..=192 => Ok(P384),
      193..=244 => Ok(ED448),
      245..=256 => Ok(BRAINPOOLP512R1),
      257.. => Ok(P521),
    }
  }

  /// Validates a finite field cryptography primitive.
  ///
  /// Examples include the DSA and key establishment algorithms such as
  /// Diffie-Hellman.
  ///
  /// If the key is not compliant then `Err` will contain the
  /// recommended key sizes L and N that one should use instead.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended key sizes L
  /// and N with the desired security level.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::ffc::{FFC_2048_224, FFC_3072_256};
  /// use wardstone_core::standard::testing::weak::Weak;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let dsa_2048 = FFC_2048_224;
  /// assert_eq!(Weak::validate_ffc(ctx, dsa_2048), Ok(dsa_2048));
  /// ```
  fn validate_ffc(ctx: Context, key: Ffc) -> Result<Ffc, Ffc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=63 => Err(FFC_1024_160),
      64..=80 => Ok(FFC_1024_160),
      81..=112 => Ok(FFC_2048_224),
      113..=128 => Ok(FFC_3072_256),
      129..=192 => Ok(FFC_7680_384),
      193.. => Ok(FFC_15360_512),
    }
  }

  /// Validates a hash function.
  ///
  /// If the hash function is not compliant then `Err` will contain the
  /// recommended primitive that one should use instead.
  ///
  /// If the hash function is compliant but the context specifies a
  /// higher security level, `Ok` will also hold the recommended
  /// primitive with the desired security level.
  ///
  /// **Note:** An alternative might be suggested for a compliant hash
  /// function with a similar security level in which a switch to the
  /// recommended primitive would likely be unwarranted. For example,
  /// when evaluating compliance for the `SHA3-256`, a recommendation
  /// to use `SHA256` will be made but switching to this as a result
  /// is likely unnecessary.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant hash
  /// function.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::hash::{SHA1, SHA256};
  /// use wardstone_core::standard::testing::weak::Weak;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Weak::validate_hash(ctx, SHA1), Ok(SHA1));
  /// ```
  fn validate_hash(ctx: Context, hash: Hash) -> Result<Hash, Hash> {
    let security = ctx.security().max(hash.security());
    match security {
      ..=63 => Err(SHAKE128),
      64 => Ok(SHAKE128),
      65..=80 => Ok(SHA1),
      81..=112 => Ok(SHA224),
      113..=128 => Ok(BLAKE3),
      129..=192 => Ok(BLAKE2B_384),
      193.. => Ok(BLAKE2B_512),
    }
  }

  /// Validates  an integer factorisation cryptography primitive the
  /// most common of which is the RSA signature algorithm.
  ///
  /// If the key is not compliant then `Err` will contain the
  /// recommended key size that one should use instead.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended key size
  /// with the desired security level.
  ///
  /// **Note:** Unlike other functions in this module, this will return
  /// a generic structure that specifies minimum private and public
  /// key sizes.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::ifc::RSA_PSS_2048;
  /// use wardstone_core::standard::testing::weak::Weak;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Weak::validate_ifc(ctx, RSA_PSS_2048), Ok(RSA_PSS_2048));
  /// ```
  fn validate_ifc(ctx: Context, key: Ifc) -> Result<Ifc, Ifc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=63 => Err(RSA_PSS_1024),
      64..=80 => Ok(RSA_PSS_1024),
      81..=112 => Ok(RSA_PSS_2048),
      113..=128 => Ok(RSA_PSS_3072),
      129..=192 => Ok(RSA_PSS_7680),
      193.. => Ok(RSA_PSS_15360),
    }
  }

  /// Validates a symmetric key primitive.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended primitive
  /// with the desired security level.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a three-key Triple
  /// DES key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::symmetric::TDEA3;
  /// use wardstone_core::standard::testing::weak::Weak;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Weak::validate_symmetric(ctx, TDEA3), Ok(TDEA3));
  /// ```
  fn validate_symmetric(ctx: Context, key: Symmetric) -> Result<Symmetric, Symmetric> {
    let security = ctx.security().max(key.security());
    match security {
      ..=63 => Err(TDEA2),
      64..=95 => Ok(TDEA2),
      96..=112 => Ok(TDEA3),
      113..=120 => Ok(DESX),
      121..=126 => Ok(IDEA),
      127..=128 => Ok(AES128),
      129..=192 => Ok(AES192),
      193.. => Ok(AES256),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{test_ecc, test_ffc, test_hash, test_ifc, test_symmetric};

  test_ecc!(p224, Weak, P224, Ok(P224));
  test_ecc!(p256, Weak, P256, Ok(ED25519));
  test_ecc!(p384, Weak, P384, Ok(P384));
  test_ecc!(p521, Weak, P521, Ok(P521));
  test_ecc!(ed25519, Weak, ED25519, Ok(ED25519));
  test_ecc!(ed488, Weak, ED448, Ok(ED448));
  test_ecc!(x25519, Weak, X25519, Ok(ED25519));
  test_ecc!(x448, Weak, X448, Ok(ED448));
  test_ecc!(brainpoolp224r1, Weak, BRAINPOOLP224R1, Ok(P224));
  test_ecc!(brainpoolp256r1, Weak, BRAINPOOLP256R1, Ok(ED25519));
  test_ecc!(brainpoolp320r1, Weak, BRAINPOOLP320R1, Ok(BRAINPOOLP320R1));
  test_ecc!(brainpoolp384r1, Weak, BRAINPOOLP384R1, Ok(P384));
  test_ecc!(brainpoolp512r1, Weak, BRAINPOOLP512R1, Ok(BRAINPOOLP512R1));
  test_ecc!(secp256k1, Weak, SECP256K1, Ok(ED25519));

  test_ffc!(ffc_1024_160, Weak, FFC_1024_160, Ok(FFC_1024_160));
  test_ffc!(ffc_2048_224, Weak, FFC_2048_224, Ok(FFC_2048_224));
  test_ffc!(ffc_3072_256, Weak, FFC_3072_256, Ok(FFC_3072_256));
  test_ffc!(ffc_7680_384, Weak, FFC_7680_384, Ok(FFC_7680_384));
  test_ffc!(ffc_15360_512, Weak, FFC_15360_512, Ok(FFC_15360_512));

  test_ifc!(ifc_1024, Weak, RSA_PSS_1024, Ok(RSA_PSS_1024));
  test_ifc!(ifc_1280, Weak, RSA_PSS_1280, Ok(RSA_PSS_1024));
  test_ifc!(ifc_1536, Weak, RSA_PSS_1536, Ok(RSA_PSS_1024));
  test_ifc!(ifc_2048, Weak, RSA_PSS_2048, Ok(RSA_PSS_2048));
  test_ifc!(ifc_3072, Weak, RSA_PSS_3072, Ok(RSA_PSS_3072));
  test_ifc!(ifc_4096, Weak, RSA_PSS_4096, Ok(RSA_PSS_3072));
  test_ifc!(ifc_7680, Weak, RSA_PSS_7680, Ok(RSA_PSS_7680));
  test_ifc!(ifc_8192, Weak, RSA_PSS_8192, Ok(RSA_PSS_7680));
  test_ifc!(ifc_15360, Weak, RSA_PSS_15360, Ok(RSA_PSS_15360));

  test_hash!(blake_224, Weak, BLAKE_224, Ok(SHA224));
  test_hash!(blake_256, Weak, BLAKE_256, Ok(BLAKE3));
  test_hash!(blake_384, Weak, BLAKE_384, Ok(BLAKE2B_384));
  test_hash!(blake_512, Weak, BLAKE_512, Ok(BLAKE2B_512));
  test_hash!(blake2b_256, Weak, BLAKE2B_256, Ok(BLAKE3));
  test_hash!(blake2b_384, Weak, BLAKE2B_384, Ok(BLAKE2B_384));
  test_hash!(blake2b_512, Weak, BLAKE2B_512, Ok(BLAKE2B_512));
  test_hash!(blake2s_256, Weak, BLAKE2S_256, Ok(BLAKE3));
  test_hash!(md4, Weak, MD4, Ok(SHAKE128));
  test_hash!(md5, Weak, MD5, Ok(SHAKE128));
  test_hash!(ripemd160, Weak, RIPEMD160, Ok(SHA1));
  test_hash!(sha1, Weak, SHA1, Ok(SHA1));
  test_hash!(sha224, Weak, SHA224, Ok(SHA224));
  test_hash!(sha256, Weak, SHA256, Ok(BLAKE3));
  test_hash!(sha384, Weak, SHA384, Ok(BLAKE2B_384));
  test_hash!(sha3_224, Weak, SHA3_224, Ok(SHA224));
  test_hash!(sha3_256, Weak, SHA3_256, Ok(BLAKE3));
  test_hash!(sha3_384, Weak, SHA3_384, Ok(BLAKE2B_384));
  test_hash!(sha3_512, Weak, SHA3_512, Ok(BLAKE2B_512));
  test_hash!(sha512, Weak, SHA512, Ok(BLAKE2B_512));
  test_hash!(sha512_224, Weak, SHA512_224, Ok(SHA224));
  test_hash!(sha512_256, Weak, SHA512_256, Ok(BLAKE3));
  test_hash!(shake128, Weak, SHAKE128, Ok(SHAKE128));
  test_hash!(shake256, Weak, SHAKE256, Ok(BLAKE3));
  test_hash!(whirlpool, Weak, WHIRLPOOL, Ok(BLAKE2B_512));

  test_symmetric!(aes128, Weak, AES128, Ok(AES128));
  test_symmetric!(aes192, Weak, AES192, Ok(AES192));
  test_symmetric!(aes256, Weak, AES256, Ok(AES256));
  test_symmetric!(camellia128, Weak, CAMELLIA128, Ok(AES128));
  test_symmetric!(camellia192, Weak, CAMELLIA192, Ok(AES192));
  test_symmetric!(camellia256, Weak, CAMELLIA256, Ok(AES256));
  test_symmetric!(des, Weak, DES, Err(TDEA2));
  test_symmetric!(desx, Weak, DESX, Ok(DESX));
  test_symmetric!(idea, Weak, IDEA, Ok(IDEA));
  test_symmetric!(serpent128, Weak, SERPENT128, Ok(AES128));
  test_symmetric!(serpent192, Weak, SERPENT192, Ok(AES192));
  test_symmetric!(serpent256, Weak, SERPENT256, Ok(AES256));
  test_symmetric!(three_key_tdea, Weak, TDEA3, Ok(TDEA3));
  test_symmetric!(two_key_tdea, Weak, TDEA2, Ok(TDEA2));
}
