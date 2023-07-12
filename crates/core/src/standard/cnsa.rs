//! Validate cryptographic primitives against the Commercial National
//! Security Algorithm Suites, [CNSA 1.0] and [CNSA 2.0].
//!
//! [CNSA 1.0]: https://media.defense.gov/2021/Sep/27/2002862527/-1/-1/0/CNSS%20WORKSHEET.PDF
//! [CNSA 2.0]: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
use std::collections::HashSet;

use once_cell::sync::Lazy;

use super::Standard;
use crate::context::Context;
use crate::primitive::ecc::Ecc;
use crate::primitive::ffc::Ffc;
use crate::primitive::hash::Hash;
use crate::primitive::ifc::Ifc;
use crate::primitive::symmetric::Symmetric;
use crate::primitive::Primitive;
use crate::standard::instances::ecc::*;
use crate::standard::instances::ffc::*;
use crate::standard::instances::hash::*;
use crate::standard::instances::ifc::*;
use crate::standard::instances::symmetric::*;

// Exclusive use of CNSA 2.0 by then.
const CUTOFF_YEAR: u16 = 2030;

static SPECIFIED_HASH_FUNCTIONS: Lazy<HashSet<Hash>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(SHA384);
  s.insert(SHA512);
  s
});

/// [`Standard`](crate::standard::Standard) implementation of the
/// Commercial National Security Algorithm Suites, [CNSA 1.0] and
/// [CNSA 2.0].
///
/// [CNSA 1.0]: https://media.defense.gov/2021/Sep/27/2002862527/-1/-1/0/CNSS%20WORKSHEET.PDF
/// [CNSA 2.0]: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
pub struct Cnsa;

impl Standard for Cnsa {
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
  /// The following illustrates a call to validate a non-compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::standard::cnsa::Cnsa;
  /// use wardstone_core::standard::instances::ecc::{P256, P384};
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Cnsa::validate_ecc(&ctx, &P256), Err(P384));
  /// ```
  fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
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
  /// If the key is not compliant then `Err` will contain the
  /// recommended key sizes L and N that one should use instead.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended key sizes L
  /// and N with the desired security level.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a non-compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::standard::cnsa::Cnsa;
  /// use wardstone_core::standard::instances::ffc::{FFC_7680_384, FFC_NOT_SUPPORTED};
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let dsa_7680 = FFC_7680_384;
  /// assert_eq!(Cnsa::validate_ffc(&ctx, &dsa_7680), Err(FFC_NOT_SUPPORTED));
  /// ```
  fn validate_ffc(_ctx: &Context, _key: &Ffc) -> Result<Ffc, Ffc> {
    Err(FFC_NOT_SUPPORTED)
  }

  /// Validates a hash function.
  ///
  /// Unlike other functions in this module, there is no distinction in
  /// security based on the application. As such this module does not
  /// have a corresponding `validate_hash_based` function. All hash
  /// function and hash based application are assessed by this single
  /// function.
  ///
  /// If the hash function is not compliant then `Err` will contain the
  /// recommended primitive that one should use instead.
  ///
  /// If the hash function is compliant but the context specifies a
  /// higher security level, `Ok` will also hold the recommended
  /// primitive with the desired security level.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a non-compliant hash
  /// function.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::standard::cnsa::Cnsa;
  /// use wardstone_core::standard::instances::hash::{SHA1, SHA384};
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Cnsa::validate_hash(&ctx, &SHA1), Err(SHA384));
  /// ```
  fn validate_hash(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
    if SPECIFIED_HASH_FUNCTIONS.contains(hash) {
      let security = ctx.security().max(hash.security());
      match security {
        ..=191 => Err(SHA384),
        192..=255 => Ok(SHA384),
        256.. => Ok(SHA512),
      }
    } else {
      Err(SHA384)
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
  /// The following illustrates a call to validate a non-compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::standard::cnsa::Cnsa;
  /// use wardstone_core::standard::instances::ifc::{IFC_2048, IFC_3072};
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let rsa_2048 = IFC_2048;
  /// let rsa_3072 = IFC_3072;
  /// assert_eq!(Cnsa::validate_ifc(&ctx, &rsa_2048), Err(rsa_3072));
  /// ```
  fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<Ifc, Ifc> {
    if ctx.year() > CUTOFF_YEAR {
      return Err(IFC_NOT_SUPPORTED);
    }

    let security = ctx.security().max(key.security());
    match security {
      ..=127 => Err(IFC_3072),
      128..=191 => Ok(IFC_3072),
      192..=255 => Ok(IFC_7680),
      256.. => Ok(IFC_15360),
    }
  }

  /// Validates a symmetric key primitive.
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
  /// The following illustrates a call to validate a non-compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::standard::cnsa::Cnsa;
  /// use wardstone_core::standard::instances::symmetric::{AES256, TDEA3};
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Cnsa::validate_symmetric(&ctx, &TDEA3), Err(AES256));
  /// ```
  fn validate_symmetric(_ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric> {
    if *key != AES256 {
      Err(AES256)
    } else {
      Ok(AES256)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{test_ecc, test_ffc, test_hash, test_ifc, test_symmetric};

  test_ecc!(p224, Cnsa, &P224, Err(P384));
  test_ecc!(p256, Cnsa, &P256, Err(P384));
  test_ecc!(p384, Cnsa, &P384, Ok(P384));
  test_ecc!(p521, Cnsa, &P521, Err(P384));
  test_ecc!(w25519, Cnsa, &W25519, Err(P384));
  test_ecc!(w448, Cnsa, &W448, Err(P384));
  test_ecc!(curve25519, Cnsa, &CURVE25519, Err(P384));
  test_ecc!(curve488, Cnsa, &CURVE448, Err(P384));
  test_ecc!(edwards25519, Cnsa, &EDWARDS25519, Err(P384));
  test_ecc!(edwards448, Cnsa, &EDWARDS448, Err(P384));
  test_ecc!(e448, Cnsa, &E448, Err(P384));
  test_ecc!(brainpoolp224r1, Cnsa, &BRAINPOOLP224R1, Err(P384));
  test_ecc!(brainpoolp256r1, Cnsa, &BRAINPOOLP256R1, Err(P384));
  test_ecc!(brainpoolp320r1, Cnsa, &BRAINPOOLP320R1, Err(P384));
  test_ecc!(brainpoolp384r1, Cnsa, &BRAINPOOLP384R1, Err(P384));
  test_ecc!(brainpoolp512r1, Cnsa, &BRAINPOOLP512R1, Err(P384));
  test_ecc!(secp256k1, Cnsa, &SECP256K1, Err(P384));

  test_hash!(blake2b_256, Cnsa, &BLAKE2B_256, Err(SHA384));
  test_hash!(blake2b_384, Cnsa, &BLAKE2B_384, Err(SHA384));
  test_hash!(blake2b_512, Cnsa, &BLAKE2B_512, Err(SHA384));
  test_hash!(blake2s_256, Cnsa, &BLAKE2S_256, Err(SHA384));
  test_hash!(md4, Cnsa, &MD4, Err(SHA384));
  test_hash!(md5, Cnsa, &MD5, Err(SHA384));
  test_hash!(ripemd160, Cnsa, &RIPEMD160, Err(SHA384));
  test_hash!(sha1, Cnsa, &SHA1, Err(SHA384));
  test_hash!(sha224, Cnsa, &SHA224, Err(SHA384));
  test_hash!(sha256, Cnsa, &SHA256, Err(SHA384));
  test_hash!(sha384, Cnsa, &SHA384, Ok(SHA384));
  test_hash!(sha3_224, Cnsa, &SHA3_224, Err(SHA384));
  test_hash!(sha3_256, Cnsa, &SHA3_256, Err(SHA384));
  test_hash!(sha3_384, Cnsa, &SHA3_384, Err(SHA384));
  test_hash!(sha3_512, Cnsa, &SHA3_512, Err(SHA384));
  test_hash!(sha512, Cnsa, &SHA512, Ok(SHA512));
  test_hash!(sha512_224, Cnsa, &SHA512_224, Err(SHA384));
  test_hash!(sha512_256, Cnsa, &SHA512_256, Err(SHA384));
  test_hash!(shake128, Cnsa, &SHAKE128, Err(SHA384));
  test_hash!(shake256, Cnsa, &SHAKE256, Err(SHA384));

  test_ffc!(ffc_1024_160, Cnsa, &FFC_1024_160, Err(FFC_NOT_SUPPORTED));
  test_ffc!(ffc_2048_224, Cnsa, &FFC_2048_224, Err(FFC_NOT_SUPPORTED));
  test_ffc!(ffc_3072_256, Cnsa, &FFC_3072_256, Err(FFC_NOT_SUPPORTED));
  test_ffc!(ffc_7680_384, Cnsa, &FFC_7680_384, Err(FFC_NOT_SUPPORTED));
  test_ffc!(ffc_15360_512, Cnsa, &FFC_15360_512, Err(FFC_NOT_SUPPORTED));

  test_ifc!(ifc_1024, Cnsa, &IFC_1024, Err(IFC_3072));
  test_ifc!(ifc_2048, Cnsa, &IFC_2048, Err(IFC_3072));
  test_ifc!(ifc_3072, Cnsa, &IFC_3072, Ok(IFC_3072));
  test_ifc!(ifc_7680, Cnsa, &IFC_7680, Ok(IFC_7680));
  test_ifc!(ifc_15360, Cnsa, &IFC_15360, Ok(IFC_15360));

  test_symmetric!(two_key_tdea, Cnsa, &TDEA2, Err(AES256));
  test_symmetric!(three_key_tdea, Cnsa, &TDEA3, Err(AES256));
  test_symmetric!(aes128, Cnsa, &AES128, Err(AES256));
  test_symmetric!(aes192, Cnsa, &AES192, Err(AES256));
  test_symmetric!(aes256, Cnsa, &AES256, Ok(AES256));
}
