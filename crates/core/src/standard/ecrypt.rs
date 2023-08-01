//! Validate cryptographic primitives against the [ECRYPT-CSA D5.4
//! Algorithms, Key Size and Protocols Report].
//!
//! [ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report]: https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf
use std::collections::HashSet;

use once_cell::sync::Lazy;

use super::Standard;
use crate::context::Context;
use crate::primitive::ecc::*;
use crate::primitive::ffc::*;
use crate::primitive::hash::*;
use crate::primitive::ifc::*;
use crate::primitive::symmetric::*;
use crate::primitive::Primitive;

// "Thus the key take home message is that decision makers now make
// plans and preparations for the phasing out of what we term legacy
// mechanisms over a period of say 5-10 years." (2018, p. 12). See p. 11
// about the criteria made to distinguish between the different
// categories of legacy algorithms.
const CUTOFF_YEAR: u16 = 2023;

static SPECIFIED_HASH_FUNCTIONS: Lazy<HashSet<&Hash>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(&BLAKE2B_256);
  s.insert(&BLAKE2B_384);
  s.insert(&BLAKE2B_512);
  s.insert(&BLAKE2S_256);
  s.insert(&BLAKE_224);
  s.insert(&BLAKE_256);
  s.insert(&BLAKE_384);
  s.insert(&BLAKE_512);
  s.insert(&RIPEMD160);
  s.insert(&SHA224);
  s.insert(&SHA256);
  s.insert(&SHA384);
  s.insert(&SHA3_224);
  s.insert(&SHA3_256);
  s.insert(&SHA3_384);
  s.insert(&SHA3_512);
  s.insert(&SHA512);
  s.insert(&SHA512_224);
  s.insert(&SHA512_256);
  s.insert(&SHAKE128);
  s.insert(&SHAKE256);
  s.insert(&WHIRLPOOL);
  s
});

static SPECIFIED_SYMMETRIC_KEYS: Lazy<HashSet<&Symmetric>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(&AES128);
  s.insert(&AES192);
  s.insert(&AES256);
  s.insert(&CAMELLIA128);
  s.insert(&CAMELLIA192);
  s.insert(&CAMELLIA256);
  s.insert(&SERPENT128);
  s.insert(&SERPENT192);
  s.insert(&SERPENT256);
  s.insert(&TDEA2);
  s.insert(&TDEA3);
  s
});

/// [`Standard`](crate::standard::Standard) implementation for the
/// [ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report].
///
/// [ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report]: https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf
pub struct Ecrypt;

impl Standard for Ecrypt {
  /// Validate an elliptic curve cryptography primitive used for digital
  /// signatures and key establishment where f is the key size according
  /// to page 47 of the report.
  ///
  /// If the key is not compliant then `Err` will contain the
  /// recommended primitive that one should use instead.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended primitive
  /// with the desired security level.
  ///
  /// **Note:** This will return a generic structure that specifies key
  /// sizes.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::ecc::{ECC_256, P224};
  /// use wardstone_core::standard::ecrypt::Ecrypt;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Ecrypt::validate_ecc(&ctx, &P224), Ok(&ECC_256));
  /// ```
  fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<&'static Ecc, &'static Ecc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=79 => Err(&ECC_256),
      80..=127 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(&ECC_256)
        } else {
          Ok(&ECC_256)
        }
      },
      128 => Ok(&ECC_256),
      129..=192 => Ok(&ECC_384),
      193.. => Ok(&ECC_512),
    }
  }

  /// Validates a finite field cryptography primitive according to page
  /// 47 of the report.
  ///
  /// Examples include the DSA and key establishment algorithms such as
  /// Diffie-Hellman and MQV which can also be implemented as such,
  /// according to page 47 of the report.
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
  /// use wardstone_core::standard::ecrypt::Ecrypt;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let dsa_2048 = FFC_2048_224;
  /// let dsa_3072 = FFC_3072_256;
  /// assert_eq!(Ecrypt::validate_ffc(&ctx, &dsa_2048), Ok(&dsa_3072));
  /// ```
  fn validate_ffc(ctx: &Context, key: &Ffc) -> Result<&'static Ffc, &'static Ffc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=79 => Err(&FFC_3072_256),
      80..=127 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(&FFC_3072_256)
        } else {
          Ok(&FFC_3072_256)
        }
      },
      128 => Ok(&FFC_3072_256),
      129..=192 => Ok(&FFC_7680_384),
      193.. => Ok(&FFC_15360_512),
    }
  }

  /// Validates a hash function according to pages 40-43 of the report.
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
  /// The following illustrates a call to validate a non-compliant hash
  /// function.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::hash::{SHA1, SHA256};
  /// use wardstone_core::standard::ecrypt::Ecrypt;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Ecrypt::validate_hash(&ctx, &SHA1), Err(&SHA256));
  /// ```
  fn validate_hash(ctx: &Context, hash: &Hash) -> Result<&'static Hash, &'static Hash> {
    if SPECIFIED_HASH_FUNCTIONS.contains(hash) {
      let security = ctx.security().max(hash.security());
      match security {
        ..=79 => Err(&SHA256),
        80..=127 => {
          if ctx.year() > CUTOFF_YEAR {
            Err(&SHA256)
          } else {
            Ok(&SHA256)
          }
        },
        128 => Ok(&SHA256),
        129..=192 => Ok(&SHA384),
        193.. => Ok(&SHA512),
      }
    } else {
      Err(&SHA256)
    }
  }

  /// Validates  an integer factorisation cryptography primitive the
  /// most common of which is the RSA signature algorithm according to
  /// pages 47-48.
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
  /// use wardstone_core::primitive::ifc::{IFC_2048, IFC_3072};
  /// use wardstone_core::standard::ecrypt::Ecrypt;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let rsa_2048 = IFC_2048;
  /// let rsa_3072 = IFC_3072;
  /// assert_eq!(Ecrypt::validate_ifc(&ctx, &rsa_2048), Ok(&rsa_3072));
  /// ```
  fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<&'static Ifc, &'static Ifc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=79 => Err(&IFC_3072),
      80..=127 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(&IFC_3072)
        } else {
          Ok(&IFC_3072)
        }
      },
      128..=191 => Ok(&IFC_3072),
      192..=255 => Ok(&IFC_7680),
      256.. => Ok(&IFC_15360),
    }
  }

  /// Validates a symmetric key primitive according to pages 37 to 40 of
  /// the report.
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
  /// use wardstone_core::primitive::symmetric::{AES128, TDEA3};
  /// use wardstone_core::standard::ecrypt::Ecrypt;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Ecrypt::validate_symmetric(&ctx, &TDEA3), Ok(&AES128));
  /// ```
  fn validate_symmetric(
    ctx: &Context,
    key: &Symmetric,
  ) -> Result<&'static Symmetric, &'static Symmetric> {
    if SPECIFIED_SYMMETRIC_KEYS.contains(key) {
      let security = ctx.security().max(key.security());
      match security {
        ..=79 => Err(&AES128),
        80..=127 => {
          if ctx.year() > CUTOFF_YEAR {
            Err(&AES128)
          } else {
            Ok(&AES128)
          }
        },
        128 => Ok(&AES128),
        129..=192 => Ok(&AES192),
        193.. => Ok(&AES256),
      }
    } else {
      Err(&AES128)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{test_ecc, test_ffc, test_hash, test_ifc, test_symmetric};

  test_ecc!(p224, Ecrypt, &P224, Ok(&ECC_256));
  test_ecc!(p256, Ecrypt, &P256, Ok(&ECC_256));
  test_ecc!(p384, Ecrypt, &P384, Ok(&ECC_384));
  test_ecc!(p521, Ecrypt, &P521, Ok(&ECC_512));
  test_ecc!(ed25519, Ecrypt, &ED25519, Ok(&ECC_256));
  test_ecc!(ed448, Ecrypt, &ED448, Ok(&ECC_512));
  test_ecc!(x25519, Ecrypt, &X25519, Ok(&ECC_256));
  test_ecc!(x448, Ecrypt, &X448, Ok(&ECC_512));
  test_ecc!(brainpoolp224r1, Ecrypt, &BRAINPOOLP224R1, Ok(&ECC_256));
  test_ecc!(brainpoolp256r1, Ecrypt, &BRAINPOOLP256R1, Ok(&ECC_256));
  test_ecc!(brainpoolp320r1, Ecrypt, &BRAINPOOLP320R1, Ok(&ECC_384));
  test_ecc!(brainpoolp384r1, Ecrypt, &BRAINPOOLP384R1, Ok(&ECC_384));
  test_ecc!(brainpoolp512r1, Ecrypt, &BRAINPOOLP512R1, Ok(&ECC_512));
  test_ecc!(secp256k1, Ecrypt, &SECP256K1, Ok(&ECC_256));

  test_ffc!(ffc_1024_160, Ecrypt, &FFC_1024_160, Ok(&FFC_3072_256));
  test_ffc!(ffc_2048_224, Ecrypt, &FFC_2048_224, Ok(&FFC_3072_256));
  test_ffc!(ffc_3072_256, Ecrypt, &FFC_3072_256, Ok(&FFC_3072_256));
  test_ffc!(ffc_7680_384, Ecrypt, &FFC_7680_384, Ok(&FFC_7680_384));
  test_ffc!(ffc_15360_512, Ecrypt, &FFC_15360_512, Ok(&FFC_15360_512));

  test_hash!(blake_224, Ecrypt, &BLAKE_224, Ok(&SHA256));
  test_hash!(blake_256, Ecrypt, &BLAKE_256, Ok(&SHA256));
  test_hash!(blake_384, Ecrypt, &BLAKE_384, Ok(&SHA384));
  test_hash!(blake_512, Ecrypt, &BLAKE_512, Ok(&SHA512));
  test_hash!(blake2b_256, Ecrypt, &BLAKE2B_256, Ok(&SHA256));
  test_hash!(blake2b_384, Ecrypt, &BLAKE2B_384, Ok(&SHA384));
  test_hash!(blake2b_512, Ecrypt, &BLAKE2B_512, Ok(&SHA512));
  test_hash!(blake2s_256, Ecrypt, &BLAKE2S_256, Ok(&SHA256));
  test_hash!(md4, Ecrypt, &MD4, Err(&SHA256));
  test_hash!(md5, Ecrypt, &MD5, Err(&SHA256));
  test_hash!(ripemd160, Ecrypt, &RIPEMD160, Ok(&SHA256));
  test_hash!(sha1, Ecrypt, &SHA1, Err(&SHA256));
  test_hash!(sha224, Ecrypt, &SHA224, Ok(&SHA256));
  test_hash!(sha256, Ecrypt, &SHA256, Ok(&SHA256));
  test_hash!(sha384, Ecrypt, &SHA384, Ok(&SHA384));
  test_hash!(sha3_224, Ecrypt, &SHA3_224, Ok(&SHA256));
  test_hash!(sha3_256, Ecrypt, &SHA3_256, Ok(&SHA256));
  test_hash!(sha3_384, Ecrypt, &SHA3_384, Ok(&SHA384));
  test_hash!(sha3_512, Ecrypt, &SHA3_512, Ok(&SHA512));
  test_hash!(sha512, Ecrypt, &SHA512, Ok(&SHA512));
  test_hash!(sha512_224, Ecrypt, &SHA512_224, Ok(&SHA256));
  test_hash!(sha512_256, Ecrypt, &SHA512_256, Ok(&SHA256));
  test_hash!(shake128, Ecrypt, &SHAKE128, Err(&SHA256));
  test_hash!(shake256, Ecrypt, &SHAKE256, Ok(&SHA256));
  test_hash!(whirlpool, Ecrypt, &WHIRLPOOL, Ok(&SHA512));

  test_ifc!(ifc_1024, Ecrypt, &IFC_1024, Ok(&IFC_3072));
  test_ifc!(ifc_2048, Ecrypt, &IFC_2048, Ok(&IFC_3072));
  test_ifc!(ifc_3072, Ecrypt, &IFC_3072, Ok(&IFC_3072));
  test_ifc!(ifc_7680, Ecrypt, &IFC_7680, Ok(&IFC_7680));
  test_ifc!(ifc_15360, Ecrypt, &IFC_15360, Ok(&IFC_15360));

  test_symmetric!(aes128, Ecrypt, &AES128, Ok(&AES128));
  test_symmetric!(aes192, Ecrypt, &AES192, Ok(&AES192));
  test_symmetric!(aes256, Ecrypt, &AES256, Ok(&AES256));
  test_symmetric!(camellia128, Ecrypt, &CAMELLIA128, Ok(&AES128));
  test_symmetric!(camellia192, Ecrypt, &CAMELLIA192, Ok(&AES192));
  test_symmetric!(camellia256, Ecrypt, &CAMELLIA256, Ok(&AES256));
  test_symmetric!(serpent128, Ecrypt, &SERPENT128, Ok(&AES128));
  test_symmetric!(serpent192, Ecrypt, &SERPENT192, Ok(&AES192));
  test_symmetric!(serpent256, Ecrypt, &SERPENT256, Ok(&AES256));
  test_symmetric!(three_key_tdea, Ecrypt, &TDEA3, Ok(&AES128));
  test_symmetric!(two_key_tdea, Ecrypt, &TDEA2, Ok(&AES128));
}
