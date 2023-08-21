//! Validate cryptographic primitives against the levels of security
//! mentioned in the paper Key Lengths, Arjen K. Lenstra, The Handbook
//! of Information Security, 06/2004.
use std::collections::HashSet;

use once_cell::sync::Lazy;

use crate::context::Context;
use crate::primitive::ecc::*;
use crate::primitive::ffc::*;
use crate::primitive::hash::*;
use crate::primitive::ifc::*;
use crate::primitive::symmetric::*;
use crate::primitive::Primitive;
use crate::standard::Standard;

#[derive(PartialEq, Eq, Debug)]
pub enum ValidationError {
  SecurityLevelTooLow,
}

const BASE_YEAR: u16 = 1982;
const BASE_SECURITY: u16 = 56;

static SPECIFIED_HASH_FUNCTIONS: Lazy<HashSet<Hash>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(RIPEMD160);
  s.insert(SHA1);
  s.insert(SHA256);
  s.insert(SHA384);
  s.insert(SHA512);
  s
});

static SPECIFIED_SYMMETRIC_KEYS: Lazy<HashSet<Symmetric>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(AES128);
  s.insert(AES192);
  s.insert(AES256);
  s.insert(DES);
  s.insert(DESX);
  s.insert(IDEA);
  s.insert(TDEA2);
  s.insert(TDEA3);
  s
});

/// [`Standard`](crate::standard::Standard) implementation of the paper
/// Key Lengths, Arjen K. Lenstra, The Handbook of Information Security,
/// 06/2004.
pub struct Lenstra;

impl Lenstra {
  /// Calculates the security according to the formula on page 7. If the
  /// year is less than the BASE_YEAR, a ValidationError is returned.
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
}

impl Standard for Lenstra {
  /// Validate an elliptic curve cryptography primitive used for digital
  /// signatures and key establishment where f is the key size.
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
  /// use wardstone_core::primitive::ecc::{BRAINPOOLP256R1, ECC_256};
  /// use wardstone_core::standard::lenstra::Lenstra;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Lenstra::validate_ecc(ctx, BRAINPOOLP256R1), Ok(ECC_256));
  /// ```
  fn validate_ecc(ctx: Context, key: Ecc) -> Result<Ecc, Ecc> {
    let implied_security = ctx.security().max(key.security());
    let min_security = match Lenstra::calculate_security(ctx.year()) {
      Ok(security) => security,
      Err(_) => return Err(ECC_NOT_ALLOWED),
    };
    let recommendation = match implied_security.max(min_security) {
      ..=111 => ECC_NOT_ALLOWED,
      112 => ECC_224,
      113..=128 => ECC_256,
      129..=192 => ECC_384,
      193.. => ECC_512,
    };
    if implied_security < min_security {
      Err(recommendation)
    } else {
      Ok(recommendation)
    }
  }

  /// Validates a finite field cryptography primitive.
  ///
  /// Examples include the DSA and key establishment algorithms such as
  /// Diffie-Hellman and MQV which can also be implemented as such.
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
  /// use wardstone_core::primitive::ffc::DSA_3072_256;
  /// use wardstone_core::standard::lenstra::Lenstra;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let dsa_3072 = DSA_3072_256;
  /// assert_eq!(Lenstra::validate_ffc(ctx, dsa_3072), Ok(dsa_3072));
  /// ```
  fn validate_ffc(ctx: Context, key: Ffc) -> Result<Ffc, Ffc> {
    let implied_security = ctx.security().max(key.security());
    let min_security = match Lenstra::calculate_security(ctx.year()) {
      Ok(security) => security,
      Err(_) => return Err(FFC_NOT_SUPPORTED),
    };
    let recommendation = match implied_security.max(min_security) {
      ..=79 => FFC_NOT_SUPPORTED,
      80 => DSA_1024_160,
      81..=112 => DSA_2048_224,
      113..=128 => DSA_3072_256,
      129..=192 => DSA_7680_384,
      193.. => DSA_15360_512,
    };
    if implied_security < min_security {
      Err(recommendation)
    } else {
      Ok(recommendation)
    }
  }

  /// Validates a hash function according to pages 12-14 of the paper.
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
  /// use wardstone_core::standard::lenstra::Lenstra;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Lenstra::validate_hash(ctx, SHA1), Err(SHA256));
  /// ```
  fn validate_hash(ctx: Context, hash: Hash) -> Result<Hash, Hash> {
    if SPECIFIED_HASH_FUNCTIONS.contains(&hash) {
      let implied_security = ctx.security().max(hash.security());
      let min_security = match Lenstra::calculate_security(ctx.year()) {
        Ok(security) => security,
        Err(_) => return Err(SHA256),
      };
      let recommendation = match implied_security.max(min_security) {
        // SHA1 and RIPEMD-160 offer less security than their digest
        // length so they are omitted even though they might cover the
        // range ..=80.
        ..=128 => SHA256,
        129..=192 => SHA384,
        193.. => SHA512,
      };
      if implied_security < min_security {
        Err(recommendation)
      } else {
        Ok(recommendation)
      }
    } else {
      Err(SHA256)
    }
  }

  /// Validates  an integer factorisation cryptography primitive the
  /// most common of which is the RSA signature algorithm based on
  /// pages 17-25.
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
  /// use wardstone_core::standard::lenstra::Lenstra;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Lenstra::validate_ifc(ctx, RSA_PSS_2048), Ok(RSA_PSS_2048));
  /// ```
  fn validate_ifc(ctx: Context, key: Ifc) -> Result<Ifc, Ifc> {
    // Per Table 4 on page 25.
    let (implied_year, implied_security) = match key.k {
      ..=1023 => (u16::MIN, u16::MIN),
      1024 => (2006, 72),
      1025..=1280 => (2014, 78),
      1281..=1536 => (2020, 82),
      1537..=2048 => (2030, 88),
      2049..=3072 => (2046, 99),
      3073..=4096 => (2060, 108),
      4097.. => (2100, 135),
    };

    let year = implied_year.max(ctx.year());
    let (security_range, recommendation) = match year {
      ..=2006 => (0..=72, RSA_PSS_1024),
      2007..=2014 => (73..=78, RSA_PSS_1280),
      2015..=2020 => (79..=82, RSA_PSS_1536),
      2021..=2030 => (83..=88, RSA_PSS_2048),
      2031..=2046 => (89..=99, RSA_PSS_3072),
      2047..=2060 => (100..=108, RSA_PSS_4096),
      2061.. => (109..=135, RSA_PSS_8192),
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
  /// use wardstone_core::primitive::symmetric::TDEA3;
  /// use wardstone_core::standard::lenstra::Lenstra;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Lenstra::validate_symmetric(ctx, TDEA3), Ok(TDEA3));
  /// ```
  fn validate_symmetric(ctx: Context, key: Symmetric) -> Result<Symmetric, Symmetric> {
    if SPECIFIED_SYMMETRIC_KEYS.contains(&key) {
      let implied_security = ctx.security().max(key.security());
      let min_security = match Lenstra::calculate_security(ctx.year()) {
        Ok(security) => security,
        Err(_) => return Err(AES128),
      };
      let recommendation = match implied_security.max(min_security) {
        ..=95 => TDEA2,
        96..=112 => TDEA3,
        113..=120 => DESX,
        121..=128 => AES128,
        129..=192 => AES192,
        193.. => AES256,
      };
      if implied_security < min_security {
        Err(recommendation)
      } else {
        Ok(recommendation)
      }
    } else {
      Err(AES128)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{test_ecc, test_ffc, test_hash, test_ifc, test_symmetric};

  test_ecc!(p224, Lenstra, P224, Ok(ECC_224));
  test_ecc!(p256, Lenstra, P256, Ok(ECC_256));
  test_ecc!(p384, Lenstra, P384, Ok(ECC_384));
  test_ecc!(p521, Lenstra, P521, Ok(ECC_512));
  test_ecc!(ed25519, Lenstra, ED25519, Ok(ECC_256));
  test_ecc!(ed448, Lenstra, ED448, Ok(ECC_512));
  test_ecc!(x25519, Lenstra, X25519, Ok(ECC_256));
  test_ecc!(x448, Lenstra, X448, Ok(ECC_512));
  test_ecc!(brainpoolp224r1, Lenstra, BRAINPOOLP224R1, Ok(ECC_224));
  test_ecc!(brainpoolp256r1, Lenstra, BRAINPOOLP256R1, Ok(ECC_256));
  test_ecc!(brainpoolp320r1, Lenstra, BRAINPOOLP320R1, Ok(ECC_384));
  test_ecc!(brainpoolp384r1, Lenstra, BRAINPOOLP384R1, Ok(ECC_384));
  test_ecc!(brainpoolp512r1, Lenstra, BRAINPOOLP512R1, Ok(ECC_512));
  test_ecc!(secp256k1, Lenstra, SECP256K1, Ok(ECC_256));

  test_ffc!(ffc_1024_160, Lenstra, DSA_1024_160, Err(DSA_2048_224));
  test_ffc!(ffc_2048_224, Lenstra, DSA_2048_224, Ok(DSA_2048_224));
  test_ffc!(ffc_3072_256, Lenstra, DSA_3072_256, Ok(DSA_3072_256));
  test_ffc!(ffc_7680_384, Lenstra, DSA_7680_384, Ok(DSA_7680_384));
  test_ffc!(ffc_15360_512, Lenstra, DSA_15360_512, Ok(DSA_15360_512));

  test_ifc!(ifc_1024, Lenstra, RSA_PSS_1024, Err(RSA_PSS_2048));
  test_ifc!(ifc_1280, Lenstra, RSA_PSS_1280, Err(RSA_PSS_2048));
  test_ifc!(ifc_1536, Lenstra, RSA_PSS_1536, Err(RSA_PSS_2048));
  test_ifc!(ifc_2048, Lenstra, RSA_PSS_2048, Ok(RSA_PSS_2048));
  test_ifc!(ifc_3072, Lenstra, RSA_PSS_3072, Ok(RSA_PSS_3072));
  test_ifc!(ifc_4096, Lenstra, RSA_PSS_4096, Ok(RSA_PSS_4096));
  test_ifc!(ifc_7680, Lenstra, RSA_PSS_7680, Ok(RSA_PSS_8192));
  test_ifc!(ifc_8192, Lenstra, RSA_PSS_8192, Ok(RSA_PSS_8192));
  test_ifc!(ifc_15360, Lenstra, RSA_PSS_15360, Ok(RSA_PSS_8192));

  test_hash!(blake_224, Lenstra, BLAKE_224, Err(SHA256));
  test_hash!(blake_256, Lenstra, BLAKE_256, Err(SHA256));
  test_hash!(blake_384, Lenstra, BLAKE_384, Err(SHA256));
  test_hash!(blake_512, Lenstra, BLAKE_512, Err(SHA256));
  test_hash!(blake2b_256, Lenstra, BLAKE2B_256, Err(SHA256));
  test_hash!(blake2b_384, Lenstra, BLAKE2B_384, Err(SHA256));
  test_hash!(blake2b_512, Lenstra, BLAKE2B_512, Err(SHA256));
  test_hash!(blake2s_256, Lenstra, BLAKE2S_256, Err(SHA256));
  test_hash!(md4, Lenstra, MD4, Err(SHA256));
  test_hash!(md5, Lenstra, MD5, Err(SHA256));
  test_hash!(ripemd160, Lenstra, RIPEMD160, Err(SHA256));
  test_hash!(sha1, Lenstra, SHA1, Err(SHA256));
  test_hash!(sha224, Lenstra, SHA224, Err(SHA256));
  test_hash!(sha256, Lenstra, SHA256, Ok(SHA256));
  test_hash!(sha384, Lenstra, SHA384, Ok(SHA384));
  test_hash!(sha3_224, Lenstra, SHA3_224, Err(SHA256));
  test_hash!(sha3_256, Lenstra, SHA3_256, Err(SHA256));
  test_hash!(sha3_384, Lenstra, SHA3_384, Err(SHA256));
  test_hash!(sha3_512, Lenstra, SHA3_512, Err(SHA256));
  test_hash!(sha512, Lenstra, SHA512, Ok(SHA512));
  test_hash!(sha512_224, Lenstra, SHA512_224, Err(SHA256));
  test_hash!(sha512_256, Lenstra, SHA512_256, Err(SHA256));
  test_hash!(shake128, Lenstra, SHAKE128, Err(SHA256));
  test_hash!(shake256, Lenstra, SHAKE256, Err(SHA256));
  test_hash!(whirlpool, Lenstra, WHIRLPOOL, Err(SHA256));

  test_symmetric!(aes128, Lenstra, AES128, Ok(AES128));
  test_symmetric!(aes192, Lenstra, AES192, Ok(AES192));
  test_symmetric!(aes256, Lenstra, AES256, Ok(AES256));
  test_symmetric!(camellia128, Lenstra, CAMELLIA128, Err(AES128));
  test_symmetric!(camellia192, Lenstra, CAMELLIA192, Err(AES128));
  test_symmetric!(camellia256, Lenstra, CAMELLIA256, Err(AES128));
  test_symmetric!(des, Lenstra, DES, Err(TDEA2));
  test_symmetric!(desx, Lenstra, DESX, Ok(DESX));
  test_symmetric!(idea, Lenstra, IDEA, Ok(AES128));
  test_symmetric!(serpent128, Lenstra, SERPENT128, Err(AES128));
  test_symmetric!(serpent192, Lenstra, SERPENT192, Err(AES128));
  test_symmetric!(serpent256, Lenstra, SERPENT256, Err(AES128));
  test_symmetric!(three_key_tdea, Lenstra, TDEA3, Ok(TDEA3));
  test_symmetric!(two_key_tdea, Lenstra, TDEA2, Ok(TDEA2));
}
