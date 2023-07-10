//! Validate cryptographic primitives against the [ECRYPT-CSA D5.4
//! Algorithms, Key Size and Protocols Report].
//!
//! [ECRYPT-CSA D5.4 Algorithms, Key Size and Protocols Report]: https://www.ecrypt.eu.org/csa/documents/D5.4-FinalAlgKeySizeProt.pdf
use std::collections::HashSet;

use crate::context::Context;
use crate::ecc::Ecc;
use crate::ffc::Ffc;
use crate::hash::Hash;
use crate::ifc::Ifc;
use crate::primitives::ecc::*;
use crate::primitives::ffc::*;
use crate::primitives::hash::*;
use crate::primitives::ifc::*;
use crate::primitives::symmetric::*;
use crate::symmetric::Symmetric;

// "Thus the key take home message is that decision makers now make
// plans and preparations for the phasing out of what we term legacy
// mechanisms over a period of say 5-10 years." (2018, p. 12). See p. 11
// about the criteria made to distinguish between the different
// categories of legacy algorithms.
const CUTOFF_YEAR: u16 = 2023;

lazy_static! {
  static ref SPECIFIED_HASH: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(BLAKE2B_256.id);
    s.insert(BLAKE2B_384.id);
    s.insert(BLAKE2B_512.id);
    s.insert(BLAKE2S_256.id);
    s.insert(BLAKE_224.id);
    s.insert(BLAKE_256.id);
    s.insert(BLAKE_384.id);
    s.insert(BLAKE_512.id);
    s.insert(RIPEMD160.id);
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
    s.insert(SHAKE128.id);
    s.insert(SHAKE256.id);
    s.insert(WHIRLPOOL.id);
    s
  };
  static ref SPECIFIED_SYMMETRIC: HashSet<u16> = {
    let mut s = HashSet::new();
    s.insert(AES128.id);
    s.insert(AES192.id);
    s.insert(AES256.id);
    s.insert(CAMELLIA128.id);
    s.insert(CAMELLIA192.id);
    s.insert(CAMELLIA256.id);
    s.insert(SERPENT128.id);
    s.insert(SERPENT192.id);
    s.insert(SERPENT256.id);
    s.insert(TDEA2.id);
    s.insert(TDEA3.id);
    s
  };
}

/// Validate an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size according
/// to page 47 of the report.
///
/// If the key is not compliant then `Err` will contain the recommended
/// primitive that one should use instead.
///
/// If the key is compliant but the context specifies a higher security
/// level, `Ok` will also hold the recommended primitive with the
/// desired security level.
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
/// use wardstone_core::primitives::ecc::{ECC_256, P224};
/// use wardstone_core::standards::ecrypt;
///
/// let ctx = Context::default();
/// assert_eq!(ecrypt::validate_ecc(&ctx, &P224), Ok(ECC_256));
/// ```
pub fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc> {
  let security = ctx.security().max(key.security());
  match security {
    ..=79 => Err(ECC_256),
    80..=127 => {
      if ctx.year() > CUTOFF_YEAR {
        Err(ECC_256)
      } else {
        Ok(ECC_256)
      }
    },
    128 => Ok(ECC_256),
    129..=192 => Ok(ECC_384),
    193.. => Ok(ECC_512),
  }
}

/// Validates a finite field cryptography primitive according to page 47
/// of the report.
///
/// Examples include the DSA and key establishment algorithms such as
/// Diffie-Hellman and MQV which can also be implemented as such,
/// according to page 47 of the report.
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
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::ffc::{FFC_2048_224, FFC_3072_256};
/// use wardstone_core::standards::ecrypt;
///
/// let ctx = Context::default();
/// let dsa_2048 = FFC_2048_224;
/// let dsa_3072 = FFC_3072_256;
/// assert_eq!(ecrypt::validate_ffc(&ctx, &dsa_2048), Ok(dsa_3072));
/// ```
pub fn validate_ffc(ctx: &Context, key: &Ffc) -> Result<Ffc, Ffc> {
  // HACK: Use the public key size n as a proxy for security.
  let mut aux = *key;
  aux.n = ctx.security().max(key.n);
  match aux {
    Ffc {
      l: ..=1023,
      n: ..=159,
    } => Err(FFC_3072_256),
    Ffc {
      l: 1024..=3071,
      n: 160..=255,
    } => {
      if ctx.year() > CUTOFF_YEAR {
        Err(FFC_3072_256)
      } else {
        Ok(FFC_3072_256)
      }
    },
    Ffc { l: 3072, n: 256 } => Ok(FFC_3072_256),
    Ffc {
      l: 3073..=7680,
      n: 257..=384,
    } => Ok(FFC_7680_384),
    Ffc {
      l: 7681..,
      n: 385..,
    } => Ok(FFC_15360_512),
    _ => Err(FFC_NOT_SUPPORTED),
  }
}

/// Validates a hash function according to pages 40-43 of the report.
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
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::hash::{SHA1, SHA256};
/// use wardstone_core::standards::ecrypt;
///
/// let ctx = Context::default();
/// assert_eq!(ecrypt::validate_hash(&ctx, &SHA1), Err(SHA256));
/// ```
pub fn validate_hash(ctx: &Context, hash: &Hash) -> Result<Hash, Hash> {
  if SPECIFIED_HASH.contains(&hash.id) {
    let security = ctx.security().max(hash.collision_resistance());
    match security {
      ..=79 => Err(SHA256),
      80..=127 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(SHA256)
        } else {
          Ok(SHA256)
        }
      },
      128 => Ok(SHA256),
      129..=192 => Ok(SHA384),
      193.. => Ok(SHA512),
    }
  } else {
    Err(SHA256)
  }
}

/// Validates  an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm according to pages
/// 47-48.
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
/// use wardstone_core::primitives::ifc::{IFC_2048, IFC_3072};
/// use wardstone_core::standards::ecrypt;
///
/// let ctx = Context::default();
/// let rsa_2048 = IFC_2048;
/// let rsa_3072 = IFC_3072;
/// assert_eq!(ecrypt::validate_ifc(&ctx, &rsa_2048), Ok(rsa_3072));
/// ```
pub fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<Ifc, Ifc> {
  let security = ctx.security().max(*key.security().start());
  match security {
    ..=79 => Err(IFC_3072),
    80..=127 => {
      if ctx.year() > CUTOFF_YEAR {
        Err(IFC_3072)
      } else {
        Ok(IFC_3072)
      }
    },
    128..=191 => Ok(IFC_3072),
    192..=255 => Ok(IFC_7680),
    256.. => Ok(IFC_15360),
  }
}

/// Validates a symmetric key primitive according to pages 37 to 40 of
/// the report.
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
/// use wardstone_core::context::Context;
/// use wardstone_core::primitives::symmetric::{AES128, TDEA3};
/// use wardstone_core::standards::ecrypt;
///
/// let ctx = Context::default();
/// assert_eq!(ecrypt::validate_symmetric(&ctx, &TDEA3), Ok(AES128));
/// ```
pub fn validate_symmetric(ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric> {
  if SPECIFIED_SYMMETRIC.contains(&key.id) {
    let security = ctx.security().max(key.security);
    match security {
      ..=79 => Err(AES128),
      80..=127 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(AES128)
        } else {
          Ok(AES128)
        }
      },
      128 => Ok(AES128),
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

  test_case!(p224, validate_ecc, &P224, Ok(ECC_256));
  test_case!(p256, validate_ecc, &P256, Ok(ECC_256));
  test_case!(p384, validate_ecc, &P384, Ok(ECC_384));
  test_case!(p521, validate_ecc, &P521, Ok(ECC_512));
  test_case!(w25519, validate_ecc, &W25519, Ok(ECC_256));
  test_case!(w448, validate_ecc, &W448, Ok(ECC_512));
  test_case!(curve25519, validate_ecc, &CURVE25519, Ok(ECC_256));
  test_case!(curve488, validate_ecc, &CURVE448, Ok(ECC_512));
  test_case!(edwards25519, validate_ecc, &EDWARDS25519, Ok(ECC_256));
  test_case!(edwards448, validate_ecc, &EDWARDS448, Ok(ECC_512));
  test_case!(e448, validate_ecc, &E448, Ok(ECC_512));
  test_case!(brainpoolp224r1, validate_ecc, &BRAINPOOLP224R1, Ok(ECC_256));
  test_case!(brainpoolp256r1, validate_ecc, &BRAINPOOLP256R1, Ok(ECC_256));
  test_case!(brainpoolp320r1, validate_ecc, &BRAINPOOLP320R1, Ok(ECC_384));
  test_case!(brainpoolp384r1, validate_ecc, &BRAINPOOLP384R1, Ok(ECC_384));
  test_case!(brainpoolp512r1, validate_ecc, &BRAINPOOLP512R1, Ok(ECC_512));
  test_case!(secp256k1, validate_ecc, &SECP256K1, Ok(ECC_256));

  test_case!(ffc_1024_160, validate_ffc, &FFC_1024_160, Ok(FFC_3072_256));
  test_case!(ffc_2048_224, validate_ffc, &FFC_2048_224, Ok(FFC_3072_256));
  test_case!(ffc_3072_256, validate_ffc, &FFC_3072_256, Ok(FFC_3072_256));
  test_case!(ffc_7680_384, validate_ffc, &FFC_7680_384, Ok(FFC_7680_384));
  test_case!(ffc_15360_512, validate_ffc, &FFC_15360_512, Ok(FFC_15360_512));

  test_case!(blake_224, validate_hash, &BLAKE_224, Ok(SHA256));
  test_case!(blake_256, validate_hash, &BLAKE_256, Ok(SHA256));
  test_case!(blake_384, validate_hash, &BLAKE_384, Ok(SHA384));
  test_case!(blake_512, validate_hash, &BLAKE_512, Ok(SHA512));
  test_case!(blake2b_256, validate_hash, &BLAKE2B_256, Ok(SHA256));
  test_case!(blake2b_384, validate_hash, &BLAKE2B_384, Ok(SHA384));
  test_case!(blake2b_512, validate_hash, &BLAKE2B_512, Ok(SHA512));
  test_case!(blake2s_256, validate_hash, &BLAKE2S_256, Ok(SHA256));
  test_case!(md4, validate_hash, &MD4, Err(SHA256));
  test_case!(md5, validate_hash, &MD5, Err(SHA256));
  test_case!(ripemd160, validate_hash, &RIPEMD160, Ok(SHA256));
  test_case!(sha1, validate_hash, &SHA1, Err(SHA256));
  test_case!(sha224, validate_hash, &SHA224, Ok(SHA256));
  test_case!(sha256, validate_hash, &SHA256, Ok(SHA256));
  test_case!(sha384, validate_hash, &SHA384, Ok(SHA384));
  test_case!(sha3_224, validate_hash, &SHA3_224, Ok(SHA256));
  test_case!(sha3_256, validate_hash, &SHA3_256, Ok(SHA256));
  test_case!(sha3_384, validate_hash, &SHA3_384, Ok(SHA384));
  test_case!(sha3_512, validate_hash, &SHA3_512, Ok(SHA512));
  test_case!(sha512, validate_hash, &SHA512, Ok(SHA512));
  test_case!(sha512_224, validate_hash, &SHA512_224, Ok(SHA256));
  test_case!(sha512_256, validate_hash, &SHA512_256, Ok(SHA256));
  test_case!(shake128, validate_hash, &SHAKE128, Err(SHA256));
  test_case!(shake256, validate_hash, &SHAKE256, Ok(SHA256));
  test_case!(whirlpool, validate_hash, &WHIRLPOOL, Ok(SHA512));

  test_case!(ifc_1024, validate_ifc, &IFC_1024, Ok(IFC_3072));
  test_case!(ifc_2048, validate_ifc, &IFC_2048, Ok(IFC_3072));
  test_case!(ifc_3072, validate_ifc, &IFC_3072, Ok(IFC_3072));
  test_case!(ifc_7680, validate_ifc, &IFC_7680, Ok(IFC_7680));
  test_case!(ifc_15360, validate_ifc, &IFC_15360, Ok(IFC_15360));

  test_case!(aes128, validate_symmetric, &AES128, Ok(AES128));
  test_case!(aes192, validate_symmetric, &AES192, Ok(AES192));
  test_case!(aes256, validate_symmetric, &AES256, Ok(AES256));
  test_case!(camellia128, validate_symmetric, &CAMELLIA128, Ok(AES128));
  test_case!(camellia192, validate_symmetric, &CAMELLIA192, Ok(AES192));
  test_case!(camellia256, validate_symmetric, &CAMELLIA256, Ok(AES256));
  test_case!(serpent128, validate_symmetric, &SERPENT128, Ok(AES128));
  test_case!(serpent192, validate_symmetric, &SERPENT192, Ok(AES192));
  test_case!(serpent256, validate_symmetric, &SERPENT256, Ok(AES256));
  test_case!(three_key_tdea, validate_symmetric, &TDEA3, Ok(AES128));
  test_case!(two_key_tdea, validate_symmetric, &TDEA2, Ok(AES128));
}
