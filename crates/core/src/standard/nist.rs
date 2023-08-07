//! Validate cryptographic primitives against the [NIST Special
//! Publication 800-57 Part 1 Revision 5 standard].
//!
//! [NIST Special Publication 800-57 Part 1 Revision 5 standard]: https://doi.org/10.6028/NIST.SP.800-57pt1r5
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

const CUTOFF_YEAR: u16 = 2031; // See p. 59.
const CUTOFF_YEAR_3TDEA: u16 = 2023; // See footnote on p. 54.
const CUTOFF_YEAR_DSA: u16 = 2023; // See FIPS-186-5 p. 16.

static SPECIFIED_CURVES: Lazy<HashSet<&Ecc>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(&ED25519);
  s.insert(&ED448);
  s.insert(&P224);
  s.insert(&P256);
  s.insert(&P384);
  s.insert(&P521);
  s.insert(&BRAINPOOLP224R1);
  s.insert(&BRAINPOOLP256R1);
  s.insert(&BRAINPOOLP320R1);
  s.insert(&BRAINPOOLP384R1);
  s.insert(&BRAINPOOLP512R1);
  s.insert(&SECP256K1);
  s
});

static SPECIFIED_HASH_FUNCTIONS: Lazy<HashSet<&Hash>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(&SHA1);
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
  s
});

static SPECIFIED_SYMMETRIC_KEYS: Lazy<HashSet<&Symmetric>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(&AES128);
  s.insert(&AES192);
  s.insert(&AES256);
  s.insert(&TDEA2);
  s.insert(&TDEA3);
  s
});

/// [`Standard`](crate::standard::Standard) implementation of the [NIST
/// Special Publication 800-57 Part 1 Revision 5 standard].
///
/// [NIST Special Publication 800-57 Part 1 Revision 5 standard]: https://doi.org/10.6028/NIST.SP.800-57pt1r5
pub struct Nist;

impl Nist {
  /// Validates a hash function according to page 56 of the standard.
  /// The reference is made with regards to applications that
  /// primarily require pre-image resistance such as message
  /// authentication codes (MACs), key derivation functions (KDFs),
  /// and random bit generation.
  ///
  /// For applications that require collision resistance such digital
  /// signatures use
  /// [`validate_hash`](crate::standard::nist::Nist::validate_hash).
  ///
  /// If the hash function is not compliant then `Err` will contain the
  /// recommended primitive that one should use instead.
  ///
  /// If the hash function is compliant but the context specifies a
  /// higher security level, `Ok` will also hold the recommended
  /// primitive with the desired security level.
  ///
  /// **Note:** that this means an alternative might be suggested for a
  /// compliant hash functions with a similar security level in which a
  /// switch to the recommended primitive would likely be unwarranted.
  /// For example, when evaluating compliance for the `SHA3-256`, a
  /// recommendation to use `SHA256` will be made but switching to this
  /// as a result is likely unnecessary.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant hash
  /// function.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::hash::{SHA1, SHAKE128};
  /// use wardstone_core::standard::nist::Nist;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let hmac_sha1 = &SHA1;
  /// assert_eq!(Nist::validate_hash_based(&ctx, hmac_sha1), Ok(hmac_sha1));
  /// ```
  pub fn validate_hash_based(ctx: &Context, hash: &Hash) -> Result<&'static Hash, &'static Hash> {
    if SPECIFIED_HASH_FUNCTIONS.contains(hash) {
      let pre_image_resistance = hash.security() << 1;
      let security = ctx.security().max(pre_image_resistance);
      match security {
        ..=111 => Err(&SHAKE128),
        112..=127 => {
          if ctx.year() > CUTOFF_YEAR {
            Err(&SHAKE128)
          } else {
            Ok(&SHAKE128)
          }
        },
        128 => Ok(&SHAKE128),
        129..=160 => Ok(&SHA1),
        161..=224 => Ok(&SHA224),
        225..=256 => Ok(&SHA256),
        257..=394 => Ok(&SHA384),
        395.. => Ok(&SHA512),
      }
    } else {
      Err(&SHAKE128)
    }
  }
}

impl Standard for Nist {
  /// Validate an elliptic curve cryptography primitive used for digital
  /// signatures and key establishment where f is the key size according
  /// to page 54-55 of the standard.
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
  /// use wardstone_core::primitive::ecc::P224;
  /// use wardstone_core::standard::nist::Nist;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Nist::validate_ecc(&ctx, &P224), Ok(&P224));
  /// ```
  fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<&'static Ecc, &'static Ecc> {
    if SPECIFIED_CURVES.contains(key) {
      let security = ctx.security().max(key.security());
      match security {
        ..=111 => {
          if ctx.year() > CUTOFF_YEAR {
            Err(&P256)
          } else {
            Err(&P224)
          }
        },
        112..=127 => {
          if ctx.year() > CUTOFF_YEAR {
            Err(&P256)
          } else {
            Ok(&P224)
          }
        },
        128..=191 => Ok(&P256),
        192..=255 => Ok(&P384),
        256.. => Ok(&P521),
      }
    } else {
      Err(&P256)
    }
  }

  /// Validates a finite field cryptography primitive.
  ///
  /// Examples include the DSA and key establishment algorithms such as
  /// Diffie-Hellman and MQV which can also be implemented as such,
  /// according to page 54-55 of the standard.
  ///
  /// A newer revision of FIPS-186, FIPS-186-5 no longer approves the
  /// DSA.
  ///
  /// If the key is not compliant then `Err` will contain the
  /// recommended key sizes L and N that one should use instead.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended key sizes L
  /// and N with the desired security level.
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
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::ffc::FFC_2048_224;
  /// use wardstone_core::standard::nist::Nist;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let dsa_2048 = &FFC_2048_224;
  /// assert_eq!(Nist::validate_ffc(&ctx, dsa_2048), Ok(dsa_2048));
  /// ```
  fn validate_ffc(ctx: &Context, key: &Ffc) -> Result<&'static Ffc, &'static Ffc> {
    if ctx.year() > CUTOFF_YEAR_DSA {
      return Err(&FFC_NOT_SUPPORTED);
    }

    let security = ctx.security().max(key.security());
    match security {
      80 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(&FFC_3072_256)
        } else {
          Err(&FFC_2048_224)
        }
      },
      112 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(&FFC_3072_256)
        } else {
          Ok(&FFC_2048_224)
        }
      },
      128 => Ok(&FFC_3072_256),
      192 => Ok(&FFC_7680_384),
      256 => Ok(&FFC_15360_512),
      _ => Err(&FFC_NOT_SUPPORTED),
    }
  }

  /// Validates a hash function according to page 56 of the standard.
  /// The reference is made with regards to applications that require
  /// collision resistance such as digital signatures.
  ///
  /// For applications that primarily require pre-image resistance such
  /// as message authentication codes (MACs), key derivation functions
  /// (KDFs), and random bit generation use
  /// [`validate_hash_based`](crate::standard::nist::Nist::validate_hash_based).
  ///
  /// If the hash function is not compliant then `Err` will contain the
  /// recommended primitive that one should use instead.
  ///
  /// If the hash function is compliant but the context specifies a
  /// higher security level, `Ok` will also hold the recommended
  /// primitive with the desired security level.
  ///
  /// **Note:** An alternative might be suggested for a compliant hash
  /// functions with a similar security level in which a switch to the
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
  /// use wardstone_core::primitive::hash::{SHA1, SHA224};
  /// use wardstone_core::standard::nist::Nist;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Nist::validate_hash(&ctx, &SHA1), Err(&SHA224));
  /// ```
  fn validate_hash(ctx: &Context, hash: &Hash) -> Result<&'static Hash, &'static Hash> {
    if SPECIFIED_HASH_FUNCTIONS.contains(hash) {
      let security = ctx.security().max(hash.security());
      match security {
        ..=111 => {
          if ctx.year() > CUTOFF_YEAR {
            Err(&SHA256)
          } else {
            Err(&SHA224)
          }
        },
        112..=127 => {
          if ctx.year() > CUTOFF_YEAR {
            Err(&SHA256)
          } else {
            Ok(&SHA224)
          }
        },
        128..=191 => Ok(&SHA256),
        192..=255 => Ok(&SHA384),
        256.. => Ok(&SHA512),
      }
    } else {
      Err(&SHA256)
    }
  }

  /// Validates  an integer factorisation cryptography primitive the
  /// most common of which is the RSA signature algorithm where k
  /// indicates the key size according to page 54-55 of the standard.
  ///
  /// If the key is not compliant then `Err` will contain the
  /// recommended key size that one should use instead.
  ///
  /// If the key is compliant but the context specifies a higher
  /// security level, `Ok` will also hold the recommended key size
  /// with the desired security level.
  ///
  /// **Note:** This will return a generic structure that specifies
  /// minimum private and public key sizes.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::ifc::IFC_2048;
  /// use wardstone_core::standard::nist::Nist;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let rsa_2048 = &IFC_2048;
  /// assert_eq!(Nist::validate_ifc(&ctx, rsa_2048), Ok(rsa_2048));
  /// ```
  fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<&'static Ifc, &'static Ifc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=111 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(&IFC_3072)
        } else {
          Err(&IFC_2048)
        }
      },
      112..=127 => {
        if ctx.year() > CUTOFF_YEAR {
          Err(&IFC_3072)
        } else {
          Ok(&IFC_2048)
        }
      },
      128..=191 => Ok(&IFC_3072),
      192..=255 => Ok(&IFC_7680),
      256.. => Ok(&IFC_15360),
    }
  }

  /// Validates a symmetric key primitive according to pages 54-55 of
  /// the standard.
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
  /// The following illustrates a call to validate a three-key Triple
  /// DES key (which is deprecated through the year 2023).
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::symmetric::{AES128, TDEA3};
  /// use wardstone_core::standard::nist::Nist;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Nist::validate_symmetric(&ctx, &TDEA3), Ok(&AES128));
  /// ```
  fn validate_symmetric(
    ctx: &Context,
    key: &Symmetric,
  ) -> Result<&'static Symmetric, &'static Symmetric> {
    if SPECIFIED_SYMMETRIC_KEYS.contains(key) {
      let security = ctx.security().max(key.security());
      match security {
        ..=111 => Err(&AES128),
        112 => {
          // See SP 800-131Ar2 p. 7.
          let cutoff = if key.id == TDEA3.id {
            CUTOFF_YEAR_3TDEA
          } else {
            CUTOFF_YEAR
          };
          if ctx.year() > cutoff {
            Err(&AES128)
          } else {
            Ok(&AES128)
          }
        },
        113..=128 => Ok(&AES128),
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
  use crate::{test_ecc, test_ffc, test_hash, test_hash_based, test_ifc, test_symmetric};

  test_ecc!(p224, Nist, &P224, Ok(&P224));
  test_ecc!(p256, Nist, &P256, Ok(&P256));
  test_ecc!(p384, Nist, &P384, Ok(&P384));
  test_ecc!(p521, Nist, &P521, Ok(&P521));
  test_ecc!(ed25519, Nist, &ED25519, Ok(&P256));
  test_ecc!(ed448, Nist, &ED448, Ok(&P384));
  test_ecc!(x25519, Nist, &X25519, Err(&P256));
  test_ecc!(x448, Nist, &X448, Err(&P256));
  test_ecc!(brainpoolp224r1, Nist, &BRAINPOOLP224R1, Ok(&P224));
  test_ecc!(brainpoolp256r1, Nist, &BRAINPOOLP256R1, Ok(&P256));
  test_ecc!(brainpoolp320r1, Nist, &BRAINPOOLP320R1, Ok(&P256));
  test_ecc!(brainpoolp384r1, Nist, &BRAINPOOLP384R1, Ok(&P384));
  test_ecc!(brainpoolp512r1, Nist, &BRAINPOOLP512R1, Ok(&P521));
  test_ecc!(secp256k1, Nist, &SECP256K1, Ok(&P256));

  test_ffc!(ffc_1024_160, Nist, &FFC_1024_160, Err(&FFC_2048_224));
  test_ffc!(ffc_2048_224, Nist, &FFC_2048_224, Ok(&FFC_2048_224));
  test_ffc!(ffc_3072_256, Nist, &FFC_3072_256, Ok(&FFC_3072_256));
  test_ffc!(ffc_7680_384, Nist, &FFC_7680_384, Ok(&FFC_7680_384));
  test_ffc!(ffc_15360_512, Nist, &FFC_15360_512, Ok(&FFC_15360_512));

  test_ifc!(ifc_1024, Nist, &IFC_1024, Err(&IFC_2048));
  test_ifc!(ifc_2048, Nist, &IFC_2048, Ok(&IFC_2048));
  test_ifc!(ifc_3072, Nist, &IFC_3072, Ok(&IFC_3072));
  test_ifc!(ifc_7680, Nist, &IFC_7680, Ok(&IFC_7680));
  test_ifc!(ifc_15360, Nist, &IFC_15360, Ok(&IFC_15360));

  test_hash!(
    blake2b_256_collision_resistance,
    Nist,
    &BLAKE2B_256,
    Err(&SHA256)
  );
  test_hash!(
    blake2b_384_collision_resistance,
    Nist,
    &BLAKE2B_384,
    Err(&SHA256)
  );
  test_hash!(
    blake2b_512_collision_resistance,
    Nist,
    &BLAKE2B_512,
    Err(&SHA256)
  );
  test_hash!(
    blake2s_256_collision_resistance,
    Nist,
    &BLAKE2S_256,
    Err(&SHA256)
  );
  test_hash!(md4_collision_resistance, Nist, &MD4, Err(&SHA256));
  test_hash!(md5_collision_resistance, Nist, &MD5, Err(&SHA256));
  test_hash!(
    ripemd160_collision_resistance,
    Nist,
    &RIPEMD160,
    Err(&SHA256)
  );
  test_hash!(sha1_collision_resistance, Nist, &SHA1, Err(&SHA224));
  test_hash!(sha224_collision_resistance, Nist, &SHA224, Ok(&SHA224));
  test_hash!(sha256_collision_resistance, Nist, &SHA256, Ok(&SHA256));
  test_hash!(sha384_collision_resistance, Nist, &SHA384, Ok(&SHA384));
  test_hash!(sha3_224_collision_resistance, Nist, &SHA3_224, Ok(&SHA224));
  test_hash!(sha3_256_collision_resistance, Nist, &SHA3_256, Ok(&SHA256));
  test_hash!(sha3_384_collision_resistance, Nist, &SHA3_384, Ok(&SHA384));
  test_hash!(sha3_512_collision_resistance, Nist, &SHA3_512, Ok(&SHA512));
  test_hash!(sha512_collision_resistance, Nist, &SHA512, Ok(&SHA512));
  test_hash!(
    sha512_224_collision_resistance,
    Nist,
    &SHA512_224,
    Ok(&SHA224)
  );
  test_hash!(
    sha512_256_collision_resistance,
    Nist,
    &SHA512_256,
    Ok(&SHA256)
  );
  test_hash!(shake128_collision_resistance, Nist, &SHAKE128, Err(&SHA224));
  test_hash!(shake256_collision_resistance, Nist, &SHAKE256, Ok(&SHA256));

  test_hash_based!(
    blake2b_256_pre_image_resistance,
    Nist,
    &BLAKE2B_256,
    Err(&SHAKE128)
  );
  test_hash_based!(
    blake2b_384_pre_image_resistance,
    Nist,
    &BLAKE2B_384,
    Err(&SHAKE128)
  );
  test_hash_based!(
    blake2b_512_pre_image_resistance,
    Nist,
    &BLAKE2B_512,
    Err(&SHAKE128)
  );
  test_hash_based!(
    blake2s_256_pre_image_resistance,
    Nist,
    &BLAKE2S_256,
    Err(&SHAKE128)
  );
  test_hash_based!(md4_pre_image_resistance, Nist, &MD4, Err(&SHAKE128));
  test_hash_based!(md5_pre_image_resistance, Nist, &MD5, Err(&SHAKE128));
  test_hash_based!(
    ripemd160_pre_image_resistance,
    Nist,
    &RIPEMD160,
    Err(&SHAKE128)
  );
  test_hash_based!(sha1_pre_image_resistance, Nist, &SHA1, Ok(&SHA1));
  test_hash_based!(sha224_pre_image_resistance, Nist, &SHA224, Ok(&SHA224));
  test_hash_based!(sha256_pre_image_resistance, Nist, &SHA256, Ok(&SHA256));
  test_hash_based!(sha384_pre_image_resistance, Nist, &SHA384, Ok(&SHA384));
  test_hash_based!(sha3_224_pre_image_resistance, Nist, &SHA3_224, Ok(&SHA224));
  test_hash_based!(sha3_256_pre_image_resistance, Nist, &SHA3_256, Ok(&SHA256));
  test_hash_based!(sha3_384_pre_image_resistance, Nist, &SHA3_384, Ok(&SHA384));
  test_hash_based!(sha3_512_pre_image_resistance, Nist, &SHA3_512, Ok(&SHA512));
  test_hash_based!(sha512_pre_image_resistance, Nist, &SHA512, Ok(&SHA512));
  test_hash_based!(
    sha512_224_pre_image_resistance,
    Nist,
    &SHA512_224,
    Ok(&SHA224)
  );
  test_hash_based!(
    sha512_256_pre_image_resistance,
    Nist,
    &SHA512_256,
    Ok(&SHA256)
  );
  test_hash_based!(
    shake128_pre_image_resistance,
    Nist,
    &SHAKE128,
    Ok(&SHAKE128)
  );
  test_hash_based!(shake256_pre_image_resistance, Nist, &SHAKE256, Ok(&SHA256));

  test_symmetric!(two_key_tdea, Nist, &TDEA2, Err(&AES128));
  test_symmetric!(three_key_tdea, Nist, &TDEA3, Ok(&AES128));
  test_symmetric!(aes128, Nist, &AES128, Ok(&AES128));
  test_symmetric!(aes192, Nist, &AES192, Ok(&AES192));
  test_symmetric!(aes256, Nist, &AES256, Ok(&AES256));
}
