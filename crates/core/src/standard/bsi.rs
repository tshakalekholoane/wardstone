//! Validate cryptographic primitives against the [BSI TR-02102-1
//! Cryptographic Mechanisms: Recommendations and Key Lengths] technical
//! guide.
//!
//! [BSI TR-02102-1 Cryptographic Mechanisms: Recommendations and Key Lengths]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html
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

const CUTOFF_YEAR_RSA: u16 = 2023; // See p. 17.

static SPECIFIED_CURVES: Lazy<HashSet<Ecc>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(SECP256R1);
  s.insert(SECP384R1);
  s.insert(SECP521R1);
  s.insert(BRAINPOOLP256R1);
  s.insert(BRAINPOOLP320R1);
  s.insert(BRAINPOOLP384R1);
  s.insert(BRAINPOOLP512R1);
  s
});

static SPECIFIED_HASH_FUNCTIONS: Lazy<HashSet<Hash>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(SHA256);
  s.insert(SHA384);
  s.insert(SHA3_256);
  s.insert(SHA3_384);
  s.insert(SHA3_512);
  s.insert(SHA512);
  s.insert(SHA512_256);
  s
});

// "The present version of this Technical Guideline does not recommend
// any other block ciphers besides AES" (2023, p. 24).
static SPECIFIED_SYMMETRIC_KEYS: Lazy<HashSet<Symmetric>> = Lazy::new(|| {
  let mut s = HashSet::new();
  s.insert(AES128);
  s.insert(AES192);
  s.insert(AES256);
  s
});

/// [`Standard`](crate::standard::Standard) implementation for the
/// [BSI TR-02102-1 Cryptographic Mechanisms: Recommendations and Key
/// Lengths] technical guide.
///
/// [BSI TR-02102-1 Cryptographic Mechanisms: Recommendations and Key Lengths]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html
pub struct Bsi;

impl Bsi {
  /// Validates a hash function. The reference is made with regards to
  /// applications that primarily require pre-image resistance such as
  /// message authentication codes (MACs), key derivation functions
  /// (KDFs), and random bit generation.
  ///
  /// For applications that require collision resistance such digital
  /// signatures use
  /// [`validate_hash`](crate::standard::bsi::Bsi::validate_hash).
  ///
  /// If the hash function is not compliant then `Err` will contain the
  /// recommended primitive that one should use instead.
  ///
  /// If the hash function is compliant but the context specifies a
  /// higher security level, `Ok` will also hold the recommended
  /// primitive with the desired security level.
  ///
  /// **Note:** For an HMAC the minimum security required is ≥ 128 (see
  /// p. 45) but the minimum digest length for a hash function that can
  /// be used with this primitive is 256 (see p. 41). This means any
  /// recommendation from this function will be likely too conservative.
  ///
  /// An alternative might also be suggested for a compliant hash
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
  /// use wardstone_core::primitive::hash::{SHA1, SHA256};
  /// use wardstone_core::standard::bsi::Bsi;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let hmac_sha1 = SHA1;
  /// let hmac_sha256 = SHA256;
  /// assert_eq!(Bsi::validate_hash_based(ctx, hmac_sha1), Err(hmac_sha256));
  /// ```
  pub fn validate_hash_based(ctx: Context, hash: Hash) -> Result<Hash, Hash> {
    if SPECIFIED_HASH_FUNCTIONS.contains(&hash) {
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
}

impl Standard for Bsi {
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
  /// **Note:** While the guide allows for elliptic curve system
  /// parameters "that are provided by a trustworthy authority"
  /// (see p. 73), this function conservatively deems any curve that is
  /// not explicitly stated as non-compliant. This means only the
  /// Brainpool and NIST curves that satisfy minimum security
  /// requirements are considered compliant.
  ///
  /// # Example
  ///
  /// The following illustrates a call to validate a compliant key.
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::ecc::BRAINPOOLP256R1;
  /// use wardstone_core::standard::bsi::Bsi;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Bsi::validate_ecc(ctx, BRAINPOOLP256R1), Ok(BRAINPOOLP256R1));
  /// ```
  fn validate_ecc(ctx: Context, key: Ecc) -> Result<Ecc, Ecc> {
    if SPECIFIED_CURVES.contains(&key) {
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
  /// use wardstone_core::primitive::ffc::{DSA_2048_224, DSA_3072_256};
  /// use wardstone_core::standard::bsi::Bsi;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let dsa_2048 = DSA_2048_224;
  /// let dsa_3072 = DSA_3072_256;
  /// assert_eq!(Bsi::validate_ffc(ctx, dsa_2048), Err(dsa_3072));
  /// ```
  fn validate_ffc(ctx: Context, key: Ffc) -> Result<Ffc, Ffc> {
    let security = ctx.security().max(key.security());
    match security {
      // Page 48 says q > 2²⁵⁰.
      ..=124 => Err(DSA_3072_256),
      125..=128 => Ok(DSA_3072_256),
      129..=192 => Ok(DSA_7680_384),
      193.. => Ok(DSA_15360_512),
    }
  }

  /// Validates a hash function according to page 41 of the guide. The
  /// reference is made with regards to applications that require
  /// collision resistance such as digital signatures.
  ///
  /// For applications that primarily require pre-image resistance such
  /// as message authentication codes (MACs), key derivation functions
  /// (KDFs), and random bit generation use
  /// [`validate_hash_based`](crate::standard::bsi::Bsi::validate_hash_based).
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
  /// use wardstone_core::standard::bsi::Bsi;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Bsi::validate_hash(ctx, SHA1), Err(SHA256));
  /// ```
  fn validate_hash(ctx: Context, hash: Hash) -> Result<Hash, Hash> {
    if SPECIFIED_HASH_FUNCTIONS.contains(&hash) {
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
  /// use wardstone_core::standard::bsi::Bsi;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Bsi::validate_ifc(ctx, RSA_PSS_2048), Ok(RSA_PSS_2048));
  /// ```
  fn validate_ifc(ctx: Context, key: Ifc) -> Result<Ifc, Ifc> {
    let security = ctx.security().max(key.security());
    match security {
      ..=111 => {
        if ctx.year() > CUTOFF_YEAR_RSA {
          Err(RSA_PSS_3072)
        } else {
          Err(RSA_PSS_2048)
        }
      },
      112..=127 => {
        if ctx.year() > CUTOFF_YEAR_RSA {
          Err(RSA_PSS_3072)
        } else {
          Ok(RSA_PSS_2048)
        }
      },
      128..=191 => Ok(RSA_PSS_3072),
      192..=255 => Ok(RSA_PSS_7680),
      256.. => Ok(RSA_PSS_15360),
    }
  }

  /// Validates a symmetric key primitive according to page 24 of the
  /// guide.
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
  /// DES key (which is not recommended by the guide).
  ///
  /// ```
  /// use wardstone_core::context::Context;
  /// use wardstone_core::primitive::symmetric::{AES128, TDEA3};
  /// use wardstone_core::standard::bsi::Bsi;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Bsi::validate_symmetric(ctx, TDEA3), Err(AES128));
  /// ```
  fn validate_symmetric(ctx: Context, key: Symmetric) -> Result<Symmetric, Symmetric> {
    if SPECIFIED_SYMMETRIC_KEYS.contains(&key) {
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
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{test_ecc, test_ffc, test_hash, test_hash_based, test_ifc, test_symmetric};

  test_ecc!(p224, Bsi, P224, Err(BRAINPOOLP256R1));
  test_ecc!(p256, Bsi, P256, Ok(BRAINPOOLP256R1));
  test_ecc!(p384, Bsi, P384, Ok(BRAINPOOLP384R1));
  test_ecc!(p521, Bsi, P521, Ok(BRAINPOOLP512R1));
  test_ecc!(x25519, Bsi, X25519, Err(BRAINPOOLP256R1));
  test_ecc!(x448, Bsi, X448, Err(BRAINPOOLP256R1));
  test_ecc!(ed25519, Bsi, ED25519, Err(BRAINPOOLP256R1));
  test_ecc!(ed448, Bsi, ED448, Err(BRAINPOOLP256R1));
  test_ecc!(brainpoolp224r1, Bsi, BRAINPOOLP224R1, Err(BRAINPOOLP256R1));
  test_ecc!(brainpoolp256r1, Bsi, BRAINPOOLP256R1, Ok(BRAINPOOLP256R1));
  test_ecc!(brainpoolp320r1, Bsi, BRAINPOOLP320R1, Ok(BRAINPOOLP320R1));
  test_ecc!(brainpoolp384r1, Bsi, BRAINPOOLP384R1, Ok(BRAINPOOLP384R1));
  test_ecc!(brainpoolp512r1, Bsi, BRAINPOOLP512R1, Ok(BRAINPOOLP512R1));
  test_ecc!(secp256k1, Bsi, SECP256K1, Err(BRAINPOOLP256R1));

  test_ffc!(ffc_1024_160, Bsi, DSA_1024_160, Err(DSA_3072_256));
  test_ffc!(ffc_2048_224, Bsi, DSA_2048_224, Err(DSA_3072_256));
  test_ffc!(ffc_3072_256, Bsi, DSA_3072_256, Ok(DSA_3072_256));
  test_ffc!(ffc_7680_384, Bsi, DSA_7680_384, Ok(DSA_7680_384));
  test_ffc!(ffc_15360_512, Bsi, DSA_15360_512, Ok(DSA_15360_512));

  test_ifc!(ifc_1024, Bsi, RSA_PSS_1024, Err(RSA_PSS_2048));
  test_ifc!(ifc_2048, Bsi, RSA_PSS_2048, Ok(RSA_PSS_2048));
  test_ifc!(ifc_3072, Bsi, RSA_PSS_3072, Ok(RSA_PSS_3072));
  test_ifc!(ifc_7680, Bsi, RSA_PSS_7680, Ok(RSA_PSS_7680));
  test_ifc!(ifc_15360, Bsi, RSA_PSS_15360, Ok(RSA_PSS_15360));

  test_hash!(
    blake2b_256_collision_resistance,
    Bsi,
    BLAKE2B_256,
    Err(SHA256)
  );
  test_hash!(
    blake2b_384_collision_resistance,
    Bsi,
    BLAKE2B_384,
    Err(SHA256)
  );
  test_hash!(
    blake2b_512_collision_resistance,
    Bsi,
    BLAKE2B_512,
    Err(SHA256)
  );
  test_hash!(
    blake2s_256_collision_resistance,
    Bsi,
    BLAKE2S_256,
    Err(SHA256)
  );
  test_hash!(md4_collision_resistance, Bsi, MD4, Err(SHA256));
  test_hash!(md5_collision_resistance, Bsi, MD5, Err(SHA256));
  test_hash!(ripemd160_collision_resistance, Bsi, RIPEMD160, Err(SHA256));
  test_hash!(sha1_collision_resistance, Bsi, SHA1, Err(SHA256));
  test_hash!(sha224_collision_resistance, Bsi, SHA224, Err(SHA256));
  test_hash!(sha256_collision_resistance, Bsi, SHA256, Ok(SHA256));
  test_hash!(sha384_collision_resistance, Bsi, SHA384, Ok(SHA384));
  test_hash!(sha3_224_collision_resistance, Bsi, SHA3_224, Err(SHA256));
  test_hash!(sha3_256_collision_resistance, Bsi, SHA3_256, Ok(SHA256));
  test_hash!(sha3_384_collision_resistance, Bsi, SHA3_384, Ok(SHA384));
  test_hash!(sha3_512_collision_resistance, Bsi, SHA3_512, Ok(SHA512));
  test_hash!(sha512_collision_resistance, Bsi, SHA512, Ok(SHA512));
  test_hash!(
    sha512_224_collision_resistance,
    Bsi,
    SHA512_224,
    Err(SHA256)
  );
  test_hash!(sha512_256_collision_resistance, Bsi, SHA512_256, Ok(SHA256));
  test_hash!(shake128_collision_resistance, Bsi, SHAKE128, Err(SHA256));
  test_hash!(shake256_collision_resistance, Bsi, SHAKE256, Err(SHA256));

  test_hash_based!(
    blake2b_256_pre_image_resistance,
    Bsi,
    BLAKE2B_256,
    Err(SHA256)
  );
  test_hash_based!(
    blake2b_384_pre_image_resistance,
    Bsi,
    BLAKE2B_384,
    Err(SHA256)
  );
  test_hash_based!(
    blake2b_512_pre_image_resistance,
    Bsi,
    BLAKE2B_512,
    Err(SHA256)
  );
  test_hash_based!(
    blake2s_256_pre_image_resistance,
    Bsi,
    BLAKE2S_256,
    Err(SHA256)
  );
  test_hash_based!(md4_pre_image_resistance, Bsi, MD4, Err(SHA256));
  test_hash_based!(md5_pre_image_resistance, Bsi, MD5, Err(SHA256));
  test_hash_based!(ripemd160_pre_image_resistance, Bsi, RIPEMD160, Err(SHA256));
  test_hash_based!(sha1_pre_image_resistance, Bsi, SHA1, Err(SHA256));
  test_hash_based!(sha224_pre_image_resistance, Bsi, SHA224, Err(SHA256));
  test_hash_based!(sha256_pre_image_resistance, Bsi, SHA256, Ok(SHA256));
  test_hash_based!(sha384_pre_image_resistance, Bsi, SHA384, Ok(SHA384));
  test_hash_based!(sha3_224_pre_image_resistance, Bsi, SHA3_224, Err(SHA256));
  test_hash_based!(sha3_256_pre_image_resistance, Bsi, SHA3_256, Ok(SHA256));
  test_hash_based!(sha3_384_pre_image_resistance, Bsi, SHA3_384, Ok(SHA384));
  test_hash_based!(sha3_512_pre_image_resistance, Bsi, SHA3_512, Ok(SHA512));
  test_hash_based!(sha512_pre_image_resistance, Bsi, SHA512, Ok(SHA512));
  test_hash_based!(
    sha512_224_pre_image_resistance,
    Bsi,
    SHA512_224,
    Err(SHA256)
  );
  test_hash_based!(sha512_256_pre_image_resistance, Bsi, SHA512_256, Ok(SHA256));
  test_hash_based!(shake128_pre_image_resistance, Bsi, SHAKE128, Err(SHA256));
  test_hash_based!(shake256_pre_image_resistance, Bsi, SHAKE256, Err(SHA256));

  test_symmetric!(two_key_tdea, Bsi, TDEA2, Err(AES128));
  test_symmetric!(three_key_tdea, Bsi, TDEA3, Err(AES128));
  test_symmetric!(aes128, Bsi, AES128, Ok(AES128));
  test_symmetric!(aes192, Bsi, AES192, Ok(AES192));
  test_symmetric!(aes256, Bsi, AES256, Ok(AES256));
}
