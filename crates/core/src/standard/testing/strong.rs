//! A mock standard with a minimum security requirement of at least
//! 256-bits.
//!
//! This is the level of security estimated to be enough to resist an
//! attack using Grover's algorithm enabled by quantum computers which
//! as of writing does not appear to be a practical concern. However,
//! bumping the security parameter may not be enough for some signature
//! schemes such as those that use elliptic curves.
use crate::context::Context;
use crate::primitive::ecc::*;
use crate::primitive::ffc::*;
use crate::primitive::hash::*;
use crate::primitive::ifc::*;
use crate::primitive::symmetric::*;
use crate::primitive::Primitive;
use crate::standard::Standard;

/// [`Standard`](crate::standard::Standard) implementation of a mock
/// standard that is intended to be relatively strong compared to all
/// the other standards defined in this crate.
pub struct Strong;

impl Standard for Strong {
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
  /// use wardstone_core::primitive::ecc::{ECC_NOT_SUPPORTED, ED25519};
  /// use wardstone_core::standard::testing::strong::Strong;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(
  ///   Strong::validate_ecc(&ctx, &ED25519),
  ///   Err(&ECC_NOT_SUPPORTED)
  /// );
  /// ```
  fn validate_ecc(_ctx: &Context, _key: &Ecc) -> Result<&'static Ecc, &'static Ecc> {
    Err(&ECC_NOT_SUPPORTED)
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
  /// use wardstone_core::primitive::ffc::{FFC_2048_224, FFC_NOT_SUPPORTED};
  /// use wardstone_core::standard::testing::strong::Strong;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let dsa_2048 = &FFC_2048_224;
  /// assert_eq!(
  ///   Strong::validate_ffc(&ctx, dsa_2048),
  ///   Err(&FFC_NOT_SUPPORTED)
  /// );
  /// ```
  fn validate_ffc(_ctx: &Context, _key: &Ffc) -> Result<&'static Ffc, &'static Ffc> {
    Err(&FFC_NOT_SUPPORTED)
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
  /// use wardstone_core::primitive::hash::{SHA256, SHA512};
  /// use wardstone_core::standard::testing::strong::Strong;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Strong::validate_hash(&ctx, &SHA256), Err(&SHA512));
  /// ```
  fn validate_hash(ctx: &Context, hash: &Hash) -> Result<&'static Hash, &'static Hash> {
    let security = ctx.security().max(hash.security());
    match security {
      ..=255 => Err(&SHA512),
      256.. => Ok(&SHA512),
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
  /// use wardstone_core::primitive::ifc::{IFC_2048, IFC_NOT_SUPPORTED};
  /// use wardstone_core::standard::testing::strong::Strong;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// let rsa_2048 = &IFC_2048;
  /// assert_eq!(
  ///   Strong::validate_ifc(&ctx, rsa_2048),
  ///   Err(&IFC_NOT_SUPPORTED)
  /// );
  /// ```
  fn validate_ifc(_ctx: &Context, _key: &Ifc) -> Result<&'static Ifc, &'static Ifc> {
    Err(&IFC_NOT_SUPPORTED)
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
  /// use wardstone_core::primitive::symmetric::{AES256, TDEA3};
  /// use wardstone_core::standard::testing::strong::Strong;
  /// use wardstone_core::standard::Standard;
  ///
  /// let ctx = Context::default();
  /// assert_eq!(Strong::validate_symmetric(&ctx, &TDEA3), Err(&AES256));
  /// ```
  fn validate_symmetric(
    ctx: &Context,
    key: &Symmetric,
  ) -> Result<&'static Symmetric, &'static Symmetric> {
    let security = ctx.security().max(key.security());
    match security {
      ..=255 => Err(&AES256),
      256.. => Ok(&AES256),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{test_ecc, test_ffc, test_hash, test_ifc, test_symmetric};

  test_ecc!(p224, Strong, &P224, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(p256, Strong, &P256, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(p384, Strong, &P384, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(p521, Strong, &P521, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(ed25519, Strong, &ED25519, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(ed448, Strong, &ED448, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(x25519, Strong, &X25519, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(x488, Strong, &X448, Err(&ECC_NOT_SUPPORTED));
  test_ecc!(
    brainpoolp224r1,
    Strong,
    &BRAINPOOLP224R1,
    Err(&ECC_NOT_SUPPORTED)
  );
  test_ecc!(
    brainpoolp256r1,
    Strong,
    &BRAINPOOLP256R1,
    Err(&ECC_NOT_SUPPORTED)
  );
  test_ecc!(
    brainpoolp320r1,
    Strong,
    &BRAINPOOLP320R1,
    Err(&ECC_NOT_SUPPORTED)
  );
  test_ecc!(
    brainpoolp384r1,
    Strong,
    &BRAINPOOLP384R1,
    Err(&ECC_NOT_SUPPORTED)
  );
  test_ecc!(
    brainpoolp512r1,
    Strong,
    &BRAINPOOLP512R1,
    Err(&ECC_NOT_SUPPORTED)
  );
  test_ecc!(secp256k1, Strong, &SECP256K1, Err(&ECC_NOT_SUPPORTED));

  test_ffc!(ffc_1024_160, Strong, &FFC_1024_160, Err(&FFC_NOT_SUPPORTED));
  test_ffc!(ffc_2048_224, Strong, &FFC_2048_224, Err(&FFC_NOT_SUPPORTED));
  test_ffc!(ffc_3072_256, Strong, &FFC_3072_256, Err(&FFC_NOT_SUPPORTED));
  test_ffc!(ffc_7680_384, Strong, &FFC_7680_384, Err(&FFC_NOT_SUPPORTED));
  test_ffc!(
    ffc_15360_512,
    Strong,
    &FFC_15360_512,
    Err(&FFC_NOT_SUPPORTED)
  );

  test_ifc!(ifc_1024, Strong, &IFC_1024, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_1280, Strong, &IFC_1280, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_1536, Strong, &IFC_1536, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_2048, Strong, &IFC_2048, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_3072, Strong, &IFC_3072, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_4096, Strong, &IFC_4096, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_7680, Strong, &IFC_7680, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_8192, Strong, &IFC_8192, Err(&IFC_NOT_SUPPORTED));
  test_ifc!(ifc_15360, Strong, &IFC_15360, Err(&IFC_NOT_SUPPORTED));

  test_hash!(blake_224, Strong, &BLAKE_224, Err(&SHA512));
  test_hash!(blake_256, Strong, &BLAKE_256, Err(&SHA512));
  test_hash!(blake_384, Strong, &BLAKE_384, Err(&SHA512));
  test_hash!(blake_512, Strong, &BLAKE_512, Ok(&SHA512));
  test_hash!(blake2b_256, Strong, &BLAKE2B_256, Err(&SHA512));
  test_hash!(blake2b_384, Strong, &BLAKE2B_384, Err(&SHA512));
  test_hash!(blake2b_512, Strong, &BLAKE2B_512, Ok(&SHA512));
  test_hash!(blake2s_256, Strong, &BLAKE2S_256, Err(&SHA512));
  test_hash!(md4, Strong, &MD4, Err(&SHA512));
  test_hash!(md5, Strong, &MD5, Err(&SHA512));
  test_hash!(ripemd160, Strong, &RIPEMD160, Err(&SHA512));
  test_hash!(sha1, Strong, &SHA1, Err(&SHA512));
  test_hash!(sha224, Strong, &SHA224, Err(&SHA512));
  test_hash!(sha256, Strong, &SHA256, Err(&SHA512));
  test_hash!(sha384, Strong, &SHA384, Err(&SHA512));
  test_hash!(sha3_224, Strong, &SHA3_224, Err(&SHA512));
  test_hash!(sha3_256, Strong, &SHA3_256, Err(&SHA512));
  test_hash!(sha3_384, Strong, &SHA3_384, Err(&SHA512));
  test_hash!(sha3_512, Strong, &SHA3_512, Ok(&SHA512));
  test_hash!(sha512, Strong, &SHA512, Ok(&SHA512));
  test_hash!(sha512_224, Strong, &SHA512_224, Err(&SHA512));
  test_hash!(sha512_256, Strong, &SHA512_256, Err(&SHA512));
  test_hash!(shake128, Strong, &SHAKE128, Err(&SHA512));
  test_hash!(shake256, Strong, &SHAKE256, Err(&SHA512));
  test_hash!(whirlpool, Strong, &WHIRLPOOL, Ok(&SHA512));

  test_symmetric!(aes128, Strong, &AES128, Err(&AES256));
  test_symmetric!(aes192, Strong, &AES192, Err(&AES256));
  test_symmetric!(aes256, Strong, &AES256, Ok(&AES256));
  test_symmetric!(camellia128, Strong, &CAMELLIA128, Err(&AES256));
  test_symmetric!(camellia192, Strong, &CAMELLIA192, Err(&AES256));
  test_symmetric!(camellia256, Strong, &CAMELLIA256, Ok(&AES256));
  test_symmetric!(des, Strong, &DES, Err(&AES256));
  test_symmetric!(desx, Strong, &DESX, Err(&AES256));
  test_symmetric!(idea, Strong, &IDEA, Err(&AES256));
  test_symmetric!(serpent128, Strong, &SERPENT128, Err(&AES256));
  test_symmetric!(serpent192, Strong, &SERPENT192, Err(&AES256));
  test_symmetric!(serpent256, Strong, &SERPENT256, Ok(&AES256));
  test_symmetric!(three_key_tdea, Strong, &TDEA3, Err(&AES256));
  test_symmetric!(two_key_tdea, Strong, &TDEA2, Err(&AES256));
}
