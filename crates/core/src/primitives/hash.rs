//! Specifies a hash or hash-based cryptography primitive and a set of
//! commonly used instances.

/// Represents a hash or hash-based function cryptographic primitive
/// where `id` is a unique identifier and `n` the digest length.
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Hash {
  pub id: u16,
  pub n: u16,
}

impl Hash {
  /// Returns the collision resistance strength of a hash function.
  ///
  /// For an L-bit hash function, the expected security strength for
  /// collision resistance is L/2 bits. See page 6 of NIST SP-800-107
  /// for details.
  pub fn collision_resistance(&self) -> u16 {
    self.n >> 1
  }

  /// Returns the pre-image resistance strength of a hash function.
  ///
  /// For an L-bit hash function, the expected security strength for
  /// pre-image resistance is L bits. See page 7 of NIST SP-800-107 for
  /// details.
  pub fn pre_image_resistance(&self) -> u16 {
    self.n
  }
}

/// The BLAKE-224 hash function.
#[no_mangle]
pub static BLAKE_224: Hash = Hash { id: 1, n: 224 };

/// The BLAKE-256 hash function.
#[no_mangle]
pub static BLAKE_256: Hash = Hash { id: 2, n: 256 };

/// The BLAKE-384 hash function.
#[no_mangle]
pub static BLAKE_384: Hash = Hash { id: 3, n: 384 };

/// The BLAKE-512 hash function.
#[no_mangle]
pub static BLAKE_512: Hash = Hash { id: 4, n: 512 };

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_256: Hash = Hash { id: 5, n: 256 };

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_384: Hash = Hash { id: 6, n: 384 };

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_512: Hash = Hash { id: 7, n: 512 };

/// The BLAKE2s hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2S_256: Hash = Hash { id: 8, n: 256 };

/// The BLAKE3 hash function.
#[no_mangle]
pub static BLAKE3: Hash = Hash { id: 9, n: 256 };

/// The MD4 hash function as defined in [RFC 1320].
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
///
/// [RFC 1320]: https://www.rfc-editor.org/rfc/rfc1320.html
#[no_mangle]
pub static MD4: Hash = Hash { id: 10, n: 128 };

/// The MD5 hash function as defined in [RFC 1321].
///
/// **Warning:** This algorithm has been shown to lack collision
/// resistance and should generally not be used for secure applications.
///
/// [RFC 1321]: https://www.rfc-editor.org/rfc/rfc1321.html
#[no_mangle]
pub static MD5: Hash = Hash { id: 11, n: 128 };

/// The RIPEMD-160 hash function.
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
#[no_mangle]
pub static RIPEMD160: Hash = Hash { id: 12, n: 160 };

/// The SHA1 hash function as defined in [RFC 3174].
///
/// **Warning:** This algorithm has been shown to lack collision
/// resistance and should generally not be used for secure applications.
///
/// While this algorithm produced a digest length of 160 bits, it's
/// security is believed to be lower. Here it is recorded to be 105 per
/// page 8 of NIST SP 800-107.
///
/// [RFC 3174]: https://www.rfc-editor.org/rfc/rfc3174.html
#[no_mangle]
pub static SHA1: Hash = Hash { id: 13, n: 105 };

/// The SHA224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA224: Hash = Hash { id: 14, n: 224 };

/// The SHA256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA256: Hash = Hash { id: 15, n: 256 };

/// The SHA384 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA384: Hash = Hash { id: 16, n: 384 };

/// The SHA3-224 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_224: Hash = Hash { id: 17, n: 224 };

/// The SHA3-256 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_256: Hash = Hash { id: 18, n: 256 };

/// The SHA3-384 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_384: Hash = Hash { id: 19, n: 384 };

/// The SHA3-512 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_512: Hash = Hash { id: 20, n: 512 };

/// The SHA512 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512: Hash = Hash { id: 21, n: 512 };

/// The SHA512/224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_224: Hash = Hash { id: 22, n: 224 };

/// The SHA512/256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_256: Hash = Hash { id: 23, n: 256 };

/// The SHAKE128 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 128-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE128: Hash = Hash { id: 24, n: 128 };

/// The SHAKE256 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 256-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE256: Hash = Hash { id: 25, n: 256 };

/// The WHIRLPOOL hash function as defined in ISO/IEC 10118-3.
#[no_mangle]
pub static WHIRLPOOL: Hash = Hash { id: 26, n: 512 };
