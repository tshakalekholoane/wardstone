//! Hash function primitive and some common instances.
use core::fmt;
use std::ffi::CStr;

use crate::primitive::{Primitive, Security};

/// Represents a hash or hash-based function cryptographic primitive
/// where `id` is a unique identifier and `n` the digest length.
#[repr(C)]
#[derive(Clone, Debug, Hash)]
pub struct Hash {
  pub id: u16,
  pub n: u16,
  pub name: &'static CStr,
}

impl Hash {
  pub const fn new(id: u16, n: u16, name: &'static [u8]) -> Self {
    Self {
      id,
      n,
      name: unsafe { CStr::from_bytes_with_nul_unchecked(name) },
    }
  }
}

impl Primitive for Hash {
  /// Returns the security of a hash function measured as the collision
  /// resistance strength of a hash function.
  ///
  /// For an L-bit hash function, the expected security strength for
  /// collision resistance is L/2 bits (see page 6 of NIST SP-800-107).
  ///
  /// Some applications that use hash functions only require pre-image
  /// resistance which imposes a less stringent security requirement of
  /// just L (see page 7 of NIST SP-800-107).
  fn security(&self) -> Security {
    self.n >> 1
  }
}

impl fmt::Display for Hash {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}", &self.name.to_string_lossy())
  }
}

impl PartialEq for Hash {
  fn eq(&self, other: &Self) -> bool {
    self.id == other.id
  }
}

impl Eq for Hash {}

/// The BLAKE-224 hash function.
#[no_mangle]
pub static BLAKE_224: Hash = Hash::new(1, 224, b"blake224\0");

/// The BLAKE-256 hash function.
#[no_mangle]
pub static BLAKE_256: Hash = Hash::new(2, 256, b"blake256\0");

/// The BLAKE-384 hash function.
#[no_mangle]
pub static BLAKE_384: Hash = Hash::new(3, 384, b"blake384\0");

/// The BLAKE-512 hash function.
#[no_mangle]
pub static BLAKE_512: Hash = Hash::new(4, 512, b"blake512\0");

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_256: Hash = Hash::new(5, 256, b"blake2b256\0");

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_384: Hash = Hash::new(6, 384, b"blake2b384\0");

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_512: Hash = Hash::new(7, 512, b"blake2b512\0");

/// The BLAKE2s hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2S_256: Hash = Hash::new(8, 256, b"blake2s256\0");

/// The BLAKE3 hash function.
#[no_mangle]
pub static BLAKE3: Hash = Hash::new(9, 256, b"blake3\0");

/// The MD4 hash function as defined in [RFC 1320].
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
///
/// [RFC 1320]: https://www.rfc-editor.org/rfc/rfc1320.html
#[no_mangle]
pub static MD4: Hash = Hash::new(10, 128, b"md4\0");

/// The MD5 hash function as defined in [RFC 1321].
///
/// **Warning:** This algorithm has been shown to lack collision
/// resistance and should generally not be used for secure applications.
///
/// [RFC 1321]: https://www.rfc-editor.org/rfc/rfc1321.html
#[no_mangle]
pub static MD5: Hash = Hash::new(11, 128, b"md5\0");

/// The RIPEMD-160 hash function.
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
#[no_mangle]
pub static RIPEMD160: Hash = Hash::new(12, 160, b"ripemd160\0");

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
pub static SHA1: Hash = Hash::new(13, 160, b"sha1\0");

/// The SHA224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA224: Hash = Hash::new(14, 224, b"sha224\0");

/// The SHA256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA256: Hash = Hash::new(15, 256, b"sha256\0");

/// The SHA384 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA384: Hash = Hash::new(16, 384, b"sha384\0");

/// The SHA3-224 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_224: Hash = Hash::new(17, 224, b"sha3-224\0");

/// The SHA3-256 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_256: Hash = Hash::new(18, 256, b"sha3-256\0");

/// The SHA3-384 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_384: Hash = Hash::new(19, 384, b"sha3-384\0");

/// The SHA3-512 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_512: Hash = Hash::new(20, 512, b"sha3-512\0");

/// The SHA512 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512: Hash = Hash::new(21, 512, b"sha512\0");

/// The SHA512/224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_224: Hash = Hash::new(22, 224, b"sha512/224\0");

/// The SHA512/256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_256: Hash = Hash::new(23, 256, b"sha512/256\0");

/// The SHAKE128 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 128-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE128: Hash = Hash::new(24, 128, b"shake128\0");

/// The SHAKE256 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 256-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE256: Hash = Hash::new(25, 256, b"shake256\0");

/// The WHIRLPOOL hash function as defined in ISO/IEC 10118-3.
#[no_mangle]
pub static WHIRLPOOL: Hash = Hash::new(26, 512, b"whirlpool\0");

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static HASH_NOT_SUPPORTED: Hash = Hash::new(u16::MAX, u16::MAX, b"not supported\0");
