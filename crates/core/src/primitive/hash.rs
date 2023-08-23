//! Hash function primitive and some common instances.
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};

use once_cell::sync::Lazy;
use serde::Serialize;

use crate::primitive::{Primitive, Security};

/// Represents a hash or hash-based function cryptographic primitive
/// where `id` is a unique identifier and `n` the digest length.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Hash {
  pub id: u16,
  pub n: u16,
}

impl Hash {
  pub const fn new(id: u16, n: u16) -> Self {
    Self { id, n }
  }
}

// The name is kept in a lookup table instead of being embedded in the
// type because sharing strings across language boundaries is a bit
// dicey.
static REPR: Lazy<HashMap<Hash, &str>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert(BLAKE_224, "blake224");
  m.insert(BLAKE_256, "blake256");
  m.insert(BLAKE_384, "blake384");
  m.insert(BLAKE_512, "blake512");
  m.insert(BLAKE2B_256, "blake2b256");
  m.insert(BLAKE2B_384, "blake2b384");
  m.insert(BLAKE2B_512, "blake2b512");
  m.insert(BLAKE2S_256, "blake2s256");
  m.insert(BLAKE3, "blake3");
  m.insert(MD4, "md4");
  m.insert(MD5, "md5");
  m.insert(RIPEMD160, "ripemd160");
  m.insert(SHA1, "sha1");
  m.insert(SHA224, "sha224");
  m.insert(SHA256, "sha256");
  m.insert(SHA384, "sha384");
  m.insert(SHA512, "sha512");
  m.insert(SHA3_224, "sha3_224");
  m.insert(SHA3_256, "sha3_256");
  m.insert(SHA3_384, "sha3_384");
  m.insert(SHA3_512, "sha3_512");
  m.insert(SHA512_224, "sha512/224");
  m.insert(SHA512_256, "sha512/256");
  m.insert(SHAKE128, "shake128");
  m.insert(SHAKE256, "shake256");
  m.insert(WHIRLPOOL, "whirlpool");
  m
});

impl Display for Hash {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    let unrecognised = "unrecognised";
    let name = REPR.get(self).unwrap_or(&unrecognised);
    write!(f, "{name}")
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

impl Serialize for Hash {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let s = format!("{}", self);
    serializer.serialize_str(&s)
  }
}

/// The BLAKE-224 hash function.
#[no_mangle]
pub static BLAKE_224: Hash = Hash::new(1, 224);

/// The BLAKE-256 hash function.
#[no_mangle]
pub static BLAKE_256: Hash = Hash::new(2, 256);

/// The BLAKE-384 hash function.
#[no_mangle]
pub static BLAKE_384: Hash = Hash::new(3, 384);

/// The BLAKE-512 hash function.
#[no_mangle]
pub static BLAKE_512: Hash = Hash::new(4, 512);

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_256: Hash = Hash::new(5, 256);

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_384: Hash = Hash::new(6, 384);

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2B_512: Hash = Hash::new(7, 512);

/// The BLAKE2s hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2S_256: Hash = Hash::new(8, 256);

/// The BLAKE3 hash function.
#[no_mangle]
pub static BLAKE3: Hash = Hash::new(9, 256);

/// The MD4 hash function as defined in [RFC 1320].
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
///
/// [RFC 1320]: https://www.rfc-editor.org/rfc/rfc1320.html
#[no_mangle]
pub static MD4: Hash = Hash::new(10, 128);

/// The MD5 hash function as defined in [RFC 1321].
///
/// **Warning:** This algorithm has been shown to lack collision
/// resistance and should generally not be used for secure applications.
///
/// [RFC 1321]: https://www.rfc-editor.org/rfc/rfc1321.html
#[no_mangle]
pub static MD5: Hash = Hash::new(11, 128);

/// The RIPEMD-160 hash function.
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
#[no_mangle]
pub static RIPEMD160: Hash = Hash::new(12, 160);

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
pub static SHA1: Hash = Hash::new(13, 160);

/// The SHA224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA224: Hash = Hash::new(14, 224);

/// The SHA256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA256: Hash = Hash::new(15, 256);

/// The SHA384 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA384: Hash = Hash::new(16, 384);

/// The SHA3-224 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_224: Hash = Hash::new(17, 224);

/// The SHA3-256 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_256: Hash = Hash::new(18, 256);

/// The SHA3-384 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_384: Hash = Hash::new(19, 384);

/// The SHA3-512 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_512: Hash = Hash::new(20, 512);

/// The SHA512 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512: Hash = Hash::new(21, 512);

/// The SHA512/224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_224: Hash = Hash::new(22, 224);

/// The SHA512/256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_256: Hash = Hash::new(23, 256);

/// The SHAKE128 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 128-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE128: Hash = Hash::new(24, 128);

/// The SHAKE256 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 256-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE256: Hash = Hash::new(25, 256);

/// The WHIRLPOOL hash function as defined in ISO/IEC 10118-3.
#[no_mangle]
pub static WHIRLPOOL: Hash = Hash::new(26, 512);

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static HASH_NOT_SUPPORTED: Hash = Hash::new(u16::MAX, u16::MAX);
