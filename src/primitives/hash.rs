/// Represents a hash or hash-based function cryptographic primitive
/// where `id` is a unique identifier and `n` the output length i.e.
/// digest length if it is a hash function or the length of
/// authentication tag if it is a message authentication code.
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Hash {
  pub id: u16,
  pub n: u16,
}

/// The BLAKE2b hash function as defined by [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2b_256: Hash = Hash { id: 1, n: 256 };

/// The BLAKE2b hash function as defined by [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2b_384: Hash = Hash { id: 2, n: 384 };

/// The BLAKE2b hash function as defined by [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2b_512: Hash = Hash { id: 3, n: 512 };

/// The BLAKE2s hash function as defined by [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static BLAKE2s_256: Hash = Hash { id: 4, n: 256 };

/// The MD4 hash function as defined in [RFC 1320].
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
///
/// [RFC 1320]: https://www.rfc-editor.org/rfc/rfc1320.html
#[no_mangle]
pub static MD4: Hash = Hash { id: 5, n: 128 };

/// The MD5 hash function as defined in [RFC 1321].
///
/// **Warning:** This algorithm has been shown to lack collision
/// resistance and should generally not be used for secure applications.
///
/// [RFC 1321]: https://www.rfc-editor.org/rfc/rfc1321.html
#[no_mangle]
pub static MD5: Hash = Hash { id: 6, n: 128 };

/// The RIPEMD-160 hash function.
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
#[no_mangle]
pub static RIPEMD160: Hash = Hash { id: 7, n: 160 };

/// The SHA1 hash function as defined in [RFC 3174].
///
/// **Warning:** This algorithm has been shown to lack collision
/// resistance and should generally not be used for secure applications.
///
/// [RFC 1321]: https://www.rfc-editor.org/rfc/rfc3174.html
#[no_mangle]
pub static SHA1: Hash = Hash { id: 8, n: 160 };

/// The SHA224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA224: Hash = Hash { id: 9, n: 224 };

/// The SHA256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA256: Hash = Hash { id: 10, n: 256 };

/// The SHA384 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA384: Hash = Hash { id: 11, n: 384 };

/// The SHA3-224 hash function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_224: Hash = Hash { id: 12, n: 224 };

/// The SHA3-256 hash function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_256: Hash = Hash { id: 13, n: 256 };

/// The SHA3-384 hash function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_384: Hash = Hash { id: 14, n: 384 };

/// The SHA3-512 hash function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_512: Hash = Hash { id: 15, n: 512 };

/// The SHA3-512/224 hash function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_512_224: Hash = Hash { id: 16, n: 224 };

/// The SHA3-512/256 hash function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHA3_512_256: Hash = Hash { id: 17, n: 256 };

/// The SHA512 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512: Hash = Hash { id: 18, n: 512 };

/// The SHA512/224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_224: Hash = Hash { id: 19, n: 224 };

/// The SHA512/256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static SHA512_256: Hash = Hash { id: 20, n: 256 };

/// The SHAKE128 extendable-output function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE128: Hash = Hash { id: 21, n: 128 };

/// The SHAKE256 extendable-output function as defined in [FIPS 202].
///
/// [FIPS]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static SHAKE256: Hash = Hash { id: 21, n: 256 };
