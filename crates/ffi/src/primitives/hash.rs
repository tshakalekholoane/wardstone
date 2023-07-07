//! Specifies a hash or hash-based cryptography primitive and a set of
//! commonly used instances.
use wardstone_core::primitives::hash::*;

/// The BLAKE-224 hash function.
#[no_mangle]
pub static WS_BLAKE_224: Hash = BLAKE_224;

/// The BLAKE-256 hash function.
#[no_mangle]
pub static WS_BLAKE_256: Hash = BLAKE_256;

/// The BLAKE-384 hash function.
#[no_mangle]
pub static WS_BLAKE_384: Hash = BLAKE_384;

/// The BLAKE-512 hash function.
#[no_mangle]
pub static WS_BLAKE_512: Hash = BLAKE_512;

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static WS_BLAKE2B_256: Hash = BLAKE2B_256;

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static WS_BLAKE2B_384: Hash = BLAKE2B_384;

/// The BLAKE2b hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static WS_BLAKE2B_512: Hash = BLAKE2B_512;

/// The BLAKE2s hash function as defined in [RFC 7693].
///
/// [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693.html
#[no_mangle]
pub static WS_BLAKE2S_256: Hash = BLAKE2S_256;

/// The BLAKE3 hash function.
#[no_mangle]
pub static WS_BLAKE3: Hash = BLAKE3;

/// The MD4 hash function as defined in [RFC 1320].
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
///
/// [RFC 1320]: https://www.rfc-editor.org/rfc/rfc1320.html
#[no_mangle]
pub static WS_MD4: Hash = MD4;

/// The MD5 hash function as defined in [RFC 1321].
///
/// **Warning:** This algorithm has been shown to lack collision
/// resistance and should generally not be used for secure applications.
///
/// [RFC 1321]: https://www.rfc-editor.org/rfc/rfc1321.html
#[no_mangle]
pub static WS_MD5: Hash = MD5;

/// The RIPEMD-160 hash function.
///
/// **Warning:** This algorithm has been shown to be broken. It should
/// only be used where compatibility with legacy systems, not security,
/// is the goal.
#[no_mangle]
pub static WS_RIPEMD160: Hash = RIPEMD160;

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
pub static WS_SHA1: Hash = SHA1;

/// The SHA224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static WS_SHA224: Hash = SHA224;

/// The SHA256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static WS_SHA256: Hash = SHA256;

/// The SHA384 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static WS_SHA384: Hash = SHA384;

/// The SHA3-224 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static WS_SHA3_224: Hash = SHA3_224;

/// The SHA3-256 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static WS_SHA3_256: Hash = SHA3_256;

/// The SHA3-384 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static WS_SHA3_384: Hash = SHA3_384;

/// The SHA3-512 hash function as defined in [FIPS 202].
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static WS_SHA3_512: Hash = SHA3_512;

/// The SHA512 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static WS_SHA512: Hash = SHA512;

/// The SHA512/224 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static WS_SHA512_224: Hash = SHA512_224;

/// The SHA512/256 hash function as defined in [FIPS 180-4].
///
/// [FIPS 180-4]: https://doi.org/10.6028/NIST.FIPS.180-4
#[no_mangle]
pub static WS_SHA512_256: Hash = SHA512_256;

/// The SHAKE128 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 128-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static WS_SHAKE128: Hash = SHAKE128;

/// The SHAKE256 extendable-output function as defined in [FIPS 202].
/// This assumes an output length of 256-bits.
///
/// [FIPS 202]: https://doi.org/10.6028/NIST.FIPS.202
#[no_mangle]
pub static WS_SHAKE256: Hash = SHAKE256;

/// The WHIRLPOOL hash function as defined in ISO/IEC 10118-3.
#[no_mangle]
pub static WS_WHIRLPOOL: Hash = WHIRLPOOL;
