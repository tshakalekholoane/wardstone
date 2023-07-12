//! Specifies a symmetric key cryptography primitive and a set of
//! commonly used instances.
use wardstone_core::primitive::symmetric::Symmetric;
use wardstone_core::standard::instances::symmetric::*;

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static WS_AES128: Symmetric = AES128;

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static WS_AES192: Symmetric = AES192;

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static WS_AES256: Symmetric = AES256;

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static WS_CAMELLIA128: Symmetric = CAMELLIA128;

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static WS_CAMELLIA192: Symmetric = CAMELLIA192;

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static WS_CAMELLIA256: Symmetric = CAMELLIA256;

/// The Data Encryption Standard algorithm.
#[no_mangle]
pub static WS_DES: Symmetric = DES;

/// The DES-X encryption algorithm.
#[no_mangle]
pub static WS_DESX: Symmetric = DESX;

/// The International Data Encryption algorithm.
#[no_mangle]
pub static WS_IDEA: Symmetric = IDEA;

/// The Serpent encryption algorithm.
#[no_mangle]
pub static WS_SERPENT128: Symmetric = SERPENT128;

/// The Serpent encryption algorithm.
#[no_mangle]
pub static WS_SERPENT192: Symmetric = SERPENT192;

/// The Serpent encryption algorithm.
#[no_mangle]
pub static WS_SERPENT256: Symmetric = SERPENT256;

/// The two-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static WS_TDEA2: Symmetric = TDEA2;

/// The three-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static WS_TDEA3: Symmetric = TDEA3;
