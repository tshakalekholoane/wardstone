//! Specifies a set of commonly used symmetric key cryptography
//! primitives.
use crate::symmetric::Symmetric;

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES128: Symmetric = Symmetric {
  id: 1,
  security: 128,
};

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES192: Symmetric = Symmetric {
  id: 2,
  security: 192,
};

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES256: Symmetric = Symmetric {
  id: 3,
  security: 256,
};

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static CAMELLIA128: Symmetric = Symmetric {
  id: 4,
  security: 128,
};

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static CAMELLIA192: Symmetric = Symmetric {
  id: 5,
  security: 192,
};

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static CAMELLIA256: Symmetric = Symmetric {
  id: 6,
  security: 256,
};

/// The Data Encryption Standard algorithm.
#[no_mangle]
pub static DES: Symmetric = Symmetric {
  id: 8,
  security: 56,
};

/// The DES-X encryption algorithm.
#[no_mangle]
pub static DESX: Symmetric = Symmetric {
  id: 9,
  security: 120,
};

/// The International Data Encryption algorithm.
#[no_mangle]
pub static IDEA: Symmetric = Symmetric {
  id: 10,
  security: 126, /* See Wikipedia article. */
};

/// The Serpent encryption algorithm.
#[no_mangle]
pub static SERPENT128: Symmetric = Symmetric {
  id: 11,
  security: 128,
};

/// The Serpent encryption algorithm.
#[no_mangle]
pub static SERPENT192: Symmetric = Symmetric {
  id: 12,
  security: 192,
};

/// The Serpent encryption algorithm.
#[no_mangle]
pub static SERPENT256: Symmetric = Symmetric {
  id: 13,
  security: 256,
};

/// The two-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static TDEA2: Symmetric = Symmetric {
  id: 14,
  security: 95,
};

/// The three-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static TDEA3: Symmetric = Symmetric {
  id: 15,
  security: 112,
};
