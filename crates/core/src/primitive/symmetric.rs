//! Symmetric key primitive and some common instances.
use crate::primitive::{Primitive, Security};

/// Represents a symmetric key cryptography primitive.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Symmetric {
  pub id: u16,
  pub security: u16,
}

impl Symmetric {
  pub const fn new(id: u16, security: u16) -> Self {
    Self { id, security }
  }
}

impl Primitive for Symmetric {
  /// Indicates the security provided by a symmetric key primitive.
  fn security(&self) -> Security {
    self.security
  }
}

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES128: Symmetric = Symmetric::new(1, 128);

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES192: Symmetric = Symmetric::new(2, 192);

/// The Advanced Encryption Standard algorithm as defined in [FIPS 197].
///
/// [FIPS 197]: https://doi.org/10.6028/NIST.FIPS.197
#[no_mangle]
pub static AES256: Symmetric = Symmetric::new(3, 256);

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static CAMELLIA128: Symmetric = Symmetric::new(4, 128);

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static CAMELLIA192: Symmetric = Symmetric::new(5, 192);

/// The Camellia encryption algorithm as defined in [RFC 3713].
///
/// [RFC 3713]: https://datatracker.ietf.org/doc/html/rfc3713
#[no_mangle]
pub static CAMELLIA256: Symmetric = Symmetric::new(6, 256);

/// The Data Encryption Standard algorithm.
#[no_mangle]
pub static DES: Symmetric = Symmetric::new(8, 56);

/// The DES-X encryption algorithm.
#[no_mangle]
pub static DESX: Symmetric = Symmetric::new(9, 120);

/// The International Data Encryption algorithm.
#[no_mangle]
pub static IDEA: Symmetric = Symmetric::new(10, 126 /* See Wikipedia article. */);

/// The Serpent encryption algorithm.
#[no_mangle]
pub static SERPENT128: Symmetric = Symmetric::new(11, 128);

/// The Serpent encryption algorithm.
#[no_mangle]
pub static SERPENT192: Symmetric = Symmetric::new(12, 192);

/// The Serpent encryption algorithm.
#[no_mangle]
pub static SERPENT256: Symmetric = Symmetric::new(13, 256);

/// The two-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static TDEA2: Symmetric = Symmetric::new(14, 95);

/// The three-key Triple Data Encryption Algorithm as defined in
/// [SP800-67].
///
/// [SP800-67]: https://doi.org/10.6028/NIST.SP.800-67r2
#[no_mangle]
pub static TDEA3: Symmetric = Symmetric::new(15, 112);
