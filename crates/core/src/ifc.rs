//! Integer factorisation primitive.
use crate::primitive::{Primitive, Security};

/// Represents an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ifc {
  pub k: u16,
}

impl Primitive for Ifc {
  /// Returns the approximate *minimum* security provided by a key of
  /// the size `k`.
  fn security(&self) -> Security {
    match self.k {
      ..=1023 => 0,
      1024..=2047 => 80,
      2048..=3071 => 112,
      3072..=7679 => 128,
      7680..=15359 => 192,
      15360.. => 256,
    }
  }
}
