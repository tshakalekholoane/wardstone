//! Elliptic curve primitive.
use crate::primitive::Security;

/// Represents an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ecc {
  pub id: u16,
  pub f: u16,
}

impl Ecc {
  /// Returns the security level of an elliptic curve key.
  pub fn security(&self) -> Security {
    self.f >> 1
  }
}

