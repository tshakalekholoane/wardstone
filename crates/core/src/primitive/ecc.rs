//! Elliptic curve primitive.
use crate::primitive::{Primitive, Security};

/// Represents an elliptic curve cryptography primitive used for digital
/// signatures and key establishment where f is the key size (the size
/// of n, where n is the order of the base point G).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ecc {
  pub id: u16,
  pub f: u16,
}

impl Primitive for Ecc {
  /// Returns the security level of an elliptic curve key (which is
  /// approximately len(n)/2).
  fn security(&self) -> Security {
    self.f >> 1
  }
}
