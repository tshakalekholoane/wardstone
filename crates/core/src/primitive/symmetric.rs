//! Symmetric key primitive.
use crate::primitive::{Primitive, Security};

/// Represents a symmetric key cryptography primitive.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Symmetric {
  pub id: u16,
  pub security: u16,
}

impl Primitive for Symmetric {
  /// Indicates the security provided by a symmetric key primitive.
  fn security(&self) -> Security {
    self.security
  }
}
