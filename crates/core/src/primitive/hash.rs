//! Hash function primitive.
use crate::primitive::{Primitive, Security};

/// Represents a hash or hash-based function cryptographic primitive
/// where `id` is a unique identifier and `n` the digest length.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Hash {
  pub id: u16,
  pub n: u16,
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
