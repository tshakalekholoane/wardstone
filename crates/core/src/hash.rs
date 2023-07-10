//! Hash function primitive.

/// Represents a hash or hash-based function cryptographic primitive
/// where `id` is a unique identifier and `n` the digest length.
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Hash {
  pub id: u16,
  pub n: u16,
}

impl Hash {
  /// Returns the collision resistance strength of a hash function.
  ///
  /// For an L-bit hash function, the expected security strength for
  /// collision resistance is L/2 bits. See page 6 of NIST SP-800-107
  /// for details.
  pub fn collision_resistance(&self) -> u16 {
    self.n >> 1
  }

  /// Returns the pre-image resistance strength of a hash function.
  ///
  /// For an L-bit hash function, the expected security strength for
  /// pre-image resistance is L bits. See page 7 of NIST SP-800-107 for
  /// details.
  pub fn pre_image_resistance(&self) -> u16 {
    self.n
  }
}
