//! Finite field primitive.
use crate::primitive::{Primitive, Security};

/// Represents a finite field cryptography primitive used to implement
/// discrete logarithm cryptography.
///
/// The choices l and n represents the bit lengths of the prime modulus
/// p and the prime divisor q.
///
/// Some of the primitives that fall under this category include
/// signature algorithms such as DSA and key establishment algorithms
/// such as Diffie-Hellman and MQV.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ffc {
  pub l: u16,
  pub n: u16,
}

impl Primitive for Ffc {
  /// The security of a finite field cryptography primitive defined as
  /// the minimum of the (L, N) pair where the hash function used
  /// provides at least the same level of security.
  fn security(&self) -> Security {
    // FIPS-186-4 cites that the security strength associated with the
    // DSA digital signature process is no greater than the minimum of
    // the security strength of the (L, N) pair (2013, p. 15). The
    // public keys are usually the shorter of the two and this value is
    // divided by 2 to produce the security value (see page 54 of
    // SP-800-57 Part 1 Rev. 5).
    self.l.min(self.n) >> 1
  }
}
