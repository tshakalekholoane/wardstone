//! Finite field primitive.

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

