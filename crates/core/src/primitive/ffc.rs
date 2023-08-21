//! Finite field primitive and some common instances.
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ffc {
  pub id: u16,
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

impl Ffc {
  pub const fn new(id: u16, l: u16, n: u16) -> Self {
    Self { id, l, n }
  }
}

/// Generic instance that represents a choice of L = 1024 and N = 160
/// for a finite field cryptography primitive.
#[no_mangle]
pub static DSA_1024_160: Ffc = Ffc::new(1, 1024, 160);

/// Generic instance that represents a choice of L = 2048 and N = 224
/// for a finite field cryptography primitive.
#[no_mangle]
pub static DSA_2048_224: Ffc = Ffc::new(2, 2048, 224);

/// Generic instance that represents a choice of L = 2048 and N = 256
/// for a finite field cryptography primitive.
#[no_mangle]
pub static DSA_2048_256: Ffc = Ffc::new(3, 2048, 256);

/// Generic instance that represents a choice of L = 3072 and N = 256
/// for a finite field cryptography primitive.
#[no_mangle]
pub static DSA_3072_256: Ffc = Ffc::new(4, 3072, 256);

/// Generic instance that represents a choice of L = 7680 and N = 384
/// for a finite field cryptography primitive.
#[no_mangle]
pub static DSA_7680_384: Ffc = Ffc::new(5, 7680, 384);

/// Generic instance that represents a choice of L = 15360 and N = 512
/// for a finite field cryptography primitive.
#[no_mangle]
pub static DSA_15360_512: Ffc = Ffc::new(6, 15360, 512);

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static FFC_NOT_SUPPORTED: Ffc = Ffc::new(u16::MAX, u16::MAX, u16::MAX);
