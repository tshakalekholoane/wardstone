//! Symmetric key primitive.

/// Represents a symmetric key cryptography primitive.
#[repr(C)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Symmetric {
  pub id: u16,
  pub security: u16,
}
