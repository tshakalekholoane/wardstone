//! Specifies a cryptographic primitive.
pub mod asymmetric;
pub mod ecc;
pub mod ffc;
pub mod hash;
pub mod ifc;
pub mod symmetric;

/// The level of security of a symmetric cryptosystem which is a
/// standard measure used to assess the security of all other
/// cryptographic primitives.
pub type Security = u16;

/// Represents a cryptographic primitive.
pub trait Primitive {
  fn security(&self) -> Security;
}
