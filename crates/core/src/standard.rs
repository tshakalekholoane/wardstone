//! Assess the security of a cryptographic primitive against a standard
//! or research publication.
pub mod bsi;
pub mod cnsa;
pub mod ecrypt;
pub mod lenstra;
pub mod nist;
pub mod testing;
mod utilities;

use crate::context::Context;
use crate::primitive::ecc::Ecc;
use crate::primitive::ffc::Ffc;
use crate::primitive::hash::Hash;
use crate::primitive::ifc::Ifc;
use crate::primitive::symmetric::Symmetric;

/// Represents a cryptographic standard or research publication.
///
/// The functions are used to assess the validity of various
/// cryptographic primitives against the standard.
pub trait Standard {
  fn validate_ecc(ctx: Context, key: Ecc) -> Result<Ecc, Ecc>;
  fn validate_ffc(ctx: Context, key: Ffc) -> Result<Ffc, Ffc>;
  fn validate_ifc(ctx: Context, key: Ifc) -> Result<Ifc, Ifc>;
  fn validate_hash(ctx: Context, key: Hash) -> Result<Hash, Hash>;
  fn validate_symmetric(ctx: Context, key: Symmetric) -> Result<Symmetric, Symmetric>;
}
