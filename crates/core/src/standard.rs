//! Assess primitives against a cryptographic standard or research
//! publication.
use crate::context::Context;
use crate::ecc::Ecc;
use crate::ffc::Ffc;
use crate::hash::Hash;
use crate::ifc::Ifc;
use crate::symmetric::Symmetric;

/// Represents a cryptographic standard or research publication.
///
/// The functions are used to assess the validity of various
/// cryptographic primitives against the standard.
pub trait Standard {
  fn validate_ecc(ctx: &Context, key: &Ecc) -> Result<Ecc, Ecc>;
  fn validate_ffc(ctx: &Context, key: &Ffc) -> Result<Ffc, Ffc>;
  fn validate_ifc(ctx: &Context, key: &Ifc) -> Result<Ifc, Ifc>;
  fn validate_hash(ctx: &Context, key: &Hash) -> Result<Hash, Hash>;
  fn validate_symmetric(ctx: &Context, key: &Symmetric) -> Result<Symmetric, Symmetric>;
}
