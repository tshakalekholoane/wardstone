//! An asymmetric key primitive.
use std::fmt::{Display, Formatter, Result};

use wardstone_core::primitive::ecc::*;
use wardstone_core::primitive::ifc::*;

// Rust enums cannot be easily represented in C so this type only exists
// in this crate.
/// Represents an asymmetric key primitive.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Asymmetric {
  Ecc(Ecc),
  Ifc(Ifc),
}

impl Display for Asymmetric {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    match self {
      Asymmetric::Ecc(ecc) => ecc.fmt(f),
      Asymmetric::Ifc(ifc) => ifc.fmt(f),
    }
  }
}

impl From<Ecc> for Asymmetric {
  fn from(ecc: Ecc) -> Self {
    Self::Ecc(ecc)
  }
}

impl From<Ifc> for Asymmetric {
  fn from(ifc: Ifc) -> Self {
    Self::Ifc(ifc)
  }
}
