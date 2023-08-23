//! An asymmetric key primitive.
//!
//! This is just a thin wrapper around asymmetric key primitives defined
//! in other modules that are bridged here to avoid incompatibility with
//! C/C++.
use std::fmt::{Display, Formatter, Result};

use crate::primitive::ecc::Ecc;
use crate::primitive::ffc::Ffc;
use crate::primitive::ifc::Ifc;
use crate::primitive::{Primitive, Security};

/// Represents an asymmetric key primitive.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Asymmetric {
  Ecc(Ecc),
  Ifc(Ifc),
  Ffc(Ffc),
}

impl Primitive for Asymmetric {
  fn security(&self) -> Security {
    match self {
      Asymmetric::Ecc(ecc) => ecc.security(),
      Asymmetric::Ifc(ifc) => ifc.security(),
      Asymmetric::Ffc(ffc) => ffc.security(),
    }
  }
}

impl Display for Asymmetric {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    match self {
      Asymmetric::Ecc(ecc) => ecc.fmt(f),
      Asymmetric::Ifc(ifc) => ifc.fmt(f),
      Asymmetric::Ffc(ffc) => ffc.fmt(f),
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

impl From<Ffc> for Asymmetric {
  fn from(ffc: Ffc) -> Self {
    Self::Ffc(ffc)
  }
}
