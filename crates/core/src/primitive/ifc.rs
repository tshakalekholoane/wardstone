//! Integer factorisation primitive and some common instances.
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result};

use once_cell::sync::Lazy;

use crate::primitive::{Primitive, Security};

/// Represents an integer factorisation cryptography primitive the most
/// common of which is the RSA signature algorithm where k indicates the
/// key size.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ifc {
  pub id: u16,
  pub k: u16,
}

impl Ifc {
  pub const fn new(id: u16, k: u16) -> Self {
    Self { id, k }
  }
}

// The name is kept in a lookup table instead of being embedded in the
// type because sharing strings across language boundaries is a bit
// dicey.
static REPR: Lazy<HashMap<Ifc, &str>> = Lazy::new(|| {
  let mut m = HashMap::new();
  m.insert(IFC_1024, "ifc1024");
  m
});

impl Display for Ifc {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    let unrecognised = "unrecognised";
    let name = REPR.get(self).unwrap_or(&unrecognised);
    write!(f, "{name}")
  }
}

impl Primitive for Ifc {
  /// Returns the approximate *minimum* security provided by a key of
  /// the size `k`.
  fn security(&self) -> Security {
    match self.k {
      ..=1023 => 0,
      1024..=2047 => 80,
      2048..=3071 => 112,
      3072..=7679 => 128,
      7680..=15359 => 192,
      15360.. => 256,
    }
  }
}

/// Generic instance that represents a choice of k = 1024 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1024: Ifc = Ifc::new(65526, 1024);

/// Generic instance that represents a choice of k = 1280 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1280: Ifc = Ifc::new(65527, 1280);

/// Generic instance that represents a choice of k = 1536 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_1536: Ifc = Ifc::new(65528, 1536);

/// Generic instance that represents a choice of k = 2048 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_2048: Ifc = Ifc::new(65529, 2048);

/// Generic instance that represents a choice of k = 3072 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_3072: Ifc = Ifc::new(65530, 3072);

/// Generic instance that represents a choice of k = 4096 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_4096: Ifc = Ifc::new(65531, 4096);

/// Generic instance that represents a choice of k = 7680 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_7680: Ifc = Ifc::new(65532, 7680);

/// Generic instance that represents a choice of k = 8192 for an integer
/// factorisation cryptography primitive.
#[no_mangle]
pub static IFC_8192: Ifc = Ifc::new(65533, 8192);

/// Generic instance that represents a choice of k = 15360 for an
/// integer factorisation cryptography primitive.
#[no_mangle]
pub static IFC_15360: Ifc = Ifc::new(65534, 15360);

/// Placeholder for use in where this primitive is not supported.
#[no_mangle]
pub static IFC_NOT_SUPPORTED: Ifc = Ifc::new(u16::MAX, u16::MAX);
